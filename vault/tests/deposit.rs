//! Deposits (design §6): a_L outputs are merged and folded into the vault.
//! Runs in the simulator. A rejected case runs the a input on its own and checks
//! the failing rule, so it cannot pass for a bad signature; each has an honest control.

mod common;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use bitcoin_simulator::spending_requirements::P2TRChecker;
use bitcoinl2_vault::program_a::{AShape, ProgramA, MAX_A_INPUTS};
use bitcoinl2_vault::state::{caboose, AppState, Phase, State};
use bitcoinl2_vault::tx::{input, Plan, Vault};
use common::World;

const AGGREGATOR: &[u8] = b"aggregator L2 address";

fn aggregator_out() -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(PushBytesBuf::try_from(AGGREGATOR.to_vec()).unwrap()),
    }
}

/// A vault line after its first transition, and its deposit program a_L.
struct Line {
    id: [u8; 32],
    a: ProgramA,
    grand: Transaction,
    parent: Transaction,
    state: State,
    app: AppState,
}

impl Line {
    fn new(w: &mut World) -> Self {
        let (t0, s0) = w.genesis();
        let a0 = World::app0();
        let p1 = w.plan_f(&t0, &s0, &a0);
        let t1 = w.accept(&p1);
        let id = t0.compute_txid().to_byte_array();
        let a = ProgramA::new(id, &w.vault.script_pubkey()).unwrap();
        Self { id, a, grand: t0, parent: t1, state: p1.new_state, app: p1.new_app }
    }

    fn balance(&self) -> u64 {
        self.parent.output[0].value.to_sat()
    }

    /// The honest plan folding `deposits` (a plain transition if there are none).
    fn plan(&self, w: &mut World, deposits: Vec<(OutPoint, TxOut)>) -> Plan {
        let p = w.plan(&self.parent, &self.grand, &self.state, &self.app);
        if deposits.is_empty() {
            p
        } else {
            w.vault.with_deposits(p, deposits, aggregator_out())
        }
    }

    /// `plan` with `a` signing the deposit inputs and the wallet the fee input.
    fn build(w: &World, a: &ProgramA, plan: &Plan) -> Transaction {
        let mut x = if plan.deposits.is_empty() { w.vault.build(plan) } else { a.fold_tx(&w.vault, plan) };
        let fee = x.input.len() - 1;
        w.wallet.sign(&mut x, fee, &plan.fee_prevout);
        x
    }

    fn accept(&mut self, w: &World, plan: &Plan) -> Transaction {
        let x = Self::build(w, &self.a, plan);
        w.db.verify_transaction(&x).unwrap();
        w.db.insert_transaction_unconditionally(&x).unwrap();
        self.grand = std::mem::replace(&mut self.parent, x.clone());
        self.state = plan.new_state;
        self.app = plan.new_app;
        x
    }
}

/// One deposit transaction paying each of `values` to `a`, each a output followed
/// by its recipient OP_RETURN. Returns the a outputs.
fn deposit(w: &mut World, a: &ProgramA, values: &[u64]) -> Vec<(OutPoint, TxOut)> {
    let (coin, prevout) = w.fee_coin();
    let mut output = vec![];
    for (i, v) in values.iter().enumerate() {
        output.extend(a.deposit_outputs(Amount::from_sat(*v), &[i as u8 + 1; 20]));
    }
    let total: u64 = values.iter().sum();
    output.push(w.wallet.out(prevout.value.to_sat() - total - 1_000));
    let mut d = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![input(coin)], output };
    w.wallet.sign(&mut d, 0, &prevout);
    w.db.verify_transaction(&d).unwrap();
    w.db.insert_transaction_unconditionally(&d).unwrap();
    let txid = d.compute_txid();
    (0..values.len()).map(|i| (OutPoint::new(txid, 2 * i as u32), d.output[2 * i].clone())).collect()
}

/// Merge `inputs` with `a` and accept it; returns the new a output.
fn merge(w: &mut World, a: &ProgramA, inputs: &[(OutPoint, TxOut)]) -> (OutPoint, TxOut) {
    let fee = w.fee_coin();
    let change = w.wallet.out(fee.1.value.to_sat() - 1_000);
    let mut m = a.merge_tx(inputs, fee.clone(), change, AGGREGATOR);
    w.wallet.sign(&mut m, inputs.len(), &fee.1);
    w.db.verify_transaction(&m).unwrap();
    eprintln!("merge of {} weighs {} WU ({} vB)", inputs.len(), m.weight().to_wu(), m.vsize());
    w.db.insert_transaction_unconditionally(&m).unwrap();
    (OutPoint::new(m.compute_txid(), 0), m.output[0].clone())
}

/// A merge of `inputs` changed by `edit` before signing. Each a input is signed
/// by the program in `progs` whose address it spends. Returns the transaction
/// and its prevouts.
fn merge_edited(
    w: &mut World,
    progs: &[&ProgramA],
    inputs: &[(OutPoint, TxOut)],
    fee: (OutPoint, TxOut),
    edit: impl Fn(&mut Transaction),
) -> (Transaction, Vec<TxOut>) {
    let shape = AShape::Merge(inputs.len());
    let mut prevouts: Vec<TxOut> = inputs.iter().map(|x| x.1.clone()).collect();
    prevouts.push(fee.1.clone());
    let change = w.wallet.out(fee.1.value.to_sat() - 1_000);
    let mut tx = (0u32..)
        .find_map(|nonce| {
            let mut tx = progs[0].merge_unsigned(inputs, fee.0, change.clone(), AGGREGATOR, nonce);
            edit(&mut tx);
            for i in shape.a_inputs() {
                let a = progs.iter().find(|a| a.script_pubkey() == prevouts[i].script_pubkey).unwrap();
                tx.input[i].witness = a.witness(shape, &tx, &prevouts, i, None)?;
            }
            Some(tx)
        })
        .unwrap();
    if fee.1.script_pubkey == w.wallet.spk() {
        w.wallet.sign(&mut tx, inputs.len(), &fee.1);
    }
    (tx, prevouts)
}

/// Input `idx` fails inside its script with `want`.
fn rejects(tx: &Transaction, prevouts: &[TxOut], idx: usize, want: &str) {
    let e = P2TRChecker::check(tx, prevouts, idx).expect_err("the input must be rejected").to_string();
    assert!(e.contains(&format!("Some({want})")), "input {idx}: {e}");
}

/// Deposit, merge twice (recursively), fold into the vault, and keep going.
#[test]
fn deposit_merge_fold() {
    let mut w = World::new(0);
    let mut line = Line::new(&mut w);
    let d = deposit(&mut w, &line.a, &[10_000, 20_000, 25_000, 35_000]);
    let m1 = merge(&mut w, &line.a, &d[0..2]);
    assert_eq!(m1.1.value.to_sat(), 30_000);
    let m2 = merge(&mut w, &line.a, &[m1, d[2].clone()]);
    assert_eq!(m2.1.value.to_sat(), 55_000);

    let before = line.balance();
    let old_app = line.app;
    let parent = line.parent.compute_txid();
    let plan = line.plan(&mut w, vec![m2, d[3].clone()]);
    let x = line.accept(&w, &plan);
    assert_eq!(line.balance(), before + 90_000);
    assert_eq!(line.state.phase, Phase::Active { genesis_id: line.id });
    assert_eq!(line.app, old_app.next(parent));

    // the next transition reflects the fold transaction as its parent
    let plan = line.plan(&mut w, vec![]);
    line.accept(&w, &plan);
    assert_eq!(line.balance(), before + 90_000);
    assert_eq!(line.app, old_app.next(parent).next(x.compute_txid()));
}

/// Every leaf: merges of 2..=4 and folds of 1..=4 a outputs.
#[test]
fn every_shape() {
    let mut w = World::new(0);
    let mut line = Line::new(&mut w);
    let d = deposit(&mut w, &line.a, &[1_000; 9]);
    let m2 = merge(&mut w, &line.a, &d[0..2]);
    let m3 = merge(&mut w, &line.a, &d[2..5]);
    let m4 = merge(&mut w, &line.a, &d[5..9]);
    let e = deposit(&mut w, &line.a, &[1_000; 7]);
    let before = line.balance();
    let folds = [vec![m2], vec![m3, e[0].clone()], vec![m4, e[1].clone(), e[2].clone()], e[3..7].to_vec()];
    for f in folds {
        let plan = line.plan(&mut w, f);
        let x = line.accept(&w, &plan);
        eprintln!("fold of {} weighs {} WU ({} vB)", plan.deposits.len(), x.weight().to_wu(), x.vsize());
    }
    assert_eq!(line.balance(), before + 16_000);
    let plan = line.plan(&mut w, vec![]);
    line.accept(&w, &plan);

    assert_eq!(line.a.shapes.len(), 2 * MAX_A_INPUTS - 1);
    for (i, shape) in line.a.shapes.iter().enumerate() {
        eprintln!("a leaf {shape:?}: {} bytes", line.a.tree.scripts[i].len());
    }
}

/// Merge rules, each on input 0 (an a input), against an honest control.
#[test]
fn merge_rules() {
    let mut w = World::new(0);
    let line = Line::new(&mut w);
    let a = &line.a;
    let d = deposit(&mut w, a, &[10_000, 20_000, 30_000]);
    let two = &d[0..2];

    let fee = w.fee_coin();
    let (ok, _) = merge_edited(&mut w, &[a], two, fee, |_| {});
    w.db.verify_transaction(&ok).unwrap();

    // out0 must be exactly the total, no less and no more
    for delta in [-1i64, 1] {
        let fee = w.fee_coin();
        let (tx, prevouts) = merge_edited(&mut w, &[a], two, fee, |tx| {
            tx.output[0].value = Amount::from_sat((30_000 + delta) as u64);
        });
        rejects(&tx, &prevouts, 0, "NumEqualVerify");
        assert!(w.db.verify_transaction(&tx).is_err());
    }
    // out0 must pay a_L
    let wallet_spk = w.wallet.spk();
    let fee = w.fee_coin();
    let (tx, prevouts) = merge_edited(&mut w, &[a], two, fee, |tx| tx.output[0].script_pubkey = wallet_spk.clone());
    rejects(&tx, &prevouts, 0, "EqualVerify");
    // no second a_L output
    let a_spk = a.script_pubkey();
    let fee = w.fee_coin();
    let (tx, prevouts) = merge_edited(&mut w, &[a], two, fee, |tx| tx.output[1].script_pubkey = a_spk.clone());
    rejects(&tx, &prevouts, 0, "Verify");
    // the fee input (last) must not be an a output
    let (tx, prevouts) = merge_edited(&mut w, &[a], two, d[2].clone(), |_| {});
    rejects(&tx, &prevouts, 0, "Verify");
}

/// a outputs of different L2s do not merge with each other.
#[test]
fn merge_is_per_l2() {
    let mut w = World::new(0);
    let one = Line::new(&mut w);
    let two = Line::new(&mut w);
    assert_ne!(one.a.script_pubkey(), two.a.script_pubkey());
    let x = deposit(&mut w, &one.a, &[10_000, 10_000]);
    let y = deposit(&mut w, &two.a, &[10_000]);

    let fee = w.fee_coin();
    let (ok, _) = merge_edited(&mut w, &[&one.a], &x, fee, |_| {});
    w.db.verify_transaction(&ok).unwrap();

    let fee = w.fee_coin();
    let (tx, prevouts) = merge_edited(&mut w, &[&one.a, &two.a], &[x[0].clone(), y[0].clone()], fee, |_| {});
    rejects(&tx, &prevouts, 0, "EqualVerify");
    rejects(&tx, &prevouts, 1, "EqualVerify");
}

/// Fold rules, each on input 1 (an a input), against an honest control.
#[test]
fn fold_rules() {
    let mut w = World::new(0);
    let line = Line::new(&mut w);
    let clone = Line::new(&mut w); // same P, its own id
    let d = deposit(&mut w, &line.a, &[10_000, 20_000]);
    let e = deposit(&mut w, &clone.a, &[10_000]);

    let honest = line.plan(&mut w, d[0..1].to_vec());
    let ok = Line::build(&w, &line.a, &honest);
    w.db.verify_transaction(&ok).unwrap();

    // a_L folds only into the vault with id L: the clone vault's own leaf is
    // satisfied, a_L's is not
    let plan = clone.plan(&mut w, d[1..2].to_vec());
    let tx = Line::build(&w, &line.a, &plan);
    P2TRChecker::check(&tx, &Vault::prevouts(&plan), 0).unwrap();
    rejects(&tx, &Vault::prevouts(&plan), 1, "EqualVerify");
    // ... and another L2's a does not fold into this vault
    let plan = line.plan(&mut w, e.clone());
    let tx = Line::build(&w, &clone.a, &plan);
    P2TRChecker::check(&tx, &Vault::prevouts(&plan), 0).unwrap();
    rejects(&tx, &Vault::prevouts(&plan), 1, "EqualVerify");

    // the change must not be a new a_L output (the vault's leaf allows any segwit change)
    let mut plan = line.plan(&mut w, d[0..1].to_vec());
    plan.change.script_pubkey = line.a.script_pubkey();
    let tx = Line::build(&w, &line.a, &plan);
    P2TRChecker::check(&tx, &Vault::prevouts(&plan), 0).unwrap();
    rejects(&tx, &Vault::prevouts(&plan), 1, "Verify");

    // the vault must grow by exactly the a total
    let mut plan = line.plan(&mut w, d[0..1].to_vec());
    plan.successor.value -= Amount::from_sat(1);
    let tx = Line::build(&w, &line.a, &plan);
    rejects(&tx, &Vault::prevouts(&plan), 1, "NumEqualVerify");

    // the revealed S' must be the one in the caboose
    let plan = line.plan(&mut w, d[0..1].to_vec());
    let mut other = plan.new_state;
    other.app_root = [0x33; 32];
    let prevouts = Vault::prevouts(&plan);
    let mut tx = w.vault.build_with(&plan, |tx, i| line.a.witness(AShape::Fold(1), tx, &prevouts, i, Some(&other)));
    w.wallet.sign(&mut tx, 2, &plan.fee_prevout);
    rejects(&tx, &prevouts, 1, "EqualVerify");
}

/// Input 0 of a fold must be the vault P: an ordinary output with a caboose
/// that claims id L cannot collect a deposit.
#[test]
fn fold_needs_the_vault() {
    let mut w = World::new(0);
    let line = Line::new(&mut w);
    let d = deposit(&mut w, &line.a, &[10_000]);
    let (coin, coin_out) = w.fee_coin();
    let (fee, fee_out) = w.fee_coin();
    let fake = State { phase: Phase::Active { genesis_id: line.id }, app_root: [0x44; 32] };
    let prevouts = vec![coin_out.clone(), d[0].1.clone(), fee_out.clone()];
    let mut tx = (0u32..)
        .find_map(|r| {
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![input(coin), input(d[0].0), input(fee)],
                output: vec![
                    w.wallet.out(coin_out.value.to_sat() + 10_000),
                    w.wallet.out(fee_out.value.to_sat() - 1_000),
                    aggregator_out(),
                    caboose(&fake, r),
                ],
            };
            line.a.sign(AShape::Fold(1), &tx, &prevouts, Some(&fake))
        })
        .unwrap();
    w.wallet.sign(&mut tx, 0, &coin_out);
    w.wallet.sign(&mut tx, 2, &fee_out);
    rejects(&tx, &prevouts, 1, "EqualVerify");
    assert!(w.db.verify_transaction(&tx).is_err());
}

#[test]
fn a_leaves_have_no_op_success() {
    let a = ProgramA::new([0x81; 32], &ScriptBuf::new()).unwrap();
    for s in &a.tree.scripts {
        gsr_gadgets::leaf::assert_no_op_success(s).unwrap();
    }
}
