//! Deposits (design §6): a_L outputs are merged and folded into the vault.
//! Runs in the simulator. A rejected case runs the a input on its own and checks
//! the failing rule, so it cannot pass for a bad signature; each has an honest control.

mod common;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, ScriptHash, Transaction, TxOut};
use bitcoin_simulator::spending_requirements::P2TRChecker;
use bitcoinl2_vault::program_a::{AShape, Deposit, ProgramA, Source, MAX_A_INPUTS, MAX_DEPOSIT_INPUTS};
use bitcoinl2_vault::state::{caboose, Phase, State};
use bitcoinl2_vault::tx::{input, op_return, Vault};
use common::{aggregator_out, deposit, rejects, Line, World, AGGREGATOR};

/// Merge `inputs` with `a` and accept it; returns the new a output.
fn merge(w: &mut World, a: &ProgramA, inputs: &[(OutPoint, TxOut)]) -> (OutPoint, TxOut) {
    let fee = w.fee_coin();
    let change = w.wallet.out(fee.1.value.to_sat() - 1_000);
    let mut m = a.merge_tx(inputs, fee.0, change, AGGREGATOR);
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
    let mut tx = progs[0].merge_unsigned(inputs, fee.0, change, AGGREGATOR);
    edit(&mut tx);
    for i in shape.a_inputs() {
        let a = progs.iter().find(|a| a.script_pubkey() == prevouts[i].script_pubkey).unwrap();
        tx.input[i].witness = a.witness(shape, None);
    }
    if fee.1.script_pubkey == w.wallet.spk() {
        w.wallet.sign(&mut tx, inputs.len(), &fee.1);
    }
    (tx, prevouts)
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
    // exactly three outputs
    let fee = w.fee_coin();
    let extra = w.wallet.out(1_000);
    let (tx, prevouts) = merge_edited(&mut w, &[a], two, fee, |tx| tx.output.push(extra.clone()));
    rejects(&tx, &prevouts, 0, "EqualVerify");
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
    let mut tx = w.vault.build_with(&plan, |_| line.a.witness(AShape::Fold(1), Some(&other)));
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
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(coin), input(d[0].0), input(fee)],
        output: vec![
            w.wallet.out(coin_out.value.to_sat() + 10_000),
            w.wallet.out(fee_out.value.to_sat() - 1_000),
            aggregator_out(),
            caboose(&fake, 0),
        ],
    };
    let mut tx = line.a.sign(AShape::Fold(1), &tx, Some(&fake));
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

/// A merge's change and fee input are native segwit: the change cannot carry
/// the deposit tag (which would pass the merged total off as a deposit to
/// whoever the tag names), and the fee input cannot bring a scriptSig.
#[test]
fn merge_change_and_fee_are_native_segwit() {
    let mut w = World::new(0);
    let line = Line::new(&mut w);
    let a = &line.a;
    let d = deposit(&mut w, a, &[10_000, 20_000]);

    let fee = w.fee_coin();
    let (ok, _) = merge_edited(&mut w, &[a], &d, fee, |_| {});
    w.db.verify_transaction(&ok).unwrap();

    let tag = a.deposit_outputs(Amount::ZERO, &[0xee; 32])[1].script_pubkey.clone();
    let fee = w.fee_coin();
    let (tx, prevouts) = merge_edited(&mut w, &[a], &d, fee, |tx| tx.output[1].script_pubkey = tag.clone());
    rejects(&tx, &prevouts, 0, "Verify");

    let (coin, mut p2sh) = w.fee_coin();
    p2sh.script_pubkey = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([7; 20]));
    let (tx, prevouts) = merge_edited(&mut w, &[a], &d, (coin, p2sh), |_| {});
    rejects(&tx, &prevouts, 0, "Verify");
}

/// The deposit format, and how a tracer tells a deposit from a merge.
#[test]
fn deposit_format_and_classification() {
    let mut w = World::new(0);
    let line = Line::new(&mut w);
    let a = &line.a;
    let (coin, _) = w.fee_coin();
    let r = [0x42; 32];
    let change = w.wallet.out(50_000);
    let ok = a.deposit_tx(&[coin], Amount::from_sat(10_000), &r, Some(change.clone()));
    let dep = Deposit { amount: Amount::from_sat(10_000), recipient: r };
    assert_eq!(a.deposit_of(&ok), Some(dep));
    assert_eq!(a.classify(&ok, 0), Source::Deposit(dep));
    assert_eq!(a.classify(&ok, 2), Source::Unattributed); // only output 0 is the deposit
    assert_eq!(a.deposit_of(&a.deposit_tx(&[coin; 8], Amount::from_sat(10_000), &r, None)), Some(dep));

    let edits: Vec<Box<dyn Fn(&mut Transaction)>> = vec![
        Box::new(|tx| tx.output.push(change.clone())),                         // a fourth output
        Box::new(|tx| tx.output[2] = op_return(vec![1])),                      // change not native segwit
        Box::new(|tx| tx.output[0].script_pubkey = change.script_pubkey.clone()), // output 0 is not a_L
        Box::new(|tx| tx.output[1] = op_return(vec![0; 36])),                  // no tag
        Box::new(|tx| tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51])), // a scriptSig
        Box::new(|tx| tx.input = vec![tx.input[0].clone(); MAX_DEPOSIT_INPUTS + 1]), // too many inputs
    ];
    for edit in edits {
        let mut tx = ok.clone();
        edit(&mut tx);
        assert_eq!(a.deposit_of(&tx), None);
        assert_eq!(a.classify(&tx, 0), Source::Unattributed);
    }

    // a merge in the merge template, with its a inputs to trace next
    let d = deposit(&mut w, a, &[10_000, 20_000, 30_000]);
    let fee = w.fee_coin();
    let (m, _) = merge_edited(&mut w, &[a], &d, fee, |_| {});
    assert_eq!(a.classify(&m, 0), Source::Merge(3));
}
