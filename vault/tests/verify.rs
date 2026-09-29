//! Locking the vault for a withdrawal proof, completing, and timing out
//! (design §7, §8.4). The proof is a placeholder: the franker signs the
//! completion. A rejected case runs the vault input on its own and checks the
//! failing rule; each has an honest control.

mod common;

use bitcoin::key::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use bitcoinl2_vault::state::{AppState, Lock, Mode, Params};
use bitcoinl2_vault::da::{chain_hash, Change, DaData};
use bitcoinl2_vault::program_b::SplitTree;
use bitcoinl2_vault::tx::{Batch, Plan, Vault};
use bitcoinl2_vault::verifier::{Franker, Statement};
use common::{deposit, rejects, Line, World};

/// Lock height (the lock transaction's nLockTime).
const H: u32 = 800_000;
const BOND: u64 = 20_000;
const LOCKER: [u8; 32] = [0x4c; 32];

/// The locker's refund address.
fn refund(w: &World) -> ScriptBuf {
    w.wallet.spk()
}

/// A proven batch: DA data with two withdrawals and three changed accounts,
/// the split tree of the withdrawals (one split of 2,000 + 2,500 sats plus
/// the 500-sat split fee), and a new L2 state root.
fn batch(w: &World) -> Batch {
    let payout = |sats| TxOut { value: Amount::from_sat(sats), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) };
    let da = DaData {
        withdrawals: vec![payout(2_000), payout(2_500)],
        new_accounts: vec![[0x61; 32]],
        changes: vec![
            Change { index: 0, balance: 7_000, nonce: 3 },
            Change { index: 5, balance: 0, nonce: 9 },
            Change { index: 6, balance: 1_000, nonce: 0 },
        ],
    };
    let tree = SplitTree::from_da(&da, w.franker.fan_out, w.franker.split_fee, &w.b.script_pubkey());
    assert_eq!(tree.root().value, Amount::from_sat(5_000));
    Batch { amount: tree.root().value, root: tree.root().root(), da: da.encode(), l2_root: [0x5f; 32], params: new_params() }
}

/// A completion franked without the franker's checks, with its fee input signed.
fn careless(w: &World, p: &Plan) -> Transaction {
    let mut x = w.vault.build_complete_with(p, |tx| w.franker.sign(&w.vault, p, tx)).unwrap();
    w.wallet.sign(&mut x, 1, &p.fee_prevout);
    x
}

fn new_params() -> Params {
    Params { b_min: 15_000, n: 100 }
}

/// A lock at `height` with `bond`, paid from the locker's fee input.
fn lock_with(w: &mut World, line: &Line, height: u32, bond: u64, refund: &ScriptBuf) -> Plan {
    let p = line.plan(w, vec![]);
    let mut p = w.vault.lock(p, height, Amount::from_sat(bond), LOCKER, refund);
    p.change.value -= Amount::from_sat(bond);
    p
}

fn lock_plan(w: &mut World, line: &Line) -> Plan {
    let refund = refund(w);
    lock_with(w, line, H, BOND, &refund)
}

/// A line locked at height H.
fn locked(w: &mut World) -> Line {
    let mut line = Line::new(w);
    w.db.set_height(H + 1);
    let p = lock_plan(w, &line);
    line.accept(w, &p);
    line
}

fn complete_plan(w: &mut World, line: &Line) -> Plan {
    let p = line.plan(w, vec![]);
    let refund = refund(w);
    w.vault.complete(p, &batch(w), refund)
}

/// Lock, complete (withdraw, refund the bond, new parameters), and carry on.
#[test]
fn lock_then_complete() {
    let mut w = World::new(0);
    let mut line = Line::new(&mut w);
    let before = line.balance();
    w.db.set_height(H + 1);
    let p = lock_plan(&mut w, &line);
    let x = line.accept(&w, &p);
    eprintln!("lock weighs {} WU ({} vB)", x.weight().to_wu(), x.vsize());
    assert_eq!(line.balance(), before + BOND);
    assert!(matches!(line.app.mode, Mode::Verifying(Lock { height: H, bond: BOND, locker: LOCKER, .. })));

    let p = complete_plan(&mut w, &line);
    let x = line.accept(&w, &p);
    eprintln!("completion weighs {} WU ({} vB)", x.weight().to_wu(), x.vsize());
    assert_eq!(line.balance(), before - 5_000);
    assert_eq!(x.output[2], TxOut { value: Amount::from_sat(5_000), script_pubkey: w.b.script_pubkey() });
    assert_eq!(x.output[4], TxOut { value: Amount::from_sat(BOND), script_pubkey: refund(&w) });
    assert_eq!(line.app.mode, Mode::Normal);
    assert_eq!(line.app.params, new_params());
    assert_eq!(line.app.l2_root, batch(&w).l2_root);

    // the vault carries on: a fold, then a lock under the new B_min
    let d = deposit(&mut w, &line.a, &[10_000]);
    let p = line.plan(&mut w, d);
    line.accept(&w, &p);
    let refund_spk = refund(&w);
    let low = lock_with(&mut w, &line, H, BOND - 6_000, &refund_spk);
    let tx = Line::build(&w, &line.a, &low);
    rejects(&tx, &Vault::prevouts(&low), 0, "Verify");
    let p = lock_plan(&mut w, &line);
    line.accept(&w, &p);
}

/// Lock rules on the vault input.
#[test]
fn lock_rules() {
    let mut w = World::new(0);
    let line = Line::new(&mut w);
    w.db.set_height(H + 1);
    let check = |w: &World, p: &Plan, want: &str| {
        let tx = Line::build(w, &line.a, p);
        rejects(&tx, &Vault::prevouts(p), 0, want);
    };

    let ok = lock_plan(&mut w, &line);
    let tx = Line::build(&w, &line.a, &ok);
    w.db.verify_transaction(&tx).unwrap();
    // nLockTime H is final only from height H + 1
    w.db.set_height(H);
    assert!(w.db.verify_transaction(&tx).unwrap_err().to_string().contains("not final"));
    w.db.set_height(H + 1);

    // the bond is at least B_min
    let refund_spk = refund(&w);
    let p = lock_with(&mut w, &line, H, 9_999, &refund_spk);
    check(&w, &p, "Verify");
    // the vault grows by exactly the recorded bond
    let mut p = lock_plan(&mut w, &line);
    p.successor.value -= Amount::from_sat(1);
    check(&w, &p, "NumEqualVerify");
    // h is a height, not a time
    let p = lock_with(&mut w, &line, 500_000_000, BOND, &refund_spk);
    check(&w, &p, "Verify");
    // the state records h = nLockTime
    let mut p = lock_plan(&mut w, &line);
    p.lock_time = H - 1;
    check(&w, &p, "EqualVerify");
}

/// While VERIFYING, the vault only completes or times out.
#[test]
fn locked_vault_is_frozen() {
    let mut w = World::new(0);
    let line = locked(&mut w);
    let check = |w: &World, p: &Plan| {
        let tx = Line::build(w, &line.a, p);
        rejects(&tx, &Vault::prevouts(p), 0, "NumEqualVerify"); // the old application state's length
    };
    let p = lock_plan(&mut w, &line);
    check(&w, &p);
    let p = line.plan(&mut w, vec![]);
    check(&w, &p);
    let d = deposit(&mut w, &line.a, &[10_000]);
    let p = line.plan(&mut w, d);
    check(&w, &p);

    // and a completion needs a locked vault
    let normal = Line::new(&mut w);
    let mut p = normal.plan(&mut w, vec![]);
    let fake = Lock { height: H, bond: 1_000, locker: LOCKER, refund_hash: [0; 32] };
    p.set_app(AppState { mode: Mode::Verifying(fake), ..p.new_app });
    let p = w.vault.complete(p, &batch(&w), refund(&w));
    let tx = careless(&w, &p);
    rejects(&tx, &Vault::prevouts(&p), 0, "NumEqualVerify");
}

/// Completion rules on the vault input.
#[test]
fn complete_rules() {
    let mut w = World::new(0);
    let line = locked(&mut w);
    let check = |w: &World, p: &Plan, want: &str| {
        let tx = Line::build(w, &line.a, p);
        rejects(&tx, &Vault::prevouts(p), 0, want);
    };

    let ok = complete_plan(&mut w, &line);
    w.db.verify_transaction(&Line::build(&w, &line.a, &ok)).unwrap();

    // only the franker's signature stands in for the proof
    let other = Franker { key: Keypair::from_seckey_slice(&Secp256k1::new(), &[8; 32]).unwrap(), ..w.franker.clone() };
    let tx = {
        let mut x = w.vault.build_complete(&ok, &other).unwrap();
        w.wallet.sign(&mut x, 1, &ok.fee_prevout);
        x
    };
    rejects(&tx, &Vault::prevouts(&ok), 0, "SchnorrSig");
    // the withdrawal goes to program b
    let mut p = complete_plan(&mut w, &line);
    p.extra_outputs[0].script_pubkey = w.wallet.spk();
    check(&w, &p, "EqualVerify");
    // the published DA data is the one the OP_RETURN commits to
    // (the franker refuses such a batch, so sign without its checks)
    let mut p = complete_plan(&mut w, &line);
    p.hints.extra[1] = vec![0x58; 3 * 43];
    assert!(w.vault.build_complete(&p, &w.franker).is_err());
    rejects(&careless(&w, &p), &Vault::prevouts(&p), 0, "EqualVerify");
    // the vault pays out exactly W + bond
    let mut p = complete_plan(&mut w, &line);
    p.successor.value -= Amount::from_sat(1);
    check(&w, &p, "NumEqualVerify");
    // the whole bond goes back ...
    let mut p = complete_plan(&mut w, &line);
    p.extra_outputs[2].value -= Amount::from_sat(1);
    check(&w, &p, "EqualVerify");
    // ... to the recorded refund address
    let p = line.plan(&mut w, vec![]);
    let p = w.vault.complete(p, &batch(&w), w.b.script_pubkey());
    check(&w, &p, "EqualVerify");
}

/// A refund address equal to P would put a second P output in the completion
/// and freeze the vault (the next transition's parse forbids it): the
/// completion is rejected, and the lock can only time out.
#[test]
fn refund_to_the_vault_is_rejected() {
    let mut w = World::new(0);
    let mut line = Line::new(&mut w);
    w.db.set_height(H + 1);
    let vault_spk = w.vault.script_pubkey();
    let p = lock_with(&mut w, &line, H, BOND, &vault_spk);
    line.accept(&w, &p);

    let p = line.plan(&mut w, vec![]);
    let p = w.vault.complete(p, &batch(&w), vault_spk);
    let tx = Line::build(&w, &line.a, &p);
    rejects(&tx, &Vault::prevouts(&p), 0, "Verify");

    w.db.set_height(H + 145);
    let p = line.plan(&mut w, vec![]);
    let p = w.vault.timeout(p, H + 144);
    line.accept(&w, &p);
    assert_eq!(line.app.mode, Mode::Normal);
}

/// Timeout: from height h + N anyone returns the vault to NORMAL; the bond stays in it.
#[test]
fn timeout() {
    let mut w = World::new(0);
    let mut line = locked(&mut w);
    let balance = line.balance();
    let n = World::app0().params.n;

    // before h + N: nLockTime too low for CLTV, or not final yet
    let p = line.plan(&mut w, vec![]);
    let early = w.vault.timeout(p, H + n - 1);
    let tx = Line::build(&w, &line.a, &early);
    rejects(&tx, &Vault::prevouts(&early), 0, "UnsatisfiedLocktime");
    let p = line.plan(&mut w, vec![]);
    let p = w.vault.timeout(p, H + n);
    let tx = Line::build(&w, &line.a, &p);
    w.db.set_height(H + n);
    assert!(w.db.verify_transaction(&tx).unwrap_err().to_string().contains("not final"));
    w.db.set_height(H + n + 1);
    w.db.verify_transaction(&tx).unwrap();

    // the bond stays, the parameters stay
    let p = line.plan(&mut w, vec![]);
    let mut take = w.vault.timeout(p, H + n);
    take.successor.value -= Amount::from_sat(BOND);
    take.change.value += Amount::from_sat(BOND);
    let tx = Line::build(&w, &line.a, &take);
    rejects(&tx, &Vault::prevouts(&take), 0, "NumEqualVerify");
    let p = line.plan(&mut w, vec![]);
    let mut params = w.vault.timeout(p, H + n);
    params.set_app(AppState { params: new_params(), ..params.new_app });
    let tx = Line::build(&w, &line.a, &params);
    rejects(&tx, &Vault::prevouts(&params), 0, "EqualVerify");
    let p = line.plan(&mut w, vec![]);
    let mut root = w.vault.timeout(p, H + n);
    root.set_app(AppState { l2_root: [0x03; 32], ..root.new_app });
    let tx = Line::build(&w, &line.a, &root);
    rejects(&tx, &Vault::prevouts(&root), 0, "EqualVerify");

    let p = line.plan(&mut w, vec![]);
    let p = w.vault.timeout(p, H + n);
    let x = line.accept(&w, &p);
    eprintln!("timeout weighs {} WU ({} vB)", x.weight().to_wu(), x.vsize());
    assert_eq!(line.balance(), balance);
    assert_eq!(line.app.mode, Mode::Normal);
    assert_eq!(line.app.params, World::app0().params);

    // lock again and complete
    let p = lock_plan(&mut w, &line);
    line.accept(&w, &p);
    let p = complete_plan(&mut w, &line);
    line.accept(&w, &p);
}

/// The placeholder verifier: the statement is read off the completion, and the
/// franker refuses batches whose R or W do not come from the published
/// withdrawal list, or whose DA data is malformed.
#[test]
fn franker_checks_the_statement() {
    let mut w = World::new(0);
    let line = locked(&mut w);

    let p = complete_plan(&mut w, &line);
    let x = w.vault.build_complete(&p, &w.franker).unwrap();
    let stmt = Statement::of_completion(&p, &x).unwrap();
    let b = batch(&w);
    assert_eq!(stmt.vault_id, line.id);
    assert_eq!(stmt.acc, p.new_app.acc);
    assert_eq!(stmt.l2_root, World::app0().l2_root);
    assert_eq!((stmt.new_l2_root, stmt.new_params), (b.l2_root, b.params));
    assert_eq!((stmt.amount, stmt.split_root, stmt.da_hash), (b.amount, b.root, chain_hash(&[&b.da])));
    assert_eq!(stmt.encode().len(), 212);

    let refuse = |w: &mut World, b: Batch, why: &str| {
        let p = line.plan(w, vec![]);
        let p = w.vault.complete(p, &b, refund(w));
        let e = w.vault.build_complete(&p, &w.franker).unwrap_err().to_string();
        assert!(e.contains(why), "{e}");
    };
    let wrong_root = Batch { root: [0x52; 32], ..batch(&w) };
    refuse(&mut w, wrong_root, "R is not");
    let wrong_amount = Batch { amount: Amount::from_sat(5_001), ..batch(&w) };
    refuse(&mut w, wrong_amount, "W is not");
    let mut da = batch(&w).da;
    da.push(0);
    let malformed = Batch { da, ..batch(&w) };
    refuse(&mut w, malformed, "trailing bytes");
}
