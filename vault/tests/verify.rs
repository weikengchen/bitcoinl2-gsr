//! Locking the vault for a withdrawal proof, completing, and timing out
//! (design §7, §8.4). The proof is a placeholder: the operator signs the
//! completion. A rejected case runs the vault input on its own and checks the
//! failing rule; each has an honest control.

mod common;

use bitcoin::key::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, ScriptBuf, TxOut};
use bitcoinl2_vault::state::{AppState, Lock, Mode, Params};
use bitcoinl2_vault::tx::{Plan, Vault, Withdrawal};
use common::{deposit, rejects, Line, World};

/// Lock height (the lock transaction's nLockTime).
const H: u32 = 800_000;
const BOND: u64 = 20_000;
const LOCKER: [u8; 32] = [0x4c; 32];

/// The locker's refund address.
fn refund(w: &World) -> ScriptBuf {
    w.wallet.spk()
}

/// A batch of three 43-byte withdrawals paying 5,000 sats in total.
fn withdrawal() -> Withdrawal {
    Withdrawal { amount: Amount::from_sat(5_000), root: [0x52; 32], list: vec![0x57; 3 * 43] }
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
    w.vault.complete(p, &withdrawal(), refund, new_params())
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
    let p = w.vault.complete(p, &withdrawal(), refund(&w), new_params());
    let tx = Line::build(&w, &normal.a, &p);
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

    // only the operator's signature stands in for the proof
    let other = Keypair::from_seckey_slice(&Secp256k1::new(), &[8; 32]).unwrap();
    let tx = {
        let mut x = w.vault.build_complete(&ok, &other);
        w.wallet.sign(&mut x, 1, &ok.fee_prevout);
        x
    };
    rejects(&tx, &Vault::prevouts(&ok), 0, "SchnorrSig");
    // the withdrawal goes to program b
    let mut p = complete_plan(&mut w, &line);
    p.extra_outputs[0].script_pubkey = w.wallet.spk();
    check(&w, &p, "EqualVerify");
    // the published list is the one the OP_RETURN commits to
    let mut p = complete_plan(&mut w, &line);
    p.hints.extra[1] = vec![0x58; 3 * 43];
    check(&w, &p, "EqualVerify");
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
    let p = w.vault.complete(p, &withdrawal(), w.b.script_pubkey(), new_params());
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
    let p = w.vault.complete(p, &withdrawal(), vault_spk, new_params());
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
