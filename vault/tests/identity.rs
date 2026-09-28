//! Identity and linearity of the vault (spec §10–§11), following
//! docs/spec/.../verification-cases.md. Runs in the simulator.

mod common;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut};
use bitcoinl2_vault::state::{caboose, Phase, State};
use bitcoinl2_vault::tx::{input, Vault};
use common::{err, World};

/// G01, G09, A08: genesis, first transition, and continuations; id = txid(T0) forever.
#[test]
fn lineage() {
    let mut w = World::new(10);
    let (t0, s0) = w.genesis();
    let a0 = World::app0();

    let p1 = w.plan_f(&t0, &s0, &a0);
    let t1 = w.accept(&p1);
    assert_eq!(p1.new_state.phase, Phase::Active { genesis_id: t0.compute_txid().to_byte_array() });
    assert_eq!(p1.new_app.acc, a0.next(t0.compute_txid()).acc);

    let (mut parent, mut grand, mut s, mut a) = (t1, t0.clone(), p1.new_state, p1.new_app);
    for _ in 0..3 {
        let p = w.plan(&parent, &grand, &s, &a);
        let x = w.accept(&p);
        assert_eq!(p.new_state.phase, Phase::Active { genesis_id: t0.compute_txid().to_byte_array() });
        (grand, parent, s, a) = (parent, x, p.new_state, p.new_app);
    }
    eprintln!(
        "leaf {} bytes; a transition weighs {} WU ({} vB)",
        w.vault.tree.scripts[0].len(),
        parent.weight().to_wu(),
        parent.vsize()
    );
}

/// 11.3: a vault output is spent once; a second successor of the same output is rejected.
#[test]
fn single_successor() {
    let mut w = World::new(10);
    let (t0, s0) = w.genesis();
    let p1 = w.plan_f(&t0, &s0, &World::app0());
    w.accept(&p1);
    let again = w.plan_f(&t0, &s0, &World::app0());
    assert!(err(w.check(&again)).contains("already been spent"));
}

/// G03, G04: ordinary funds create P with a copied (or arbitrary) ACTIVE state.
#[test]
fn counterfeit_active_output() {
    let mut w = World::new(10);
    let (t0, _) = w.genesis();
    let real_id = t0.compute_txid().to_byte_array();
    for id in [real_id, [0x77; 32]] {
        let a = World::app0();
        let fake = State { phase: Phase::Active { genesis_id: id }, app_root: a.root() };
        let (coin, prevout) = w.coin();
        let mut c = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input(coin)],
            output: vec![
                TxOut { value: Amount::from_sat(20_000), script_pubkey: w.vault.script_pubkey() },
                caboose(&fake, 0),
            ],
        };
        w.wallet.sign(&mut c, 0, &prevout);
        w.db.insert_transaction_unconditionally(&c).unwrap();

        // keep the copied id (the attacker's goal) ...
        let mut p = w.plan_f(&c, &fake, &a);
        p.new_state.phase = Phase::Active { genesis_id: id };
        p.hints.new_state = p.new_state.encode();
        assert!(w.check(&p).is_err());
        // ... or take the fresh id: the old state is still not GENESIS.
        let p = w.plan_f(&c, &fake, &a);
        assert!(w.check(&p).is_err());
    }
}

/// G02: T0 must have exactly one input.
#[test]
fn genesis_with_two_inputs() {
    let mut w = World::new(10);
    let (c1, o1) = w.coin();
    let (c2, o2) = w.coin();
    let a = World::app0();
    let (mut t0, s0) = w.vault.genesis_tx(c1, Amount::from_sat(20_000), &a, vec![w.wallet.out(179_000)]);
    t0.input.push(input(c2));
    w.wallet.sign(&mut t0, 0, &o1);
    w.wallet.sign(&mut t0, 1, &o2);
    w.db.insert_transaction_unconditionally(&t0).unwrap();
    let p = w.plan_f(&t0, &s0, &a);
    assert!(w.check(&p).is_err());
}

/// G05, G06: the first transition must write txid(T0) into an ACTIVE state.
#[test]
fn first_transition_identity() {
    let mut w = World::new(10);
    let (t0, s0) = w.genesis();
    let a0 = World::app0();

    let mut wrong_id = w.plan_f(&t0, &s0, &a0);
    wrong_id.new_state.phase = Phase::Active { genesis_id: [0x55; 32] };
    wrong_id.hints.new_state = wrong_id.new_state.encode();
    assert!(w.check(&wrong_id).is_err());

    let mut still_genesis = w.plan_f(&t0, &s0, &a0);
    still_genesis.new_state.phase = Phase::Genesis;
    still_genesis.hints.new_state = still_genesis.new_state.encode();
    assert!(w.check(&still_genesis).is_err());

    let ok = w.plan_f(&t0, &s0, &a0);
    w.check(&ok).unwrap();
}

/// G08, acc rule, mode, E04: a continuation keeps the id, follows the acc rule,
/// and commits to exactly the state it reveals.
#[test]
fn continuation_rules() {
    let mut w = World::new(20);
    let (t0, s0) = w.genesis();
    let a0 = World::app0();
    let p1 = w.plan_f(&t0, &s0, &a0);
    let t1 = w.accept(&p1);
    let honest = |w: &mut World| w.plan(&t1, &t0, &p1.new_state, &p1.new_app);

    let mut changed_id = honest(&mut w);
    changed_id.new_state.phase = Phase::Active { genesis_id: [0x01; 32] };
    changed_id.hints.new_state = changed_id.new_state.encode();
    assert!(w.check(&changed_id).is_err());

    let mut bad_acc = honest(&mut w);
    bad_acc.new_app.acc = [0x02; 32];
    bad_acc.new_state.app_root = bad_acc.new_app.root();
    bad_acc.hints.new_app = bad_acc.new_app.encode();
    bad_acc.hints.new_state = bad_acc.new_state.encode();
    assert!(w.check(&bad_acc).is_err());

    let mut bad_mode = honest(&mut w);
    bad_mode.new_app.mode = 1;
    bad_mode.new_state.app_root = bad_mode.new_app.root();
    bad_mode.hints.new_app = bad_mode.new_app.encode();
    bad_mode.hints.new_state = bad_mode.new_state.encode();
    assert!(w.check(&bad_mode).is_err());

    // E04: reveal a state other than the committed one
    let mut mismatch = honest(&mut w);
    let mut other = mismatch.new_state;
    other.app_root = [0x03; 32];
    mismatch.hints.new_state = other.encode();
    assert!(w.check(&mismatch).is_err());

    let ok = honest(&mut w);
    w.check(&ok).unwrap();
}

/// L02, L04, L06 and VALUE: position and uniqueness of the main program, and its amount.
#[test]
fn positions_and_amounts() {
    let mut w = World::new(20);
    let (t0, s0) = w.genesis();
    let a0 = World::app0();
    let honest = |w: &mut World| w.plan_f(&t0, &s0, &a0);

    let mut second_p = honest(&mut w);
    second_p.change.script_pubkey = w.vault.script_pubkey();
    assert!(w.check(&second_p).is_err());

    let mut other_spk = honest(&mut w);
    other_spk.successor.script_pubkey = w.wallet.spk();
    assert!(w.check(&other_spk).is_err());

    let mut less = honest(&mut w);
    less.successor.value = Amount::from_sat(19_000);
    assert!(w.check(&less).is_err());

    // L02: a P output at index 1 cannot be spent
    let (coin, prevout) = w.coin();
    let mut t = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(coin)],
        output: vec![
            w.wallet.out(1_000),
            TxOut { value: Amount::from_sat(20_000), script_pubkey: w.vault.script_pubkey() },
            caboose(&s0, 0),
        ],
    };
    w.wallet.sign(&mut t, 0, &prevout);
    w.db.insert_transaction_unconditionally(&t).unwrap();
    let mut at_one = w.plan_f(&t, &s0, &a0);
    at_one.vault_in = OutPoint::new(t.compute_txid(), 1);
    at_one.vault_prevout = t.output[1].clone();
    at_one.successor = t.output[1].clone();
    assert!(w.check(&at_one).is_err());

    let ok = honest(&mut w);
    w.check(&ok).unwrap();
}

/// A01, A04, A06: ancestors must be the real ones.
#[test]
fn ancestors_are_authenticated() {
    let mut w = World::new(20);
    let (t0, s0) = w.genesis();
    let a0 = World::app0();
    let p1 = w.plan_f(&t0, &s0, &a0);
    let t1 = w.accept(&p1);
    let honest = |w: &mut World| w.plan(&t1, &t0, &p1.new_state, &p1.new_app);

    // A01: another parent than the one referenced by input 0
    let mut wrong_parent = honest(&mut w);
    wrong_parent.hints.parent = gsr_gadgets::parse::tx_blob(&t0);
    assert!(w.check(&wrong_parent).is_err());

    // A04 / A06: a grandparent that pretends T spent a P output
    let mut wrong_grand = honest(&mut w);
    wrong_grand.hints.grandparent = gsr_gadgets::parse::tx_blob(&t1);
    assert!(w.check(&wrong_grand).is_err());

    // the old state must be the one committed by the parent's caboose
    let mut wrong_old = honest(&mut w);
    wrong_old.hints.old_state = s0.encode();
    assert!(w.check(&wrong_old).is_err());

    let ok = honest(&mut w);
    w.check(&ok).unwrap();
}

/// G10: a clone of P with its own genesis is a different instance.
#[test]
fn clone_gets_its_own_id() {
    let mut w = World::new(20);
    let (t0, s0) = w.genesis();
    let (u0, r0) = w.genesis();
    let a0 = World::app0();
    let p = w.plan_f(&t0, &s0, &a0);
    let q = w.plan_f(&u0, &r0, &a0);
    w.accept(&p);
    w.accept(&q);
    assert_ne!(p.new_state.phase, q.new_state.phase);
}

#[test]
fn leaf_has_no_op_success() {
    let v = Vault::new().unwrap();
    gsr_gadgets::leaf::assert_no_op_success(&v.tree.scripts[0]).unwrap();
    let _ = TxIn::default();
}
