//! End-to-end tests of the gadgets in the simulator (tapscript v2).

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_simulator::database::Database;
use gsr_gadgets::leaf::{assert_no_op_success, V2Tree};
use gsr_gadgets::pseudo::*;
use gsr_gadgets::schnorr::{schnorr_trick_hints, SchnorrTrickGadget};
use gsr_gadgets::sighash::{Field, SighashAllData, SighashAllGadget};
use gsr_gadgets::tx::{tx_hints, TxBuildGadget, TxField};
use gsr_gadgets::Script;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn op(o: bitcoin::opcodes::Opcode) -> Script {
    Builder::new().push_opcode(o).into_script()
}

struct Wallet {
    sk: SecretKey,
    pk: CompressedPublicKey,
}

impl Wallet {
    fn new() -> Self {
        let sk = SecretKey::from_slice(&[9; 32]).unwrap();
        let pk = CompressedPublicKey(PublicKey::from_secret_key(&Secp256k1::new(), &sk));
        Self { sk, pk }
    }
    fn spk(&self) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&self.pk.wpubkey_hash())
    }
    fn sign(&self, tx: &mut Transaction, idx: usize, prevout: &TxOut) {
        let h = SighashCache::new(tx.clone())
            .p2wpkh_signature_hash(idx, &prevout.script_pubkey, prevout.value, EcdsaSighashType::All)
            .unwrap();
        let sig = Secp256k1::new().sign_ecdsa(&Message::from(h), &self.sk);
        let sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };
        tx.input[idx].witness = Witness::p2wpkh(&sig, &self.pk.0);
    }
}

fn tx(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|o| TxIn {
                previous_output: *o,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    }
}

fn out(sats: u64, spk: &ScriptBuf) -> TxOut {
    TxOut { value: Amount::from_sat(sats), script_pubkey: spk.clone() }
}

/// Fill in input 0's covenant witness, lowering the change (output 1) until
/// the Schnorr trick works, then sign the fee input 1.
fn finalize(
    x: &mut Transaction,
    prevouts: &[TxOut],
    tree: &V2Tree,
    wallet: &Wallet,
    extra_hints: &[Vec<u8>],
) {
    loop {
        let data = SighashAllData::new(x, prevouts, 0, tree.leaf_hash(0));
        if let Ok(trick) = schnorr_trick_hints(&data.preimage()) {
            let mut hints = data.hints();
            hints.extend(trick);
            hints.extend(extra_hints.iter().cloned());
            x.input[0].witness = tree.witness(0, &hints);
            break;
        }
        x.output[1].value -= Amount::from_sat(1);
    }
    wallet.sign(x, 1, &prevouts[1]);
}

#[test]
fn sighash_matches_rust_bitcoin() {
    let mut prng = ChaCha20Rng::seed_from_u64(1);
    let spks: Vec<ScriptBuf> = (0..3)
        .map(|i| ScriptBuf::from_bytes((0..(20 + 7 * i)).map(|_| prng.gen()).collect()))
        .collect();
    let prevouts: Vec<TxOut> = spks.iter().map(|s| out(prng.gen_range(1_000..1_000_000), s)).collect();
    let inputs: Vec<OutPoint> =
        (0..3).map(|i| OutPoint::new(bitcoin::Txid::from_byte_array(prng.gen()), i)).collect();
    let mut x = tx(&inputs, spks.iter().map(|s| out(prng.gen_range(1..1_000), s)).collect());
    x.lock_time = LockTime::from_consensus(123_456);
    let leaf = ScriptBuf::from_bytes(vec![0x51]);
    let leaf_hash = bitcoin::TapLeafHash::from_script(&leaf, gsr_gadgets::leaf::leaf_version());
    for idx in 0..3 {
        let expected = SighashCache::new(x.clone())
            .taproot_script_spend_signature_hash(idx, &Prevouts::All(&prevouts), leaf_hash, TapSighashType::All)
            .unwrap();
        let data = SighashAllData::new(&x, &prevouts, idx, leaf_hash);
        assert_eq!(data.sighash(), expected.to_byte_array());
    }
}

#[test]
fn op_success_guard() {
    // script! turns the byte 0x81 into OP_1NEGATE, which is OP_SUCCESS79 in tapscript v2
    let bad = Builder::new().push_opcode(OP_PUSHNUM_NEG1).into_script();
    assert!(assert_no_op_success(&bad).is_err());
    assert!(V2Tree::new(vec![bad]).is_err());
    // push_data keeps it a data push
    assert!(assert_no_op_success(&push_data(&[0x81])).is_ok());
    for leaf in [self_replicating_leaf(), reflecting_leaf()] {
        assert_no_op_success(&leaf).unwrap();
    }
}

/// Output 0 must repeat input 0: same amount and same scriptPubKey.
fn self_replicating_leaf() -> Script {
    let (n, m) = (2, 2);
    let d = |f| SighashAllGadget::depth(n, m, f);
    cat(&[
        SighashAllGadget::build(n, m, 0, 2),
        SchnorrTrickGadget::verify(),
        pick(d(Field::Amount(0))),
        pick(d(Field::ScriptPubKey(0)) + 1),
        op(OP_CAT),
        pick(d(Field::Output(0)) + 1),
        op(OP_EQUALVERIFY),
        drop_n(SighashAllGadget::items(n, m)),
        op(OP_PUSHNUM_1),
    ])
}

#[test]
fn self_replicating_covenant() {
    let wallet = Wallet::new();
    let tree = V2Tree::new(vec![self_replicating_leaf()]).unwrap();
    let p = tree.script_pubkey.clone();
    let db = Database::connect_temporary_database().unwrap();

    let dummy = |i| OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), i);
    let f = tx(&[dummy(0), dummy(1)], vec![out(10_000, &p), out(50_000, &wallet.spk())]);
    db.insert_transaction_unconditionally(&f).unwrap();
    let prevouts = [f.output[0].clone(), f.output[1].clone()];
    let ins = [OutPoint::new(f.compute_txid(), 0), OutPoint::new(f.compute_txid(), 1)];

    // Keeping the covenant's amount passes.
    let mut x = tx(&ins, vec![out(10_000, &p), out(49_000, &wallet.spk())]);
    finalize(&mut x, &prevouts, &tree, &wallet, &[]);
    db.verify_transaction(&x).unwrap();

    // Taking 1,000 sats out of the covenant fails at the covenant check.
    let mut bad = tx(&ins, vec![out(9_000, &p), out(50_000, &wallet.spk())]);
    finalize(&mut bad, &prevouts, &tree, &wallet, &[]);
    let err = db.verify_transaction(&bad).unwrap_err().to_string();
    assert!(err.contains("Some(EqualVerify)"), "{err}");

    // Hints describing another transaction (here: a different lock time), with
    // a challenge recomputed to match them, fail at CHECKSIGVERIFY: the trick
    // binds the rebuilt message to the real transaction.
    let mut other = x.clone();
    other.lock_time = LockTime::from_consensus(7);
    let (hints, trick) = loop {
        let data = SighashAllData::new(&other, &prevouts, 0, tree.leaf_hash(0));
        if let Ok(trick) = schnorr_trick_hints(&data.preimage()) {
            break (data.hints(), trick);
        }
        other.lock_time = LockTime::from_consensus(other.lock_time.to_consensus_u32() + 1);
    };
    let mut forged = x.clone();
    forged.input[0].witness = tree.witness(0, &[hints, trick].concat());
    let err = db.verify_transaction(&forged).unwrap_err().to_string();
    assert!(err.contains("Some(SchnorrSig)"), "{err}");
}

/// Also rebuild the parent transaction: its txid must be input 0's outpoint
/// and its output 0 must equal this transaction's output 0.
fn reflecting_leaf() -> Script {
    let (n, m) = (2, 2);
    let d = |f| SighashAllGadget::depth(n, m, f);
    let t = TxBuildGadget::items(2, 2);
    cat(&[
        SighashAllGadget::build(n, m, 0, 2),
        SchnorrTrickGadget::verify(),
        TxBuildGadget::build(2, 2),
        pick(d(Field::Outpoint(0)) + t + 1),
        push_u64(32),
        op(OP_LEFT),
        op(OP_EQUALVERIFY),
        pick(TxBuildGadget::depth(2, 2, TxField::Output(0))),
        pick(d(Field::Output(0)) + t + 1),
        op(OP_EQUALVERIFY),
        drop_n(t + SighashAllGadget::items(n, m)),
        op(OP_PUSHNUM_1),
    ])
}

#[test]
fn parent_reflection_chain() {
    let wallet = Wallet::new();
    let tree = V2Tree::new(vec![reflecting_leaf()]).unwrap();
    let p = tree.script_pubkey.clone();
    let db = Database::connect_temporary_database().unwrap();

    let dummy = |i| OutPoint::new(bitcoin::Txid::from_byte_array([2; 32]), i);
    let f = tx(&[dummy(0), dummy(1)], vec![out(10_000, &p), out(50_000, &wallet.spk())]);
    db.insert_transaction_unconditionally(&f).unwrap();

    let mut parent = f;
    for step in 0..3 {
        let prevouts = [parent.output[0].clone(), parent.output[1].clone()];
        let ins = [OutPoint::new(parent.compute_txid(), 0), OutPoint::new(parent.compute_txid(), 1)];
        let change = parent.output[1].value.to_sat() - 1_000;
        let mut x = tx(&ins, vec![out(10_000, &p), out(change, &wallet.spk())]);
        finalize(&mut x, &prevouts, &tree, &wallet, &tx_hints(&parent));
        db.verify_transaction(&x).unwrap_or_else(|e| panic!("step {step}: {e}"));

        // Hints of a different parent do not reflect.
        let mut other = parent.clone();
        other.lock_time = LockTime::from_consensus(1);
        let mut wrong = tx(&ins, vec![out(10_000, &p), out(change, &wallet.spk())]);
        finalize(&mut wrong, &prevouts, &tree, &wallet, &tx_hints(&other));
        let err = db.verify_transaction(&wrong).unwrap_err().to_string();
        assert!(err.contains("Some(EqualVerify)"), "{err}");

        db.insert_transaction_unconditionally(&x).unwrap();
        parent = x;
    }
}
