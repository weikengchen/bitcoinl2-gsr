//! End-to-end spends of tapscript leaf version 0xc2 (BIP 440/441) in the simulator.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, UntweakedPublicKey};
use bitcoin::opcodes::all::*;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, WitnessProgram};
use bitcoin_scriptexec::v2;
use bitcoin_simulator::database::Database;

fn v2_leaf() -> LeafVersion {
    LeafVersion::from_consensus(v2::TAPROOT_LEAF_TAPSCRIPT_V2).unwrap()
}

fn nums() -> UntweakedPublicKey {
    // BIP 341 NUMS point H
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".parse().unwrap()
}

struct Leaf {
    script: ScriptBuf,
    spk: ScriptBuf,
    control_block: Vec<u8>,
}

fn leaf(script: ScriptBuf) -> Leaf {
    let secp = Secp256k1::new();
    let info = TaprootBuilder::new()
        .add_leaf_with_ver(0, script.clone(), v2_leaf())
        .unwrap()
        .finalize(&secp, nums())
        .unwrap();
    let spk = ScriptBuf::new_witness_program(&WitnessProgram::p2tr(&secp, nums(), info.merkle_root()));
    let control_block = info.control_block(&(script.clone(), v2_leaf())).unwrap().serialize();
    Leaf { script, spk, control_block }
}

fn fund(db: &Database, spk: &ScriptBuf, sats: u64) -> (OutPoint, TxOut) {
    let out = TxOut { value: Amount::from_sat(sats), script_pubkey: spk.clone() };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([7; 32]), sats as u32),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![out.clone()],
    };
    db.insert_transaction_unconditionally(&tx).unwrap();
    (OutPoint::new(tx.compute_txid(), 0), out)
}

fn spend(inputs: &[OutPoint]) -> Transaction {
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
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_op_return([0x42; 4]),
        }],
    }
}

fn witness(items: &[Vec<u8>], leaf: &Leaf) -> Witness {
    let mut w = Witness::new();
    for i in items {
        w.push(i);
    }
    w.push(leaf.script.as_bytes());
    w.push(&leaf.control_block);
    w
}

/// `<pk> CHECKSIGVERIFY MUL <a*b> EQUAL` with 40-byte operands.
#[test]
fn checksig_and_bignum_mul() {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32]).unwrap());
    let (pk, _) = keypair.x_only_public_key();
    let a = vec![0xff; 40];
    let b = vec![0xfe; 40];
    let product = v2::mul(&a, &b);
    assert_eq!(product.len(), 80);

    let script = Builder::new()
        .push_x_only_key(&pk)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_MUL)
        .push_slice(PushBytesBuf::try_from(product).unwrap())
        .push_opcode(OP_EQUAL)
        .into_script();
    let leaf = leaf(script);

    let db = Database::connect_temporary_database().unwrap();
    let (outpoint, prevout) = fund(&db, &leaf.spk, 100_000);
    let mut tx = spend(&[outpoint]);

    let sign = |tx: &Transaction, version: LeafVersion| {
        let leaf_hash = TapLeafHash::from_script(&leaf.script, version);
        let sighash = SighashCache::new(tx.clone())
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout.clone()]),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        secp.sign_schnorr_no_aux_rand(&msg, &keypair).as_ref().to_vec()
    };

    // A signature over the 0xc0 leaf hash does not verify for a 0xc2 leaf.
    let bad_sig = sign(&tx, LeafVersion::TapScript);
    tx.input[0].witness = witness(&[a.clone(), b.clone(), bad_sig], &leaf);
    assert!(db.verify_transaction(&tx).is_err());

    let sig = sign(&tx, v2_leaf());
    tx.input[0].witness = witness(&[a.clone(), vec![0xfd; 40], sig.clone()], &leaf);
    assert!(db.verify_transaction(&tx).is_err(), "wrong product must fail");

    tx.input[0].witness = witness(&[a, b, sig], &leaf);
    db.verify_transaction(&tx).unwrap();

    // The output is spent once, then never again.
    db.insert_transaction_unconditionally(&tx).unwrap();
    let err = db.verify_transaction(&tx).unwrap_err();
    assert!(err.to_string().contains("already been spent"), "{err}");
}

/// `rounds` x (DUP SHA256 DROP), then leave SIZE of the element; optionally NIP padding first.
fn heavy_leaf(rounds: usize, drop_padding: bool) -> Leaf {
    let mut b = Builder::new();
    if drop_padding {
        b = b.push_opcode(OP_NIP);
    }
    for _ in 0..rounds {
        b = b.push_opcode(OP_DUP).push_opcode(OP_SHA256).push_opcode(OP_DROP);
    }
    leaf(b.push_opcode(OP_SIZE).push_opcode(OP_NIP).into_script())
}

/// The varops budget is `weight * 10,000` for the whole transaction.
#[test]
fn varops_budget_is_shared_by_inputs() {
    // 400 x (DUP SHA256 DROP) on 2,000 bytes = 400 * (2,000 * 3 + 2,000 * 50) = 42,400,000 varops.
    let heavy = heavy_leaf(400, false);
    let data = vec![0x11; 2_000];

    let db = Database::connect_temporary_database().unwrap();
    let (o1, _) = fund(&db, &heavy.spk, 50_000);
    let (o2, _) = fund(&db, &heavy.spk, 60_000);

    // One input weighs ~3,400 WU, i.e. ~34,000,000 varops: not enough.
    let mut one = spend(&[o1]);
    one.input[0].witness = witness(&[data.clone()], &heavy);
    assert!(one.weight().to_wu() * 10_000 < 42_400_000);
    let err = db.verify_transaction(&one).unwrap_err();
    assert!(err.to_string().contains("VaropCount"), "{err}");

    // Two such inputs: the budget is transaction-wide, still not enough for both.
    let mut two = spend(&[o1, o2]);
    two.input[0].witness = witness(&[data.clone()], &heavy);
    two.input[1].witness = witness(&[data.clone()], &heavy);
    assert!(two.weight().to_wu() * 10_000 < 2 * 42_400_000);
    let err = db.verify_transaction(&two).unwrap_err();
    assert!(err.to_string().contains("VaropCount"), "{err}");

    // The same work passes once the transaction carries enough weight (6,000 bytes of padding).
    let padded = heavy_leaf(400, true);
    let (o3, _) = fund(&db, &padded.spk, 70_000);
    let mut ok = spend(&[o3]);
    ok.input[0].witness = witness(&[vec![0x22; 6_000], data], &padded);
    assert!(ok.weight().to_wu() * 10_000 > 42_400_000);
    db.verify_transaction(&ok).unwrap();
}

/// OP_TX (0xbd): a leaf that requires output 0 to pay exactly 1,000 sats to a
/// given script; a future selector version makes the leaf succeed at once.
#[test]
fn op_tx_covenant() {
    let db = Database::connect_temporary_database().unwrap();
    let target = ScriptBuf::new_op_return([0x42; 4]);
    // output 0 (SINGLE scope, operand 0 below the selector): amount, scriptPubKey
    let selector = [0x00, 0x00, 0x00, 0x03, 0x00, 0x03];
    let covenant = leaf(
        Builder::new()
            .push_opcode(OP_PUSHBYTES_0)
            .push_slice(selector)
            .push_opcode(OP_RETURN_189) // OP_TX
            .push_slice(PushBytesBuf::try_from(target.to_bytes()).unwrap())
            .push_opcode(OP_EQUALVERIFY)
            .push_slice([0xe8, 0x03]) // 1,000
            .push_opcode(OP_EQUAL)
            .into_script(),
    );
    let (o, _) = fund(&db, &covenant.spk, 5_000);
    let mut ok = spend(&[o]);
    ok.input[0].witness = witness(&[], &covenant);
    db.verify_transaction(&ok).unwrap();
    let mut bad = ok.clone();
    bad.output[0].value = Amount::from_sat(999);
    assert!(db.verify_transaction(&bad).unwrap_err().to_string().contains("EvalFalse"));

    // selector version 1: validation succeeds whatever follows
    let future = leaf(Builder::new().push_opcode(OP_PUSHNUM_1).push_opcode(OP_RETURN_189).push_opcode(OP_RETURN).into_script());
    let (o, _) = fund(&db, &future.spk, 5_001);
    let mut tx = spend(&[o]);
    tx.input[0].witness = witness(&[], &future);
    db.verify_transaction(&tx).unwrap();
}
