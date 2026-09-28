//! TxParse against rust-bitcoin on random transactions, and malformed inputs.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_scriptexec::{eval_tapscript_v2, ExecError};
use gsr_gadgets::parse::{parse_tx, tx_blob, TxParse};
use gsr_gadgets::stack::Stk;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const CFG: TxParse = TxParse { max_inputs: 4, max_outputs: 5, sequence: None };

fn random_tx(prng: &mut ChaCha20Rng, n_in: usize, n_out: usize) -> Transaction {
    Transaction {
        version: Version(prng.gen_range(1..3)),
        lock_time: LockTime::from_consensus(prng.gen()),
        input: (0..n_in)
            .map(|_| TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array(prng.gen()), prng.gen()),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(prng.gen()),
                witness: Witness::new(),
            })
            .collect(),
        output: (0..n_out)
            .map(|_| {
                let len = prng.gen_range(0..120);
                TxOut {
                    value: Amount::from_sat(prng.gen_range(0..u64::MAX >> 1)),
                    script_pubkey: ScriptBuf::from_bytes((0..len).map(|_| prng.gen()).collect()),
                }
            })
            .collect(),
    }
}

/// Run the parser with k and forbid on the stack: `forbid k tx`.
fn run(blob: Vec<u8>, k: u32, forbid: Vec<u8>, cfg: &TxParse) -> Result<Vec<Vec<u8>>, ExecError> {
    let mut s = Stk::new(&["forbid", "k", "tx"]);
    parse_tx(&mut s, "tx", "t", cfg, Some("k"), Some("forbid"));
    let res = eval_tapscript_v2(s.script(), vec![forbid, bitcoin_scriptexec::v2::from_u64(k as u64), blob], None);
    match res.error {
        Some(e) => Err(e),
        None => {
            assert_eq!(res.final_stack.len(), s.names().len());
            Ok(res.final_stack)
        }
    }
}

#[test]
fn matches_rust_bitcoin() {
    let mut prng = ChaCha20Rng::seed_from_u64(7);
    for round in 0..60 {
        let n_in = 1 + round % 4;
        let n_out = 1 + round % 5;
        let tx = random_tx(&mut prng, n_in, n_out);
        let k = prng.gen_range(0..n_out) as u32;
        let stack = run(tx_blob(&tx), k, vec![0xaa; 3], &CFG).unwrap();
        // forbid k | txid version n_in in0 n_out out0 out_k last lock_time
        let got = &stack[2..];
        assert_eq!(got[0], tx.compute_txid().to_byte_array().to_vec());
        assert_eq!(got[1], serialize(&tx.version));
        assert_eq!(got[2], vec![n_in as u8]);
        assert_eq!(got[3], serialize(&tx.input[0].previous_output));
        assert_eq!(got[4], vec![n_out as u8]);
        assert_eq!(got[5], serialize(&tx.output[0]));
        assert_eq!(got[6], serialize(&tx.output[k as usize]));
        assert_eq!(got[7], serialize(tx.output.last().unwrap()));
        assert_eq!(got[8], tx.lock_time.to_consensus_u32().to_le_bytes().to_vec());
    }
}

#[test]
fn rejects_malformed() {
    let mut prng = ChaCha20Rng::seed_from_u64(8);
    let tx = random_tx(&mut prng, 2, 3);
    let blob = tx_blob(&tx);
    assert!(run(blob.clone(), 0, vec![0xaa], &CFG).is_ok());

    // trailing byte / truncated
    let mut longer = blob.clone();
    longer.push(0);
    assert!(run(longer, 0, vec![0xaa], &CFG).is_err());
    assert!(run(blob[..blob.len() - 1].to_vec(), 0, vec![0xaa], &CFG).is_err());

    // non-empty scriptSig on input 1
    let mut t = tx.clone();
    t.input[1].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    assert!(run(serialize(&t), 0, vec![0xaa], &CFG).is_err());

    // witness serialization (marker 0x00 as input count)
    let mut t = tx.clone();
    t.input[0].witness.push([1u8]);
    assert!(run(serialize(&t), 0, vec![0xaa], &CFG).is_err());

    // too many outputs for the bound
    let many = random_tx(&mut prng, 1, 6);
    assert!(run(tx_blob(&many), 0, vec![0xaa], &CFG).is_err());

    // k out of range
    assert!(run(blob.clone(), 3, vec![0xaa], &CFG).is_err());

    // forbidden scriptPubKey at output 2 (allowed at output 0)
    let spk2 = serialize(&tx.output[2].script_pubkey);
    assert!(run(blob.clone(), 0, spk2, &CFG).is_err());
    let spk0 = serialize(&tx.output[0].script_pubkey);
    assert!(run(blob.clone(), 0, spk0, &CFG).is_ok());

    // required sequence
    let cfg = TxParse { sequence: Some(0xfffffffd), ..CFG };
    let mut t = tx.clone();
    for i in t.input.iter_mut() {
        i.sequence = Sequence(0xfffffffd);
    }
    assert!(run(tx_blob(&t), 0, vec![0xaa], &cfg).is_ok());
    t.input[1].sequence = Sequence(0xffffffff);
    assert!(run(tx_blob(&t), 0, vec![0xaa], &cfg).is_err());
}

#[test]
fn script_size() {
    let mut s = Stk::new(&["forbid", "k", "tx"]);
    parse_tx(&mut s, "tx", "t", &TxParse { max_inputs: 8, max_outputs: 8, sequence: Some(0) }, Some("k"), Some("forbid"));
    eprintln!("parse_tx(8, 8, k, forbid, sequence): {} bytes", s.script().len());
}
