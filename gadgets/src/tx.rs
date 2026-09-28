//! Transaction (txid) reflection: rebuild a non-witness serialization from
//! hints, so its fields can be read and its txid compared with an outpoint.
//! All inputs must have empty scriptSigs and both counts must be below 253.

use crate::pseudo::*;
use crate::sighash::check_txout;
use crate::treepp::*;
use bitcoin::consensus::Encodable;
use bitcoin::Transaction;

fn ser<T: Encodable>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    v.consensus_encode(&mut out).unwrap();
    out
}

/// A field left on the stack by [TxBuildGadget::build].
#[derive(Clone, Copy, Debug)]
pub enum TxField {
    Version,
    Outpoint(usize),
    Sequence(usize),
    Output(usize),
    LockTime,
}

/// Hints for [TxBuildGadget::build], in consumption order.
pub fn tx_hints(tx: &Transaction) -> Vec<Vec<u8>> {
    assert!(tx.input.iter().all(|i| i.script_sig.is_empty()), "scriptSigs must be empty");
    assert!(tx.input.len() < 253 && tx.output.len() < 253);
    let mut h = vec![ser(&tx.version)];
    h.extend(tx.input.iter().map(|i| ser(&i.previous_output)));
    h.extend(tx.input.iter().map(|i| i.sequence.0.to_le_bytes().to_vec()));
    h.extend(tx.output.iter().map(ser));
    h.push(tx.lock_time.to_consensus_u32().to_le_bytes().to_vec());
    h
}

pub struct TxBuildGadget;

impl TxBuildGadget {
    /// `( -- version outpoints[n] sequences[n] outputs[m] lock_time txid )`
    ///
    /// `txid` is in internal byte order, as in an outpoint.
    pub fn build(n_inputs: usize, n_outputs: usize) -> Script {
        let (n, m) = (n_inputs, n_outputs);
        assert!(n < 253 && m < 253);
        let k = Self::items(n, m);
        let mut parts = vec![cat(&[OP_HINT(), script! { OP_SIZE 4 OP_EQUALVERIFY }])];
        for _ in 0..n {
            parts.push(cat(&[OP_HINT(), script! { OP_SIZE 36 OP_EQUALVERIFY }]));
        }
        for _ in 0..n {
            parts.push(cat(&[OP_HINT(), script! { OP_SIZE 4 OP_EQUALVERIFY }]));
        }
        for _ in 0..m {
            parts.push(cat(&[OP_HINT(), check_txout()]));
        }
        parts.push(cat(&[OP_HINT(), script! { OP_SIZE 4 OP_EQUALVERIFY }]));

        // With the accumulator on top, the item at position p is at depth k - p.
        let get = |p: usize| cat(&[pick(k - p), script! { OP_CAT }]);
        parts.push(script! { OP_0 });
        parts.push(get(0));
        parts.push(cat(&[push_data(&[n as u8]), script! { OP_CAT }]));
        for i in 0..n {
            parts.push(get(1 + i));
            parts.push(cat(&[push_data(&[0x00]), script! { OP_CAT }]));
            parts.push(get(1 + n + i));
        }
        parts.push(cat(&[push_data(&[m as u8]), script! { OP_CAT }]));
        for j in 0..m {
            parts.push(get(1 + 2 * n + j));
        }
        parts.push(get(1 + 2 * n + m));
        parts.push(script! { OP_HASH256 });
        cat(&parts)
    }

    /// Number of items left below the txid.
    pub fn items(n_inputs: usize, n_outputs: usize) -> usize {
        2 + 2 * n_inputs + n_outputs
    }

    /// Depth of `field` once the txid has been consumed and nothing else was pushed.
    pub fn depth(n_inputs: usize, n_outputs: usize, field: TxField) -> usize {
        let n = n_inputs;
        let pos = match field {
            TxField::Version => 0,
            TxField::Outpoint(i) => 1 + i,
            TxField::Sequence(i) => 1 + n + i,
            TxField::Output(j) => 1 + 2 * n + j,
            TxField::LockTime => 1 + 2 * n + n_outputs,
        };
        Self::items(n_inputs, n_outputs) - 1 - pos
    }
}
