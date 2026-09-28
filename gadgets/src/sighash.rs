//! SIGHASH_ALL signature message of a tapscript input (BIP 341/342), rebuilt in
//! script from hints so that the Schnorr trick can bind it to the transaction.

use crate::pseudo::*;
use crate::tagged_hash::{tagged_hash, HashTag};
use crate::treepp::*;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{TapLeafHash, Transaction, TxOut};
use sha2::{Digest, Sha256};

pub const SIGHASH_ALL: u8 = 0x01;

fn ser<T: Encodable>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    v.consensus_encode(&mut out).unwrap();
    out
}

/// Everything a SIGHASH_ALL signature of a tapscript input commits to
/// (no annex, no executed OP_CODESEPARATOR).
#[derive(Clone, Debug)]
pub struct SighashAllData {
    pub version: u32,
    pub lock_time: u32,
    /// 36 bytes each.
    pub outpoints: Vec<Vec<u8>>,
    /// 8 bytes each.
    pub amounts: Vec<Vec<u8>>,
    /// compact size || scriptPubKey.
    pub script_pubkeys: Vec<Vec<u8>>,
    /// 4 bytes each.
    pub sequences: Vec<Vec<u8>>,
    /// Serialized outputs.
    pub outputs: Vec<Vec<u8>>,
    pub input_index: u32,
    pub tapleaf_hash: [u8; 32],
}

impl SighashAllData {
    pub fn new(tx: &Transaction, prevouts: &[TxOut], input_index: usize, leaf_hash: TapLeafHash) -> Self {
        assert_eq!(tx.input.len(), prevouts.len());
        Self {
            version: tx.version.0 as u32,
            lock_time: tx.lock_time.to_consensus_u32(),
            outpoints: tx.input.iter().map(|i| ser(&i.previous_output)).collect(),
            amounts: prevouts.iter().map(|o| o.value.to_sat().to_le_bytes().to_vec()).collect(),
            script_pubkeys: prevouts.iter().map(|o| ser(&o.script_pubkey)).collect(),
            sequences: tx.input.iter().map(|i| i.sequence.0.to_le_bytes().to_vec()).collect(),
            outputs: tx.output.iter().map(ser).collect(),
            input_index: input_index as u32,
            tapleaf_hash: leaf_hash.to_byte_array(),
        }
    }

    /// `0x00 || SigMsg || ext`, the message of the TapSighash tagged hash.
    pub fn preimage(&self) -> Vec<u8> {
        let mut p = vec![0x00, SIGHASH_ALL];
        p.extend(self.version.to_le_bytes());
        p.extend(self.lock_time.to_le_bytes());
        for blob in [&self.outpoints, &self.amounts, &self.script_pubkeys, &self.sequences, &self.outputs] {
            p.extend(Sha256::digest(blob.concat()));
        }
        p.push(0x02); // spend_type: ext_flag = 1, no annex
        p.extend(self.input_index.to_le_bytes());
        p.extend(self.tapleaf_hash);
        p.push(0x00); // key_version
        p.extend(u32::MAX.to_le_bytes()); // codesep_pos
        p
    }

    pub fn sighash(&self) -> [u8; 32] {
        tagged_hash(HashTag::TapSighash, &self.preimage())
    }

    /// Hints for [SighashAllGadget::build], in consumption order.
    pub fn hints(&self) -> Vec<Vec<u8>> {
        let mut h = vec![];
        h.extend(self.outpoints.iter().cloned());
        h.extend(self.amounts.iter().cloned());
        h.extend(self.script_pubkeys.iter().cloned());
        h.extend(self.sequences.iter().cloned());
        h.extend(self.outputs.iter().cloned());
        h.push(self.lock_time.to_le_bytes().to_vec());
        h.push(self.tapleaf_hash.to_vec());
        h
    }
}

/// A field left on the stack by [SighashAllGadget::build].
#[derive(Clone, Copy, Debug)]
pub enum Field {
    Outpoint(usize),
    Amount(usize),
    ScriptPubKey(usize),
    Sequence(usize),
    Output(usize),
    LockTime,
}

/// `( item -- item )` for `compact_size(len) || data` with a one-byte length.
pub fn check_compact_prefixed() -> Script {
    cat(&[
        script! { OP_DUP 0 1 OP_SUBSTR OP_DUP },
        push_u64(0xfd),
        script! { OP_LESSTHAN OP_VERIFY OP_1ADD OP_OVER OP_SIZE OP_NIP OP_NUMEQUALVERIFY },
    ])
}

/// `( txout -- txout )` for a serialized output with a one-byte script length.
pub fn check_txout() -> Script {
    cat(&[
        script! { OP_DUP 8 1 OP_SUBSTR OP_DUP },
        push_u64(0xfd),
        script! { OP_LESSTHAN OP_VERIFY 9 OP_ADD OP_OVER OP_SIZE OP_NIP OP_NUMEQUALVERIFY },
    ])
}

/// Rebuilds the SIGHASH_ALL message of the executing input from hints.
pub struct SighashAllGadget;

impl SighashAllGadget {
    /// `( -- outpoints[n] amounts[n] script_pubkeys[n] sequences[n] outputs[m] lock_time preimage )`
    ///
    /// Every item is size-checked so the hints partition the committed vectors uniquely.
    pub fn build(n_inputs: usize, n_outputs: usize, input_index: u32, version: u32) -> Script {
        let (n, m) = (n_inputs, n_outputs);
        let items = 4 * n + m + 1;
        let mut parts = vec![];
        for _ in 0..n {
            parts.push(cat(&[OP_HINT(), script! { OP_SIZE 36 OP_EQUALVERIFY }]));
        }
        for _ in 0..n {
            parts.push(cat(&[OP_HINT(), script! { OP_SIZE 8 OP_EQUALVERIFY }]));
        }
        for _ in 0..n {
            parts.push(cat(&[OP_HINT(), check_compact_prefixed()]));
        }
        for _ in 0..n {
            parts.push(cat(&[OP_HINT(), script! { OP_SIZE 4 OP_EQUALVERIFY }]));
        }
        for _ in 0..m {
            parts.push(cat(&[OP_HINT(), check_txout()]));
        }
        parts.push(cat(&[OP_HINT(), script! { OP_SIZE 4 OP_EQUALVERIFY }]));

        // epoch || hash_type || nVersion || nLockTime
        let mut prefix = vec![0x00, SIGHASH_ALL];
        prefix.extend(version.to_le_bytes());
        parts.push(cat(&[push_data(&prefix), script! { OP_OVER OP_CAT }]));

        // sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, sha_outputs
        for (start, count) in [(0, n), (n, n), (2 * n, n), (3 * n, n), (4 * n, m)] {
            parts.push(script! { OP_0 });
            for i in 0..count {
                // stack: items.. preimage acc
                parts.push(pick(items + 1 - (start + i)));
                parts.push(script! { OP_CAT });
            }
            parts.push(script! { OP_SHA256 OP_CAT });
        }

        let mut spend = vec![0x02];
        spend.extend(input_index.to_le_bytes());
        parts.push(cat(&[push_data(&spend), script! { OP_CAT }]));
        parts.push(cat(&[OP_HINT(), script! { OP_SIZE 32 OP_EQUALVERIFY OP_CAT }]));
        parts.push(cat(&[push_data(&[0x00, 0xff, 0xff, 0xff, 0xff]), script! { OP_CAT }]));
        cat(&parts)
    }

    /// Number of items left below the preimage.
    pub fn items(n_inputs: usize, n_outputs: usize) -> usize {
        4 * n_inputs + n_outputs + 1
    }

    /// Depth of `field` once the preimage has been consumed and nothing else was pushed.
    pub fn depth(n_inputs: usize, n_outputs: usize, field: Field) -> usize {
        let n = n_inputs;
        let pos = match field {
            Field::Outpoint(i) => i,
            Field::Amount(i) => n + i,
            Field::ScriptPubKey(i) => 2 * n + i,
            Field::Sequence(i) => 3 * n + i,
            Field::Output(j) => 4 * n + j,
            Field::LockTime => 4 * n + n_outputs,
        };
        Self::items(n_inputs, n_outputs) - 1 - pos
    }
}
