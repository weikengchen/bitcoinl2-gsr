//! The L2's data availability (design §7, item 5): the DA data a completion
//! publishes in its witness, and its commitment H.
//!
//! DA data = withdrawal list || state changes, in Bitcoin's encodings
//! (CompactSize for counts and numbers, minimal only):
//! - withdrawals: a consensus-serialized `Vec<TxOut>`;
//! - new accounts: a count, then each 32-byte address, in index order (their
//!   indices continue from the current number of accounts);
//! - changed accounts: a count, then for each account, sorted by index without
//!   repeats, the index as the difference from the previous one (the first
//!   from 0), the new balance and the new nonce.
//!
//! H is a hash chain over the chunks the data is published in: the last link
//! is 32 zero bytes, each link is SHA256(chunk || next link), and H is the
//! first link. Published as one chunk, H = SHA256(data || 0^32).
//!
//! Binding: start from e = H; each step reveals (chunk, next) with |next| = 32,
//! requires SHA256(chunk || next) = e and sets e = next; publication is
//! complete when e = 0^32. Unless SHA256 has a collision or a preimage of
//! 0^32 is found, each step reveals exactly the true chunk and next link (the
//! 32-byte suffix fixes the split of the preimage), so the chunks revealed
//! are exactly the ones behind H, in order and all of them.

use crate::state::sha256;
use anyhow::{ensure, Result};
use bitcoin::consensus::encode::{Decodable, Encodable, VarInt};
use bitcoin::TxOut;

/// The last link of the DA hash chain.
pub const CHAIN_END: [u8; 32] = [0; 32];

/// H of data published as `chunks`, in this order.
pub fn chain_hash(chunks: &[&[u8]]) -> [u8; 32] {
    chunks.iter().rev().fold(CHAIN_END, |next, chunk| {
        let mut v = chunk.to_vec();
        v.extend(next);
        sha256(&v)
    })
}

/// New values of a changed account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    pub index: u64,
    pub balance: u64,
    pub nonce: u64,
}

/// The DA data of one batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DaData {
    pub withdrawals: Vec<TxOut>,
    pub new_accounts: Vec<[u8; 32]>,
    /// Sorted by index, without repeats.
    pub changes: Vec<Change>,
}

impl DaData {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![];
        let put = |n: u64, v: &mut Vec<u8>| {
            VarInt(n).consensus_encode(v).expect("writing to a Vec");
        };
        self.withdrawals.consensus_encode(&mut v).expect("writing to a Vec");
        put(self.new_accounts.len() as u64, &mut v);
        for a in &self.new_accounts {
            v.extend(a);
        }
        put(self.changes.len() as u64, &mut v);
        let mut prev = 0;
        for (i, c) in self.changes.iter().enumerate() {
            assert!(i == 0 || c.index > prev, "changes must be sorted by index without repeats");
            put(c.index - prev, &mut v);
            put(c.balance, &mut v);
            put(c.nonce, &mut v);
            prev = c.index;
        }
        v
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = bytes;
        let withdrawals = Vec::<TxOut>::consensus_decode(&mut r)?;
        let n = VarInt::consensus_decode(&mut r)?.0;
        let mut new_accounts = vec![];
        for _ in 0..n {
            ensure!(r.len() >= 32, "truncated address");
            new_accounts.push(r[..32].try_into().unwrap());
            r = &r[32..];
        }
        let m = VarInt::consensus_decode(&mut r)?.0;
        let mut changes = vec![];
        let mut prev = 0u64;
        for i in 0..m {
            let delta = VarInt::consensus_decode(&mut r)?.0;
            ensure!(i == 0 || delta > 0, "changes must be sorted by index without repeats");
            let index = prev.checked_add(delta).ok_or_else(|| anyhow::anyhow!("index overflow"))?;
            let balance = VarInt::consensus_decode(&mut r)?.0;
            let nonce = VarInt::consensus_decode(&mut r)?.0;
            changes.push(Change { index, balance, nonce });
            prev = index;
        }
        ensure!(r.is_empty(), "trailing bytes");
        Ok(Self { withdrawals, new_accounts, changes })
    }

    /// H of the data published as one chunk.
    pub fn hash(&self) -> [u8; 32] {
        chain_hash(&[&self.encode()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf};

    fn sample() -> DaData {
        DaData {
            withdrawals: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }],
            new_accounts: vec![[7; 32], [8; 32]],
            changes: vec![
                Change { index: 3, balance: 5_000, nonce: 1 },
                Change { index: 4, balance: 70_000, nonce: 0 },
                Change { index: 300, balance: 1 << 40, nonce: 65_536 },
            ],
        }
    }

    #[test]
    fn round_trip() {
        let d = sample();
        let bytes = d.encode();
        assert_eq!(DaData::decode(&bytes).unwrap(), d);
        // each change costs a few bytes: index difference, balance, nonce
        let empty = DaData { changes: vec![], ..sample() }.encode().len();
        assert_eq!(bytes.len() - empty, (1 + 3 + 1) + (1 + 5 + 1) + (3 + 9 + 5));
        assert_eq!(DaData::decode(&DaData::default().encode()).unwrap(), DaData::default());
    }

    #[test]
    fn rejects_malformed() {
        let bytes = sample().encode();
        let mut long = bytes.clone();
        long.push(0);
        assert!(DaData::decode(&long).is_err());
        assert!(DaData::decode(&bytes[..bytes.len() - 1]).is_err());
        // a repeated index (difference 0 after the first change)
        let mut rep = DaData { changes: vec![], ..sample() }.encode();
        rep.pop();
        rep.extend([2, 3, 0x10, 0, 0, 0x10, 0]);
        assert!(DaData::decode(&rep).is_err());
        // a non-minimal CompactSize
        let mut nm = DaData { changes: vec![], ..sample() }.encode();
        nm.pop();
        nm.extend([1, 0xfd, 3, 0, 0x10, 0]);
        assert!(DaData::decode(&nm).is_err());
    }

    #[test]
    fn chain() {
        let d = b"abc".to_vec();
        let mut one = d.clone();
        one.extend([0; 32]);
        assert_eq!(chain_hash(&[&d]), sha256(&one));
        let tail = chain_hash(&[b"c"]);
        let mut two = b"ab".to_vec();
        two.extend(tail);
        assert_eq!(chain_hash(&[b"ab", b"c"]), sha256(&two));
        assert_ne!(chain_hash(&[b"ab", b"c"]), chain_hash(&[&d]));
    }
}
