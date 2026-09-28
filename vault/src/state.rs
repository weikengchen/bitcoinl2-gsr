//! State envelope (spec §6), application state and caboose (spec §7, as a bare OP_RETURN).

use anyhow::{bail, ensure, Result};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, TxOut, Txid};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 7] = b"UTXOLIN";
pub const ENVELOPE_VERSION: u8 = 0x01;
pub const PHASE_GENESIS: u8 = 0x00;
pub const PHASE_ACTIVE: u8 = 0x01;
/// Application mode byte: normal operation.
pub const MODE_NORMAL: u8 = 0x00;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Genesis,
    Active { genesis_id: [u8; 32] },
}

/// The state envelope: `magic || version || phase || [genesis_id] || app_root`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub phase: Phase,
    pub app_root: [u8; 32],
}

impl State {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(ENVELOPE_VERSION);
        match self.phase {
            Phase::Genesis => v.push(PHASE_GENESIS),
            Phase::Active { genesis_id } => {
                v.push(PHASE_ACTIVE);
                v.extend(genesis_id);
            }
        }
        v.extend(self.app_root);
        v
    }

    /// STATE-1: exact magic, version, phase and length.
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() >= 9 && &b[..7] == MAGIC && b[7] == ENVELOPE_VERSION, "bad envelope header");
        let phase = match (b[8], b.len()) {
            (PHASE_GENESIS, 41) => Phase::Genesis,
            (PHASE_ACTIVE, 73) => Phase::Active { genesis_id: b[9..41].try_into().unwrap() },
            _ => bail!("bad phase or length"),
        };
        Ok(Self { phase, app_root: b[b.len() - 32..].try_into().unwrap() })
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.encode())
    }
}

/// The application state committed by `app_root`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppState {
    pub acc: [u8; 32],
    pub mode: u8,
}

impl AppState {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.acc.to_vec();
        v.push(self.mode);
        v
    }

    pub fn root(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// `acc' = SHA256(acc || txid(parent))`, txid in internal byte order.
    pub fn next(&self, parent: Txid) -> AppState {
        let mut v = self.acc.to_vec();
        v.extend(parent.to_byte_array());
        AppState { acc: sha256(&v), mode: self.mode }
    }
}

/// `OP_RETURN PUSHBYTES_36 <SHA256(state) || LE32(r)>`, amount 0.
pub fn caboose(state: &State, r: u32) -> TxOut {
    let mut spk = vec![0x6a, 0x24];
    spk.extend(state.hash());
    spk.extend(r.to_le_bytes());
    TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) }
}
