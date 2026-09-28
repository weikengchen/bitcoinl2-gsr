//! Building vault transactions and their witnesses.

use crate::leaf::{transition_leaf, SEQUENCE};
use crate::state::{caboose, AppState, Phase, State};
use anyhow::{bail, Result};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use gsr_gadgets::leaf::V2Tree;
use gsr_gadgets::parse::tx_blob;
use gsr_gadgets::schnorr::schnorr_trick_hints;
use gsr_gadgets::sighash::SighashAllData;

pub fn input(prevout: OutPoint) -> TxIn {
    TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence(SEQUENCE),
        witness: Witness::new(),
    }
}

/// Hint bytes of a transition, in the leaf's consumption order after the
/// SIGHASH_ALL and Schnorr-trick hints.
#[derive(Clone, Debug)]
pub struct TransitionHints {
    pub parent: Vec<u8>,
    pub old_state: Vec<u8>,
    pub old_app: Vec<u8>,
    pub new_state: Vec<u8>,
    pub new_app: Vec<u8>,
    pub grandparent: Vec<u8>,
}

/// Everything needed to build a transition; tests tamper with it.
#[derive(Clone, Debug)]
pub struct Plan {
    pub vault_in: OutPoint,
    pub vault_prevout: TxOut,
    pub fee_in: OutPoint,
    pub fee_prevout: TxOut,
    pub successor: TxOut,
    pub change: TxOut,
    /// State committed by the new caboose.
    pub new_state: State,
    pub new_app: AppState,
    pub hints: TransitionHints,
}

pub struct Vault {
    pub tree: V2Tree,
}

impl Vault {
    pub fn new() -> Result<Self> {
        Ok(Self { tree: V2Tree::new(vec![transition_leaf()])? })
    }

    /// The main-program scriptPubKey P.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.tree.script_pubkey.clone()
    }

    /// T0: spends `funding`, creates `[P(value), extra..., caboose(GENESIS)]`.
    /// The funding input is left unsigned.
    pub fn genesis_tx(&self, funding: OutPoint, value: Amount, app: &AppState, extra: Vec<TxOut>) -> (Transaction, State) {
        let state = State { phase: Phase::Genesis, app_root: app.root() };
        let mut output = vec![TxOut { value, script_pubkey: self.script_pubkey() }];
        output.extend(extra);
        output.push(caboose(&state, 0));
        let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![input(funding)], output };
        (tx, state)
    }

    /// The honest plan for spending `parent`'s vault output. `grandparent` created the
    /// output spent by `parent`'s input 0.
    pub fn plan(
        &self,
        parent: &Transaction,
        grandparent: &Transaction,
        old_state: &State,
        old_app: &AppState,
        fee: (OutPoint, TxOut),
        change: TxOut,
    ) -> Result<Plan> {
        let k = parent.input[0].previous_output.vout as usize;
        if grandparent.compute_txid() != parent.input[0].previous_output.txid || k >= grandparent.output.len() {
            bail!("grandparent does not match the parent's input 0");
        }
        let parent_txid = parent.compute_txid();
        let genesis_id = if grandparent.output[k].script_pubkey == self.script_pubkey() {
            match old_state.phase {
                Phase::Active { genesis_id } => genesis_id,
                Phase::Genesis => bail!("a continuation needs an ACTIVE old state"),
            }
        } else {
            parent_txid.to_byte_array()
        };
        let new_app = old_app.next(parent_txid);
        let new_state = State { phase: Phase::Active { genesis_id }, app_root: new_app.root() };
        Ok(Plan {
            vault_in: OutPoint::new(parent_txid, 0),
            vault_prevout: parent.output[0].clone(),
            fee_in: fee.0,
            fee_prevout: fee.1,
            successor: parent.output[0].clone(),
            change,
            new_state,
            new_app,
            hints: TransitionHints {
                parent: tx_blob(parent),
                old_state: old_state.encode(),
                old_app: old_app.encode(),
                new_state: new_state.encode(),
                new_app: new_app.encode(),
                grandparent: tx_blob(grandparent),
            },
        })
    }

    /// Build the transition, choosing the caboose randomizer r so the Schnorr
    /// trick applies (spec CAB-3), and fill in the vault input's witness.
    /// The fee input (index 1) is left unsigned.
    pub fn build(&self, plan: &Plan) -> Transaction {
        let prevouts = [plan.vault_prevout.clone(), plan.fee_prevout.clone()];
        for r in 0u32.. {
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![input(plan.vault_in), input(plan.fee_in)],
                output: vec![plan.successor.clone(), plan.change.clone(), caboose(&plan.new_state, r)],
            };
            let data = SighashAllData::new(&tx, &prevouts, 0, self.tree.leaf_hash(0));
            let Ok(trick) = schnorr_trick_hints(&data.preimage()) else { continue };
            let h = &plan.hints;
            let mut hints = data.hints();
            hints.extend(trick);
            hints.extend([
                h.parent.clone(),
                h.old_state.clone(),
                h.old_app.clone(),
                h.new_state.clone(),
                h.new_app.clone(),
                h.grandparent.clone(),
            ]);
            let mut tx = tx;
            tx.input[0].witness = self.tree.witness(0, &hints);
            return tx;
        }
        unreachable!()
    }
}
