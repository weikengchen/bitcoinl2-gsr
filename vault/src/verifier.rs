//! The withdrawal proof's interface, and a placeholder for its verifier
//! (design §7, item 6).
//!
//! A completion is valid only if a proof of its [Statement] verifies. The real
//! verifier is being built separately. Until then a franker stands in for it:
//! off chain it runs the checks the circuit makes that do not depend on the
//! L2's internals, and if they pass it signs ("franks") the completion
//! transaction with BIP 340 and SIGHASH_DEFAULT, i.e. all its inputs and
//! outputs. The vault's completion leaf checks that signature against the
//! franker's key, which is baked into P.
//!
//! Every statement field is fixed by the franked transaction: W, R and H by
//! its outputs, the new L2 state root and parameters by its caboose, and the
//! vault id, acc and the old L2 state root through its input's parent, which
//! the vault's leaf authenticates.

use crate::da::{chain_hash, DaData};
use crate::program_b::SplitTree;
use crate::state::{app_offset, AppState, Params, Phase};
use crate::tx::{Plan, Vault};
use crate::leaf::Kind;
use anyhow::{bail, ensure, Result};
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Amount, ScriptBuf, Transaction, XOnlyPublicKey};

/// The public inputs of a withdrawal proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    /// L: the vault's id.
    pub vault_id: [u8; 32],
    /// acc after the completion: the vault's history up to and including the lock.
    pub acc: [u8; 32],
    /// The L2 state root the proof starts from (the vault's current one).
    pub l2_root: [u8; 32],
    /// The L2 state root the proof ends at.
    pub new_l2_root: [u8; 32],
    pub new_params: Params,
    /// W: the amount paid to program b.
    pub amount: Amount,
    /// R: root of the split tree that pays the withdrawals.
    pub split_root: [u8; 32],
    /// H: commitment to the DA data.
    pub da_hash: [u8; 32],
}

impl Statement {
    /// `L || acc || l2_root || new_l2_root || LE64(B_min') || LE32(N') || LE64(W) || R || H`, 212 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.vault_id.to_vec();
        v.extend(self.acc);
        v.extend(self.l2_root);
        v.extend(self.new_l2_root);
        v.extend(self.new_params.encode());
        v.extend(self.amount.to_sat().to_le_bytes());
        v.extend(self.split_root);
        v.extend(self.da_hash);
        v
    }

    /// The statement that the completion `tx`, built from `plan`, realizes.
    pub fn of_completion(plan: &Plan, tx: &Transaction) -> Result<Self> {
        ensure!(plan.kind == Kind::Complete && tx.output.len() == 6, "not a completion");
        let Phase::Active { genesis_id } = plan.new_state.phase else { bail!("the new state is not ACTIVE") };
        // the new state is the one the caboose commits to
        ensure!(plan.new_state.app_root == plan.new_app.root(), "new application state");
        ensure!(tx.output[5].script_pubkey.as_bytes()[2..34] == plan.new_state.hash(), "caboose");
        let old = &plan.hints.old_app;
        ensure!(old.len() == AppState::VERIFYING_LEN, "the old state is not VERIFYING");
        let data = tx.output[3].script_pubkey.as_bytes();
        ensure!(data.len() == 66 && data[..2] == [0x6a, 0x40], "OP_RETURN <R || H>");
        Ok(Statement {
            vault_id: genesis_id,
            acc: plan.new_app.acc,
            l2_root: old[app_offset::L2_ROOT..app_offset::L2_ROOT + 32].try_into().unwrap(),
            new_l2_root: plan.new_app.l2_root,
            new_params: plan.new_app.params,
            amount: tx.output[2].value,
            split_root: data[2..34].try_into().unwrap(),
            da_hash: data[34..66].try_into().unwrap(),
        })
    }
}

/// The placeholder verifier.
#[derive(Clone, Debug)]
pub struct Franker {
    pub key: Keypair,
    /// The split-tree layout the circuit uses to derive (R, W) from the withdrawal list.
    pub fan_out: usize,
    pub split_fee: Amount,
    pub b_spk: ScriptBuf,
}

impl Franker {
    pub fn public_key(&self) -> XOnlyPublicKey {
        self.key.x_only_public_key().0
    }

    /// The circuit's checks that do not depend on the L2's internals: the DA
    /// data `da` is canonical and committed by H, and R and W are the split
    /// tree of its withdrawal list. The L2 transition itself (from `l2_root`
    /// to `new_l2_root` with the published state changes) is taken as given.
    pub fn check(&self, stmt: &Statement, da: &[u8]) -> Result<()> {
        ensure!(chain_hash(&[da]) == stmt.da_hash, "the DA data does not match H");
        let data = DaData::decode(da)?;
        ensure!(!data.withdrawals.is_empty(), "no withdrawals");
        let tree = SplitTree::from_da(&data, self.fan_out, self.split_fee, &self.b_spk);
        ensure!(tree.root().root() == stmt.split_root, "R is not the split tree of the withdrawal list");
        ensure!(tree.root().value == stmt.amount, "W is not the split tree's amount");
        Ok(())
    }

    /// Frank the completion `tx` built from `plan`: check its statement and
    /// the DA data, then sign input 0 (SIGHASH_DEFAULT).
    pub fn frank(&self, vault: &Vault, plan: &Plan, tx: &Transaction) -> Result<Vec<u8>> {
        let stmt = Statement::of_completion(plan, tx)?;
        let da = plan.hints.extra.get(1).ok_or_else(|| anyhow::anyhow!("no DA data"))?;
        self.check(&stmt, da)?;
        self.sign(vault, plan, tx)
    }

    /// Sign the completion `tx` without any check (tests of the on-chain rules use it).
    pub fn sign(&self, vault: &Vault, plan: &Plan, tx: &Transaction) -> Result<Vec<u8>> {
        let leaf_hash = vault.tree.leaf_hash(vault.leaf_index(Kind::Complete));
        let prevouts = Vault::prevouts(plan);
        let sighash = SighashCache::new(tx).taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )?;
        let msg = Message::from_digest(sighash.to_byte_array());
        Ok(Secp256k1::new().sign_schnorr_no_aux_rand(&msg, &self.key).as_ref().to_vec())
    }
}
