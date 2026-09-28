//! Building vault transactions and their witnesses.

use crate::da::chain_hash;
use crate::leaf::{vault_leaf, Kind, VaultConfig, SEQUENCE};
use crate::state::{caboose, sha256, AppState, Lock, Mode, Params, Phase, State};
use anyhow::{bail, Result};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness};
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

/// An amount-0 `OP_RETURN <data>` output.
pub fn op_return(data: Vec<u8>) -> TxOut {
    let data = PushBytesBuf::try_from(data).expect("OP_RETURN data too long");
    TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new_op_return(data) }
}

/// Hint bytes of a vault transaction, in the leaf's consumption order after the
/// SIGHASH_ALL and Schnorr-trick hints. A completion's operator signature is
/// added when building (it signs the final transaction).
#[derive(Clone, Debug)]
pub struct TransitionHints {
    pub parent: Vec<u8>,
    pub old_state: Vec<u8>,
    pub old_app: Vec<u8>,
    /// The kind's own hints: a lock's data; a completion's new L2 state root and
    /// parameters, and its DA data.
    pub extra: Vec<Vec<u8>>,
    pub grandparent: Vec<u8>,
}

/// What a proof establishes and a completion carries out (design §7):
/// `amount` goes to program b, whose split tree has root `root`; the DA data
/// `da` is published in the completion's witness (one chunk); the L2 state
/// root and the parameters become `l2_root` and `params`.
#[derive(Clone, Debug)]
pub struct Batch {
    pub amount: Amount,
    pub root: [u8; 32],
    pub da: Vec<u8>,
    pub l2_root: [u8; 32],
    pub params: Params,
}

/// Everything needed to build a vault transaction; tests tamper with it.
#[derive(Clone, Debug)]
pub struct Plan {
    pub kind: Kind,
    pub vault_in: OutPoint,
    pub vault_prevout: TxOut,
    /// Deposit inputs (between the vault input and the fee input).
    pub deposits: Vec<(OutPoint, TxOut)>,
    pub fee_in: OutPoint,
    pub fee_prevout: TxOut,
    pub lock_time: u32,
    pub successor: TxOut,
    pub change: TxOut,
    /// Outputs between the change and the caboose (see [Kind]).
    pub extra_outputs: Vec<TxOut>,
    /// State committed by the new caboose.
    pub new_state: State,
    pub new_app: AppState,
    pub hints: TransitionHints,
}

impl Plan {
    /// Set the new application state, and the state the caboose commits to.
    pub fn set_app(&mut self, app: AppState) {
        self.new_app = app;
        self.new_state.app_root = app.root();
    }
}

/// Deposit inputs a fold can take.
pub const MAX_FOLD_DEPOSITS: usize = 4;

pub struct Vault {
    pub tree: V2Tree,
    pub kinds: Vec<Kind>,
    pub config: VaultConfig,
}

impl Vault {
    /// Leaves: plain, folds of 1..=MAX_FOLD_DEPOSITS deposits, lock, complete, timeout.
    pub fn new(config: VaultConfig) -> Result<Self> {
        let mut kinds = vec![Kind::Plain];
        kinds.extend((1..=MAX_FOLD_DEPOSITS).map(Kind::Fold));
        kinds.extend([Kind::Lock, Kind::Complete, Kind::Timeout]);
        let tree = V2Tree::new(kinds.iter().map(|k| vault_leaf(*k, &config)).collect())?;
        Ok(Self { tree, kinds, config })
    }

    pub fn leaf_index(&self, kind: Kind) -> usize {
        self.kinds.iter().position(|x| *x == kind).expect("kind has a leaf")
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

    /// The honest plain transition spending `parent`'s vault output. `grandparent`
    /// created the output spent by `parent`'s input 0. The other kinds start from it.
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
            kind: Kind::Plain,
            vault_in: OutPoint::new(parent_txid, 0),
            vault_prevout: parent.output[0].clone(),
            deposits: vec![],
            fee_in: fee.0,
            fee_prevout: fee.1,
            lock_time: 0,
            successor: parent.output[0].clone(),
            change,
            extra_outputs: vec![],
            new_state,
            new_app,
            hints: TransitionHints {
                parent: tx_blob(parent),
                old_state: old_state.encode(),
                old_app: old_app.encode(),
                extra: vec![],
                grandparent: tx_blob(grandparent),
            },
        })
    }

    /// Fold `deposits` (the vault grows by their total).
    pub fn with_deposits(&self, mut plan: Plan, deposits: Vec<(OutPoint, TxOut)>, aggregator: TxOut) -> Plan {
        let total: u64 = deposits.iter().map(|d| d.1.value.to_sat()).sum();
        plan.kind = Kind::Fold(deposits.len());
        plan.successor.value += Amount::from_sat(total);
        plan.deposits = deposits;
        plan.extra_outputs = vec![aggregator];
        plan
    }

    /// Lock the vault for verification at height `height` (the nLockTime): the
    /// vault grows by `bond`, which is refunded to `refund` on completion.
    pub fn lock(&self, mut plan: Plan, height: u32, bond: Amount, locker: [u8; 32], refund: &ScriptBuf) -> Plan {
        let lock = Lock { height, bond: bond.to_sat(), locker, refund_hash: sha256(&serialize(refund)) };
        plan.kind = Kind::Lock;
        plan.lock_time = height;
        plan.successor.value += bond;
        plan.hints.extra = vec![lock.data()];
        plan.set_app(AppState { mode: Mode::Verifying(lock), ..plan.new_app });
        plan
    }

    /// Complete a verification with `batch`: pay out to program b, publish the
    /// DA data, refund the bond to `refund` (whose hash the lock recorded), and
    /// set the new L2 state root and parameters.
    pub fn complete(&self, mut plan: Plan, batch: &Batch, refund: ScriptBuf) -> Plan {
        let Mode::Verifying(lock) = plan.new_app.mode else { panic!("the vault is not locked") };
        let bond = Amount::from_sat(lock.bond);
        plan.kind = Kind::Complete;
        plan.successor.value = plan.successor.value - batch.amount - bond;
        let mut data = batch.root.to_vec();
        data.extend(chain_hash(&[&batch.da]));
        plan.extra_outputs = vec![
            TxOut { value: batch.amount, script_pubkey: self.config.b_spk.clone() },
            op_return(data),
            TxOut { value: bond, script_pubkey: refund },
        ];
        let mut proof = batch.l2_root.to_vec();
        proof.extend(batch.params.encode());
        plan.hints.extra = vec![proof, batch.da.clone()];
        plan.set_app(AppState { l2_root: batch.l2_root, params: batch.params, mode: Mode::Normal, ..plan.new_app });
        plan
    }

    /// Time a lock out with nLockTime `lock_time` (at least h + N); the bond stays in the vault.
    pub fn timeout(&self, mut plan: Plan, lock_time: u32) -> Plan {
        plan.kind = Kind::Timeout;
        plan.lock_time = lock_time;
        plan.set_app(AppState { mode: Mode::Normal, ..plan.new_app });
        plan
    }

    /// The transaction of `plan` with caboose randomizer `r` and no witnesses.
    pub fn unsigned(&self, plan: &Plan, r: u32) -> Transaction {
        let mut inputs = vec![input(plan.vault_in)];
        inputs.extend(plan.deposits.iter().map(|d| input(d.0)));
        inputs.push(input(plan.fee_in));
        let mut outputs = vec![plan.successor.clone(), plan.change.clone()];
        outputs.extend(plan.extra_outputs.iter().cloned());
        outputs.push(caboose(&plan.new_state, r));
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(plan.lock_time),
            input: inputs,
            output: outputs,
        }
    }

    pub fn prevouts(plan: &Plan) -> Vec<TxOut> {
        let mut v = vec![plan.vault_prevout.clone()];
        v.extend(plan.deposits.iter().map(|d| d.1.clone()));
        v.push(plan.fee_prevout.clone());
        v
    }

    /// The vault input's witness for `tx`, or `None` if the Schnorr trick needs a
    /// new `r`. A completion carries the signature of `operator`.
    pub fn vault_witness(&self, plan: &Plan, tx: &Transaction, operator: Option<&Keypair>) -> Option<Witness> {
        let leaf = self.leaf_index(plan.kind);
        let leaf_hash = self.tree.leaf_hash(leaf);
        let prevouts = Self::prevouts(plan);
        let data = SighashAllData::new(tx, &prevouts, 0, leaf_hash);
        let trick = schnorr_trick_hints(&data.preimage()).ok()?;
        let h = &plan.hints;
        let mut hints = data.hints();
        hints.extend(trick);
        hints.extend([h.parent.clone(), h.old_state.clone(), h.old_app.clone()]);
        hints.extend(h.extra.iter().cloned());
        if let Some(key) = operator {
            hints.push(operator_signature(tx, &prevouts, leaf_hash, key));
        }
        hints.push(h.grandparent.clone());
        Some(self.tree.witness(leaf, &hints))
    }

    /// Build the transaction, choosing the caboose randomizer r so the Schnorr
    /// trick applies (spec CAB-3), and fill in the vault input's witness.
    /// Deposit inputs get their witnesses from `deposit_witness(tx, input_index)`;
    /// the fee input (last) is left unsigned.
    pub fn build_with(
        &self,
        plan: &Plan,
        deposit_witness: impl Fn(&Transaction, usize) -> Option<Witness>,
    ) -> Transaction {
        self.build_inner(plan, deposit_witness, None)
    }

    /// Build a transaction without deposit inputs (see [Vault::build_with]).
    pub fn build(&self, plan: &Plan) -> Transaction {
        assert!(plan.deposits.is_empty(), "use build_with for folds");
        self.build_inner(plan, |_, _| None, None)
    }

    /// Build a completion; `operator`'s signature stands in for the proof.
    pub fn build_complete(&self, plan: &Plan, operator: &Keypair) -> Transaction {
        self.build_inner(plan, |_, _| None, Some(operator))
    }

    fn build_inner(
        &self,
        plan: &Plan,
        deposit_witness: impl Fn(&Transaction, usize) -> Option<Witness>,
        operator: Option<&Keypair>,
    ) -> Transaction {
        for r in 0u32.. {
            let mut tx = self.unsigned(plan, r);
            let Some(w) = self.vault_witness(plan, &tx, operator) else { continue };
            let deposits: Option<Vec<Witness>> =
                (1..=plan.deposits.len()).map(|i| deposit_witness(&tx, i)).collect();
            let Some(deposits) = deposits else { continue };
            tx.input[0].witness = w;
            for (i, dw) in deposits.into_iter().enumerate() {
                tx.input[1 + i].witness = dw;
            }
            return tx;
        }
        unreachable!()
    }
}

/// BIP 340 signature (SIGHASH_DEFAULT) of input 0 of `tx` spending the leaf `leaf_hash`.
fn operator_signature(tx: &Transaction, prevouts: &[TxOut], leaf_hash: TapLeafHash, key: &Keypair) -> Vec<u8> {
    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(prevouts), leaf_hash, TapSighashType::Default)
        .expect("sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    Secp256k1::new().sign_schnorr_no_aux_rand(&msg, key).as_ref().to_vec()
}
