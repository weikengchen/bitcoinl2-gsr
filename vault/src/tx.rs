//! Building vault transactions and their witnesses.

use crate::leaf::{vault_leaf, Template, SEQUENCE};
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

/// Everything needed to build a vault transaction; tests tamper with it.
#[derive(Clone, Debug)]
pub struct Plan {
    pub template: Template,
    pub vault_in: OutPoint,
    pub vault_prevout: TxOut,
    /// Deposit inputs (between the vault input and the fee input).
    pub deposits: Vec<(OutPoint, TxOut)>,
    pub fee_in: OutPoint,
    pub fee_prevout: TxOut,
    pub successor: TxOut,
    pub change: TxOut,
    /// The aggregator OP_RETURN output of templates that have one.
    pub aggregator: Option<TxOut>,
    /// State committed by the new caboose.
    pub new_state: State,
    pub new_app: AppState,
    pub hints: TransitionHints,
}

/// Deposit inputs a fold template can take.
pub const MAX_FOLD_DEPOSITS: usize = 4;

pub struct Vault {
    pub tree: V2Tree,
    pub templates: Vec<Template>,
}

impl Vault {
    /// Leaves: the transition, and folds of 1..=MAX_FOLD_DEPOSITS deposits.
    pub fn new() -> Result<Self> {
        let mut templates = vec![Template::TRANSITION];
        templates.extend((1..=MAX_FOLD_DEPOSITS).map(Template::fold));
        let tree = V2Tree::new(templates.iter().map(|t| vault_leaf(*t)).collect())?;
        Ok(Self { tree, templates })
    }

    pub fn leaf_index(&self, t: Template) -> usize {
        self.templates.iter().position(|x| *x == t).expect("template has a leaf")
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
            template: Template::TRANSITION,
            vault_in: OutPoint::new(parent_txid, 0),
            vault_prevout: parent.output[0].clone(),
            deposits: vec![],
            fee_in: fee.0,
            fee_prevout: fee.1,
            successor: parent.output[0].clone(),
            change,
            aggregator: None,
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

    /// Turn an honest transition plan into a fold of `deposits` (the vault
    /// amount grows by their total).
    pub fn with_deposits(&self, mut plan: Plan, deposits: Vec<(OutPoint, TxOut)>, aggregator: TxOut) -> Plan {
        let total: u64 = deposits.iter().map(|d| d.1.value.to_sat()).sum();
        plan.template = Template::fold(deposits.len());
        plan.successor.value += Amount::from_sat(total);
        plan.deposits = deposits;
        plan.aggregator = Some(aggregator);
        plan
    }

    /// The transaction of `plan` with caboose randomizer `r` and no witnesses.
    pub fn unsigned(&self, plan: &Plan, r: u32) -> Transaction {
        let mut inputs = vec![input(plan.vault_in)];
        inputs.extend(plan.deposits.iter().map(|d| input(d.0)));
        inputs.push(input(plan.fee_in));
        let mut outputs = vec![plan.successor.clone(), plan.change.clone()];
        outputs.extend(plan.aggregator.clone());
        outputs.push(caboose(&plan.new_state, r));
        Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: inputs, output: outputs }
    }

    pub fn prevouts(plan: &Plan) -> Vec<TxOut> {
        let mut v = vec![plan.vault_prevout.clone()];
        v.extend(plan.deposits.iter().map(|d| d.1.clone()));
        v.push(plan.fee_prevout.clone());
        v
    }

    /// The vault input's witness for `tx`, or `None` if the Schnorr trick needs a new `r`.
    pub fn vault_witness(&self, plan: &Plan, tx: &Transaction) -> Option<Witness> {
        let leaf = self.leaf_index(plan.template);
        let data = SighashAllData::new(tx, &Self::prevouts(plan), 0, self.tree.leaf_hash(leaf));
        let trick = schnorr_trick_hints(&data.preimage()).ok()?;
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
        for r in 0u32.. {
            let mut tx = self.unsigned(plan, r);
            let Some(w) = self.vault_witness(plan, &tx) else { continue };
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

    /// Build a transaction without deposit inputs (see [Vault::build_with]).
    pub fn build(&self, plan: &Plan) -> Transaction {
        assert!(plan.deposits.is_empty(), "use build_with for folds");
        self.build_with(plan, |_, _| None)
    }
}
