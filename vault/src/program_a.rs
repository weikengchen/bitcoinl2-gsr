//! Program a: deposits waiting to be folded into the vault (design §6).
//!
//! The address a_L bakes in the L2 id L (the vault's genesis id) and the vault's
//! scriptPubKey P. a outputs carry no data; the leaves look only at the spending
//! transaction and may run at any input position (the input index is a hint,
//! authenticated by the signature check). An a output can only be
//! - merged: inputs `[a x j, fee]`, outputs `[a(total), change, aggregator]`;
//! - folded: inputs `[vault, a x j, fee]`, outputs
//!   `[vault, change, aggregator OP_RETURN, caboose]`, where the vault's new
//!   state has id L and the vault grows by exactly the a total.
//!
//! The vault's own leaf on input 0 guarantees that the new state is the genuine
//! successor, so a clone vault (same P, other id) cannot take a_L's funds.

use crate::leaf::{caboose_hash, eq, eq_const, left, neq, op, ops, sha256, size_eq, spk_of_output, TX_VERSION};
use crate::state::{State, ENVELOPE_VERSION, MAGIC, PHASE_ACTIVE};
use crate::tx::{input, op_return, Plan, Vault};
use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::opcodes::all::*;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Witness};
use gsr_gadgets::leaf::V2Tree;
use gsr_gadgets::pseudo::{drop_n, OP_HINT};
use gsr_gadgets::schnorr::{schnorr_trick_hints, SchnorrTrickGadget};
use gsr_gadgets::sighash::{SighashAllData, SighashAllGadget};
use gsr_gadgets::stack::Stk;
use gsr_gadgets::Script;

/// Most a inputs of one merge or fold transaction.
pub const MAX_A_INPUTS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AShape {
    /// Merge `j >= 2` a outputs.
    Merge(usize),
    /// Fold `j >= 1` a outputs into the vault.
    Fold(usize),
}

impl AShape {
    pub fn n_inputs(&self) -> usize {
        match self {
            AShape::Merge(j) => j + 1,
            AShape::Fold(j) => j + 2,
        }
    }

    pub fn n_outputs(&self) -> usize {
        match self {
            AShape::Merge(_) => 3,
            AShape::Fold(_) => 4,
        }
    }

    /// Input positions of the a outputs; the fee input is the last input.
    pub fn a_inputs(&self) -> std::ops::Range<usize> {
        match self {
            AShape::Merge(j) => 0..*j,
            AShape::Fold(j) => 1..1 + j,
        }
    }
}

/// Copy element `index` of the group that starts at `first` (element i lies at
/// depth `depth(first) - i`), where `index` is a stack element.
fn pick_indexed(s: &mut Stk, first: &str, index: &str, as_: &str) {
    let d0 = s.depth(first);
    s.pick(index, "_i");
    s.push_u64(d0 as u64, "_d");
    s.apply(ops(&[OP_SWAP, OP_SUB]), 2, &["_depth"]);
    s.apply(op(OP_PICK), 1, &[as_]);
}

/// The a_L leaf for one shape. Hints: SIGHASH_ALL data with the input index,
/// the two Schnorr-trick hints and, for a fold, the vault's new state S'.
pub fn a_leaf(shape: AShape, l2_id: &[u8; 32], vault_spk: &ScriptBuf) -> Script {
    let (n, m) = (shape.n_inputs(), shape.n_outputs());
    let mut s = Stk::new(&[]);
    let names = SighashAllGadget::names("x", n, m, true);
    let names: Vec<&str> = names.iter().map(|x| x.as_str()).collect();
    s.gadget(SighashAllGadget::build_ext(n, m, None, TX_VERSION), 0, &names);
    s.gadget(SchnorrTrickGadget::verify(), 1, &[]);

    // self: the scriptPubKey spent by this input, i.e. a_L.
    pick_indexed(&mut s, "x.spk0", "x.index", "self");
    // Exactly the template's a positions spend a_L; the fee input does not.
    let a = shape.a_inputs();
    for k in a.clone() {
        eq(&mut s, &format!("x.spk{k}"), "self");
    }
    neq(&mut s, &format!("x.spk{}", n - 1), "self");
    s.pick(&format!("x.am{}", a.start), "total");
    for k in a.start + 1..a.end {
        s.pick(&format!("x.am{k}"), "_d");
        s.apply(op(OP_ADD), 2, &["total"]);
    }
    // No output pays to a_L, except a merge's output 0.
    let first = matches!(shape, AShape::Merge(_)) as usize;
    for j in first..m {
        spk_of_output(&mut s, &format!("x.out{j}"), "_spk");
        neq(&mut s, "_spk", "self");
        s.drop("_spk");
    }

    match shape {
        AShape::Merge(_) => {
            // output 0: a_L with exactly the total
            spk_of_output(&mut s, "x.out0", "_spk");
            s.pick("self", "_y");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            left(&mut s, "x.out0", 8, "_amount");
            s.pick("total", "_t");
            s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
        }
        AShape::Fold(_) => {
            // input 0 spends P, and the vault grows by exactly the total
            eq_const(&mut s, "x.spk0", &serialize(vault_spk));
            left(&mut s, "x.out0", 8, "_new");
            s.pick("x.am0", "_old");
            s.apply(op(OP_SUB), 2, &["_gain"]);
            s.pick("total", "_t");
            s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
            // the new state S' in the caboose (last output) is ACTIVE with id L
            caboose_hash(&mut s, &format!("x.out{}", m - 1), "h_new");
            s.gadget(OP_HINT(), 0, &["S2"]);
            size_eq(&mut s, "S2", 73);
            sha256(&mut s, "S2", "_h");
            s.pick("h_new", "_x");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            let mut header = MAGIC.to_vec();
            header.extend([ENVELOPE_VERSION, PHASE_ACTIVE]);
            header.extend(l2_id);
            left(&mut s, "S2", header.len(), "_hdr");
            s.push_data(&header, "_c");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
        }
    }

    let left_over = s.names().len();
    s.apply(drop_n(left_over), left_over, &[]);
    s.push(op(OP_PUSHNUM_1), "ok");
    s.script()
}

pub struct ProgramA {
    pub tree: V2Tree,
    pub shapes: Vec<AShape>,
}

impl ProgramA {
    /// a_L for the L2 whose vault has genesis id `l2_id` and scriptPubKey `vault_spk`.
    /// Leaves: merges of 2..=MAX_A_INPUTS, folds of 1..=MAX_A_INPUTS.
    pub fn new(l2_id: [u8; 32], vault_spk: &ScriptBuf) -> Result<Self> {
        let mut shapes: Vec<AShape> = (2..=MAX_A_INPUTS).map(AShape::Merge).collect();
        shapes.extend((1..=MAX_A_INPUTS).map(AShape::Fold));
        let tree = V2Tree::new(shapes.iter().map(|sh| a_leaf(*sh, &l2_id, vault_spk)).collect())?;
        Ok(Self { tree, shapes })
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.tree.script_pubkey.clone()
    }

    pub fn leaf_index(&self, shape: AShape) -> usize {
        self.shapes.iter().position(|x| *x == shape).expect("shape has a leaf")
    }

    /// The outputs a deposit transaction creates: `a_L(value)` immediately
    /// followed by the OP_RETURN holding the L2 recipient (read only by the SNARK).
    pub fn deposit_outputs(&self, value: Amount, recipient: &[u8]) -> [TxOut; 2] {
        [TxOut { value, script_pubkey: self.script_pubkey() }, op_return(recipient.to_vec())]
    }

    /// Witness of the a input at `index`, or `None` if the Schnorr trick needs a
    /// tweak. A fold needs the vault's new state.
    pub fn witness(
        &self,
        shape: AShape,
        tx: &Transaction,
        prevouts: &[TxOut],
        index: usize,
        new_state: Option<&State>,
    ) -> Option<Witness> {
        let leaf = self.leaf_index(shape);
        let data = SighashAllData::new(tx, prevouts, index, self.tree.leaf_hash(leaf));
        let mut hints = data.hints_ext(true);
        hints.extend(schnorr_trick_hints(&data.preimage()).ok()?);
        hints.extend(new_state.map(|s| s.encode()));
        Some(self.tree.witness(leaf, &hints))
    }

    /// `tx` with witnesses on its a inputs (the shape's positions), or `None` if
    /// some input's Schnorr trick needs a tweak.
    pub fn sign(&self, shape: AShape, tx: &Transaction, prevouts: &[TxOut], new_state: Option<&State>) -> Option<Transaction> {
        let mut tx = tx.clone();
        for i in shape.a_inputs() {
            tx.input[i].witness = self.witness(shape, &tx, prevouts, i, new_state)?;
        }
        Some(tx)
    }

    /// The unsigned merge of `inputs` (a outputs) and a fee input into
    /// `[a(total), change, OP_RETURN(aggregator || nonce)]`.
    pub fn merge_unsigned(
        &self,
        inputs: &[(OutPoint, TxOut)],
        fee: OutPoint,
        change: TxOut,
        aggregator: &[u8],
        nonce: u32,
    ) -> Transaction {
        let total: u64 = inputs.iter().map(|x| x.1.value.to_sat()).sum();
        let mut data = aggregator.to_vec();
        data.extend(nonce.to_le_bytes());
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs.iter().map(|x| input(x.0)).chain([input(fee)]).collect(),
            output: vec![
                TxOut { value: Amount::from_sat(total), script_pubkey: self.script_pubkey() },
                change,
                op_return(data),
            ],
        }
    }

    /// The merge with the first nonce for which every a input's Schnorr trick
    /// applies, with the a inputs' witnesses. The fee input (last) is left unsigned.
    pub fn merge_tx(&self, inputs: &[(OutPoint, TxOut)], fee: (OutPoint, TxOut), change: TxOut, aggregator: &[u8]) -> Transaction {
        let shape = AShape::Merge(inputs.len());
        let mut prevouts: Vec<TxOut> = inputs.iter().map(|x| x.1.clone()).collect();
        prevouts.push(fee.1);
        (0u32..)
            .find_map(|nonce| {
                let tx = self.merge_unsigned(inputs, fee.0, change.clone(), aggregator, nonce);
                self.sign(shape, &tx, &prevouts, None)
            })
            .unwrap()
    }

    /// Build the fold transaction of `plan` (from [Vault::with_deposits], whose
    /// deposits are all a_L outputs), with witnesses for the vault input and
    /// every a input. The fee input (last) is left unsigned.
    pub fn fold_tx(&self, vault: &Vault, plan: &Plan) -> Transaction {
        let shape = AShape::Fold(plan.deposits.len());
        let prevouts = Vault::prevouts(plan);
        vault.build_with(plan, |tx, i| self.witness(shape, tx, &prevouts, i, Some(&plan.new_state)))
    }
}
