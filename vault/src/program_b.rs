//! Program b: pays out a withdrawal batch (design §7).
//!
//! Every b output belongs to a node of a split tree. The node's commitment R is
//! the sha_outputs of the transaction that splits it, so spending b rebuilds the
//! SIGHASH_ALL message with sha_outputs = R and the Schnorr trick pins every
//! output. A split has exactly one input (the b); its nLockTime is free and is
//! the grinding nonce; its fee (the b amount minus the outputs) is fixed by the
//! tree.
//!
//! R is read from the parent, in the data output right after the spent b:
//! - the root b, created by the vault's completion, is followed by
//!   `OP_RETURN PUSHBYTES_64 <R || H(list)>` (the "root" leaf parses the parent);
//! - a b created by a split is followed by `OP_RETURN PUSHBYTES_32 <R>`. A split
//!   of an internal node has outputs `[b_1, D_1, b_2, D_2, ...]`, all 43 bytes,
//!   so the "internal" leaf finds them at fixed offsets without parsing.
//!
//! b has no identity: a b output made by anyone else only pays out that
//! person's money, and b never merges.

use crate::leaf::{left, op, ops, right, size_eq, substr, MAX_INPUTS, MAX_OUTPUTS, TX_VERSION};
use crate::state::sha256;
use crate::tx::{input, op_return, Withdrawal};
use anyhow::{ensure, Result};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::{deserialize_partial, serialize};
use bitcoin::opcodes::all::*;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Witness};
use gsr_gadgets::leaf::V2Tree;
use gsr_gadgets::parse::{parse_tx, tx_blob, TxParse};
use gsr_gadgets::pseudo::{cat, drop_n, OP_HINT};
use gsr_gadgets::schnorr::{schnorr_trick_hints, SchnorrTrickGadget};
use gsr_gadgets::sighash::{check_compact_prefixed, SighashAllData, SIGHASH_ALL};
use gsr_gadgets::stack::Stk;
use gsr_gadgets::Script;

/// Serialized size of a b output (P2TR) and of a split's data output.
pub const PAIR_ITEM: usize = 43;
/// `version || input count || the one input || output count` of a split.
pub const SPLIT_HEAD: usize = 47;
/// Most children of a node, so that an internal split has fewer than 253 outputs.
pub const MAX_FAN_OUT: usize = 126;

/// Leaf used to spend a b output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BLeaf {
    /// The root b, created by the vault's completion.
    Root,
    /// A b created by a split.
    Internal,
}

/// This input's fields (a split has one input): outpoint, amount, scriptPubKey,
/// sequence, and the transaction's nLockTime.
fn take_input(s: &mut Stk) {
    s.gadget(OP_HINT(), 0, &["op"]);
    size_eq(s, "op", 36);
    s.gadget(OP_HINT(), 0, &["am"]);
    size_eq(s, "am", 8);
    s.gadget(cat(&[OP_HINT(), check_compact_prefixed()]), 0, &["spk"]);
    s.gadget(OP_HINT(), 0, &["seq"]);
    size_eq(s, "seq", 4);
    s.gadget(OP_HINT(), 0, &["lt"]);
    size_eq(s, "lt", 4);
}

/// Rebuild this input's SIGHASH_ALL message with sha_outputs = R and verify it
/// with the Schnorr trick; then leave only `OP_1`.
fn sign_off(s: &mut Stk) {
    let mut prefix = vec![0x00, SIGHASH_ALL];
    prefix.extend(TX_VERSION.to_le_bytes());
    s.push_data(&prefix, "m");
    s.pick("lt", "_x");
    s.apply(op(OP_CAT), 2, &["m"]);
    for f in ["op", "am", "spk", "seq"] {
        s.pick(f, "_x");
        s.apply(ops(&[OP_SHA256, OP_CAT]), 2, &["m"]);
    }
    s.pick("R", "_x");
    s.apply(op(OP_CAT), 2, &["m"]);
    s.push_data(&[0x02, 0, 0, 0, 0], "_x"); // spend type, input index 0
    s.apply(op(OP_CAT), 2, &["m"]);
    s.gadget(OP_HINT(), 0, &["_leaf"]); // tapleaf hash
    size_eq(s, "_leaf", 32);
    s.apply(op(OP_CAT), 2, &["m"]);
    s.push_data(&[0x00, 0xff, 0xff, 0xff, 0xff], "_x"); // key version, codesep position
    s.apply(op(OP_CAT), 2, &["m"]);
    s.gadget(SchnorrTrickGadget::verify(), 1, &[]);
    let left_over = s.names().len();
    s.apply(drop_n(left_over), left_over, &[]);
    s.push(op(OP_PUSHNUM_1), "ok");
}

/// Spend the root b: the parent is parsed, and R is in the output after the spent one.
/// Hints: the input's fields, the parent, the tapleaf hash, the two Schnorr-trick hints.
pub fn root_leaf() -> Script {
    let mut s = Stk::new(&[]);
    take_input(&mut s);
    s.gadget(OP_HINT(), 0, &["T"]);
    right(&mut s, "op", 4, "_vout");
    s.apply(op(OP_1ADD), 1, &["k"]);
    let bounds = TxParse { max_inputs: MAX_INPUTS, max_outputs: MAX_OUTPUTS, sequence: None };
    parse_tx(&mut s, "T", "t", &bounds, Some("k"), None);
    left(&mut s, "op", 32, "_ptxid");
    s.pick("t.txid", "_x");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    // 8-byte amount || 0x42 || OP_RETURN PUSHBYTES_64 || R || H(list)
    size_eq(&mut s, "t.out_k", 75);
    substr(&mut s, "t.out_k", 8, 3, "_pfx");
    s.push_data(&[0x42, 0x6a, 0x40], "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    substr(&mut s, "t.out_k", 11, 32, "R");
    sign_off(&mut s);
    s.script()
}

/// Spend a b created by a split. The parent comes in pieces:
/// `head || outputs before the spent one || the spent output || its data output || rest`.
/// Hints: the input's fields, the five pieces, the tapleaf hash, the two Schnorr-trick hints.
pub fn internal_leaf() -> Script {
    let mut s = Stk::new(&[]);
    take_input(&mut s);
    // head: version || 0x01 || outpoint || empty scriptSig || sequence || output count < 0xfd
    s.gadget(OP_HINT(), 0, &["head"]);
    size_eq(&mut s, "head", SPLIT_HEAD as u64);
    substr(&mut s, "head", 4, 1, "_n_in");
    s.push_data(&[0x01], "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    substr(&mut s, "head", 41, 1, "_ss");
    s.apply(ops(&[OP_NOT, OP_VERIFY]), 1, &[]);
    substr(&mut s, "head", 46, 1, "_n_out");
    s.push_u64(0xfd, "_c");
    s.apply(ops(&[OP_LESSTHAN, OP_VERIFY]), 2, &[]);
    // the outputs before the spent one: vout pairs' worth of 43-byte items
    s.gadget(OP_HINT(), 0, &["pre"]);
    s.pick("pre", "_x");
    s.apply(ops(&[OP_SIZE, OP_NIP]), 1, &["_sz"]);
    right(&mut s, "op", 4, "_vout");
    s.push_u64(PAIR_ITEM as u64, "_c");
    s.apply(op(OP_MUL), 2, &["_want"]);
    s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
    // the spent output is at that offset ...
    s.gadget(OP_HINT(), 0, &["own"]);
    s.pick("am", "_a");
    s.pick("spk", "_s");
    s.apply(op(OP_CAT), 2, &["_o"]);
    s.pick("own", "_x");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    // ... followed by OP_RETURN PUSHBYTES_32 <R> with amount 0
    s.gadget(OP_HINT(), 0, &["data"]);
    size_eq(&mut s, "data", PAIR_ITEM as u64);
    let mut pfx = vec![0u8; 8];
    pfx.extend([0x22, 0x6a, 0x20]);
    left(&mut s, "data", 11, "_pfx");
    s.push_data(&pfx, "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    right(&mut s, "data", 32, "R");
    // the pieces make up the parent that the outpoint names
    s.gadget(OP_HINT(), 0, &["tail"]);
    s.pick("head", "_p");
    for piece in ["pre", "own", "data", "tail"] {
        s.pick(piece, "_x");
        s.apply(op(OP_CAT), 2, &["_p"]);
    }
    s.apply(op(OP_HASH256), 1, &["_txid"]);
    left(&mut s, "op", 32, "_ptxid");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    sign_off(&mut s);
    s.script()
}

/// The five pieces of a split `parent` for spending its output `vout` with the internal leaf.
pub fn pieces(parent: &Transaction, vout: usize) -> Vec<Vec<u8>> {
    let blob = tx_blob(parent);
    let a = SPLIT_HEAD;
    let b = a + PAIR_ITEM * vout;
    let (c, d) = (b + PAIR_ITEM, b + 2 * PAIR_ITEM);
    vec![blob[..a].to_vec(), blob[a..b].to_vec(), blob[b..c].to_vec(), blob[c..d].to_vec(), blob[d..].to_vec()]
}

/// A node of a split tree.
#[derive(Clone, Debug)]
pub struct Node {
    /// Outputs of the transaction that splits this node.
    pub outputs: Vec<TxOut>,
    /// Amount of the b output that funds the split: the outputs plus the fee.
    pub value: Amount,
    /// Child nodes (indices into [SplitTree::nodes]); child i is paid by output 2i.
    pub children: Vec<usize>,
}

impl Node {
    /// R: SHA256 of the serialized outputs, i.e. the split's sha_outputs.
    pub fn root(&self) -> [u8; 32] {
        sha256(&self.outputs.iter().flat_map(serialize).collect::<Vec<u8>>())
    }
}

/// A withdrawal batch laid out as a tree of splits (design §7): leaves pay
/// up to `fan_out` recipients, internal nodes fund up to `fan_out` children,
/// and every split pays `fee`. The layout is canonical, so anyone can rebuild
/// it from the published list.
#[derive(Clone, Debug)]
pub struct SplitTree {
    /// Children before parents; the last node is the root.
    pub nodes: Vec<Node>,
    /// The payouts, serialized back to back: the list published by the completion.
    pub list: Vec<u8>,
}

impl SplitTree {
    pub fn new(payouts: &[TxOut], fan_out: usize, fee: Amount, b_spk: &ScriptBuf) -> Self {
        assert!((2..=MAX_FAN_OUT).contains(&fan_out) && !payouts.is_empty());
        let mut nodes: Vec<Node> = vec![];
        let sum = |outs: &[TxOut]| outs.iter().map(|o| o.value).sum::<Amount>();
        let mut level: Vec<usize> = vec![];
        for chunk in payouts.chunks(fan_out) {
            nodes.push(Node { outputs: chunk.to_vec(), value: sum(chunk) + fee, children: vec![] });
            level.push(nodes.len() - 1);
        }
        while level.len() > 1 {
            let mut next = vec![];
            for group in level.chunks(fan_out) {
                let mut outputs = vec![];
                for &c in group {
                    outputs.push(TxOut { value: nodes[c].value, script_pubkey: b_spk.clone() });
                    outputs.push(op_return(nodes[c].root().to_vec()));
                }
                let value = sum(&outputs) + fee;
                nodes.push(Node { outputs, value, children: group.to_vec() });
                next.push(nodes.len() - 1);
            }
            level = next;
        }
        let list = payouts.iter().flat_map(serialize).collect();
        SplitTree { nodes, list }
    }

    /// Rebuild the tree from a published list.
    pub fn from_list(list: &[u8], fan_out: usize, fee: Amount, b_spk: &ScriptBuf) -> Result<Self> {
        let mut payouts = vec![];
        let mut rest = list;
        while !rest.is_empty() {
            let (o, used): (TxOut, usize) = deserialize_partial(rest)?;
            payouts.push(o);
            rest = &rest[used..];
        }
        ensure!(!payouts.is_empty(), "empty list");
        Ok(Self::new(&payouts, fan_out, fee, b_spk))
    }

    pub fn root(&self) -> &Node {
        self.nodes.last().expect("a tree has a root")
    }

    /// What the vault's completion pays out and publishes.
    pub fn withdrawal(&self) -> Withdrawal {
        Withdrawal { amount: self.root().value, root: self.root().root(), list: self.list.clone() }
    }
}

pub struct ProgramB {
    pub tree: V2Tree,
}

impl ProgramB {
    /// Leaves: root, internal.
    pub fn new() -> Result<Self> {
        Ok(Self { tree: V2Tree::new(vec![root_leaf(), internal_leaf()])? })
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.tree.script_pubkey.clone()
    }

    pub fn leaf_index(leaf: BLeaf) -> usize {
        match leaf {
            BLeaf::Root => 0,
            BLeaf::Internal => 1,
        }
    }

    /// The split of `parent`'s output `vout` into `outputs` with nLockTime `lock_time`, unsigned.
    pub fn unsigned(parent: &Transaction, vout: usize, outputs: &[TxOut], lock_time: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(lock_time),
            input: vec![input(OutPoint::new(parent.compute_txid(), vout as u32))],
            output: outputs.to_vec(),
        }
    }

    /// Witness for spending `parent`'s output `vout` in `tx` with `leaf`, or
    /// `None` if the Schnorr trick needs another nLockTime.
    pub fn witness(&self, leaf: BLeaf, tx: &Transaction, parent: &Transaction, vout: usize) -> Option<Witness> {
        let prevout = parent.output[vout].clone();
        let data = SighashAllData::new(tx, &[prevout], 0, self.tree.leaf_hash(Self::leaf_index(leaf)));
        self.witness_from(leaf, &data, parent, vout)
    }

    /// Like [ProgramB::witness], from the signature message data `data` (tests
    /// pass data whose outputs differ from the transaction's).
    pub fn witness_from(&self, leaf: BLeaf, data: &SighashAllData, parent: &Transaction, vout: usize) -> Option<Witness> {
        let i = Self::leaf_index(leaf);
        let trick = schnorr_trick_hints(&data.preimage()).ok()?;
        let mut hints = vec![
            data.outpoints[0].clone(),
            data.amounts[0].clone(),
            data.script_pubkeys[0].clone(),
            data.sequences[0].clone(),
            data.lock_time.to_le_bytes().to_vec(),
        ];
        match leaf {
            BLeaf::Root => hints.push(tx_blob(parent)),
            BLeaf::Internal => hints.extend(pieces(parent, vout)),
        }
        hints.push(data.tapleaf_hash.to_vec());
        hints.extend(trick);
        Some(self.tree.witness(i, &hints))
    }

    /// Split `parent`'s b output `vout` into `outputs` (its node's outputs),
    /// choosing the nLockTime so the Schnorr trick applies. The root b's parent
    /// is the vault's completion (two inputs); any other b's parent is a split.
    pub fn split_tx(&self, parent: &Transaction, vout: usize, outputs: &[TxOut]) -> Transaction {
        let leaf = if parent.input.len() == 1 { BLeaf::Internal } else { BLeaf::Root };
        self.split_with(leaf, parent, vout, outputs)
    }

    pub fn split_with(&self, leaf: BLeaf, parent: &Transaction, vout: usize, outputs: &[TxOut]) -> Transaction {
        (0u32..)
            .find_map(|lock_time| {
                let mut tx = Self::unsigned(parent, vout, outputs, lock_time);
                tx.input[0].witness = self.witness(leaf, &tx, parent, vout)?;
                Some(tx)
            })
            .unwrap()
    }
}
