//! The vault's tapscript v2 leaves. Each leaf enforces the whole protocol
//! (spec ENV-2) for one transaction template.

use crate::state::{ENVELOPE_VERSION, MAGIC, MODE_NORMAL, PHASE_ACTIVE};
use bitcoin::opcodes::all::*;
use bitcoin::opcodes::Opcode;
use bitcoin::script::Builder;
use gsr_gadgets::parse::{parse_tx, TxParse};
use gsr_gadgets::pseudo::{cat, drop_n, OP_HINT};
use gsr_gadgets::schnorr::SchnorrTrickGadget;
use gsr_gadgets::sighash::SighashAllGadget;
use gsr_gadgets::stack::Stk;
use gsr_gadgets::Script;

/// Bounds on the parent (T) and grandparent (Q) transactions.
pub const MAX_INPUTS: usize = 8;
pub const MAX_OUTPUTS: usize = 8;
/// nSequence of every protocol transaction input (spec §8.1).
pub const SEQUENCE: u32 = 0xfffffffd;
/// nVersion of every protocol transaction (spec §8.1).
pub const TX_VERSION: u32 = 2;

fn op(o: Opcode) -> Script {
    Builder::new().push_opcode(o).into_script()
}

fn ops(o: &[Opcode]) -> Script {
    cat(&o.iter().map(|x| op(*x)).collect::<Vec<_>>())
}

/// `name == bytes`
fn eq_const(s: &mut Stk, name: &str, bytes: &[u8]) {
    s.pick(name, "_x");
    s.push_data(bytes, "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
}

/// `a == b`
fn eq(s: &mut Stk, a: &str, b: &str) {
    s.pick(a, "_x");
    s.pick(b, "_y");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
}

/// `a != b`
fn neq(s: &mut Stk, a: &str, b: &str) {
    s.pick(a, "_x");
    s.pick(b, "_y");
    s.apply(ops(&[OP_EQUAL, OP_NOT, OP_VERIFY]), 2, &[]);
}

/// Numeric `name == n`.
fn num_eq(s: &mut Stk, name: &str, n: u64) {
    s.pick(name, "_x");
    s.push_u64(n, "_c");
    s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
}

fn left(s: &mut Stk, src: &str, n: usize, as_: &str) {
    s.pick(src, "_x");
    s.push_u64(n as u64, "_n");
    s.apply(op(OP_LEFT), 2, &[as_]);
}

fn right(s: &mut Stk, src: &str, n: usize, as_: &str) {
    s.pick(src, "_x");
    s.push_u64(n as u64, "_n");
    s.apply(op(OP_RIGHT), 2, &[as_]);
}

fn substr(s: &mut Stk, src: &str, off: usize, len: usize, as_: &str) {
    s.pick(src, "_x");
    s.push_u64(off as u64, "_o");
    s.push_u64(len as u64, "_n");
    s.apply(op(OP_SUBSTR), 3, &[as_]);
}

fn sha256(s: &mut Stk, src: &str, as_: &str) {
    s.pick(src, "_x");
    s.apply(op(OP_SHA256), 1, &[as_]);
}

fn size_eq(s: &mut Stk, name: &str, n: u64) {
    s.pick(name, "_x");
    s.apply(ops(&[OP_SIZE, OP_NIP]), 1, &["_sz"]);
    s.push_u64(n, "_c");
    s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
}

/// The compact-size-prefixed scriptPubKey of a serialized output.
fn spk_of_output(s: &mut Stk, out: &str, as_: &str) {
    s.pick(out, "_x");
    s.pick(out, "_y");
    s.apply(ops(&[OP_SIZE, OP_NIP]), 1, &["_sz"]);
    s.push_u64(8, "_c");
    s.apply(op(OP_SUB), 2, &["_n"]);
    s.apply(op(OP_RIGHT), 2, &[as_]);
}

/// A compact-size-prefixed P2WPKH, P2WSH or P2TR scriptPubKey (spec §8.1).
fn native_segwit(s: &mut Stk, spk: &str) {
    left(s, spk, 3, "_pfx");
    let mut first = true;
    for pfx in [[0x16, 0x00, 0x14], [0x22, 0x00, 0x20], [0x22, 0x51, 0x20]] {
        s.pick("_pfx", "_x");
        s.push_data(&pfx, "_c");
        s.apply(op(OP_EQUAL), 2, &["_e"]);
        if !first {
            s.apply(op(OP_BOOLOR), 2, &["_e"]);
        }
        first = false;
    }
    s.verify();
    s.drop("_pfx");
}

/// A caboose output `0 || 0x26 || OP_RETURN PUSHBYTES_36 <h || r>`: returns `h`.
fn caboose_hash(s: &mut Stk, out: &str, as_: &str) {
    size_eq(s, out, 8 + 1 + 38);
    let mut prefix = vec![0u8; 8];
    prefix.extend([0x26, 0x6a, 0x24]);
    left(s, out, 11, "_pfx");
    s.push_data(&prefix, "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    substr(s, out, 11, 32, as_);
}

/// The minimal transition: inputs `[vault, fee]`, outputs `[vault, change, caboose]`,
/// vault amount unchanged.
///
/// Hints, in order: SIGHASH_ALL data of the transaction, the two Schnorr-trick
/// hints, the parent T, the old state S, the old application state A, the new
/// state S', the new application state A', and the grandparent Q.
pub fn transition_leaf() -> Script {
    let (n, m) = (2, 3);
    let mut s = Stk::new(&[]);

    // AUTH-1: authenticate the whole transaction (SIGHASH_ALL, input index 0, version 2).
    s.gadget(
        SighashAllGadget::build(n, m, 0, TX_VERSION),
        0,
        &[
            "x.op0", "x.op1", "x.am0", "x.am1", "x.spk0", "x.spk1", "x.seq0", "x.seq1", "x.out0",
            "x.out1", "x.out2", "x.lt", "x.pre",
        ],
    );
    s.gadget(SchnorrTrickGadget::verify(), 1, &[]);

    // Protocol format (§8.1) and roles (LIN, ROLE, CAB).
    eq_const(&mut s, "x.lt", &[0; 4]);
    eq_const(&mut s, "x.seq0", &SEQUENCE.to_le_bytes());
    eq_const(&mut s, "x.seq1", &SEQUENCE.to_le_bytes());
    right(&mut s, "x.op0", 4, "_vout"); // LIN-2: spends output 0
    s.push_data(&[0; 4], "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    native_segwit(&mut s, "x.spk1"); // fee input
    neq(&mut s, "x.spk1", "x.spk0"); // LIN-1: no second main-program input
    // successor: same scriptPubKey P, same amount (VALUE: no vault costs in this template)
    s.pick("x.am0", "_a");
    s.pick("x.spk0", "_p");
    s.apply(op(OP_CAT), 2, &["_succ"]);
    s.pick("x.out0", "_o");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    spk_of_output(&mut s, "x.out1", "x.out1.spk"); // change
    native_segwit(&mut s, "x.out1.spk");
    neq(&mut s, "x.out1.spk", "x.spk0"); // LIN-1: no second main-program output
    caboose_hash(&mut s, "x.out2", "h_new"); // CAB-1: the last output is the caboose

    // AUTH-2: the parent T.
    s.gadget(OP_HINT(), 0, &["T"]);
    s.pick("x.spk0", "P");
    let bounds = |sequence| TxParse { max_inputs: MAX_INPUTS, max_outputs: MAX_OUTPUTS, sequence };
    parse_tx(&mut s, "T", "t", &bounds(Some(SEQUENCE)), None, Some("P"));
    left(&mut s, "x.op0", 32, "_ptxid");
    s.pick("t.txid", "_x");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    s.pick("x.am0", "_a"); // T.output[0] == Spent(X, 0)
    s.pick("x.spk0", "_p");
    s.apply(op(OP_CAT), 2, &["_prev"]);
    s.pick("t.out0", "_o");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    eq_const(&mut s, "t.version", &TX_VERSION.to_le_bytes());
    eq_const(&mut s, "t.lock_time", &[0; 4]);
    caboose_hash(&mut s, "t.last", "h_old");

    // The old state S (STATE-1) and its application state A.
    s.gadget(OP_HINT(), 0, &["S"]);
    sha256(&mut s, "S", "_h");
    eq(&mut s, "_h", "h_old");
    s.drop("_h");
    let mut header = MAGIC.to_vec();
    header.push(ENVELOPE_VERSION);
    left(&mut s, "S", 8, "_hdr");
    s.push_data(&header, "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    substr(&mut s, "S", 8, 1, "phase");
    s.pick("phase", "_x");
    s.push_u64(2, "_c");
    s.apply(ops(&[OP_LESSTHAN, OP_VERIFY]), 2, &[]);
    s.pick("phase", "_x"); // length 41 (GENESIS) or 73 (ACTIVE)
    s.push_u64(32, "_c");
    s.apply(op(OP_MUL), 2, &["_x"]);
    s.push_u64(41, "_c");
    s.apply(op(OP_ADD), 2, &["_want"]);
    s.pick("S", "_y");
    s.apply(ops(&[OP_SIZE, OP_NIP]), 1, &["_sz"]);
    s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
    substr(&mut s, "S", 9, 32, "id");
    right(&mut s, "S", 32, "root");
    s.gadget(OP_HINT(), 0, &["A"]);
    size_eq(&mut s, "A", 33);
    sha256(&mut s, "A", "_h");
    eq(&mut s, "_h", "root");
    s.drop("_h");
    right(&mut s, "A", 1, "_mode");
    s.push_data(&[MODE_NORMAL], "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    left(&mut s, "A", 32, "acc");

    // AUTH-5: the new state S' committed by this transaction's caboose.
    s.gadget(OP_HINT(), 0, &["S2"]);
    size_eq(&mut s, "S2", 73);
    sha256(&mut s, "S2", "_h");
    eq(&mut s, "_h", "h_new");
    s.drop("_h");
    let mut active = header.clone();
    active.push(PHASE_ACTIVE);
    left(&mut s, "S2", 9, "_hdr"); // INIT-3 / NEXT-2: the new state is ACTIVE
    s.push_data(&active, "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    substr(&mut s, "S2", 9, 32, "id2");
    right(&mut s, "S2", 32, "root2");
    s.gadget(OP_HINT(), 0, &["A2"]);
    size_eq(&mut s, "A2", 33);
    sha256(&mut s, "A2", "_h");
    eq(&mut s, "_h", "root2");
    s.drop("_h");
    right(&mut s, "A2", 1, "_mode");
    s.push_data(&[MODE_NORMAL], "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    left(&mut s, "A2", 32, "acc2");
    // acc' = SHA256(acc || txid(T))
    s.pick("acc", "_a");
    s.pick("t.txid", "_t");
    s.apply(ops(&[OP_CAT, OP_SHA256]), 2, &["_acc"]);
    s.pick("acc2", "_b");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);

    // AUTH-3: the grandparent Q and the output spent by T's input 0.
    s.gadget(OP_HINT(), 0, &["Q"]);
    substr(&mut s, "t.in0", 32, 4, "k");
    parse_tx(&mut s, "Q", "q", &bounds(None), Some("k"), None);
    left(&mut s, "t.in0", 32, "_qtxid");
    s.pick("q.txid", "_x");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    spk_of_output(&mut s, "q.out_k", "qspk");

    // AUTH-4: the branch is chosen by the authenticated predecessor script.
    s.pick("qspk", "_x");
    s.pick("P", "_y");
    s.apply(op(OP_EQUAL), 2, &["_cont"]);
    s.if_else(
        |s| {
            // continuation: NEXT-1, NEXT-2 (Step: acc rule above)
            s.pick("k", "_x");
            s.apply(ops(&[OP_NOT, OP_VERIFY]), 1, &[]);
            num_eq(s, "phase", 1);
            eq(s, "id2", "id");
        },
        |s| {
            // genesis: GEN-1, INIT-2, INIT-3 (Init/First: acc rule above)
            num_eq(s, "t.n_in", 1);
            s.pick("phase", "_x");
            s.apply(ops(&[OP_NOT, OP_VERIFY]), 1, &[]);
            eq(s, "id2", "t.txid");
        },
    );

    let left_over = s.names().len();
    s.apply(drop_n(left_over), left_over, &[]);
    s.push(op(OP_PUSHNUM_1), "ok");
    s.script()
}
