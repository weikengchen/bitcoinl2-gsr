//! The vault's tapscript v2 leaves. Each leaf enforces the whole protocol
//! (spec ENV-2) for one kind of transaction.

use crate::da::CHAIN_END;
use crate::state::{app_offset as off, AppState, ENVELOPE_VERSION, MAGIC, MODE_NORMAL, MODE_VERIFYING, PHASE_ACTIVE};
use bitcoin::absolute::LOCK_TIME_THRESHOLD;
use bitcoin::consensus::serialize;
use bitcoin::opcodes::all::*;
use bitcoin::opcodes::Opcode;
use bitcoin::script::Builder;
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use gsr_gadgets::parse::{parse_tx, TxParse};
use gsr_gadgets::pseudo::{cat, drop_n, OP_HINT};
use gsr_gadgets::optx::TxFieldsGadget;
use gsr_gadgets::stack::Stk;
use gsr_gadgets::Script;

/// Bounds on the parent (T) and grandparent (Q) transactions.
pub const MAX_INPUTS: usize = 8;
pub const MAX_OUTPUTS: usize = 8;
/// nSequence of every protocol transaction input (spec §8.1).
pub const SEQUENCE: u32 = 0xfffffffd;
/// nVersion of every protocol transaction (spec §8.1).
pub const TX_VERSION: u32 = 2;

pub(crate) fn op(o: Opcode) -> Script {
    Builder::new().push_opcode(o).into_script()
}

pub(crate) fn ops(o: &[Opcode]) -> Script {
    cat(&o.iter().map(|x| op(*x)).collect::<Vec<_>>())
}

/// `name == bytes`
pub(crate) fn eq_const(s: &mut Stk, name: &str, bytes: &[u8]) {
    s.pick(name, "_x");
    s.push_data(bytes, "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
}

/// `a == b`
pub(crate) fn eq(s: &mut Stk, a: &str, b: &str) {
    s.pick(a, "_x");
    s.pick(b, "_y");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
}

/// `a != b`
pub(crate) fn neq(s: &mut Stk, a: &str, b: &str) {
    s.pick(a, "_x");
    s.pick(b, "_y");
    s.apply(ops(&[OP_EQUAL, OP_NOT, OP_VERIFY]), 2, &[]);
}

/// Numeric `name == n`.
pub(crate) fn num_eq(s: &mut Stk, name: &str, n: u64) {
    s.pick(name, "_x");
    s.push_u64(n, "_c");
    s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
}

pub(crate) fn left(s: &mut Stk, src: &str, n: usize, as_: &str) {
    s.pick(src, "_x");
    s.push_u64(n as u64, "_n");
    s.apply(op(OP_LEFT), 2, &[as_]);
}

pub(crate) fn right(s: &mut Stk, src: &str, n: usize, as_: &str) {
    s.pick(src, "_x");
    s.push_u64(n as u64, "_n");
    s.apply(op(OP_RIGHT), 2, &[as_]);
}

pub(crate) fn substr(s: &mut Stk, src: &str, off: usize, len: usize, as_: &str) {
    s.pick(src, "_x");
    s.push_u64(off as u64, "_o");
    s.push_u64(len as u64, "_n");
    s.apply(op(OP_SUBSTR), 3, &[as_]);
}

pub(crate) fn sha256(s: &mut Stk, src: &str, as_: &str) {
    s.pick(src, "_x");
    s.apply(op(OP_SHA256), 1, &[as_]);
}

pub(crate) fn size_eq(s: &mut Stk, name: &str, n: u64) {
    s.pick(name, "_x");
    s.apply(ops(&[OP_SIZE, OP_NIP]), 1, &["_sz"]);
    s.push_u64(n, "_c");
    s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
}

/// The compact-size-prefixed scriptPubKey of a serialized output.
pub(crate) fn spk_of_output(s: &mut Stk, out: &str, as_: &str) {
    s.pick(out, "_x");
    s.pick(out, "_y");
    s.apply(ops(&[OP_SIZE, OP_NIP]), 1, &["_sz"]);
    s.push_u64(8, "_c");
    s.apply(op(OP_SUB), 2, &["_n"]);
    s.apply(op(OP_RIGHT), 2, &[as_]);
}

/// A compact-size-prefixed P2WPKH, P2WSH or P2TR scriptPubKey (spec §8.1).
pub(crate) fn native_segwit(s: &mut Stk, spk: &str) {
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
pub(crate) fn caboose_hash(s: &mut Stk, out: &str, as_: &str) {
    size_eq(s, out, 8 + 1 + 38);
    let mut prefix = vec![0u8; 8];
    prefix.extend([0x26, 0x6a, 0x24]);
    left(s, out, 11, "_pfx");
    s.push_data(&prefix, "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    substr(s, out, 11, 32, as_);
}

/// A kind of vault transaction (design §6, §8.4). Inputs are
/// `[vault, deposit x j, fee]`, outputs `[vault, change, extra..., caboose]`:
///
/// | kind | mode | extra outputs | vault amount | nLockTime |
/// |---|---|---|---|---|
/// | `Plain` | NORMAL -> NORMAL | - | unchanged | 0 |
/// | `Fold(j)` | NORMAL -> NORMAL | aggregator OP_RETURN | + deposits | 0 |
/// | `Lock` | NORMAL -> VERIFYING | - | + bond (>= B_min) | h |
/// | `Complete` | VERIFYING -> NORMAL | b, OP_RETURN(R \|\| H), refund | - W - bond | 0 |
/// | `Timeout` | VERIFYING -> NORMAL | - | unchanged | >= h + N |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Plain,
    Fold(usize),
    Lock,
    Complete,
    Timeout,
}

impl Kind {
    pub fn deposits(&self) -> usize {
        match self {
            Kind::Fold(j) => *j,
            _ => 0,
        }
    }

    pub fn n_inputs(&self) -> usize {
        2 + self.deposits()
    }

    pub fn n_outputs(&self) -> usize {
        match self {
            Kind::Fold(_) => 4,
            Kind::Complete => 6,
            _ => 3,
        }
    }

    /// Mode of the application state this kind starts from.
    pub fn old_mode(&self) -> u8 {
        match self {
            Kind::Complete | Kind::Timeout => MODE_VERIFYING,
            _ => MODE_NORMAL,
        }
    }
}

/// What the vault's scripts bake in besides the protocol.
#[derive(Clone, Debug)]
pub struct VaultConfig {
    /// Placeholder for the withdrawal proof verifier: the franker's key, which
    /// signs a completion after checking its statement off chain ([crate::verifier]).
    pub franker: XOnlyPublicKey,
    /// scriptPubKey of program b, which receives the withdrawals.
    pub b_spk: ScriptBuf,
}

/// The vault leaf for one kind.
///
/// Hints, in order: the parent T, the old state S, the old application state
/// A, the kind's own hints (a lock: its data; a completion: the new L2 state root and
/// parameters, the DA data and the franking), and the grandparent Q.
/// The new state is not a hint: the leaf builds it and checks that the caboose
/// commits to it.
pub fn vault_leaf(kind: Kind, cfg: &VaultConfig) -> Script {
    let (n, m) = (kind.n_inputs(), kind.n_outputs());
    let caboose = m - 1;
    let mut s = Stk::new(&[]);

    // AUTH-1: read the spending transaction with OP_TX (version 2, exactly n
    // inputs and m outputs, this is input 0).
    let names = TxFieldsGadget::names("x", n, m, false);
    let names: Vec<&str> = names.iter().map(|x| x.as_str()).collect();
    s.gadget(TxFieldsGadget::build(n, m, Some(0), TX_VERSION), 0, &names);

    // Protocol format (§8.1) and roles (LIN, ROLE, CAB).
    match kind {
        // the lock height h: a block height, not a time
        Kind::Lock => {
            s.pick("x.lt", "_x");
            s.push_u64(LOCK_TIME_THRESHOLD as u64, "_c");
            s.apply(ops(&[OP_LESSTHAN, OP_VERIFY]), 2, &[]);
        }
        // checked by CLTV below
        Kind::Timeout => {}
        _ => eq_const(&mut s, "x.lt", &[0; 4]),
    }
    for i in 0..n {
        eq_const(&mut s, &format!("x.seq{i}"), &SEQUENCE.to_le_bytes());
    }
    right(&mut s, "x.op0", 4, "_vout"); // LIN-2: spends output 0
    s.push_data(&[0; 4], "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    for i in 1..n {
        // deposits and the fee input: native segwit, not a second main program (LIN-1)
        let spk = format!("x.spk{i}");
        native_segwit(&mut s, &spk);
        neq(&mut s, &spk, "x.spk0");
    }
    spk_of_output(&mut s, "x.out0", "_succ_spk"); // the successor pays to P
    s.pick("x.spk0", "_p");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    spk_of_output(&mut s, "x.out1", "x.out1.spk"); // change
    native_segwit(&mut s, "x.out1.spk");
    neq(&mut s, "x.out1.spk", "x.spk0");
    caboose_hash(&mut s, &format!("x.out{caboose}"), "h_new"); // CAB-1
    match kind {
        Kind::Fold(_) => {
            // an OP_RETURN that is not the caboose's script (CAB-4)
            spk_of_output(&mut s, "x.out2", "x.out2.spk");
            substr(&mut s, "x.out2.spk", 1, 1, "_op");
            s.push_data(&[0x6a], "_c");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            spk_of_output(&mut s, &format!("x.out{caboose}"), "_cab_spk");
            neq(&mut s, "x.out2.spk", "_cab_spk");
        }
        Kind::Complete => {
            // out2: program b
            spk_of_output(&mut s, "x.out2", "_b_spk");
            s.push_data(&serialize(&cfg.b_spk), "_c");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            // out3: OP_RETURN PUSHBYTES_64 <R || H>, H the DA commitment
            spk_of_output(&mut s, "x.out3", "_opr");
            size_eq(&mut s, "_opr", 67);
            left(&mut s, "_opr", 3, "_pfx");
            s.push_data(&[0x42, 0x6a, 0x40], "_c");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            right(&mut s, "_opr", 32, "da_hash");
            // out4: the bond refund; not a second main program, which would
            // make the next transition's parse of this transaction fail
            spk_of_output(&mut s, "x.out4", "refund_spk");
            neq(&mut s, "refund_spk", "x.spk0");
        }
        _ => {}
    }

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
    // T's nLockTime is not checked: a lock or a timeout has a non-zero one.
    caboose_hash(&mut s, "t.last", "h_old");

    // The old state S (STATE-1).
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

    // The old application state A, in the mode this kind starts from:
    // acc || mode || l2_root || B_min || N || [h || bond || locker || refund hash].
    s.gadget(OP_HINT(), 0, &["A"]);
    let old_len = match kind.old_mode() {
        MODE_NORMAL => AppState::NORMAL_LEN,
        _ => AppState::VERIFYING_LEN,
    };
    size_eq(&mut s, "A", old_len as u64);
    sha256(&mut s, "A", "_h");
    eq(&mut s, "_h", "root");
    s.drop("_h");
    substr(&mut s, "A", off::MODE, 1, "_mode");
    s.push_data(&[kind.old_mode()], "_c");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    left(&mut s, "A", 32, "acc");
    // acc' = SHA256(acc || txid(T))
    s.pick("acc", "_a");
    s.pick("t.txid", "_t");
    s.apply(ops(&[OP_CAT, OP_SHA256]), 2, &["acc2"]);

    // The vault amount (VALUE) and the new application state after acc' ("tail2").
    left(&mut s, "x.out0", 8, "new_amount");
    match kind {
        Kind::Plain | Kind::Fold(_) => {
            // + deposits; mode and parameters unchanged
            s.pick("x.am0", "_sum");
            for i in 1..=kind.deposits() {
                s.pick(&format!("x.am{i}"), "_d");
                s.apply(op(OP_ADD), 2, &["_sum"]);
            }
            s.pick("new_amount", "_n");
            s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
            right(&mut s, "A", AppState::NORMAL_LEN - off::MODE, "tail2");
        }
        Kind::Lock => {
            // the locker's data: bond || locker's L2 address || refund hash
            s.gadget(OP_HINT(), 0, &["L"]);
            size_eq(&mut s, "L", 72);
            left(&mut s, "L", 8, "bond");
            s.pick("x.am0", "_sum");
            s.pick("bond", "_b");
            s.apply(op(OP_ADD), 2, &["_sum"]);
            s.pick("new_amount", "_n");
            s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
            s.pick("bond", "_b");
            substr(&mut s, "A", off::B_MIN, 8, "_b_min");
            s.apply(ops(&[OP_GREATERTHANOREQUAL, OP_VERIFY]), 2, &[]);
            // VERIFYING || l2_root || params || h (= nLockTime) || data
            s.push_data(&[MODE_VERIFYING], "tail2");
            right(&mut s, "A", AppState::NORMAL_LEN - off::L2_ROOT, "_p");
            s.apply(op(OP_CAT), 2, &["tail2"]);
            s.pick("x.lt", "_h");
            s.apply(op(OP_CAT), 2, &["tail2"]);
            s.pick("L", "_l");
            s.apply(op(OP_CAT), 2, &["tail2"]);
        }
        Kind::Complete => {
            // the new L2 state root and parameters, set by the proof
            s.gadget(OP_HINT(), 0, &["proof2"]);
            size_eq(&mut s, "proof2", (AppState::NORMAL_LEN - off::L2_ROOT) as u64);
            // DA: the data is published in this witness as one chunk, so
            // H = SHA256(data || CHAIN_END)
            s.gadget(OP_HINT(), 0, &["da"]);
            s.pick("da", "_x");
            s.push_data(&CHAIN_END, "_e");
            s.apply(ops(&[OP_CAT, OP_SHA256]), 2, &["_h"]);
            s.pick("da_hash", "_x");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            // Placeholder for the proof verifier: the franker's signature over this
            // transaction, given after it checked the statement off chain.
            s.gadget(OP_HINT(), 0, &["sig"]);
            s.push_data(&cfg.franker.serialize(), "_k");
            s.apply(op(OP_CHECKSIGVERIFY), 2, &[]);
            // new amount + W + bond == old amount
            substr(&mut s, "A", off::BOND, 8, "bond");
            s.pick("new_amount", "_sum");
            left(&mut s, "x.out2", 8, "_w");
            s.apply(op(OP_ADD), 2, &["_sum"]);
            s.pick("bond", "_b");
            s.apply(op(OP_ADD), 2, &["_sum"]);
            s.pick("x.am0", "_a");
            s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
            // the bond goes back to the recorded refund address
            left(&mut s, "x.out4", 8, "_r");
            s.pick("bond", "_b");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            sha256(&mut s, "refund_spk", "_h");
            right(&mut s, "A", 32, "_rh");
            s.apply(op(OP_EQUALVERIFY), 2, &[]);
            // NORMAL || l2_root' || params'
            s.push_data(&[MODE_NORMAL], "tail2");
            s.pick("proof2", "_p");
            s.apply(op(OP_CAT), 2, &["tail2"]);
        }
        Kind::Timeout => {
            // nLockTime >= h + N: from height h + N anyone may time the lock out
            substr(&mut s, "A", off::HEIGHT, 4, "_t");
            substr(&mut s, "A", off::N, 4, "_n");
            s.apply(op(OP_ADD), 2, &["_t"]);
            s.apply(ops(&[OP_CLTV, OP_DROP]), 1, &[]);
            // the bond stays in the vault
            s.pick("x.am0", "_a");
            s.pick("new_amount", "_n");
            s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
            // NORMAL || l2_root || params
            s.push_data(&[MODE_NORMAL], "tail2");
            substr(&mut s, "A", off::L2_ROOT, AppState::NORMAL_LEN - off::L2_ROOT, "_p");
            s.apply(op(OP_CAT), 2, &["tail2"]);
        }
    }
    s.pick("acc2", "_a");
    s.pick("tail2", "_t");
    s.apply(ops(&[OP_CAT, OP_SHA256]), 2, &["root2"]);

    // AUTH-3: the grandparent Q and the output spent by T's input 0.
    s.gadget(OP_HINT(), 0, &["Q"]);
    substr(&mut s, "t.in0", 32, 4, "k");
    parse_tx(&mut s, "Q", "q", &bounds(None), Some("k"), None);
    left(&mut s, "t.in0", 32, "_qtxid");
    s.pick("q.txid", "_x");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);
    spk_of_output(&mut s, "q.out_k", "qspk");

    // AUTH-4: the branch is chosen by the authenticated predecessor script and
    // fixes the new state's id.
    s.pick("qspk", "_x");
    s.pick("P", "_y");
    s.apply(op(OP_EQUAL), 2, &["_cont"]);
    s.if_else(
        |s| {
            // continuation: NEXT-1, NEXT-2, the id is kept
            s.pick("k", "_x");
            s.apply(ops(&[OP_NOT, OP_VERIFY]), 1, &[]);
            num_eq(s, "phase", 1);
            s.pick("id", "id2");
        },
        |s| {
            // genesis: GEN-1, INIT-2, INIT-3, the id is txid(T0)
            num_eq(s, "t.n_in", 1);
            s.pick("phase", "_x");
            s.apply(ops(&[OP_NOT, OP_VERIFY]), 1, &[]);
            s.pick("t.txid", "id2");
        },
    );

    // AUTH-5: the caboose commits to exactly the new state (ACTIVE, id2, root2).
    let mut active = header.clone();
    active.push(PHASE_ACTIVE);
    s.push_data(&active, "_s");
    s.pick("id2", "_i");
    s.apply(op(OP_CAT), 2, &["_s"]);
    s.pick("root2", "_r");
    s.apply(ops(&[OP_CAT, OP_SHA256]), 2, &["_h"]);
    s.pick("h_new", "_x");
    s.apply(op(OP_EQUALVERIFY), 2, &[]);

    let left_over = s.names().len();
    s.apply(drop_n(left_over), left_over, &[]);
    s.push(op(OP_PUSHNUM_1), "ok");
    s.script()
}
