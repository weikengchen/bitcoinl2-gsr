//! Canonical parsing of a non-witness transaction serialization given as one
//! stack element. Bounded loops validate the whole serialization (one-byte
//! counts, empty scriptSigs, one-byte script lengths, exactly 4 bytes left for
//! the lock time), so the fields read are exactly the transaction's fields.

use crate::pseudo::*;
use crate::stack::Stk;
use crate::treepp::*;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::Transaction;

fn op(o: bitcoin::opcodes::Opcode) -> Script {
    Builder::new().push_opcode(o).into_script()
}

/// Limits and checks of [parse_tx].
#[derive(Clone, Debug)]
pub struct TxParse {
    pub max_inputs: usize,
    pub max_outputs: usize,
    /// Require every input's nSequence to equal this value.
    pub sequence: Option<u32>,
}

/// Non-witness serialization (the txid preimage). All scriptSigs must be empty.
pub fn tx_blob(tx: &Transaction) -> Vec<u8> {
    let mut t = tx.clone();
    for i in t.input.iter_mut() {
        assert!(i.script_sig.is_empty(), "scriptSigs must be empty");
        i.witness.clear();
    }
    bitcoin::consensus::serialize(&t)
}

fn substr_const(s: &mut Stk, src: &str, off: usize, len: usize, name: &str) {
    s.pick(src, "_src");
    s.push_u64(off as u64, "_off");
    s.push_u64(len as u64, "_len");
    s.apply(op(OP_SUBSTR), 3, &[name]);
}

/// value != 0 and value <= max (so a one-byte compact size when max < 253).
fn check_count(s: &mut Stk, name: &str, max: usize) {
    assert!(max < 253);
    s.pick(name, "_t");
    s.apply(op(OP_0NOTEQUAL), 1, &["_c"]);
    s.verify();
    s.pick(name, "_t");
    s.push_u64(max as u64 + 1, "_u");
    s.apply(op(OP_LESSTHAN), 2, &["_c"]);
    s.verify();
}

/// `if cond { new } else { old }` for the two elements on top: `( old new cond -- x )`.
fn select() -> Script {
    script! { OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF }
}

/// Parse the transaction `tx` (consumed) and push, with names prefixed by `p.`:
/// `txid version n_in in0 n_out out0 [out_k] last lock_time`.
///
/// - `txid` is HASH256 of the serialization (internal byte order);
/// - `in0` is input 0's outpoint, `out0`/`last` are serialized outputs;
/// - `k`: also return output `k` (a number on the stack, left in place) and require `k < n_out`;
/// - `forbid`: fail if an output other than output 0 has this compact-size-prefixed
///   scriptPubKey (left in place).
pub fn parse_tx(s: &mut Stk, tx: &str, p: &str, cfg: &TxParse, k: Option<&str>, forbid: Option<&str>) {
    let n = |x: &str| format!("{p}.{x}");

    s.pick(tx, "_t");
    s.apply(op(OP_HASH256), 1, &[&n("txid")]);
    substr_const(s, tx, 0, 4, &n("version"));
    substr_const(s, tx, 4, 1, &n("n_in"));
    check_count(s, &n("n_in"), cfg.max_inputs);
    substr_const(s, tx, 5, 36, &n("in0"));

    for i in 0..cfg.max_inputs {
        s.pick(&n("n_in"), "_t");
        s.push_u64(i as u64, "_u");
        s.apply(op(OP_GREATERTHAN), 2, &["_c"]);
        s.if_(|s| {
            // empty scriptSig
            substr_const(s, tx, 5 + 41 * i + 36, 1, "_ss");
            s.apply(cat(&[op(OP_NOT), op(OP_VERIFY)]), 1, &[]);
            if let Some(seq) = cfg.sequence {
                substr_const(s, tx, 5 + 41 * i + 37, 4, "_seq");
                s.push_data(&seq.to_le_bytes(), "_e");
                s.apply(op(OP_EQUALVERIFY), 2, &[]);
            }
        });
    }

    // cursor at the output count
    s.pick(&n("n_in"), "_t");
    s.push_u64(41, "_u");
    s.apply(op(OP_MUL), 2, &["_m"]);
    s.push_u64(5, "_u");
    s.apply(op(OP_ADD), 2, &["_cur"]);
    s.pick(tx, "_src");
    s.pick("_cur", "_off");
    s.push_u64(1, "_len");
    s.apply(op(OP_SUBSTR), 3, &[&n("n_out")]);
    check_count(s, &n("n_out"), cfg.max_outputs);
    s.roll("_cur");
    s.apply(op(OP_1ADD), 1, &["_cur"]);
    if let Some(k) = k {
        s.pick(k, "_t");
        s.pick(&n("n_out"), "_u");
        s.apply(op(OP_LESSTHAN), 2, &["_c"]);
        s.verify();
    }

    s.push(op(OP_PUSHBYTES_0), &n("out0"));
    if k.is_some() {
        s.push(op(OP_PUSHBYTES_0), &n("out_k"));
    }
    s.push(op(OP_PUSHBYTES_0), &n("last"));

    for j in 0..cfg.max_outputs {
        s.pick(&n("n_out"), "_t");
        s.push_u64(j as u64, "_u");
        s.apply(op(OP_GREATERTHAN), 2, &["_c"]);
        s.if_(|s| {
            // script length at cursor + 8, one byte
            s.pick(tx, "_src");
            s.pick("_cur", "_off");
            s.push_u64(8, "_e");
            s.apply(op(OP_ADD), 2, &["_off"]);
            s.push_u64(1, "_len");
            s.apply(op(OP_SUBSTR), 3, &["_slen"]);
            s.pick("_slen", "_t");
            s.push_u64(0xfd, "_u");
            s.apply(op(OP_LESSTHAN), 2, &["_c"]);
            s.verify();
            s.push_u64(9, "_u");
            s.apply(op(OP_ADD), 2, &["_size"]);
            s.pick(tx, "_src");
            s.pick("_cur", "_off");
            s.pick("_size", "_len");
            s.apply(op(OP_SUBSTR), 3, &["_item"]);

            if j == 0 {
                s.drop(&n("out0"));
                s.pick("_item", &n("out0"));
            }
            if let Some(k) = k {
                s.roll(&n("out_k"));
                s.pick("_item", "_new");
                s.pick(k, "_t");
                s.push_u64(j as u64, "_u");
                s.apply(op(OP_NUMEQUAL), 2, &["_c"]);
                s.apply(select(), 3, &[&n("out_k")]);
            }
            s.roll(&n("last"));
            s.pick("_item", "_new");
            s.pick(&n("n_out"), "_t");
            s.push_u64(j as u64 + 1, "_u");
            s.apply(op(OP_NUMEQUAL), 2, &["_c"]);
            s.apply(select(), 3, &[&n("last")]);
            if let (true, Some(f)) = (j >= 1, forbid) {
                s.pick("_item", "_t");
                s.pick("_size", "_u");
                s.push_u64(8, "_e");
                s.apply(op(OP_SUB), 2, &["_u"]);
                s.apply(op(OP_RIGHT), 2, &["_spk"]);
                s.pick(f, "_f");
                s.apply(cat(&[op(OP_EQUAL), op(OP_NOT), op(OP_VERIFY)]), 2, &[]);
            }
            s.drop("_item");
            s.roll("_cur");
            s.roll("_size");
            s.apply(op(OP_ADD), 2, &["_cur"]);
        });
    }

    // exactly the 4-byte lock time must remain
    s.roll("_cur");
    s.push_u64(4, "_u");
    s.apply(op(OP_ADD), 2, &["_end"]);
    s.pick(tx, "_t");
    s.apply(cat(&[op(OP_SIZE), op(OP_NIP)]), 1, &["_sz"]);
    s.apply(op(OP_NUMEQUALVERIFY), 2, &[]);
    s.pick(tx, "_t");
    s.push_u64(4, "_u");
    s.apply(op(OP_RIGHT), 2, &[&n("lock_time")]);
    s.drop(tx);
}
