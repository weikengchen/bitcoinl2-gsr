//! Transaction introspection with OP_TX (tapscript v2 opcode 0xbd, as
//! implemented in jmoik/bitcoin `gsr-full`; see `bitcoin_scriptexec::optx`).
//!
//! Selectors are always script constants: a selector whose first byte is not
//! zero makes the leaf succeed, so a selector must never come from the witness.

use crate::pseudo::{cat, push_data, push_u64};
use crate::treepp::*;
use bitcoin_scriptexec::optx::*;

/// `<selector> OP_TX` for a constant selector.
pub fn op_tx(globals: u8, context: u8, input_scope: u8, output_scope: u8, input_fields: u8, output_fields: u8) -> Script {
    let selector = [0, globals, context, (input_scope << 4) | output_scope, input_fields, output_fields];
    cat(&[push_data(&selector), Script::from_bytes(vec![OP_TX])])
}

/// `( -- fields )`: `fields` of input `i`, collated.
pub fn input_fields(i: usize, fields: u8) -> Script {
    cat(&[push_u64(i as u64), op_tx(COLLATE, 0, SCOPE_SINGLE, SCOPE_NONE, fields, 0)])
}

/// `( -- output )`: output `j` serialized (8-byte amount, compact-size-prefixed script).
pub fn output(j: usize) -> Script {
    cat(&[push_u64(j as u64), op_tx(COLLATE, 0, SCOPE_NONE, SCOPE_SINGLE, 0, OUTPUT_AMOUNT | OUTPUT_SCRIPTPUBKEY)])
}

/// `( -- outputs )`: all outputs serialized back to back, i.e. the preimage of
/// BIP 341's sha_outputs.
pub fn all_outputs() -> Script {
    op_tx(COLLATE, 0, SCOPE_NONE, SCOPE_ALL, 0, OUTPUT_AMOUNT | OUTPUT_SCRIPTPUBKEY)
}

/// `( -- )`: fail unless the transaction has nVersion `version`, `n_inputs`
/// inputs and `n_outputs` outputs.
pub fn check_shape(version: u32, n_inputs: usize, n_outputs: usize) -> Script {
    let mut want = version.to_le_bytes().to_vec();
    want.extend((n_inputs as u32).to_le_bytes());
    want.extend((n_outputs as u32).to_le_bytes());
    cat(&[
        op_tx(COLLATE | TX_VERSION | INPUT_TOTAL_COUNT | OUTPUT_TOTAL_COUNT, 0, SCOPE_NONE, SCOPE_NONE, 0, 0),
        push_data(&want),
        script! { OP_EQUALVERIFY },
    ])
}

/// `( -- index )`: the executing input's index as 4 bytes, little-endian.
pub fn current_input_index() -> Script {
    op_tx(COLLATE, CURRENT_INPUT_INDEX, SCOPE_NONE, SCOPE_NONE, 0, 0)
}

/// The fields of the spending transaction in the serialized forms of BIP 341
/// signature messages, read with OP_TX.
pub struct TxFieldsGadget;

impl TxFieldsGadget {
    /// `( -- outpoints[n] amounts[n] script_pubkeys[n] sequences[n] outputs[m] lock_time [input_index] )`:
    /// 36-byte outpoints, 8-byte amounts, compact-size-prefixed scriptPubKeys,
    /// 4-byte sequences, serialized outputs and the 4-byte lock time. It first
    /// checks nVersion and that there are exactly n inputs and m outputs. With
    /// `input_index = Some(i)` it checks that the executing input is i;
    /// with `None` it leaves the 4-byte input index on top.
    pub fn build(n_inputs: usize, n_outputs: usize, input_index: Option<u32>, version: u32) -> Script {
        let mut parts = vec![check_shape(version, n_inputs, n_outputs)];
        if let Some(i) = input_index {
            parts.push(current_input_index());
            parts.push(push_data(&i.to_le_bytes()));
            parts.push(script! { OP_EQUALVERIFY });
        }
        for field in [INPUT_PREVOUT_TXID | INPUT_PREVOUT_INDEX, INPUT_PREVOUT_AMOUNT, INPUT_PREVOUT_SCRIPTPUBKEY, INPUT_SEQUENCE] {
            for i in 0..n_inputs {
                parts.push(input_fields(i, field));
            }
        }
        for j in 0..n_outputs {
            parts.push(output(j));
        }
        parts.push(op_tx(COLLATE | TX_LOCKTIME, 0, SCOPE_NONE, SCOPE_NONE, 0, 0));
        if input_index.is_none() {
            parts.push(current_input_index());
        }
        cat(&parts)
    }

    /// Stack names for [crate::stack::Stk] after [TxFieldsGadget::build], bottom
    /// to top: `{p}.op{i}`, `{p}.am{i}`, `{p}.spk{i}`, `{p}.seq{i}`, `{p}.out{j}`,
    /// `{p}.lt` and, with a runtime index, `{p}.index`.
    pub fn names(p: &str, n_inputs: usize, n_outputs: usize, runtime_index: bool) -> Vec<String> {
        let mut v = vec![];
        for f in ["op", "am", "spk", "seq"] {
            for i in 0..n_inputs {
                v.push(format!("{p}.{f}{i}"));
            }
        }
        for j in 0..n_outputs {
            v.push(format!("{p}.out{j}"));
        }
        v.push(format!("{p}.lt"));
        if runtime_index {
            v.push(format!("{p}.index"));
        }
        v
    }
}
