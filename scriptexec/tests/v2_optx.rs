//! Runs the OP_TX reference vectors, mirroring the `reference_vectors` case of
//! `src/test/op_tx_tests.cpp` in jmoik/bitcoin `gsr-full` at d2799052604e.

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{ScriptBuf, Transaction, TxOut};
use bitcoin_scriptexec::optx::{eval, Context, Error, Outcome, Stacks};
use bitcoin_scriptexec::v2::TAPROOT_LEAF_TAPSCRIPT_V2;
use serde_json::Value;

const DEFAULT_VAROPS: u64 = 40_000_000_000;

/// A hex string, or `{"repeat": hex, "count": n}`.
fn bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => hex::decode(s).unwrap(),
        Value::Object(o) => hex::decode(o["repeat"].as_str().unwrap()).unwrap().repeat(o["count"].as_u64().unwrap() as usize),
        _ => panic!("bad hex value {v}"),
    }
}

fn optional(v: &Value) -> Option<Vec<u8>> {
    (!v.is_null()).then(|| bytes(v))
}

/// Stack elements; `{"element": hex, "items": n}` repeats one element n times.
fn stack(v: Option<&Value>) -> Vec<Vec<u8>> {
    let mut out = vec![];
    for e in v.and_then(|v| v.as_array()).into_iter().flatten() {
        match e.get("items") {
            Some(n) => out.extend(std::iter::repeat(bytes(&e["element"])).take(n.as_u64().unwrap() as usize)),
            None => out.push(bytes(e)),
        }
    }
    out
}

fn expected_error(name: &str) -> Error {
    match name {
        "missing_selector" | "missing_scope_operand" => Error::InvalidStackOperation,
        "varops_exhausted" => Error::VaropCount,
        "stack_item_limit" => Error::StackSize,
        "stack_byte_limit" => Error::TotalStackSize,
        "element_size_limit" => Error::ElementSize,
        "amount_overflow" | "unavailable_context" | "unavailable_record" | "invalid_current_input" => Error::Context,
        _ => Error::Selector,
    }
}

#[test]
fn reference_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("data/op_tx.json")).unwrap();
    assert_eq!(vectors.len(), 76);
    for t in &vectors {
        let id = t["id"].as_str().unwrap();
        let tx: Transaction = deserialize(&hex::decode(t["spending_tx"].as_str().unwrap()).unwrap()).unwrap();
        let spent: Vec<TxOut> = t["spent_outputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| deserialize(&hex::decode(o.as_str().unwrap()).unwrap()).unwrap())
            .collect();

        let c = &t["context"];
        let annex = optional(&c["annex"]);
        let tapscript = optional(&c["tapscript"]);
        let control_block = optional(&c["control_block"]);
        let leaf_version = LeafVersion::from_consensus(TAPROOT_LEAF_TAPSCRIPT_V2).unwrap();
        let leaf_hash = tapscript
            .as_ref()
            .map(|s| TapLeafHash::from_script(&ScriptBuf::from_bytes(s.clone()), leaf_version).to_byte_array());
        let taptree_root = match (&control_block, leaf_hash) {
            (Some(cb), Some(h)) => Context::taptree_root(cb, h),
            _ => None,
        };
        let ctx = Context {
            tx: &tx,
            spent_outputs: &spent,
            input_index: t["input_index"].as_u64().unwrap() as usize,
            annex: Some(annex.as_deref()),
            tapscript: tapscript.as_deref(),
            tapleaf_hash: leaf_hash,
            control_block: control_block.as_deref(),
            taptree_root,
            codesep_pos: c["codesep_pos"].as_u64().map(|p| p as u32),
        };

        let initial = stack(t.get("initial_stack"));
        let operands = stack(t.get("scope_operands"));
        let mut invocation = initial.clone();
        invocation.extend(operands.iter().cloned());
        let mut full = invocation.clone();
        if let Some(sel) = t.get("selector").filter(|s| !s.is_null()) {
            full.push(bytes(sel));
        }
        let alt = stack(t.get("initial_altstack"));
        let stacks = Stacks {
            len: full.len(),
            bytes: full.iter().map(|e| e.len()).sum(),
            alt_len: alt.len(),
            alt_bytes: alt.iter().map(|e| e.len()).sum(),
        };
        let top: Vec<Vec<u8>> = full.iter().rev().take(5).cloned().collect();
        let budget = t.get("available_varops").and_then(|v| v.as_u64()).unwrap_or(DEFAULT_VAROPS);

        let result = eval(&top, &stacks, &ctx, budget);
        let e = &t["expected"];
        if e["success"].as_bool().unwrap() {
            let outputs = stack(e.get("outputs"));
            let immediate = e.get("immediate_success").and_then(|v| v.as_bool()).unwrap_or(false);
            match result {
                Ok(Outcome::ImmediateSuccess) => {
                    assert!(immediate, "{id}: unexpected immediate success");
                    assert!(outputs.is_empty(), "{id}");
                    assert_eq!(e["varops"].as_u64().unwrap(), 0, "{id}");
                }
                Ok(Outcome::Push { pop, outputs: got, cost }) => {
                    assert!(!immediate, "{id}: expected immediate success");
                    assert_eq!(pop, full.len() - initial.len(), "{id}: popped elements");
                    assert_eq!(got, outputs, "{id}: outputs");
                    assert_eq!(cost, e["varops"].as_u64().unwrap(), "{id}: varops");
                }
                Err(err) => panic!("{id}: unexpected error {err:?}"),
            }
        } else {
            let want = expected_error(e["error"].as_str().unwrap());
            assert_eq!(result, Err(want), "{id}");
        }
    }
}
