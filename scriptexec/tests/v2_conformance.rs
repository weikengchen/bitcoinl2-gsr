//! Runs the BIP 440/441 reference vectors against the tapscript v2 evaluator,
//! mirroring `src/test/tapscript_v2_json_tests.cpp` of the reference implementation.

use bitcoin::opcodes::Opcode;
use bitcoin::ScriptBuf;
use bitcoin_scriptexec::eval_tapscript_v2;
use serde_json::Value;
use std::collections::HashMap;

const BUDGET: u64 = 250_000_000;

fn opcode_names() -> HashMap<String, u8> {
    let mut m = HashMap::new();
    for code in 0..=255u8 {
        let name = format!("{}", Opcode::from(code));
        if let Some(short) = name.strip_prefix("OP_") {
            m.insert(short.to_string(), code);
        }
        m.insert(name, code);
    }
    m
}

/// Hex with `{n}` meaning "repeat the previous byte n times in total".
fn parse_expanded_hex(input: &str) -> Vec<u8> {
    let mut input = input.strip_prefix("0x").unwrap_or(input);
    let mut out = Vec::new();
    while !input.is_empty() {
        let open = input.find('{');
        let literal = &input[..open.unwrap_or(input.len())];
        out.extend(hex::decode(literal).expect("hex"));
        let Some(open) = open else { break };
        let close = open + input[open..].find('}').expect("closing brace");
        let count: usize = input[open + 1..close].parse().expect("repeat count");
        let last = *out.last().expect("byte to repeat");
        out.extend(std::iter::repeat(last).take(count - 1));
        input = &input[close + 1..];
    }
    out
}

fn run(file: &str) -> (usize, Vec<String>) {
    let names = opcode_names();
    let data: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    let mut failures = Vec::new();
    let mut count = 0;
    for category in data.as_array().unwrap() {
        for test in category["tests"].as_array().unwrap() {
            count += 1;
            let name = test["name"].as_str().unwrap();
            let mut script = Vec::new();
            for op in test["opcodes"].as_array().unwrap() {
                let op = op.as_str().unwrap();
                match names.get(op) {
                    Some(code) => script.push(*code),
                    None => script.extend(parse_expanded_hex(op)),
                }
            }
            let stack = |key: &str| -> Vec<Vec<u8>> {
                test.get(key)
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().map(|v| parse_expanded_hex(v.as_str().unwrap())).collect())
                    .unwrap_or_default()
            };
            let initial = stack("initial stack");
            let expected = stack("final stack");
            let expected_cost = test["varops cost"].as_u64().unwrap();

            let res = eval_tapscript_v2(ScriptBuf::from_bytes(script), initial, Some(BUDGET));
            if let Some(err) = res.error {
                failures.push(format!("{name}: error {err:?}"));
                continue;
            }
            if res.final_stack != expected {
                let show = |s: &Vec<Vec<u8>>| {
                    s.iter()
                        .map(|e| {
                            let h = hex::encode(e);
                            if h.len() > 64 { format!("{}..({} bytes)", &h[..64], e.len()) } else { h }
                        })
                        .collect::<Vec<_>>()
                };
                failures.push(format!(
                    "{name}: final stack {:?}, expected {:?}",
                    show(&res.final_stack),
                    show(&expected)
                ));
            }
            if res.varops_used != expected_cost {
                failures.push(format!(
                    "{name}: varops {} expected {}",
                    res.varops_used, expected_cost
                ));
            }
        }
    }
    (count, failures)
}

fn check(file: &str) {
    let (count, failures) = run(file);
    for f in &failures {
        eprintln!("FAIL {f}");
    }
    assert!(failures.is_empty(), "{} of {} vectors failed in {file}", failures.len(), count);
    eprintln!("{count} vectors passed in {file}");
}

#[test]
fn restored_ops_vectors() {
    check("tests/data/tapscript_v2_restored_ops.json");
}

#[test]
fn varops_vectors() {
    check("tests/data/tapscript_v2_varops.json");
}
