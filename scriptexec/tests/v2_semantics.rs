//! Failure paths and final-check rules of tapscript v2 (BIP 440/441).

use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::{Transaction, Version};
use bitcoin::ScriptBuf;
use bitcoin_scriptexec::{eval_tapscript_v2, execute_tapscript_v2, Error, ExecError, TxTemplate};

fn ops(ops: &[bitcoin::opcodes::Opcode]) -> ScriptBuf {
    let mut b = Builder::new();
    for op in ops {
        b = b.push_opcode(*op);
    }
    b.into_script()
}

fn err(script: ScriptBuf, stack: Vec<Vec<u8>>, budget: Option<u64>) -> Option<ExecError> {
    eval_tapscript_v2(script, stack, budget).error
}

fn template() -> TxTemplate {
    TxTemplate {
        tx: Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        },
        prevouts: vec![],
        input_idx: 0,
        taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        taproot_control_block: None,
    }
}

#[test]
fn arithmetic_failures() {
    assert_eq!(err(ops(&[OP_SUB]), vec![vec![1], vec![2]], None), Some(ExecError::SubUnderflow));
    assert_eq!(err(ops(&[OP_1SUB]), vec![vec![]], None), Some(ExecError::SubUnderflow));
    assert_eq!(err(ops(&[OP_1SUB]), vec![vec![0, 0]], None), Some(ExecError::SubUnderflow));
    assert_eq!(err(ops(&[OP_DIV]), vec![vec![7], vec![]], None), Some(ExecError::DivByZero));
    assert_eq!(err(ops(&[OP_MOD]), vec![vec![7], vec![0, 0]], None), Some(ExecError::DivByZero));
    // large values are fine
    let r = eval_tapscript_v2(ops(&[OP_MUL]), vec![vec![0xff; 40], vec![0xff; 40]], None);
    assert_eq!(r.error, None);
    assert_eq!(r.final_stack[0].len(), 80);
}

#[test]
fn size_limits() {
    // UPSHIFT past 4,000,000 bytes
    let bits = (4_000_000u64 * 8).to_le_bytes().to_vec();
    assert_eq!(err(ops(&[OP_LSHIFT]), vec![vec![1], bits], None), Some(ExecError::StackElementSize));
    // CAT past 4,000,000 bytes
    assert_eq!(
        err(ops(&[OP_CAT]), vec![vec![1; 2_000_000], vec![2; 2_000_001]], None),
        Some(ExecError::StackElementSize)
    );
    // exactly 4,000,000 is fine
    assert_eq!(err(ops(&[OP_CAT]), vec![vec![1; 2_000_000], vec![2; 2_000_000]], None), None);
    // total stack > 8,000,000 at start
    assert_eq!(
        err(ops(&[OP_NOP]), vec![vec![1; 3_000_000], vec![1; 3_000_000], vec![1; 3_000_000]], None),
        Some(ExecError::TotalStackSize)
    );
    // DUP pushing the total past 8,000,000
    assert_eq!(
        err(ops(&[OP_DUP]), vec![vec![1; 3_000_000], vec![1; 3_000_000]], None),
        Some(ExecError::TotalStackSize)
    );
    // legacy hash operand limit
    assert_eq!(err(ops(&[OP_RIPEMD160]), vec![vec![0; 521]], None), Some(ExecError::HashOperandSize));
    assert_eq!(err(ops(&[OP_SHA1]), vec![vec![0; 520]], None), None);
    // 40,000 elements
    assert_eq!(err(ops(&[OP_NOP]), vec![vec![]; 40_000], None), Some(ExecError::StackSize));
}

#[test]
fn varops_budget() {
    // SHA256 of 100 bytes costs 5,000
    assert_eq!(err(ops(&[OP_SHA256]), vec![vec![0; 100]], Some(4_999)), Some(ExecError::VaropCount));
    assert_eq!(err(ops(&[OP_SHA256]), vec![vec![0; 100]], Some(5_000)), None);
    // MUL is charged before the multiplication
    let mul = 2 * 3 + 8 / 8 * 8 * 27;
    assert_eq!(err(ops(&[OP_MUL]), vec![vec![3], vec![4]], Some(mul - 1)), Some(ExecError::VaropCount));
    assert_eq!(eval_tapscript_v2(ops(&[OP_MUL]), vec![vec![3], vec![4]], None).varops_used, mul);
}

#[test]
fn control_flow() {
    assert_eq!(err(ops(&[OP_VERIFY]), vec![vec![0, 0]], None), Some(ExecError::Verify));
    assert_eq!(err(ops(&[OP_VERIFY]), vec![vec![0, 1]], None), None);
    assert_eq!(
        err(ops(&[OP_IF, OP_ENDIF]), vec![vec![2]], None),
        Some(ExecError::TapscriptMinimalIf)
    );
    assert_eq!(err(ops(&[OP_IF]), vec![vec![]], None), Some(ExecError::UnbalancedConditional));
    let big = vec![0, 0, 0, 0, 1];
    assert_eq!(err(ops(&[OP_CLTV]), vec![big], None), Some(ExecError::UnsatisfiedLocktime));
    // numbers compare numerically, EQUAL compares bytes
    let r = eval_tapscript_v2(ops(&[OP_2DUP, OP_EQUAL, OP_TOALTSTACK, OP_NUMEQUAL]), vec![vec![1], vec![1, 0]], None);
    assert_eq!(r.final_stack, vec![vec![1]]);
}

#[test]
fn final_check_and_op_success() {
    let run = |script: ScriptBuf, witness: Vec<Vec<u8>>| execute_tapscript_v2(script, template(), witness, None);
    // exactly one element with a non-zero byte
    assert!(run(ops(&[OP_NOP]), vec![vec![0, 1]]).unwrap().success);
    assert_eq!(run(ops(&[OP_NOP]), vec![vec![0, 0]]).unwrap().error, Some(ExecError::EvalFalse));
    assert_eq!(run(ops(&[OP_NOP]), vec![vec![1], vec![1]]).unwrap().error, Some(ExecError::CleanStack));
    // final check is charged: wordspan(2) * 2 = 16
    let info = run(ops(&[OP_NOP]), vec![vec![0, 1]]).unwrap();
    assert_eq!(info.stats.varops_final_check, 16);
    // OP_NEGATE is OP_SUCCESS143: the script succeeds regardless of what precedes it
    assert!(run(ops(&[OP_RETURN, OP_NEGATE]), vec![]).unwrap().success);
    // initial stack limits are checked when there is no OP_SUCCESS
    assert!(matches!(
        run(ops(&[OP_NOP]), vec![vec![0; 4_000_001]]),
        Err(Error::Exec(ExecError::StackElementSize))
    ));
}
