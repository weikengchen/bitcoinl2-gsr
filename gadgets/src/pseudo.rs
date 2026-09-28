#![allow(non_snake_case)]

use crate::treepp::*;
use bitcoin::opcodes::all::OP_PUSHBYTES_0;
use bitcoin::opcodes::Opcode;
use bitcoin::script::{Builder, PushBytesBuf};

/// Concatenate 2 elements.
pub fn OP_CAT2() -> Script {
    script! { OP_CAT }
}

/// Concatenate 3 elements.
pub fn OP_CAT3() -> Script {
    script! { OP_CAT OP_CAT }
}

/// Concatenate 4 elements.
pub fn OP_CAT4() -> Script {
    script! { OP_CAT OP_CAT OP_CAT }
}

/// Pull the next hint from the bottom of the stack.
pub fn OP_HINT() -> Script {
    script! { OP_DEPTH OP_1SUB OP_ROLL }
}

/// Push bytes exactly, without the `script!` small-integer conversion that
/// turns `[0x81]` into `OP_1NEGATE` (OP_SUCCESS in tapscript v2).
/// `[]` uses OP_0 and `[1..=16]` use OP_1..OP_16, which push the same bytes.
pub fn push_data(data: &[u8]) -> Script {
    let b = Builder::new();
    let b = if data.is_empty() {
        b.push_opcode(OP_PUSHBYTES_0)
    } else if data.len() == 1 && (1..=16).contains(&data[0]) {
        b.push_opcode(Opcode::from(0x50 + data[0]))
    } else {
        b.push_slice(PushBytesBuf::try_from(data.to_vec()).unwrap())
    };
    b.into_script()
}

/// Push `n` as a minimal unsigned little-endian number (tapscript v2).
pub fn push_u64(n: u64) -> Script {
    push_data(&bitcoin_scriptexec::v2::from_u64(n))
}

/// Minimal unsigned little-endian encoding of `n`.
pub fn u64_bytes(n: u64) -> Vec<u8> {
    bitcoin_scriptexec::v2::from_u64(n)
}

/// Concatenate scripts.
pub fn cat(parts: &[Script]) -> Script {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p.as_bytes());
    }
    Script::from_bytes(v)
}

/// `OP_PICK` with a v2-safe depth push.
pub fn pick(depth: usize) -> Script {
    cat(&[push_u64(depth as u64), script! { OP_PICK }])
}

/// Drop `n` elements.
pub fn drop_n(n: usize) -> Script {
    let mut parts = vec![];
    for _ in 0..n / 2 {
        parts.push(script! { OP_2DROP });
    }
    if n % 2 == 1 {
        parts.push(script! { OP_DROP });
    }
    cat(&parts)
}
