//! Tapscript leaf version 0xc2 (BIP 440 varops budget, BIP 441 restored script).
//!
//! Values are arbitrary-length unsigned little-endian byte strings. Arithmetic
//! operations normalize their results (no trailing zero bytes); bit and byte
//! operations do not. Semantics and costs follow the reference implementation
//! (jmoik/bitcoin `gsr-inquisition`, `src/script/val64.cpp` and `varops.h`).

use core::cmp::Ordering;
use num_bigint::BigUint;

/// Tapscript v2 leaf version.
pub const TAPROOT_LEAF_TAPSCRIPT_V2: u8 = 0xc2;
/// Maximum size of a single stack element.
pub const MAX_STACK_ELEMENT_SIZE: usize = 4_000_000;
/// Maximum total size of all stack and altstack elements.
pub const MAX_TOTAL_STACK_SIZE: usize = 2 * MAX_STACK_ELEMENT_SIZE;
/// Maximum number of stack and altstack elements.
pub const MAX_STACK_SIZE: usize = 32_768;
/// OP_RIPEMD160 and OP_SHA1 operands are limited to the old element size.
pub const MAX_LEGACY_HASH_OPERAND_SIZE: usize = 520;

/// BIP 440 cost constants and per-opcode cost formulas.
pub mod varops {
    pub const COST_FAST: u64 = 2;
    pub const COST_COPYING: u64 = 3;
    pub const COST_OTHER: u64 = 4;
    pub const COST_ARITH: u64 = 6;
    pub const COST_MUL_QUAD: u64 = 27;
    pub const COST_ROLL: u64 = 48;
    pub const COST_HASH: u64 = 50;
    pub const BUDGET_PER_WEIGHT_UNIT: u64 = 10_000;
    pub const COST_PER_SIGOP: u64 = BUDGET_PER_WEIGHT_UNIT * 50;

    /// Transaction-wide budget.
    pub fn tx_budget(weight: u64) -> u64 {
        weight * BUDGET_PER_WEIGHT_UNIT
    }

    /// Byte count rounded up to the 64-bit word span.
    pub fn ws(size: usize) -> u64 {
        (size as u64 + 7) / 8 * 8
    }

    pub fn length_conversion(size: usize) -> u64 {
        ws(size) * COST_FAST
    }
    pub fn compare_zero(size: usize) -> u64 {
        ws(size) * COST_FAST
    }
    pub fn comparison(a: usize, b: usize) -> u64 {
        ws(a).max(ws(b)) * COST_FAST
    }
    pub fn add(a: usize, b: usize) -> u64 {
        ws(a).max(ws(b)) * (COST_ARITH + COST_COPYING)
    }
    pub fn sub(a: usize, b: usize) -> u64 {
        ws(a).max(ws(b)) * COST_ARITH
    }
    pub fn mul(a: usize, b: usize) -> u64 {
        (a as u64 + b as u64) * COST_COPYING + ws(a) / 8 * ws(b) * COST_MUL_QUAD
    }
    pub fn div(a: usize, b: usize) -> u64 {
        let s1 = ws(a);
        let s2 = ws(b);
        s1 * (3 * COST_ARITH) + s2 * COST_OTHER + s1 * s1 * 2 / 3
    }
    pub fn bool_and_or(a: usize, b: usize) -> u64 {
        (ws(a) + ws(b)) * COST_FAST
    }
    pub fn within(a: usize, b: usize, c: usize) -> u64 {
        ws(a).max(ws(b)) * COST_FAST + ws(a).max(ws(c)) * COST_FAST
    }
    pub fn invert(a: usize) -> u64 {
        ws(a) * COST_OTHER
    }
    pub fn and(a: usize, b: usize) -> u64 {
        (ws(a) + ws(b)) * COST_FAST
    }
    pub fn or_xor(a: usize, b: usize) -> u64 {
        ws(a).min(ws(b)) * COST_OTHER
    }
    pub fn min_max(a: usize, b: usize) -> u64 {
        ws(a).max(ws(b)) * COST_OTHER
    }
    pub fn two_mul(a: usize) -> u64 {
        ws(a) * (COST_COPYING + COST_OTHER)
    }
    pub fn two_div(a: usize) -> u64 {
        ws(a) * COST_OTHER
    }
    pub fn unaligned_upshift(size: usize, prepended: usize) -> u64 {
        ws(size + prepended) * COST_OTHER
    }
    pub fn checksigadd_increment(number_size: usize) -> u64 {
        ws(1).max(ws(number_size)) * (COST_ARITH + COST_COPYING)
    }
}

/// OP_SUCCESSx opcodes in tapscript v2.
pub fn is_op_success(op: u8) -> bool {
    op == 79 // OP_1NEGATE
        || op == 80 // OP_RESERVED
        || op == 98 // OP_VER
        || op == 137 // OP_RESERVED1
        || op == 138 // OP_RESERVED2
        || op == 143 // OP_NEGATE
        || op == 144 // OP_ABS
        || (187..=254).contains(&op)
}

/// Drop trailing zero bytes.
pub fn trim(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    v
}

/// Minimal little-endian encoding of `n` (zero is empty).
pub fn from_u64(n: u64) -> Vec<u8> {
    trim(n.to_le_bytes().to_vec())
}

/// `[1]` for true, `[]` for false.
pub fn from_bool(b: bool) -> Vec<u8> {
    if b {
        vec![1]
    } else {
        vec![]
    }
}

pub fn is_zero(v: &[u8]) -> bool {
    v.iter().all(|b| *b == 0)
}

/// Numeric comparison, ignoring trailing zero bytes.
pub fn compare(a: &[u8], b: &[u8]) -> Ordering {
    let n = a.len().max(b.len());
    for i in (0..n).rev() {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            o => return o,
        }
    }
    Ordering::Equal
}

/// Value as u64, or `max` if it is larger than `max`. Costs LENGTHCONV.
pub fn to_u64_ceil(v: &[u8], max: u64, cost: &mut u64) -> u64 {
    *cost += varops::length_conversion(v.len());
    if v.len() > 8 && !is_zero(&v[8..]) {
        return max;
    }
    let mut buf = [0u8; 8];
    let n = v.len().min(8);
    buf[..n].copy_from_slice(&v[..n]);
    u64::from_le_bytes(buf).min(max)
}

fn big(v: &[u8]) -> BigUint {
    BigUint::from_bytes_le(v)
}

fn unbig(v: BigUint) -> Vec<u8> {
    trim(v.to_bytes_le())
}

pub fn add(a: &[u8], b: &[u8]) -> Vec<u8> {
    unbig(big(a) + big(b))
}

/// `None` on underflow.
pub fn sub(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    let (x, y) = (big(a), big(b));
    if x < y {
        None
    } else {
        Some(unbig(x - y))
    }
}

pub fn mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    unbig(big(a) * big(b))
}

/// `None` if the divisor is zero.
pub fn div(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    let y = big(b);
    if y.bits() == 0 {
        None
    } else {
        Some(unbig(big(a) / y))
    }
}

/// `None` if the divisor is zero.
pub fn rem(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    let y = big(b);
    if y.bits() == 0 {
        None
    } else {
        Some(unbig(big(a) % y))
    }
}

pub fn two_mul(a: &[u8]) -> Vec<u8> {
    unbig(big(a) << 1usize)
}

pub fn two_div(a: &[u8]) -> Vec<u8> {
    unbig(big(a) >> 1usize)
}

pub fn invert(a: &[u8]) -> Vec<u8> {
    a.iter().map(|b| b ^ 0xff).collect()
}

/// Result has the length of the longer operand.
pub fn and(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    (0..n)
        .map(|i| a.get(i).unwrap_or(&0) & b.get(i).unwrap_or(&0))
        .collect()
}

/// Result has the length of the longer operand.
pub fn or(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    (0..n)
        .map(|i| a.get(i).unwrap_or(&0) | b.get(i).unwrap_or(&0))
        .collect()
}

/// Result has the length of the longer operand.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    (0..n)
        .map(|i| a.get(i).unwrap_or(&0) ^ b.get(i).unwrap_or(&0))
        .collect()
}

/// OP_UPSHIFT (OP_LSHIFT). `None` if the result would exceed the element size limit.
///
/// Byte-aligned shifts prepend `bits / 8` zero bytes. Unaligned shifts produce
/// `len + bits / 8 + 1` bytes. Trailing zeros are kept.
pub fn upshift(a: &[u8], bits_v: &[u8], cost: &mut u64) -> Option<Vec<u8>> {
    let max_bits = MAX_STACK_ELEMENT_SIZE as u64 * 8;
    let bits = to_u64_ceil(bits_v, max_bits + 1, cost);
    if bits + a.len() as u64 * 8 > max_bits {
        return None;
    }
    let prebytes = (bits / 8) as usize;
    *cost += prebytes as u64 * varops::COST_FAST + a.len() as u64 * varops::COST_COPYING;
    let r = (bits % 8) as u32;
    if r == 0 {
        let mut out = vec![0u8; prebytes];
        out.extend_from_slice(a);
        return Some(out);
    }
    *cost += varops::unaligned_upshift(a.len(), prebytes);
    let mut out = vec![0u8; a.len() + prebytes + 1];
    for (i, byte) in a.iter().enumerate() {
        out[i + prebytes] |= byte << r;
        out[i + prebytes + 1] |= byte >> (8 - r);
    }
    Some(out)
}

/// OP_DOWNSHIFT (OP_RSHIFT). The result keeps `len - bits / 8` bytes, or is
/// empty if everything is shifted out.
pub fn downshift(a: &[u8], bits_v: &[u8], cost: &mut u64) -> Vec<u8> {
    let bits = to_u64_ceil(bits_v, a.len() as u64 * 8, cost);
    let bytes = (bits / 8) as usize;
    if bytes >= a.len() {
        return vec![];
    }
    *cost += (a.len() - bytes) as u64 * varops::COST_COPYING;
    let r = (bits % 8) as u32;
    let n = a.len() - bytes;
    if r == 0 {
        return a[bytes..].to_vec();
    }
    (0..n)
        .map(|i| {
            let lo = a[i + bytes] >> r;
            let hi = a.get(i + bytes + 1).map(|b| b << (8 - r)).unwrap_or(0);
            lo | hi
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_is_minimal() {
        assert_eq!(add(&[0xff], &[0x01]), vec![0x00, 0x01]);
        assert_eq!(add(&[], &[]), Vec::<u8>::new());
        assert_eq!(sub(&[0x00, 0x01], &[0x01]), Some(vec![0xff]));
        assert_eq!(sub(&[0x01], &[0x02]), None);
        assert_eq!(mul(&[0x02, 0x00], &[0x03]), vec![0x06]);
        assert_eq!(div(&[0x07], &[]), None);
        assert_eq!(rem(&[0x07], &[0x03]), Some(vec![0x01]));
        assert_eq!(two_mul(&[0x80]), vec![0x00, 0x01]);
        assert_eq!(two_div(&[0x01]), Vec::<u8>::new());
    }

    #[test]
    fn shifts_keep_length_rules() {
        let mut c = 0;
        assert_eq!(upshift(&[0x01], &[0x01], &mut c), Some(vec![0x02, 0x00]));
        assert_eq!(upshift(&[0x01], &[0x08], &mut c), Some(vec![0x00, 0x01]));
        assert_eq!(downshift(&[0x00, 0x02], &[0x09], &mut c), vec![0x01]);
        assert_eq!(downshift(&[0x02], &[0x10], &mut c), Vec::<u8>::new());
    }

    #[test]
    fn ceil_conversion() {
        let mut c = 0;
        assert_eq!(to_u64_ceil(&[0x05, 0x00], 3, &mut c), 3);
        assert_eq!(to_u64_ceil(&[0x05, 0, 0, 0, 0, 0, 0, 0, 0x01], u64::MAX, &mut c), u64::MAX);
        assert_eq!(to_u64_ceil(&[0x05, 0, 0, 0, 0, 0, 0, 0, 0x00], 100, &mut c), 5);
        assert_eq!(c, 8 * 2 + 16 * 2 + 16 * 2);
    }
}
