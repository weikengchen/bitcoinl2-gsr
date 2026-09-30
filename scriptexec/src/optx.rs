//! OP_TX (0xbd in tapscript v2): pushes selected fields of the spending
//! transaction and of the executing input's context.
//!
//! Semantics, encodings, error cases and costs follow jmoik/bitcoin `gsr-full`
//! at d2799052604e (src/script/op_tx.cpp), whose reference vectors
//! (tests/data/op_tx.json) pass. That branch also charges a fixed execution
//! cost per opcode; only OP_TX's charge is taken over here, the other opcodes
//! keep the costs of the BIP 440/441 reference at 8384b7a.
//!
//! The selector is 6 bytes: a version byte (non-zero means a future version:
//! the script succeeds), globals, context, the input and output scopes (one
//! nibble each), the input fields and the output fields. SINGLE and RANGE
//! scopes take their operands from the stack below the selector (output
//! operands first, then input operands).

use crate::v2;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::taproot::{TapLeafHash, TapNodeHash};
use bitcoin::{Transaction, TxOut, VarInt};

pub const OP_TX: u8 = 0xbd;

/// Fixed execution charge of OP_TX.
pub const EXECUTION_COST: u64 = 1_250;
const COST_COPYING: u64 = 3;
const COST_ARITH: u64 = 6;
const TOTAL_AMOUNT_COST_PER_ITEM: u64 = 8 * COST_ARITH;

// Selector byte 1: globals.
pub const COLLATE: u8 = 0x01;
pub const TX_VERSION: u8 = 0x02;
pub const TX_LOCKTIME: u8 = 0x04;
pub const TX_WEIGHT: u8 = 0x08;
pub const INPUT_TOTAL_COUNT: u8 = 0x10;
pub const INPUT_TOTAL_AMOUNT: u8 = 0x20;
pub const OUTPUT_TOTAL_COUNT: u8 = 0x40;
pub const OUTPUT_TOTAL_AMOUNT: u8 = 0x80;

// Selector byte 2: context of the executing input.
pub const CURRENT_INPUT_INDEX: u8 = 0x01;
pub const CURRENT_TAPROOT_ANNEX: u8 = 0x02;
pub const CURRENT_TAPSCRIPT: u8 = 0x04;
pub const CURRENT_TAPLEAF_HASH: u8 = 0x08;
pub const CURRENT_CONTROL_BLOCK: u8 = 0x10;
pub const CURRENT_INTERNAL_KEY: u8 = 0x20;
pub const CURRENT_TAPTREE_ROOT: u8 = 0x40;
pub const CURRENT_CODESEPARATOR_POSITION: u8 = 0x80;

// Selector byte 3: scopes, inputs in the high nibble, outputs in the low one.
pub const SCOPE_NONE: u8 = 0;
pub const SCOPE_CURRENT: u8 = 1;
pub const SCOPE_ALL: u8 = 2;
pub const SCOPE_SINGLE: u8 = 3;
pub const SCOPE_RANGE: u8 = 4;

// Selector byte 4: fields of each selected input.
pub const INPUT_PREVOUT_TXID: u8 = 0x01;
pub const INPUT_PREVOUT_INDEX: u8 = 0x02;
pub const INPUT_PREVOUT_AMOUNT: u8 = 0x04;
pub const INPUT_PREVOUT_SCRIPTPUBKEY: u8 = 0x08;
pub const INPUT_SCRIPTSIG: u8 = 0x10;
pub const INPUT_SEQUENCE: u8 = 0x20;
pub const INPUT_WITNESS_ITEM_COUNT: u8 = 0x40;
pub const INPUT_WITNESS_ITEMS: u8 = 0x80;

// Selector byte 5: fields of each selected output.
pub const OUTPUT_AMOUNT: u8 = 0x01;
pub const OUTPUT_SCRIPTPUBKEY: u8 = 0x02;

/// The context OP_TX reads. `None` marks a field the caller cannot provide;
/// OP_TX then fails whatever it selects, as in the reference.
pub struct Context<'a> {
    pub tx: &'a Transaction,
    pub spent_outputs: &'a [TxOut],
    pub input_index: usize,
    /// `Some(None)`: known to have no annex.
    pub annex: Option<Option<&'a [u8]>>,
    pub tapscript: Option<&'a [u8]>,
    pub tapleaf_hash: Option<[u8; 32]>,
    pub control_block: Option<&'a [u8]>,
    pub taptree_root: Option<[u8; 32]>,
    pub codesep_pos: Option<u32>,
}

impl<'a> Context<'a> {
    /// The taptree root from a control block and the leaf hash, if the control block is well formed.
    pub fn taptree_root(control_block: &[u8], leaf_hash: [u8; 32]) -> Option<[u8; 32]> {
        if control_block.len() < 33 || control_block.len() > 33 + 32 * 128 || (control_block.len() - 33) % 32 != 0 {
            return None;
        }
        let mut h = TapNodeHash::from(TapLeafHash::from_byte_array(leaf_hash));
        for node in control_block[33..].chunks(32) {
            h = TapNodeHash::from_node_hashes(h, TapNodeHash::from_byte_array(node.try_into().unwrap()));
        }
        Some(h.to_byte_array())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Missing selector or scope operand.
    InvalidStackOperation,
    Selector,
    Context,
    StackSize,
    TotalStackSize,
    ElementSize,
    VaropCount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A future selector version: the script succeeds, like OP_SUCCESS.
    ImmediateSuccess,
    /// Pop `pop` elements (the selector and the scope operands), then push `outputs`.
    Push { pop: usize, outputs: Vec<Vec<u8>>, cost: u64 },
}

/// Sizes of the stacks when OP_TX runs (the selector included).
pub struct Stacks {
    pub len: usize,
    pub bytes: usize,
    pub alt_len: usize,
    pub alt_bytes: usize,
}

#[derive(Clone, Copy, Default)]
struct Scope {
    kind: u8,
    start: u32,
    count: u32,
}

struct Selector {
    collate: bool,
    globals: u8,
    context: u8,
    input_fields: u8,
    output_fields: u8,
    inputs: Scope,
    outputs: Scope,
}

fn parse_selector(b: &[u8]) -> Option<Selector> {
    if b.len() != 6 || b[0] != 0 {
        return None;
    }
    let (input_scope, output_scope) = (b[3] >> 4, b[3] & 0x0f);
    if input_scope > SCOPE_RANGE || output_scope > SCOPE_RANGE {
        return None;
    }
    let s = Selector {
        collate: b[1] & COLLATE != 0,
        globals: b[1] & !COLLATE,
        context: b[2],
        input_fields: b[4],
        output_fields: b[5],
        inputs: Scope { kind: input_scope, ..Default::default() },
        outputs: Scope { kind: output_scope, ..Default::default() },
    };
    if s.output_fields & !(OUTPUT_AMOUNT | OUTPUT_SCRIPTPUBKEY) != 0
        || (input_scope == SCOPE_NONE) != (s.input_fields == 0)
        || (output_scope == SCOPE_NONE) != (s.output_fields == 0)
        || (s.globals == 0 && s.context == 0 && s.input_fields == 0 && s.output_fields == 0)
    {
        return None;
    }
    Some(s)
}

/// A scope operand: at most 4 bytes, minimally encoded.
fn scope_operand(b: &[u8]) -> Option<u32> {
    if b.len() > 4 || b.last() == Some(&0) {
        return None;
    }
    Some(b.iter().rev().fold(0u32, |acc, x| (acc << 8) | *x as u32))
}

/// Read the operands of `scope` from `top` (index 0 is the selector),
/// advancing `depth`; `len` is the stack length.
fn read_operands(scope: &mut Scope, top: &[Vec<u8>], len: usize, depth: &mut usize) -> Result<(), Error> {
    let read = |depth: &mut usize| -> Result<u32, Error> {
        if *depth >= len {
            return Err(Error::InvalidStackOperation);
        }
        let v = scope_operand(&top[*depth]).ok_or(Error::Selector)?;
        *depth += 1;
        Ok(v)
    };
    match scope.kind {
        SCOPE_SINGLE => {
            scope.start = read(depth)?;
            scope.count = 1;
        }
        SCOPE_RANGE => {
            scope.count = read(depth)?;
            scope.start = read(depth)?;
            if scope.count == 0 {
                return Err(Error::Selector);
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve(scope: &mut Scope, total: u32, current: u32) -> bool {
    match scope.kind {
        SCOPE_NONE => true,
        SCOPE_CURRENT => {
            if current >= total {
                return false;
            }
            scope.start = current;
            scope.count = 1;
            true
        }
        SCOPE_ALL => {
            scope.count = total;
            true
        }
        SCOPE_SINGLE => scope.start < total,
        _ => scope.start < total && scope.count <= total - scope.start,
    }
}

enum Value<'a> {
    U32(u32),
    U64(u64),
    Fixed(&'a [u8]),
    Var(&'a [u8]),
}

fn minimal(n: u64) -> Vec<u8> {
    let mut v = n.to_le_bytes().to_vec();
    while v.last() == Some(&0) {
        v.pop();
    }
    v
}

impl Value<'_> {
    fn semantic_size(&self) -> usize {
        match self {
            Value::U32(n) => minimal(*n as u64).len(),
            Value::U64(n) => minimal(*n).len(),
            Value::Fixed(b) | Value::Var(b) => b.len(),
        }
    }

    fn collated_size(&self) -> usize {
        match self {
            Value::U32(_) => 4,
            Value::U64(_) => 8,
            Value::Fixed(b) => b.len(),
            Value::Var(b) => VarInt(b.len() as u64).size() + b.len(),
        }
    }

    fn semantic(&self, out: &mut Vec<u8>) {
        match self {
            Value::U32(n) => out.extend(minimal(*n as u64)),
            Value::U64(n) => out.extend(minimal(*n)),
            Value::Fixed(b) | Value::Var(b) => out.extend_from_slice(b),
        }
    }

    fn collated(&self, out: &mut Vec<u8>) {
        match self {
            Value::U32(n) => out.extend(n.to_le_bytes()),
            Value::U64(n) => out.extend(n.to_le_bytes()),
            Value::Fixed(b) => out.extend_from_slice(b),
            Value::Var(b) => {
                VarInt(b.len() as u64).consensus_encode(out).expect("vec");
                out.extend_from_slice(b);
            }
        }
    }
}

fn sum(amounts: impl Iterator<Item = u64>) -> Option<u64> {
    amounts.fold(Some(0u64), |acc, a| acc?.checked_add(a))
}

/// Evaluate OP_TX. `top[d]` is the stack element at depth `d` (0 is the
/// selector); pass at least the top five elements, or all if there are fewer.
/// `budget` is the remaining varops budget.
pub fn eval(top: &[Vec<u8>], stacks: &Stacks, ctx: &Context, budget: u64) -> Result<Outcome, Error> {
    let selector = if stacks.len == 0 { return Err(Error::InvalidStackOperation) } else { &top[0] };
    if selector.is_empty() {
        return Err(Error::Selector);
    }
    if selector[0] != 0 {
        return Ok(Outcome::ImmediateSuccess);
    }
    let mut sel = parse_selector(selector).ok_or(Error::Selector)?;
    let mut depth = 1;
    read_operands(&mut sel.outputs, top, stacks.len, &mut depth)?;
    read_operands(&mut sel.inputs, top, stacks.len, &mut depth)?;

    let tx = ctx.tx;
    let (n_in, n_out) = (tx.input.len(), tx.output.len());
    if ctx.input_index >= n_in || ctx.spent_outputs.len() != n_in || n_in > u32::MAX as usize || n_out > u32::MAX as usize {
        return Err(Error::Context);
    }
    let current = ctx.input_index as u32;
    if !resolve(&mut sel.inputs, n_in as u32, current) || !resolve(&mut sel.outputs, n_out as u32, current) {
        return Err(Error::Context);
    }
    let (Some(annex), Some(tapscript), Some(leaf_hash), Some(control_block), Some(taptree_root), Some(codesep)) =
        (ctx.annex, ctx.tapscript, ctx.tapleaf_hash.as_ref(), ctx.control_block, ctx.taptree_root.as_ref(), ctx.codesep_pos)
    else {
        return Err(Error::Context);
    };

    // The selected values, in the reference's order.
    let mut values: Vec<Value> = vec![];
    let mut additional = 0u64;
    if sel.globals & TX_VERSION != 0 {
        values.push(Value::U32(tx.version.0 as u32));
    }
    if sel.globals & TX_LOCKTIME != 0 {
        values.push(Value::U32(tx.lock_time.to_consensus_u32()));
    }
    if sel.globals & TX_WEIGHT != 0 {
        let (stripped, total) = (tx.base_size() as u64, tx.total_size() as u64);
        let weight = stripped * 3 + total;
        if weight > u32::MAX as u64 {
            return Err(Error::Context);
        }
        values.push(Value::U32(weight as u32));
        additional += COST_COPYING * (stripped + total);
    }
    if sel.globals & INPUT_TOTAL_COUNT != 0 {
        values.push(Value::U32(n_in as u32));
    }
    if sel.globals & INPUT_TOTAL_AMOUNT != 0 {
        let total = sum(ctx.spent_outputs.iter().map(|o| o.value.to_sat())).ok_or(Error::Context)?;
        values.push(Value::U64(total));
        additional += TOTAL_AMOUNT_COST_PER_ITEM * n_in as u64;
    }
    let f = sel.input_fields;
    for i in sel.inputs.start..sel.inputs.start + sel.inputs.count {
        let input = &tx.input[i as usize];
        let spent = &ctx.spent_outputs[i as usize];
        if f & INPUT_PREVOUT_TXID != 0 {
            values.push(Value::Fixed(input.previous_output.txid.as_byte_array()));
        }
        if f & INPUT_PREVOUT_INDEX != 0 {
            values.push(Value::U32(input.previous_output.vout));
        }
        if f & INPUT_PREVOUT_AMOUNT != 0 {
            values.push(Value::U64(spent.value.to_sat()));
        }
        if f & INPUT_PREVOUT_SCRIPTPUBKEY != 0 {
            values.push(Value::Var(spent.script_pubkey.as_bytes()));
        }
        if f & INPUT_SCRIPTSIG != 0 {
            values.push(Value::Var(input.script_sig.as_bytes()));
        }
        if f & INPUT_SEQUENCE != 0 {
            values.push(Value::U32(input.sequence.0));
        }
        if f & INPUT_WITNESS_ITEM_COUNT != 0 {
            values.push(Value::U32(input.witness.len() as u32));
        }
        if f & INPUT_WITNESS_ITEMS != 0 {
            for item in input.witness.iter() {
                values.push(Value::Var(item));
            }
        }
    }
    if sel.globals & OUTPUT_TOTAL_COUNT != 0 {
        values.push(Value::U32(n_out as u32));
    }
    if sel.globals & OUTPUT_TOTAL_AMOUNT != 0 {
        let total = sum(tx.output.iter().map(|o| o.value.to_sat())).ok_or(Error::Context)?;
        values.push(Value::U64(total));
        additional += TOTAL_AMOUNT_COST_PER_ITEM * n_out as u64;
    }
    for j in sel.outputs.start..sel.outputs.start + sel.outputs.count {
        let output = &tx.output[j as usize];
        if sel.output_fields & OUTPUT_AMOUNT != 0 {
            values.push(Value::U64(output.value.to_sat()));
        }
        if sel.output_fields & OUTPUT_SCRIPTPUBKEY != 0 {
            values.push(Value::Var(output.script_pubkey.as_bytes()));
        }
    }
    let c = sel.context;
    if c & CURRENT_INPUT_INDEX != 0 {
        values.push(Value::U32(current));
    }
    if c & CURRENT_TAPROOT_ANNEX != 0 {
        values.push(Value::Var(annex.unwrap_or(&[])));
    }
    if c & CURRENT_TAPSCRIPT != 0 {
        values.push(Value::Var(tapscript));
    }
    if c & CURRENT_TAPLEAF_HASH != 0 {
        values.push(Value::Fixed(leaf_hash));
    }
    if c & CURRENT_CONTROL_BLOCK != 0 {
        values.push(Value::Var(control_block));
    }
    if c & CURRENT_INTERNAL_KEY != 0 {
        if control_block.len() < 33 {
            return Err(Error::Context);
        }
        values.push(Value::Fixed(&control_block[1..33]));
    }
    if c & CURRENT_TAPTREE_ROOT != 0 {
        values.push(Value::Fixed(taptree_root));
    }
    if c & CURRENT_CODESEPARATOR_POSITION != 0 {
        values.push(Value::U32(codesep));
    }

    // Sizes and limits, in the reference's order.
    let output_count = if sel.collate { 1 } else { values.len() };
    let mut total_output = 0usize;
    for v in &values {
        let size = if sel.collate { v.collated_size() } else { v.semantic_size() };
        if !sel.collate && size > v2::MAX_STACK_ELEMENT_SIZE {
            return Err(Error::ElementSize);
        }
        if size > v2::MAX_TOTAL_STACK_SIZE - total_output {
            return Err(Error::TotalStackSize);
        }
        total_output += size;
    }
    if sel.collate && total_output > v2::MAX_STACK_ELEMENT_SIZE {
        return Err(Error::ElementSize);
    }
    let cost = EXECUTION_COST + total_output as u64 * COST_COPYING + additional;
    let len = stacks.len - depth;
    let bytes = stacks.bytes - top[..depth].iter().map(|v| v.len()).sum::<usize>();
    if len > v2::MAX_STACK_SIZE || stacks.alt_len > v2::MAX_STACK_SIZE - len {
        return Err(Error::StackSize);
    }
    if output_count > v2::MAX_STACK_SIZE - (len + stacks.alt_len) {
        return Err(Error::StackSize);
    }
    if bytes > v2::MAX_TOTAL_STACK_SIZE || stacks.alt_bytes > v2::MAX_TOTAL_STACK_SIZE - bytes {
        return Err(Error::TotalStackSize);
    }
    if total_output > v2::MAX_TOTAL_STACK_SIZE - (bytes + stacks.alt_bytes) {
        return Err(Error::TotalStackSize);
    }
    if cost > budget {
        return Err(Error::VaropCount);
    }

    let outputs = if sel.collate {
        let mut out = Vec::with_capacity(total_output);
        for v in &values {
            v.collated(&mut out);
        }
        vec![out]
    } else {
        values
            .iter()
            .map(|v| {
                let mut out = vec![];
                v.semantic(&mut out);
                out
            })
            .collect()
    };
    Ok(Outcome::Push { pop: depth, outputs, cost })
}
