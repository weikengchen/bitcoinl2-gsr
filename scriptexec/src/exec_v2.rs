//! Execution of tapscript leaf version 0xc2 (BIP 440 varops, BIP 441 restored script).
//!
//! Mirrors `EvalTapscriptV2` and `CheckTapscriptV2ScriptResult` of the reference
//! implementation (jmoik/bitcoin `gsr-inquisition`, commit 8384b7a).

use bitcoin::hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash};
use bitcoin::opcodes::{all::*, Opcode};
use bitcoin::script::{Instruction, ScriptBuf};
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Transaction;
use core::cmp::Ordering;

use crate::data_structures::StackEntry;
use crate::v2::{self, varops};
use crate::*;

/// Result of a raw tapscript v2 evaluation, without the final stack check.
#[derive(Debug, Clone)]
pub struct V2Eval {
    pub error: Option<ExecError>,
    pub final_stack: Vec<Vec<u8>>,
    pub varops_used: u64,
}

fn entry_len(e: &StackEntry) -> usize {
    match e {
        StackEntry::Num(v) => utils::scriptint_vec(*v).len(),
        StackEntry::StrRef(v) => v.borrow().len(),
    }
}

impl Exec {
    /// Charge varops against the transaction-wide budget.
    pub(crate) fn spend_varops(&mut self, cost: u64) -> Result<(), ExecError> {
        self.varops_used = self.varops_used.saturating_add(cost);
        if let Some(budget) = self.opt.varops_budget {
            if self.varops_used.saturating_add(self.varops_final_check) > budget {
                return Err(ExecError::VaropCount);
            }
        }
        Ok(())
    }

    fn v2_limits(&self) -> Result<(), ExecError> {
        if self.stack.len() + self.altstack.len() > v2::MAX_STACK_SIZE {
            return Err(ExecError::StackSize);
        }
        let mut total = 0usize;
        let mut largest = 0usize;
        for e in self.stack.0.iter().chain(self.altstack.0.iter()) {
            let l = entry_len(e);
            total += l;
            largest = largest.max(l);
        }
        if total > v2::MAX_TOTAL_STACK_SIZE {
            return Err(ExecError::TotalStackSize);
        }
        if largest > v2::MAX_STACK_ELEMENT_SIZE {
            return Err(ExecError::StackElementSize);
        }
        Ok(())
    }

    /// OP_CHECKSIG semantics for tapscript v2: no BIP 342 validation weight,
    /// signatures are charged through varops instead.
    pub(crate) fn check_sig_tap_v2(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        let success = !sig.is_empty();
        if pk.is_empty() {
            return Err(ExecError::PubkeyType);
        }
        if pk.len() == 32 && success {
            self.check_sig_schnorr(sig, pk)?;
        }
        Ok(success)
    }

    pub(crate) fn exec_next_v2(&mut self) -> Result<(), &ExecutionResult> {
        if self.result.is_some() {
            return Err(self.result.as_ref().unwrap());
        }

        self.current_position = self.script.len() - self.instructions.as_script().len();
        let instruction = match self.instructions.next() {
            Some(Ok(i)) => i,
            None => return self.finish_v2(),
            Some(Err(_)) => unreachable!("we checked the script beforehand"),
        };
        let pos = self.v2_opcode_pos;
        self.v2_opcode_pos += 1;

        let exec = self.cond_stack.all_true();
        let mut cost = 0u64;
        match instruction {
            Instruction::PushBytes(p) => {
                if p.len() > v2::MAX_STACK_ELEMENT_SIZE {
                    return self.fail(ExecError::PushSize);
                }
                if exec {
                    self.stack.pushstr(p.as_bytes());
                }
            }
            Instruction::Op(op) => {
                self.opcode_count += 1;
                if exec || (op.to_u8() >= OP_IF.to_u8() && op.to_u8() <= OP_ENDIF.to_u8()) {
                    if let Err(err) = self.exec_opcode_v2(op, pos, &mut cost) {
                        return self.failop(err, op);
                    }
                }
            }
        }

        if let Err(err) = self.v2_limits() {
            return self.fail(err);
        }
        if let Err(err) = self.spend_varops(cost) {
            return self.fail(err);
        }
        self.update_stats();
        Ok(())
    }

    fn finish_v2(&mut self) -> Result<(), &ExecutionResult> {
        if !self.cond_stack.is_empty() {
            return self.fail(ExecError::UnbalancedConditional);
        }
        if !self.v2_skip_final_check {
            if self.stack.len() != 1 {
                return self.fail(ExecError::CleanStack);
            }
            let top = self.stack.topstr(-1).unwrap();
            self.varops_final_check = varops::compare_zero(top.len());
            if let Err(err) = self.spend_varops(0) {
                return self.fail(err);
            }
            if v2::is_zero(&top) {
                return self.fail(ExecError::EvalFalse);
            }
        }
        self.update_stats();
        self.result = Some(ExecutionResult {
            success: true,
            error: None,
            opcode: None,
            final_stack: self.stack.clone(),
            #[cfg(feature = "profiler")]
            profiler: None,
        });
        Err(self.result.as_ref().unwrap())
    }

    fn exec_opcode_v2(&mut self, op: Opcode, pos: u32, cost: &mut u64) -> Result<(), ExecError> {
        let exec = self.cond_stack.all_true();

        match op {
            //
            // Push value
            OP_PUSHNUM_NEG1 => self.stack.pushvec(vec![0x81]),
            OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4 | OP_PUSHNUM_5
            | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9 | OP_PUSHNUM_10
            | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14 | OP_PUSHNUM_15
            | OP_PUSHNUM_16 => {
                let n = op.to_u8() - OP_PUSHNUM_1.to_u8() + 1;
                self.stack.pushvec(vec![n]);
            }

            //
            // Control
            OP_NOP => {}

            OP_CLTV => {
                if self.opt.verify_cltv {
                    let v = self.stack.popstr()?;
                    let n = v2::to_u64_ceil(&v, 1 << 32, cost);
                    if n == 1 << 32 {
                        return Err(ExecError::UnsatisfiedLocktime);
                    }
                    self.stack.pushvec(v);
                    if !self.check_lock_time(n as i64) {
                        return Err(ExecError::UnsatisfiedLocktime);
                    }
                }
            }

            OP_CSV => {
                if self.opt.verify_csv {
                    let v = self.stack.popstr()?;
                    let n = v2::to_u64_ceil(&v, 1 << 32, cost);
                    if n == 1 << 32 {
                        return Err(ExecError::UnsatisfiedLocktime);
                    }
                    self.stack.pushvec(v);
                    if n & (1 << 31) == 0 && !self.check_sequence(n as i64) {
                        return Err(ExecError::UnsatisfiedLocktime);
                    }
                }
            }

            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {}

            OP_IF | OP_NOTIF => {
                let mut value = false;
                if exec {
                    if self.stack.is_empty() {
                        return Err(ExecError::UnbalancedConditional);
                    }
                    let top = self.stack.topstr(-1)?;
                    if top.len() > 1 || (top.len() == 1 && top[0] != 1) {
                        return Err(ExecError::TapscriptMinimalIf);
                    }
                    value = top.len() == 1;
                    if op == OP_NOTIF {
                        value = !value;
                    }
                    self.stack.pop();
                }
                self.cond_stack.push(value);
            }

            OP_ELSE => {
                if !self.cond_stack.toggle_top() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_ENDIF => {
                if !self.cond_stack.pop() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_VERIFY => {
                let v = self.stack.popstr()?;
                *cost += varops::compare_zero(v.len());
                if v2::is_zero(&v) {
                    return Err(ExecError::Verify);
                }
            }

            OP_RETURN => return Err(ExecError::OpReturn),

            //
            // Stack operations
            OP_TOALTSTACK => {
                let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
                self.altstack.push(top);
            }

            OP_FROMALTSTACK => {
                let top = self
                    .altstack
                    .pop()
                    .ok_or(ExecError::InvalidStackOperation)?;
                self.stack.push(top);
            }

            OP_2DROP => {
                self.stack.needn(2)?;
                self.stack.popn(2)?;
            }

            OP_2DUP | OP_3DUP | OP_2OVER => {
                let (n, from) = match op {
                    OP_2DUP => (2, -2),
                    OP_3DUP => (3, -3),
                    _ => (4, -4),
                };
                self.stack.needn(n)?;
                let copies = if op == OP_3DUP { 3 } else { 2 };
                let items: Vec<Vec<u8>> = (0..copies)
                    .map(|i| self.stack.topstr(from + i as isize))
                    .collect::<Result<_, _>>()?;
                for item in items {
                    *cost += item.len() as u64 * varops::COST_COPYING;
                    self.stack.pushvec(item);
                }
            }

            OP_2ROT => {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                self.stack.needn(6)?;
                let x6 = self.stack.pop().unwrap();
                let x5 = self.stack.pop().unwrap();
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                for x in [x3, x4, x5, x6, x1, x2] {
                    self.stack.push(x);
                }
            }

            OP_2SWAP => {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                for x in [x3, x4, x1, x2] {
                    self.stack.push(x);
                }
            }

            OP_IFDUP => {
                let v = self.stack.popstr()?;
                let nonzero = !v2::is_zero(&v);
                *cost += varops::compare_zero(v.len()) + v.len() as u64 * varops::COST_COPYING;
                if nonzero {
                    self.stack.pushvec(v.clone());
                }
                self.stack.pushvec(v);
            }

            OP_DEPTH => {
                let n = self.stack.len() as u64;
                self.stack.pushvec(v2::from_u64(n));
            }

            OP_DROP => {
                self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
            }

            OP_DUP => {
                let v = self.stack.topstr(-1)?;
                *cost += v.len() as u64 * varops::COST_COPYING;
                self.stack.pushvec(v);
            }

            OP_NIP => {
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                self.stack.pop().unwrap();
                self.stack.push(x2);
            }

            OP_OVER => {
                let v = self.stack.topstr(-2)?;
                *cost += v.len() as u64 * varops::COST_COPYING;
                self.stack.pushvec(v);
            }

            OP_PICK | OP_ROLL => {
                self.stack.needn(2)?;
                let n = self.stack.popstr()?;
                let depth = v2::to_u64_ceil(&n, self.stack.len() as u64, cost) as usize;
                if depth >= self.stack.len() {
                    return Err(ExecError::InvalidStackOperation);
                }
                if op == OP_ROLL {
                    let idx = self.stack.len() - depth - 1;
                    let elem = self.stack.0.remove(idx);
                    self.stack.push(elem);
                    *cost += depth as u64 * varops::COST_ROLL;
                } else {
                    let v = self.stack.topstr(-(depth as isize) - 1)?;
                    *cost += v.len() as u64 * varops::COST_COPYING;
                    self.stack.pushvec(v);
                }
            }

            OP_ROT => {
                // (x1 x2 x3 -- x2 x3 x1)
                self.stack.needn(3)?;
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                for x in [x2, x3, x1] {
                    self.stack.push(x);
                }
            }

            OP_SWAP => {
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2);
                self.stack.push(x1);
            }

            OP_TUCK => {
                // (x1 x2 -- x2 x1 x2)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr()?;
                let x1 = self.stack.pop().unwrap();
                *cost += x2.len() as u64 * varops::COST_COPYING;
                self.stack.pushvec(x2.clone());
                self.stack.push(x1);
                self.stack.pushvec(x2);
            }

            OP_SIZE => {
                let v = self.stack.topstr(-1)?;
                self.stack.pushvec(v2::from_u64(v.len() as u64));
            }

            //
            // Bitwise logic
            OP_EQUAL | OP_EQUALVERIFY => {
                self.stack.needn(2)?;
                let b = self.stack.popstr()?;
                let a = self.stack.popstr()?;
                if a.len() == b.len() {
                    *cost += a.len() as u64 * varops::COST_FAST;
                }
                let equal = a == b;
                if op == OP_EQUALVERIFY {
                    if !equal {
                        return Err(ExecError::EqualVerify);
                    }
                } else {
                    self.stack.pushvec(v2::from_bool(equal));
                }
            }

            //
            // Numeric
            OP_1ADD | OP_1SUB | OP_NOT | OP_0NOTEQUAL => {
                let v = self.stack.popstr()?;
                let r = match op {
                    OP_1ADD => {
                        *cost += varops::add(v.len(), 1);
                        v2::add(&v, &[1])
                    }
                    OP_1SUB => {
                        *cost += varops::sub(v.len(), 1);
                        v2::sub(&v, &[1]).ok_or(ExecError::SubUnderflow)?
                    }
                    OP_NOT => {
                        *cost += varops::compare_zero(v.len());
                        v2::from_bool(v2::is_zero(&v))
                    }
                    _ => {
                        *cost += varops::compare_zero(v.len());
                        v2::from_bool(!v2::is_zero(&v))
                    }
                };
                self.stack.pushvec(r);
            }

            OP_ADD | OP_SUB | OP_BOOLAND | OP_BOOLOR | OP_NUMEQUAL | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL | OP_LESSTHAN | OP_GREATERTHAN | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL | OP_MIN | OP_MAX => {
                self.stack.needn(2)?;
                let b = self.stack.popstr()?;
                let a = self.stack.popstr()?;
                let (la, lb) = (a.len(), b.len());
                let r = match op {
                    OP_ADD => {
                        *cost += varops::add(la, lb);
                        v2::add(&a, &b)
                    }
                    OP_SUB => {
                        *cost += varops::sub(la, lb);
                        v2::sub(&a, &b).ok_or(ExecError::SubUnderflow)?
                    }
                    OP_BOOLAND => {
                        *cost += varops::bool_and_or(la, lb);
                        v2::from_bool(!v2::is_zero(&a) && !v2::is_zero(&b))
                    }
                    OP_BOOLOR => {
                        *cost += varops::bool_and_or(la, lb);
                        v2::from_bool(!v2::is_zero(&a) || !v2::is_zero(&b))
                    }
                    OP_MIN | OP_MAX => {
                        *cost += varops::min_max(la, lb);
                        let ord = v2::compare(&a, &b);
                        let pick_b = if op == OP_MIN {
                            ord == Ordering::Greater
                        } else {
                            ord == Ordering::Less
                        };
                        v2::trim(if pick_b { b } else { a })
                    }
                    _ => {
                        *cost += varops::comparison(la, lb);
                        let ord = v2::compare(&a, &b);
                        let res = match op {
                            OP_NUMEQUAL | OP_NUMEQUALVERIFY => ord == Ordering::Equal,
                            OP_NUMNOTEQUAL => ord != Ordering::Equal,
                            OP_LESSTHAN => ord == Ordering::Less,
                            OP_GREATERTHAN => ord == Ordering::Greater,
                            OP_LESSTHANOREQUAL => ord != Ordering::Greater,
                            _ => ord != Ordering::Less,
                        };
                        if op == OP_NUMEQUALVERIFY {
                            if !res {
                                return Err(ExecError::NumEqualVerify);
                            }
                            return Ok(());
                        }
                        v2::from_bool(res)
                    }
                };
                self.stack.pushvec(r);
            }

            OP_WITHIN => {
                // (x min max -- out)
                self.stack.needn(3)?;
                let max = self.stack.popstr()?;
                let min = self.stack.popstr()?;
                let x = self.stack.popstr()?;
                *cost += varops::within(x.len(), min.len(), max.len());
                let res = v2::compare(&x, &min) != Ordering::Less
                    && v2::compare(&x, &max) == Ordering::Less;
                self.stack.pushvec(v2::from_bool(res));
            }

            //
            // Crypto
            OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                let v = self.stack.topstr(-1)?;
                if op == OP_RIPEMD160 || op == OP_SHA1 {
                    if v.len() > v2::MAX_LEGACY_HASH_OPERAND_SIZE {
                        return Err(ExecError::HashOperandSize);
                    }
                } else {
                    *cost += v.len() as u64 * varops::COST_HASH;
                }
                let h = match op {
                    OP_RIPEMD160 => ripemd160::Hash::hash(&v).to_byte_array().to_vec(),
                    OP_SHA1 => sha1::Hash::hash(&v).to_byte_array().to_vec(),
                    OP_SHA256 => sha256::Hash::hash(&v).to_byte_array().to_vec(),
                    OP_HASH160 => hash160::Hash::hash(&v).to_byte_array().to_vec(),
                    _ => sha256d::Hash::hash(&v).to_byte_array().to_vec(),
                };
                self.stack.pop();
                self.stack.pushvec(h);
            }

            OP_CODESEPARATOR => {
                self.last_codeseparator_pos = Some(pos);
            }

            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                self.stack.needn(2)?;
                let sig = self.stack.topstr(-2)?;
                let pk = self.stack.topstr(-1)?;
                if !sig.is_empty() {
                    self.spend_varops(varops::COST_PER_SIGOP)?;
                }
                let res = self.check_sig_tap_v2(&sig, &pk)?;
                self.stack.popn(2)?;
                if op == OP_CHECKSIGVERIFY {
                    if !res {
                        return Err(ExecError::CheckSigVerify);
                    }
                } else {
                    self.stack.pushvec(v2::from_bool(res));
                }
            }

            OP_CHECKSIGADD => {
                self.stack.needn(3)?;
                let sig = self.stack.topstr(-3)?;
                let num_len = self.stack.topstr(-2)?.len();
                let pk = self.stack.topstr(-1)?;
                let sigop = if sig.is_empty() { 0 } else { varops::COST_PER_SIGOP };
                self.spend_varops(sigop + varops::checksigadd_increment(num_len))?;
                let res = self.check_sig_tap_v2(&sig, &pk)?;
                self.stack.pop();
                let num = self.stack.popstr()?;
                self.stack.pop();
                let r = if res {
                    v2::add(&num, &[1])
                } else {
                    v2::trim(num)
                };
                self.stack.pushvec(r);
            }

            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                return Err(ExecError::TapscriptCheckMultiSig);
            }

            //
            // Restored opcodes (BIP 441)
            OP_CAT => {
                self.stack.needn(2)?;
                let b = self.stack.popstr()?;
                let mut a = self.stack.popstr()?;
                *cost += (a.len() + b.len()) as u64 * varops::COST_COPYING;
                a.extend_from_slice(&b);
                self.stack.pushvec(a);
            }

            OP_SUBSTR => {
                // (a begin len -- a[begin..begin+len])
                let len_v = self.stack.popstr()?;
                let begin_v = self.stack.popstr()?;
                let a = self.stack.popstr()?;
                let begin = v2::to_u64_ceil(&begin_v, a.len() as u64, cost) as usize;
                let len = v2::to_u64_ceil(&len_v, (a.len() - begin) as u64, cost) as usize;
                *cost += len as u64 * varops::COST_COPYING;
                self.stack.pushvec(a[begin..begin + len].to_vec());
            }

            OP_LEFT => {
                let off_v = self.stack.popstr()?;
                let mut a = self.stack.popstr()?;
                let off = v2::to_u64_ceil(&off_v, a.len() as u64, cost) as usize;
                a.truncate(off);
                self.stack.pushvec(a);
            }

            OP_RIGHT => {
                let off_v = self.stack.popstr()?;
                let a = self.stack.popstr()?;
                let off = v2::to_u64_ceil(&off_v, a.len() as u64, cost) as usize;
                *cost += off as u64 * varops::COST_COPYING;
                self.stack.pushvec(a[a.len() - off..].to_vec());
            }

            OP_INVERT | OP_2MUL | OP_2DIV => {
                let v = self.stack.popstr()?;
                let r = match op {
                    OP_INVERT => {
                        *cost += varops::invert(v.len());
                        v2::invert(&v)
                    }
                    OP_2MUL => {
                        *cost += varops::two_mul(v.len());
                        v2::two_mul(&v)
                    }
                    _ => {
                        *cost += varops::two_div(v.len());
                        v2::two_div(&v)
                    }
                };
                self.stack.pushvec(r);
            }

            OP_AND | OP_OR | OP_XOR | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                self.stack.needn(2)?;
                let b = self.stack.popstr()?;
                let a = self.stack.popstr()?;
                let (la, lb) = (a.len(), b.len());
                let r = match op {
                    OP_AND => {
                        *cost += varops::and(la, lb);
                        v2::and(&a, &b)
                    }
                    OP_OR => {
                        *cost += varops::or_xor(la, lb);
                        v2::or(&a, &b)
                    }
                    OP_XOR => {
                        *cost += varops::or_xor(la, lb);
                        v2::xor(&a, &b)
                    }
                    OP_MUL => {
                        self.spend_varops(varops::mul(la, lb))?;
                        v2::mul(&a, &b)
                    }
                    OP_DIV => {
                        self.spend_varops(varops::div(la, lb))?;
                        v2::div(&a, &b).ok_or(ExecError::DivByZero)?
                    }
                    OP_MOD => {
                        self.spend_varops(varops::div(la, lb))?;
                        v2::rem(&a, &b).ok_or(ExecError::DivByZero)?
                    }
                    OP_LSHIFT => v2::upshift(&a, &b, cost).ok_or(ExecError::StackElementSize)?,
                    _ => v2::downshift(&a, &b, cost),
                };
                self.stack.pushvec(r);
            }

            _ => return Err(ExecError::BadOpcode),
        }

        Ok(())
    }
}

fn dummy_tx_template() -> TxTemplate {
    TxTemplate {
        tx: Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        },
        prevouts: vec![],
        input_idx: 0,
        taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
    }
}

/// Evaluate a tapscript v2 script on an initial stack, like the reference
/// `EvalTapscriptV2`: no final stack check and no transaction context.
pub fn eval_tapscript_v2(
    script: ScriptBuf,
    initial_stack: Vec<Vec<u8>>,
    varops_budget: Option<u64>,
) -> V2Eval {
    let opts = Options {
        require_minimal: false,
        varops_budget,
        ..Default::default()
    };
    let mut exec = match Exec::new(
        ExecCtx::TapscriptV2,
        opts,
        dummy_tx_template(),
        script,
        initial_stack.clone(),
    ) {
        Ok(e) => e,
        Err(Error::Exec(err)) => {
            return V2Eval { error: Some(err), final_stack: initial_stack, varops_used: 0 }
        }
        Err(_) => {
            return V2Eval {
                error: Some(ExecError::BadOpcode),
                final_stack: initial_stack,
                varops_used: 0,
            }
        }
    };
    exec.v2_skip_final_check = true;
    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    V2Eval {
        error: res.error.clone(),
        final_stack: exec.stack().to_u8_array(),
        varops_used: exec.varops_used,
    }
}

/// Execute a tapscript v2 leaf in its transaction context, including the
/// OP_SUCCESSx scan, stack limits and the final stack check.
///
/// `varops_budget` is the remaining transaction-wide budget; the amount used
/// is reported in [ExecStats::varops_used] plus [ExecStats::varops_final_check].
pub fn execute_tapscript_v2(
    script: ScriptBuf,
    tx_template: TxTemplate,
    witness: Vec<Vec<u8>>,
    varops_budget: Option<u64>,
) -> Result<ExecuteInfo, Error> {
    let opts = Options {
        varops_budget,
        ..Default::default()
    };
    let mut exec = Exec::new(ExecCtx::TapscriptV2, opts, tx_template, script, witness)?;
    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    Ok(ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
        #[cfg(feature = "profiler")]
        profiler: exec.profiler.clone(),
    })
}
