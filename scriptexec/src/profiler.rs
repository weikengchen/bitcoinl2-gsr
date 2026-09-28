use anyhow::{Error, Result};
use bitcoin::opcodes::all::{OP_DROP, OP_NOP10, OP_NOP9};
use bitcoin::script::{Builder, Instruction, PushBytesBuf};
use bitcoin::ScriptBuf;
use core::fmt::{Debug, Formatter};
use indexmap::IndexMap;

#[derive(Eq, PartialEq, Clone)]
enum Stage {
    Pending,
    WaitingForPushbytesToStart,
    WaitingForDropToStart,
    WaitingForPushbytesToEnd,
    WaitingForDropToEnd,
}

impl Default for Stage {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Default, Clone)]
pub struct Profiler {
    pub count: IndexMap<String, Vec<usize>>,

    stage: Stage,
    pending_string: String,
    stack: Vec<(String, usize)>,
    opcode_count: usize,
}

impl Debug for Profiler {
    fn fmt(&self, _: &mut Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl Profiler {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn update(&mut self, instruction: &Instruction) -> Result<()> {
        match instruction {
            Instruction::PushBytes(v) => {
                if self.stage == Stage::WaitingForPushbytesToStart {
                    // waive the weight units
                    self.stage = Stage::WaitingForDropToStart;
                    self.pending_string = String::from_utf8_lossy(v.as_bytes()).to_string();
                } else if self.stage == Stage::WaitingForPushbytesToEnd {
                    // waive the weight units
                    self.stage = Stage::WaitingForDropToEnd;
                    self.pending_string = String::from_utf8_lossy(v.as_bytes()).to_string();
                } else {
                    let len = v.len();
                    self.opcode_count += v.len();

                    if len <= 75 {
                        // use one opcode from 0x01 to 0x4b to push
                        self.opcode_count += 1;
                    } else if len <= 255 {
                        // use one byte to indicate the length and OP_PUSHDATA1
                        self.opcode_count += 1;
                        self.opcode_count += 1;
                    } else if len <= 65535 {
                        // use two bytes to indicate the length and OP_PUSHDATA2
                        self.opcode_count += 1;
                        self.opcode_count += 2;
                    } else {
                        // use four bytes to indicate the length and OP_PUSHDATA4
                        self.opcode_count += 1;
                        self.opcode_count += 4;
                    }
                }

                return Ok(());
            }
            Instruction::Op(opcode) => {
                if self.stage == Stage::Pending {
                    if *opcode == OP_NOP9 {
                        self.stage = Stage::WaitingForPushbytesToStart;
                    } else if *opcode == OP_NOP10 {
                        self.stage = Stage::WaitingForPushbytesToEnd;
                    } else {
                        self.opcode_count += 1;
                    }
                    return Ok(());
                } else if self.stage == Stage::WaitingForPushbytesToStart
                    || self.stage == Stage::WaitingForPushbytesToEnd
                {
                    return Err(Error::msg("Expecting pushbytes after PROFILER_START or PROFILER_END. Found other opcodes."));
                } else {
                    if *opcode != OP_DROP {
                        return Err(Error::msg(
                            "Expecting AS_FOLLOWS after pushbytes. Found other opcodes.",
                        ));
                    } else {
                        if self.stage == Stage::WaitingForDropToStart {
                            self.stack
                                .push((self.pending_string.clone(), self.opcode_count));
                            self.stage = Stage::Pending;
                        } else if self.stage == Stage::WaitingForDropToEnd {
                            if let Some((v, count)) = self.stack.last() {
                                if *v == self.pending_string {
                                    if let Some(counts) = self.count.get_mut(v) {
                                        counts.push(self.opcode_count - count);
                                    } else {
                                        self.count
                                            .insert(v.clone(), vec![self.opcode_count - count]);
                                    }
                                    self.stack.pop().unwrap();
                                    self.stage = Stage::Pending;
                                } else {
                                    return Err(Error::msg(
                                        "Ending a profiler unit that hasn't been started.",
                                    ));
                                }
                            } else {
                                return Err(Error::msg(
                                    "Ending a profiler unit that hasn't been started.",
                                ));
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    pub(crate) fn complete(&mut self) -> Result<()> {
        if self.stage != Stage::Pending {
            return Err(Error::msg(
                "There seems to be unfinished profiling instructions.",
            ));
        }
        if !self.stack.is_empty() {
            return Err(Error::msg("There seems to be unclosed profiling steps."));
        }
        Ok(())
    }

    pub fn print_stats(&self) {
        for (k, v) in self.count.iter() {
            let total: usize = v.iter().sum();
            let average = (total as f64) / (v.len() as f64);

            println!(
                "{} occurs {} times, resulting in total {} weight units, on average {} each.",
                k,
                v.len(),
                total,
                average,
            )
        }
    }
}

pub fn profiler_start(t: &str) -> ScriptBuf {
    let mut builder = Builder::new();
    builder = builder.push_opcode(OP_NOP9);
    builder = builder.push_slice(PushBytesBuf::try_from(t.as_bytes().to_vec()).unwrap());
    builder = builder.push_opcode(OP_DROP);
    builder.into_script()
}

pub fn profiler_end(t: &str) -> ScriptBuf {
    let mut builder = Builder::new();
    builder = builder.push_opcode(OP_NOP10);
    builder = builder.push_slice(PushBytesBuf::try_from(t.as_bytes().to_vec()).unwrap());
    builder = builder.push_opcode(OP_DROP);
    builder.into_script()
}
