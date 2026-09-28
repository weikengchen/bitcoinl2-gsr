use crate::data_structures::ScriptIntError;
use bitcoin::script::write_scriptint;

///  A data type to abstract out the condition stack during script execution.
///
/// Conceptually it acts like a vector of booleans, one for each level of nested
/// IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
/// each.
///
/// The elements on the stack cannot be observed individually; we only need to
/// expose whether the stack is empty and whether or not any false values are
/// present at all. To implement OP_ELSE, a toggle_top modifier is added, which
/// flips the last value without returning it.
///
/// This uses an optimized implementation that does not materialize the
/// actual stack. Instead, it just stores the size of the would-be stack,
/// and the position of the first false value in it.
pub struct ConditionStack {
    /// The size of the implied stack.
    size: usize,
    /// The position of the first false value on the implied stack,
    /// or NO_FALSE if all true.
    first_false_pos: usize,
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self {
            size: 0,
            first_false_pos: Self::NO_FALSE,
        }
    }
}

impl ConditionStack {
    /// A constant for first_false_pos to indicate there are no falses.
    const NO_FALSE: usize = usize::MAX;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn all_true(&self) -> bool {
        self.first_false_pos == Self::NO_FALSE
    }

    pub fn push(&mut self, v: bool) {
        if self.first_false_pos == Self::NO_FALSE && !v {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            self.first_false_pos = self.size;
        }
        self.size += 1;
    }

    /// Returns [false] if it was empty, [true] otherwise.
    ///
    /// Note that the popped value is not returned.
    pub fn pop(&mut self) -> bool {
        if self.size == 0 {
            false
        } else {
            self.size -= 1;
            if self.first_false_pos == self.size {
                // When popping off the first false value, everything becomes true.
                self.first_false_pos = Self::NO_FALSE;
            }
            true
        }
    }

    pub fn toggle_top(&mut self) -> bool {
        if self.size == 0 {
            false
        } else {
            if self.first_false_pos == Self::NO_FALSE {
                // The current stack is all true values; the first false will be the top.
                self.first_false_pos = self.size - 1;
            } else if self.first_false_pos == self.size - 1 {
                // The top is the first false value; toggling it will make everything true.
                self.first_false_pos = Self::NO_FALSE;
            } else {
                // There is a false value, but not on top. No action is needed as toggling
                // anything but the first false value is unobservable.
            }
            true
        }
    }
}

/// Returns minimally encoded scriptint as a byte vector.
pub fn scriptint_vec(n: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = write_scriptint(&mut buf, n);
    buf[0..len].to_vec()
}

/// Decodes an interger in script format with flexible size limit.
///
/// Note that in the majority of cases, you will want to use either
/// [read_scriptint] or [read_scriptint_non_minimal] instead.
///
/// Panics if max_size exceeds 8.
pub fn read_scriptint_size(
    v: &[u8],
    max_size: usize,
    minimal: bool,
) -> Result<i64, ScriptIntError> {
    assert!(max_size <= 8);

    if v.len() > max_size {
        return Err(ScriptIntError::NumericOverflow);
    }

    if v.is_empty() {
        return Ok(0);
    }

    if minimal {
        let last = match v.last() {
            Some(last) => last,
            None => return Ok(0),
        };
        // Comment and code copied from Bitcoin Core:
        // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if (*last & 0x7f) == 0 {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit. An example of this case
            // is +-255, which encode to 0xff00 and 0xff80 respectively.
            // (big-endian).
            if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
                return Err(ScriptIntError::NonMinimalPush);
            }
        }
    }

    Ok(scriptint_parse(v))
}

// Caller to guarantee that `v` is not empty.
fn scriptint_parse(v: &[u8]) -> i64 {
    let (mut ret, sh) = v
        .iter()
        .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[v.len() - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    ret
}
