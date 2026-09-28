//! A tiny stack model for writing longer scripts: stack elements have names,
//! `pick`/`roll` compute depths, and `if_` restores the element order at the
//! end of the branch so both paths leave the same layout.

use crate::pseudo::*;
use crate::treepp::*;

#[derive(Clone)]
pub struct Stk {
    s: Vec<String>,
    alt: Vec<String>,
    out: Vec<Script>,
}

impl Stk {
    pub fn new(initial: &[&str]) -> Self {
        Self { s: initial.iter().map(|x| x.to_string()).collect(), alt: vec![], out: vec![] }
    }

    pub fn names(&self) -> &[String] {
        &self.s
    }

    pub fn script(&self) -> Script {
        cat(&self.out)
    }

    pub fn depth(&self, name: &str) -> usize {
        let i = self
            .s
            .iter()
            .rposition(|x| x == name)
            .unwrap_or_else(|| panic!("`{name}` is not on the stack: {:?}", self.s));
        self.s.len() - 1 - i
    }

    pub fn has(&self, name: &str) -> bool {
        self.s.iter().any(|x| x == name)
    }

    /// Emit a raw script that pops `pops` elements and pushes `pushes`.
    pub fn apply(&mut self, script: Script, pops: usize, pushes: &[&str]) {
        assert!(pops <= self.s.len(), "stack underflow: {:?}", self.s);
        self.s.truncate(self.s.len() - pops);
        self.s.extend(pushes.iter().map(|x| x.to_string()));
        self.out.push(script);
    }

    pub fn push(&mut self, script: Script, name: &str) {
        self.apply(script, 0, &[name]);
    }

    pub fn push_u64(&mut self, n: u64, name: &str) {
        self.push(push_u64(n), name);
    }

    pub fn push_data(&mut self, data: &[u8], name: &str) {
        self.push(push_data(data), name);
    }

    /// Copy `name` to the top as `as_`.
    pub fn pick(&mut self, name: &str, as_: &str) {
        let d = self.depth(name);
        self.out.push(match d {
            0 => script! { OP_DUP },
            1 => script! { OP_OVER },
            _ => pick(d),
        });
        self.s.push(as_.to_string());
    }

    /// Move `name` to the top.
    pub fn roll(&mut self, name: &str) {
        let d = self.depth(name);
        match d {
            0 => {}
            1 => self.out.push(script! { OP_SWAP }),
            2 => self.out.push(script! { OP_ROT }),
            _ => self.out.push(cat(&[push_u64(d as u64), script! { OP_ROLL }])),
        }
        let i = self.s.len() - 1 - d;
        let x = self.s.remove(i);
        self.s.push(x);
    }

    pub fn rename(&mut self, from: &str, to: &str) {
        let d = self.depth(from);
        let i = self.s.len() - 1 - d;
        self.s[i] = to.to_string();
    }

    pub fn drop(&mut self, name: &str) {
        self.roll(name);
        self.apply(script! { OP_DROP }, 1, &[]);
    }

    /// Consume the top element with OP_VERIFY.
    pub fn verify(&mut self) {
        self.apply(script! { OP_VERIFY }, 1, &[]);
    }

    pub fn to_alt(&mut self) {
        let x = self.s.pop().expect("stack underflow");
        self.alt.push(x);
        self.out.push(script! { OP_TOALTSTACK });
    }

    pub fn from_alt(&mut self) {
        let x = self.alt.pop().expect("altstack underflow");
        self.s.push(x);
        self.out.push(script! { OP_FROMALTSTACK });
    }

    /// Reorder the stack so that its names match `target` (same multiset).
    pub fn arrange(&mut self, target: &[String]) {
        let mut sorted_a = self.s.clone();
        let mut sorted_b = target.to_vec();
        sorted_a.sort();
        sorted_b.sort();
        assert_eq!(sorted_a, sorted_b, "branch changed the set of stack elements");
        let first_diff = self.s.iter().zip(target).position(|(a, b)| a != b);
        if let Some(start) = first_diff {
            for name in target[start..].to_vec() {
                self.roll(&name);
            }
        }
        assert_eq!(self.s, target);
    }

    /// `OP_IF <then> OP_ENDIF`, consuming the top element as the condition.
    /// `then` may reorder elements; the order is restored before OP_ENDIF.
    pub fn if_(&mut self, then: impl FnOnce(&mut Stk)) {
        self.apply(script! { OP_IF }, 1, &[]);
        let before = self.s.clone();
        let mut inner = Stk { s: before.clone(), alt: self.alt.clone(), out: vec![] };
        then(&mut inner);
        inner.arrange(&before);
        assert_eq!(inner.alt, self.alt, "branch changed the altstack");
        self.out.push(inner.script());
        self.out.push(script! { OP_ENDIF });
    }

    /// `OP_IF <then> OP_ELSE <else> OP_ENDIF`; both branches must end with the
    /// same element set, and are rearranged to the `then` branch's order.
    pub fn if_else(&mut self, then: impl FnOnce(&mut Stk), else_: impl FnOnce(&mut Stk)) {
        self.apply(script! { OP_IF }, 1, &[]);
        let before = self.s.clone();
        let mut a = Stk { s: before.clone(), alt: self.alt.clone(), out: vec![] };
        then(&mut a);
        let mut b = Stk { s: before, alt: self.alt.clone(), out: vec![] };
        else_(&mut b);
        b.arrange(&a.s);
        assert_eq!(a.alt, b.alt, "branches changed the altstack differently");
        self.out.push(a.script());
        self.out.push(script! { OP_ELSE });
        self.out.push(b.script());
        self.out.push(script! { OP_ENDIF });
        self.s = a.s;
        self.alt = a.alt;
    }

    /// Append another model's script whose stack effect is described by
    /// `pops` and `pushes` (for composing gadgets written without `Stk`).
    pub fn gadget(&mut self, script: Script, pops: usize, pushes: &[&str]) {
        self.apply(script, pops, pushes);
    }
}
