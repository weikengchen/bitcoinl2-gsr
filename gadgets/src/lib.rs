//! Bitcoin Script gadgets for covenants in tapscript leaf version 0xc2 (BIP 440/441).
//!
//! The structure follows covenants-gadgets (Bitcoin-Wildlife-Sanctuary): every
//! gadget is a script plus a Rust-side function that produces its hints, and
//! hints are pulled from the bottom of the stack with [pseudo::OP_HINT], so the
//! witness lists them in consumption order.
//!
//! Tapscript v2 differs from tapscript in ways that matter here:
//! - numbers are unsigned little-endian of any length, so constants are pushed
//!   with [pseudo::push_u64] / [pseudo::push_data], never as `script!` integer
//!   literals >= 128 or as raw `Vec<u8>` interpolations;
//! - `OP_1NEGATE`, `OP_NEGATE` and `OP_ABS` are OP_SUCCESS: a leaf containing
//!   one is spendable by anyone. [leaf::assert_no_op_success] guards against it.

pub(crate) mod treepp {
    pub use bitcoin_script::{define_pushable, script};

    define_pushable!();

    pub use bitcoin::ScriptBuf as Script;
}

pub mod leaf;
pub mod pseudo;
pub mod schnorr;
pub mod sighash;
pub mod tagged_hash;
pub mod tx;

pub use treepp::Script;
