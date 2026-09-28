//! The vault: a UTXO line following the UTXO linearization draft v0.1.0
//! (`docs/spec/`), with the deviations recorded in `docs/design.md`:
//! the caboose is a bare OP_RETURN output, execution is tapscript v2 (0xc2),
//! and `app_root = SHA256(acc || mode)` with `acc' = SHA256(acc || txid(parent))`.

pub mod leaf;
pub mod program_a;
pub mod program_b;
pub mod state;
pub mod tx;
