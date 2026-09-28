use crate::treepp::*;
use crate::pseudo::push_data;
use sha2::{Digest, Sha256};

/// Tags used in tagged hashes (BIP 340/341).
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HashTag {
    TapLeaf,
    TapSighash,
    BIP340Challenge,
}

impl HashTag {
    pub fn to_str(&self) -> &'static str {
        match self {
            HashTag::TapLeaf => "TapLeaf",
            HashTag::TapSighash => "TapSighash",
            HashTag::BIP340Challenge => "BIP0340/challenge",
        }
    }
}

/// SHA256 of the tag.
pub fn hashed_tag(tag: HashTag) -> Vec<u8> {
    Sha256::digest(tag.to_str().as_bytes()).to_vec()
}

/// Tagged hash computed in Rust.
pub fn tagged_hash(tag: HashTag, msg: &[u8]) -> [u8; 32] {
    let t = hashed_tag(tag);
    let mut h = Sha256::new();
    h.update(&t);
    h.update(&t);
    h.update(msg);
    h.finalize().into()
}

/// Tagged hash of the message on top of the stack: `( msg -- hash )`.
pub struct TaggedHashGadget;

impl TaggedHashGadget {
    pub fn from_provided(tag: HashTag) -> Script {
        script! {
            { push_data(&hashed_tag(tag)) }
            OP_DUP OP_CAT
            OP_SWAP OP_CAT
            OP_SHA256
        }
    }
}
