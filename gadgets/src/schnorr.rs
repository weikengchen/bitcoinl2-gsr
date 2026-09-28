//! The CAT/Schnorr trick (Poelstra): with pubkey = R = G, a valid signature on
//! the transaction is `G.x || (e + 1)`, so rebuilding `e` from a message on the
//! stack and checking that signature binds the message to the transaction.
//! Unlike the tapscript version this needs no grinding: `e + 1` is formed with
//! OP_1ADD on the last byte, which only fails if that byte is 0xff.

use crate::pseudo::*;
use crate::sighash::SIGHASH_ALL;
use crate::tagged_hash::{tagged_hash, HashTag, TaggedHashGadget};
use crate::treepp::*;

/// x coordinate of the secp256k1 generator G.
pub const G_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// secp256k1 group order n, minus one.
const N_MINUS_1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
];

/// The transaction must be tweaked (e.g. a caboose randomizer) and the hints recomputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrickError {
    /// The challenge ends in 0xff (probability 1/256).
    LastByteFF,
    /// `e + 1` would not be a valid scalar (probability ~2^-128).
    ChallengeTooLarge,
}

/// BIP 340 challenge for pubkey = R = G over the sighash of `preimage`.
pub fn challenge(preimage: &[u8]) -> [u8; 32] {
    let m = tagged_hash(HashTag::TapSighash, preimage);
    let mut msg = G_X.to_vec();
    msg.extend(G_X);
    msg.extend(m);
    tagged_hash(HashTag::BIP340Challenge, &msg)
}

/// Hints for [SchnorrTrickGadget::verify]: the first 31 bytes and the last byte of `e`.
pub fn schnorr_trick_hints(preimage: &[u8]) -> Result<Vec<Vec<u8>>, TrickError> {
    let e = challenge(preimage);
    if e[31] == 0xff {
        return Err(TrickError::LastByteFF);
    }
    if e >= N_MINUS_1 {
        return Err(TrickError::ChallengeTooLarge);
    }
    Ok(vec![e[..31].to_vec(), vec![e[31]]])
}

pub struct SchnorrTrickGadget;

impl SchnorrTrickGadget {
    /// `( preimage -- )`: fails unless `preimage` is the SIGHASH_ALL message of
    /// the executing input. Pulls two hints.
    pub fn verify() -> Script {
        cat(&[
            TaggedHashGadget::from_provided(HashTag::TapSighash),
            push_data(&G_X),
            script! { OP_DUP OP_CAT OP_SWAP OP_CAT },
            TaggedHashGadget::from_provided(HashTag::BIP340Challenge),
            OP_HINT(),
            script! { OP_SIZE 31 OP_EQUALVERIFY },
            OP_HINT(),
            script! { OP_SIZE 1 OP_EQUALVERIFY OP_2DUP OP_CAT 3 OP_ROLL OP_EQUALVERIFY OP_1ADD OP_CAT },
            push_data(&G_X),
            script! { OP_SWAP OP_CAT },
            push_data(&[SIGHASH_ALL]),
            script! { OP_CAT },
            push_data(&G_X),
            script! { OP_CHECKSIGVERIFY },
        ])
    }
}
