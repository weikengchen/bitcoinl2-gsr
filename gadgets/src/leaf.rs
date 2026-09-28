use anyhow::{bail, Result};
use bitcoin::key::UntweakedPublicKey;
use bitcoin::script::Instruction;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{ScriptBuf, WitnessProgram};
use bitcoin_scriptexec::v2;

/// Tapscript v2 leaf version (0xc2).
pub fn leaf_version() -> LeafVersion {
    LeafVersion::from_consensus(v2::TAPROOT_LEAF_TAPSCRIPT_V2).unwrap()
}

/// BIP 341 NUMS point H: an internal key with no known discrete logarithm.
pub fn nums_key() -> UntweakedPublicKey {
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        .parse()
        .unwrap()
}

/// Fail if the script contains an opcode that is OP_SUCCESS in tapscript v2,
/// which would make the leaf spendable by anyone.
pub fn assert_no_op_success(script: &ScriptBuf) -> Result<()> {
    for ins in script.instructions() {
        if let Instruction::Op(op) = ins? {
            if v2::is_op_success(op.to_u8()) {
                bail!("script contains {op}, which is OP_SUCCESS in tapscript v2");
            }
        }
    }
    Ok(())
}

/// A taproot output with a NUMS internal key whose leaves all use tapscript v2.
pub struct V2Tree {
    pub scripts: Vec<ScriptBuf>,
    pub info: TaprootSpendInfo,
    pub script_pubkey: ScriptBuf,
}

impl V2Tree {
    /// Leaves are placed in a complete binary tree, in order.
    pub fn new(scripts: Vec<ScriptBuf>) -> Result<Self> {
        if scripts.is_empty() {
            bail!("no leaves");
        }
        for s in &scripts {
            assert_no_op_success(s)?;
        }
        let n = scripts.len();
        let d = if n == 1 { 0 } else { (usize::BITS - (n - 1).leading_zeros()) as u8 };
        let deep = if n == 1 { 1 } else { 2 * (n - (1 << (d - 1))) };
        let mut builder = TaprootBuilder::new();
        for (i, s) in scripts.iter().enumerate() {
            let depth = if i < deep { d } else { d - 1 };
            builder = builder.add_leaf_with_ver(depth, s.clone(), leaf_version())?;
        }
        let secp = Secp256k1::verification_only();
        let info = builder
            .finalize(&secp, nums_key())
            .map_err(|_| anyhow::anyhow!("incomplete taproot tree"))?;
        let script_pubkey =
            ScriptBuf::new_witness_program(&WitnessProgram::p2tr(&secp, nums_key(), info.merkle_root()));
        Ok(Self { scripts, info, script_pubkey })
    }

    pub fn leaf_hash(&self, i: usize) -> TapLeafHash {
        TapLeafHash::from_script(&self.scripts[i], leaf_version())
    }

    pub fn control_block(&self, i: usize) -> Vec<u8> {
        self.info
            .control_block(&(self.scripts[i].clone(), leaf_version()))
            .expect("leaf is in the tree")
            .serialize()
    }

    /// Witness: hints (in consumption order), then the script and control block.
    pub fn witness(&self, i: usize, hints: &[Vec<u8>]) -> bitcoin::Witness {
        let mut w = bitcoin::Witness::new();
        for h in hints {
            w.push(h);
        }
        w.push(self.scripts[i].as_bytes());
        w.push(self.control_block(i));
        w
    }
}
