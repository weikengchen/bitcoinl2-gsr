//! Shared test harness: a wallet and a funded simulator world.
#![allow(dead_code)]

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, CompressedPublicKey, OutPoint, ScriptBuf, Transaction, TxOut, Witness};
use bitcoin_simulator::database::Database;
use bitcoinl2_vault::state::{AppState, State, MODE_NORMAL};
use bitcoinl2_vault::tx::{input, Plan, Vault};

pub struct Wallet {
    pub sk: SecretKey,
    pub pk: CompressedPublicKey,
}

impl Wallet {
    pub fn new(seed: u8) -> Self {
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = CompressedPublicKey(PublicKey::from_secret_key(&Secp256k1::new(), &sk));
        Self { sk, pk }
    }
    pub fn spk(&self) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&self.pk.wpubkey_hash())
    }
    pub fn out(&self, sats: u64) -> TxOut {
        TxOut { value: Amount::from_sat(sats), script_pubkey: self.spk() }
    }
    pub fn sign(&self, tx: &mut Transaction, idx: usize, prevout: &TxOut) {
        let h = SighashCache::new(tx.clone())
            .p2wpkh_signature_hash(idx, &prevout.script_pubkey, prevout.value, EcdsaSighashType::All)
            .unwrap();
        let sig = Secp256k1::new().sign_ecdsa(&Message::from(h), &self.sk);
        let sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };
        tx.input[idx].witness = Witness::p2wpkh(&sig, &self.pk.0);
    }
}

/// A funded world. `f` has 8 wallet outputs (within the parser bounds, so it can be
/// the grandparent of a first transition); `fees` pays the fee inputs.
pub struct World {
    pub db: Database,
    pub vault: Vault,
    pub wallet: Wallet,
    pub f: Transaction,
    pub fees: Transaction,
    next_f: u32,
    next_fee: u32,
}

impl World {
    pub fn new(_count: usize) -> Self {
        let wallet = Wallet::new(5);
        let funding = |seed: u8, n: usize| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input(OutPoint::new(bitcoin::Txid::from_byte_array([seed; 32]), 0))],
            output: (0..n).map(|_| wallet.out(100_000)).collect(),
        };
        let f = funding(9, 8);
        let fees = funding(10, 40);
        let db = Database::connect_temporary_database().unwrap();
        db.insert_transaction_unconditionally(&f).unwrap();
        db.insert_transaction_unconditionally(&fees).unwrap();
        Self { db, vault: Vault::new().unwrap(), wallet, f, fees, next_f: 0, next_fee: 0 }
    }

    /// The next unused output of `f`.
    pub fn coin(&mut self) -> (OutPoint, TxOut) {
        let i = self.next_f;
        self.next_f += 1;
        (OutPoint::new(self.f.compute_txid(), i), self.f.output[i as usize].clone())
    }

    /// The next unused output of `fees`.
    pub fn fee_coin(&mut self) -> (OutPoint, TxOut) {
        let i = self.next_fee;
        self.next_fee += 1;
        (OutPoint::new(self.fees.compute_txid(), i), self.fees.output[i as usize].clone())
    }

    pub fn app0() -> AppState {
        AppState { acc: [0xab; 32], mode: MODE_NORMAL }
    }

    /// T0 funded by one coin: `[P(20,000), change, caboose]`.
    pub fn genesis(&mut self) -> (Transaction, State) {
        let (coin, prevout) = self.coin();
        let (mut t0, state) =
            self.vault.genesis_tx(coin, Amount::from_sat(20_000), &Self::app0(), vec![self.wallet.out(79_000)]);
        self.wallet.sign(&mut t0, 0, &prevout);
        self.db.verify_transaction(&t0).unwrap();
        self.db.insert_transaction_unconditionally(&t0).unwrap();
        (t0, state)
    }

    pub fn plan(&mut self, parent: &Transaction, grandparent: &Transaction, s: &State, a: &AppState) -> Plan {
        let fee = self.fee_coin();
        let change = self.wallet.out(99_000);
        self.vault.plan(parent, grandparent, s, a, fee, change).unwrap()
    }

    /// A plan whose grandparent is the funding transaction `f`.
    pub fn plan_f(&mut self, parent: &Transaction, s: &State, a: &AppState) -> Plan {
        let f = self.f.clone();
        self.plan(parent, &f, s, a)
    }

    pub fn build(&self, plan: &Plan) -> Transaction {
        let mut x = self.vault.build(plan);
        self.wallet.sign(&mut x, 1, &plan.fee_prevout);
        x
    }

    pub fn check(&self, plan: &Plan) -> anyhow::Result<Transaction> {
        let x = self.build(plan);
        self.db.verify_transaction(&x)?;
        Ok(x)
    }

    pub fn accept(&self, plan: &Plan) -> Transaction {
        let x = self.check(plan).unwrap();
        self.db.insert_transaction_unconditionally(&x).unwrap();
        x
    }
}

pub fn err(r: anyhow::Result<Transaction>) -> String {
    r.expect_err("the transition must be rejected").to_string()
}
