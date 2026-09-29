//! Shared test harness: a wallet and a funded simulator world.
#![allow(dead_code)]

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, CompressedPublicKey, OutPoint, ScriptBuf, Transaction, TxOut, Witness};
use bitcoin_simulator::database::Database;
use bitcoin_simulator::spending_requirements::P2TRChecker;
use bitcoinl2_vault::leaf::{Kind, VaultConfig};
use bitcoinl2_vault::program_a::ProgramA;
use bitcoinl2_vault::program_b::ProgramB;
use bitcoinl2_vault::state::{AppState, Mode, Params, State};
use bitcoinl2_vault::tx::{input, op_return, Plan, Vault};
use bitcoinl2_vault::verifier::Franker;

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
/// `franker` franks completions (the proof placeholder); `b` is program b.
pub struct World {
    pub db: Database,
    pub vault: Vault,
    pub wallet: Wallet,
    pub franker: Franker,
    pub b: ProgramB,
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
        let b = ProgramB::new().unwrap();
        let franker = Franker {
            key: Keypair::from_seckey_slice(&Secp256k1::new(), &[6; 32]).unwrap(),
            fan_out: 4,
            split_fee: Amount::from_sat(500),
            b_spk: b.script_pubkey(),
        };
        let config = VaultConfig { franker: franker.public_key(), b_spk: b.script_pubkey() };
        let vault = Vault::new(config).unwrap();
        Self { db, vault, wallet, franker, b, f, fees, next_f: 0, next_fee: 0 }
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
        AppState { acc: [0xab; 32], l2_root: [0x5e; 32], params: Params { b_min: 10_000, n: 144 }, mode: Mode::Normal }
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

/// Input `idx` fails inside its script with `want`.
pub fn rejects(tx: &Transaction, prevouts: &[TxOut], idx: usize, want: &str) {
    let e = P2TRChecker::check(tx, prevouts, idx).expect_err("the input must be rejected").to_string();
    assert!(e.contains(&format!("Some({want})")), "input {idx}: {e}");
}

pub const AGGREGATOR: &[u8] = b"aggregator L2 address";

pub fn aggregator_out() -> TxOut {
    op_return(AGGREGATOR.to_vec())
}

/// A vault line after its first transition, and its deposit program a_L.
pub struct Line {
    pub id: [u8; 32],
    pub a: ProgramA,
    pub grand: Transaction,
    pub parent: Transaction,
    pub state: State,
    pub app: AppState,
}

impl Line {
    pub fn new(w: &mut World) -> Self {
        let (t0, s0) = w.genesis();
        let a0 = World::app0();
        let p1 = w.plan_f(&t0, &s0, &a0);
        let t1 = w.accept(&p1);
        let id = t0.compute_txid().to_byte_array();
        let a = ProgramA::new(id, &w.vault.script_pubkey()).unwrap();
        Self { id, a, grand: t0, parent: t1, state: p1.new_state, app: p1.new_app }
    }

    pub fn balance(&self) -> u64 {
        self.parent.output[0].value.to_sat()
    }

    /// The honest plan folding `deposits` (a plain transition if there are none).
    /// The other kinds start from `plan(w, vec![])`.
    pub fn plan(&self, w: &mut World, deposits: Vec<(OutPoint, TxOut)>) -> Plan {
        let p = w.plan(&self.parent, &self.grand, &self.state, &self.app);
        if deposits.is_empty() {
            p
        } else {
            w.vault.with_deposits(p, deposits, aggregator_out())
        }
    }

    /// `plan` with `a` signing the deposit inputs, the franker a completion,
    /// and the wallet the fee input.
    pub fn build(w: &World, a: &ProgramA, plan: &Plan) -> Transaction {
        let mut x = match plan.kind {
            Kind::Fold(_) => a.fold_tx(&w.vault, plan),
            Kind::Complete => w.vault.build_complete(plan, &w.franker).expect("the franker accepts the batch"),
            _ => w.vault.build(plan),
        };
        let fee = x.input.len() - 1;
        w.wallet.sign(&mut x, fee, &plan.fee_prevout);
        x
    }

    pub fn accept(&mut self, w: &World, plan: &Plan) -> Transaction {
        let x = Self::build(w, &self.a, plan);
        w.db.verify_transaction(&x).unwrap();
        w.db.insert_transaction_unconditionally(&x).unwrap();
        self.grand = std::mem::replace(&mut self.parent, x.clone());
        self.state = plan.new_state;
        self.app = plan.new_app;
        x
    }
}

/// One deposit transaction paying each of `values` to `a`, each a output followed
/// by its recipient OP_RETURN. Returns the a outputs.
pub fn deposit(w: &mut World, a: &ProgramA, values: &[u64]) -> Vec<(OutPoint, TxOut)> {
    let (coin, prevout) = w.fee_coin();
    let mut output = vec![];
    for (i, v) in values.iter().enumerate() {
        output.extend(a.deposit_outputs(Amount::from_sat(*v), &[i as u8 + 1; 20]));
    }
    let total: u64 = values.iter().sum();
    output.push(w.wallet.out(prevout.value.to_sat() - total - 1_000));
    let mut d = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![input(coin)], output };
    w.wallet.sign(&mut d, 0, &prevout);
    w.db.verify_transaction(&d).unwrap();
    w.db.insert_transaction_unconditionally(&d).unwrap();
    let txid = d.compute_txid();
    (0..values.len()).map(|i| (OutPoint::new(txid, 2 * i as u32), d.output[2 * i].clone())).collect()
}
