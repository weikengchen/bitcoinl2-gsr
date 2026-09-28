//! Withdrawals end to end (design §7): the vault's completion pays the root b,
//! and b splits down a tree to the recipients. Runs in the simulator. A
//! rejected case runs the b input on its own and checks the failing rule.

mod common;

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, WPubkeyHash};
use bitcoinl2_vault::program_b::{pieces, BLeaf, ProgramB, SplitTree};
use bitcoinl2_vault::state::sha256;
use common::{deposit, rejects, Line, Wallet, World};
use gsr_gadgets::sighash::SighashAllData;

/// Lock height.
const H: u32 = 800_000;
/// Fee of every split.
const FEE: Amount = Amount::from_sat(500);
const FAN_OUT: usize = 4;

/// `n` payouts of 1,000 + i sats to distinct wallets.
fn payouts(n: usize) -> Vec<TxOut> {
    (0..n).map(|i| Wallet::new(100 + i as u8).out(1_000 + i as u64)).collect()
}

fn tree(w: &World, n: usize) -> SplitTree {
    SplitTree::new(&payouts(n), FAN_OUT, FEE, &w.b.script_pubkey())
}

/// A vault funded by deposits, locked at H and completed with `tree`: the completion.
fn complete(w: &mut World, tree: &SplitTree) -> Transaction {
    let mut line = Line::new(w);
    let mut d = deposit(w, &line.a, &[90_000]);
    d.extend(deposit(w, &line.a, &[90_000]));
    let p = line.plan(w, d);
    line.accept(w, &p);
    w.db.set_height(H + 1);
    let p = line.plan(w, vec![]);
    let mut p = w.vault.lock(p, H, Amount::from_sat(20_000), [0x4c; 32], &w.wallet.spk());
    p.change.value -= Amount::from_sat(20_000);
    line.accept(w, &p);
    let p = line.plan(w, vec![]);
    let p = w.vault.complete(p, &tree.withdrawal(), w.wallet.spk(), World::app0().params);
    line.accept(w, &p)
}

/// Split `node`, funded by `parent`'s output `vout`, and its subtree. Returns
/// the splits (parents first) and collects the payouts.
fn run(w: &World, tree: &SplitTree, node: usize, parent: &Transaction, vout: usize, paid: &mut Vec<TxOut>) -> Vec<Transaction> {
    let n = &tree.nodes[node];
    let s = w.b.split_tx(parent, vout, &n.outputs);
    w.db.verify_transaction(&s).unwrap();
    w.db.insert_transaction_unconditionally(&s).unwrap();
    let out: Amount = s.output.iter().map(|o| o.value).sum();
    assert_eq!(parent.output[vout].value - out, FEE);
    if n.children.is_empty() {
        paid.extend(s.output.iter().cloned());
    }
    let mut splits = vec![s.clone()];
    for (i, &c) in n.children.iter().enumerate() {
        splits.extend(run(w, tree, c, &s, 2 * i, paid));
    }
    splits
}

/// Lock, complete, and split down to every recipient.
#[test]
fn withdraw_end_to_end() {
    let mut w = World::new(0);
    let t = tree(&w, 20);
    assert_eq!(t.nodes.len(), 8); // 5 leaves, 2 internal nodes, the root
    let x = complete(&mut w, &t);
    assert_eq!(x.output[2], TxOut { value: t.root().value, script_pubkey: w.b.script_pubkey() });
    let mut paid = vec![];
    for s in run(&w, &t, t.nodes.len() - 1, &x, 2, &mut paid) {
        eprintln!("split with {} outputs: {} vB", s.output.len(), s.vsize());
    }
    assert_eq!(paid, payouts(20));

    // one level: the root pays the recipients directly
    let mut w = World::new(0);
    let t = tree(&w, 3);
    let x = complete(&mut w, &t);
    let mut paid = vec![];
    run(&w, &t, 0, &x, 2, &mut paid);
    assert_eq!(paid, payouts(3));
}

/// L1 cost of paying out 256 withdrawals with fan-out 16: the root split
/// funds 16 leaf splits of 16 payouts each.
#[test]
fn split_sizes() {
    let mut w = World::new(0);
    let spk = |i: u16| {
        let mut h = [0u8; 20];
        h[..2].copy_from_slice(&i.to_le_bytes());
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(h))
    };
    let payouts: Vec<TxOut> = (0..256).map(|i| TxOut { value: Amount::from_sat(330), script_pubkey: spk(i) }).collect();
    let t = SplitTree::new(&payouts, 16, FEE, &w.b.script_pubkey());
    let x = complete(&mut w, &t);
    let mut paid = vec![];
    let splits = run(&w, &t, t.nodes.len() - 1, &x, 2, &mut paid);
    assert_eq!(paid, payouts);
    let vb: usize = splits.iter().map(|s| s.vsize()).sum();
    eprintln!(
        "256 withdrawals, fan-out 16: {} splits, {vb} vB in total, {:.0} vB per withdrawal; root split {} vB, leaf split {} vB",
        splits.len(),
        vb as f64 / 256.0,
        splits[0].vsize(),
        splits[1].vsize()
    );
}

/// DA: the list is in the completion's witness, and the tree rebuilt from it
/// has the root the completion committed to.
#[test]
fn tree_is_rebuilt_from_the_published_list() {
    let mut w = World::new(0);
    let t = tree(&w, 20);
    let x = complete(&mut w, &t);
    let committed = &x.output[3].script_pubkey.as_bytes()[2..]; // OP_RETURN PUSHBYTES_64
    let (root, list_hash) = committed.split_at(32);
    let list = x.input[0].witness.iter().find(|e| sha256(e) == list_hash).expect("the list is in the witness");
    let rebuilt = SplitTree::from_list(list, FAN_OUT, FEE, &w.b.script_pubkey()).unwrap();
    assert_eq!(rebuilt.root().root(), root);
    assert_eq!(rebuilt.root().value, x.output[2].value);
}

/// The strongest attempt to split `parent`'s b output `vout` into `outputs`:
/// every hint agrees with the node's committed outputs `claimed` (so the
/// script's message has sha_outputs = R), and only the signature check can fail.
fn forged(w: &World, parent: &Transaction, vout: usize, outputs: &[TxOut], claimed: &[TxOut]) -> Transaction {
    let leaf = if parent.input.len() == 1 { BLeaf::Internal } else { BLeaf::Root };
    let leaf_hash = w.b.tree.leaf_hash(ProgramB::leaf_index(leaf));
    (0u32..)
        .find_map(|lock_time| {
            let mut tx = ProgramB::unsigned(parent, vout, outputs, lock_time);
            let mut data = SighashAllData::new(&tx, &[parent.output[vout].clone()], 0, leaf_hash);
            data.outputs = claimed.iter().map(serialize).collect();
            tx.input[0].witness = w.b.witness_from(leaf, &data, parent, vout)?;
            Some(tx)
        })
        .unwrap()
}

/// Split rules on the b input, against honest controls.
#[test]
fn split_rules() {
    let mut w = World::new(0);
    let t = tree(&w, 20);
    let x = complete(&mut w, &t);
    let root = t.root();
    let prevout = |p: &Transaction, v: usize| vec![p.output[v].clone()];

    // the root split pays exactly the committed outputs
    let ok = w.b.split_tx(&x, 2, &root.outputs);
    w.db.verify_transaction(&ok).unwrap();
    let mut outputs = root.outputs.clone();
    outputs[0].value -= Amount::from_sat(1);
    let tx = forged(&w, &x, 2, &outputs, &root.outputs);
    rejects(&tx, &prevout(&x, 2), 0, "SchnorrSig");
    // (hints computed from the transaction itself fail earlier, in the trick)
    let tx = w.b.split_tx(&x, 2, &outputs);
    rejects(&tx, &prevout(&x, 2), 0, "EqualVerify");
    let mut outputs = root.outputs.clone();
    outputs[0].script_pubkey = w.wallet.spk();
    let tx = forged(&w, &x, 2, &outputs, &root.outputs);
    rejects(&tx, &prevout(&x, 2), 0, "SchnorrSig");
    // ... with the b as its only input
    let mut tx = ok.clone();
    let (coin, coin_out) = w.fee_coin();
    tx.input.push(bitcoinl2_vault::tx::input(coin));
    rejects(&tx, &[x.output[2].clone(), coin_out], 0, "SchnorrSig");
    // the root b is not spent as a split's child (its parent has two inputs)
    let tx = w.b.split_with(BLeaf::Internal, &x, 2, &root.outputs);
    rejects(&tx, &prevout(&x, 2), 0, "EqualVerify");
    w.db.insert_transaction_unconditionally(&ok).unwrap();

    // a child reads its commitment at its own offset in the parent
    let child = &t.nodes[root.children[1]];
    let ok2 = w.b.split_tx(&ok, 2, &child.outputs);
    w.db.verify_transaction(&ok2).unwrap();
    let mut shifted = ok2.clone();
    let mut items: Vec<Vec<u8>> = shifted.input[0].witness.iter().map(|e| e.to_vec()).collect();
    items.splice(5..10, pieces(&ok, 0));
    shifted.input[0].witness = bitcoin::Witness::from_slice(&items);
    rejects(&shifted, &prevout(&ok, 2), 0, "NumEqualVerify");
    // ... and another node's outputs do not fit it
    let other = &t.nodes[root.children[0]];
    let tx = forged(&w, &ok, 2, &other.outputs, &child.outputs);
    rejects(&tx, &prevout(&ok, 2), 0, "SchnorrSig");
}

#[test]
fn b_leaves() {
    let b = ProgramB::new().unwrap();
    for (i, name) in ["root", "internal"].iter().enumerate() {
        gsr_gadgets::leaf::assert_no_op_success(&b.tree.scripts[i]).unwrap();
        eprintln!("b leaf {name}: {} bytes", b.tree.scripts[i].len());
    }
}
