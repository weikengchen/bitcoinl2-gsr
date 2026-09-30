# Withdrawal proof: statement, rules and on-chain verification

Status: draft, 2026-09-29. Audience: whoever builds the proof circuit and its
on-chain verifier. The vault side is implemented; the circuit and the verifier
are not. Reference code lives in `vault/src/` (`verifier.rs`, `da.rs`,
`program_a.rs`, `program_b.rs`, `leaf.rs`, `state.rs`).

Conventions: all hashes are SHA256 unless stated; txids are in internal byte
order; `‖` is concatenation; LE32/LE64 are little-endian fixed-width integers;
CompactSize is Bitcoin's variable-length integer, minimal encodings only.

## 1. Where the proof sits

The vault is a single UTXO that moves along a line of transactions. Its state
(the "application state") has a mode:

```
NORMAL ──lock──▶ VERIFYING ──completion──▶ NORMAL
                     │
                     └──timeout (nLockTime ≥ h + N)──▶ NORMAL (bond stays in the vault)
```

- **Lock**: anyone freezes the vault by adding a bond ≥ B_min. The lock's
  nLockTime h is recorded. While VERIFYING, the vault accepts no deposits.
- **Completion**: pays the batch's withdrawals W to program b, publishes the DA
  data in its witness, refunds the bond, and sets the new L2 state root and
  parameters. It is valid only if a proof of its **statement** (§2) verifies.
- The proof is generated after the lock, against the frozen history. Until the
  real verifier exists, a **franker** stands in for it (§6.1).

Vault transaction templates (inputs → outputs):

| kind | inputs | outputs | nLockTime |
|---|---|---|---|
| plain | vault, fee | vault, change, caboose | 0 |
| fold j (1–4) | vault, a×j, fee | vault(+Σa), change, aggregator OP_RETURN, caboose | 0 |
| lock | vault, fee | vault(+bond), change, caboose | h |
| completion | vault, fee | vault(−W−bond), change, b(W), OP_RETURN `R ‖ H`, refund(bond), caboose | 0 |
| timeout | vault, fee | vault, change, caboose | ≥ h + N |

The caboose is `OP_RETURN PUSHBYTES_36 <SHA256(S) ‖ LE32(r)>`, where S is the
state envelope `"UTXOLIN" ‖ 01 ‖ phase ‖ [vault id L] ‖ SHA256(A)` and A is the
application state:

```
NORMAL (77 bytes):     acc(32) ‖ 00 ‖ l2_root(32) ‖ LE64(B_min) ‖ LE32(N)
VERIFYING (153 bytes): acc(32) ‖ 01 ‖ l2_root(32) ‖ LE64(B_min) ‖ LE32(N)
                       ‖ LE32(h) ‖ LE64(bond) ‖ locker L2 address(32) ‖ SHA256(refund scriptPubKey)(32)
```

`acc` is a hash chain over the vault's history: every vault transaction X with
parent T sets `acc(X) = SHA256(acc(T) ‖ txid(T))`. `l2_root` is opaque to the
vault; only the proof interprets it.

## 2. The statement

The public input of a proof, 212 bytes:

```
L ‖ acc′ ‖ l2_root ‖ l2_root′ ‖ LE64(B_min′) ‖ LE32(N′) ‖ LE64(W) ‖ R ‖ H
```

| field | meaning | where it comes from on chain |
|---|---|---|
| L | the vault's id (txid of its genesis) | the vault's state envelope |
| acc′ | the vault's history up to and including the lock | the new state's acc at the completion |
| l2_root | L2 state root the proof starts from | the old application state |
| l2_root′ | L2 state root the proof ends at | the new application state (caboose) |
| B_min′, N′ | new parameters | the new application state (caboose) |
| W | total paid to program b | the completion's output 2 |
| R | root of the withdrawal split tree | the completion's output 3 |
| H | commitment to the DA data | the completion's output 3 |

Every field is fixed by the completion transaction: W, R and H by its outputs,
l2_root′ and the parameters by its caboose, and L, acc′ and l2_root through its
input's parent, which the vault's script authenticates. `Statement::of_completion`
reads it off a completion.

## 3. What the proof establishes

The circuit's rules, given the statement and private inputs. Nodes are assumed
to hold the full L1 and L2 state.

### 3.1 Where the previous proof stopped

The L2 state (committed by `l2_root`) records `acc_synced`, the acc up to which
it has processed the vault's history. A proof:

1. opens `acc_synced` from the old L2 state;
2. takes the vault transactions after that point, in order, as private inputs
   (non-witness serializations), and checks that chaining their txids from
   `acc_synced` gives `acc′`;
3. records `acc_synced′ = acc′` in the new L2 state.

Consecutive proofs therefore cover adjacent, non-overlapping parts of the
history, so every deposit is credited exactly once. (On L1 a folded a output is
spent and cannot be folded again.)

### 3.2 Reading history

txids do not commit to witnesses, so the circuit only reads non-witness data,
or opens hashes found there against private preimages:

- vault transactions: their outputs, nLockTime, and the application states
  whose hashes their cabooses commit to;
- for each fold: the merge tree behind every a input, down to the deposits
  (outpoint → parent transaction → …);
- the lock: bond and locker address, from the VERIFYING state's preimage.

### 3.3 Deposits

A **deposit transaction** is credited only in this format (the L2's rule; L1
does not enforce it):

- at most 8 inputs, all with empty scriptSigs (native segwit);
- outputs exactly `[a_L(v), OP_RETURN PUSHBYTES_36 <"L2D\x01" ‖ recipient(32)>, optional native segwit change]`.

Its non-witness part is at most about 470 bytes, so each deposit costs the
prover a bounded amount of hashing.

**Classification.** Tracing back from a fold, let M be the transaction whose
output `vout` an a input spends:

1. If M's output 1 carries the deposit tag, M is a deposit: credit `v` to the
   recipient if `vout = 0` and M is in the deposit format, otherwise credit
   nobody. This is sound because program a requires a merge's output 1 to be
   native segwit, so no merge carries the tag.
2. Otherwise M must fit the merge template: `vout = 0`, j = 2..4 a inputs plus
   one fee input, exactly 3 outputs, output 0 is a_L, output 1 native segwit.
   Then trace its inputs `0..j`; each must spend an a_L output.
3. Anything else is unattributed; its amount stays in the vault. This includes
   a fold input that does not spend an a_L output (the vault accepts any native
   segwit input there).

`ProgramA::classify` is the reference.

### 3.4 Withdrawals and the split tree

The withdrawal list is a list of outputs (recipient scriptPubKey, amount). The
split tree that pays it is canonical, so R and W follow from the list and two
circuit parameters, the fan-out `k` (≤ 126) and the fee per split `f`:

- leaves: the list cut into chunks of k outputs, in order;
- internal level: the previous level cut into chunks of k nodes; a node's
  outputs are `[b(V_1), D_1, b(V_2), D_2, …]` with `D_i = OP_RETURN PUSHBYTES_32 <R_i>`;
- for every node, `R = SHA256(serialized outputs)` (the sha_outputs of the
  transaction that splits it) and `V = Σ output amounts + f`;
- the root's `(R, V)` is `(R, W)`.

`SplitTree` is the reference.

### 3.5 DA data and H

The DA data of a batch, published in the completion's witness:

```
Vec<TxOut> withdrawals            (consensus serialization: count, then outputs)
CompactSize n, then n addresses    (new accounts, 32 bytes each, in index order)
CompactSize m, then m changes      (per changed account, sorted by index, no repeats:
                                     CompactSize index difference (first from 0),
                                     CompactSize balance, CompactSize nonce)
```

The circuit must prove that this is exactly the state difference from
`l2_root` to `l2_root′` plus the withdrawal list behind R.

H commits to the data as a hash chain over the chunks it is published in: the
last link is 32 zero bytes, each link is SHA256(chunk ‖ next link), and H is the
first link. Published as one chunk, `H = SHA256(data ‖ 0^32)`, which is what the
completion checks today. The 32-byte link fixes how each preimage splits, so
unless SHA256 has a collision (or a preimage of 0^32), a chain of reveals
starting at H and ending at 0^32 reveals exactly the committed chunks.
`DaData` and `chain_hash` are the reference.

### 3.6 Left to the circuit (not specified here)

The L2's own transactions and state tree; rewards to aggregators and lockers;
adjudication of forfeited bonds; the reference fee rate from L1 headers.

## 4. On-chain verification

### 4.1 Multi-step verification

The verifier runs in the style of bitcoin-circle-stark: split into parts, one
part per transaction, with intermediate values carried between transactions in
a hash-linked memory ("LDM": every value written or read is folded into a
running hash; the last part checks the running hash).

In the vault, each part is a vault transition in VERIFYING mode, so no new
program identity is needed. Proposed vault changes (not implemented yet):

- The VERIFYING state gains `LE32(pc) ‖ ldm(32) ‖ statement hash(32)`.
  The lock sets `pc = 0`.
- Step 1 absorbs the statement. It cannot see the completion's outputs, so W,
  R, H, l2_root′ and the parameters enter as values the proof binds, and their
  hash is stored in the state. acc′ is the acc after the lock, which step 1 sees
  as its own new acc.
- Step i runs verifier part i. P's tap tree gets one leaf per part; the leaf
  checks `pc = i − 1`, opens the values it reads against `ldm`, and writes
  `pc = i` and the new `ldm`.
- The completion checks `pc = last`, checks the LDM, and checks that its
  outputs and new state match the statement hash.
- Proof data (commitments, decommitments, FRI layers) enters as hints in the
  step witnesses and is absorbed into the transcript as usual.

Given the proof, every step transaction is determined up to its fee input, so
the prover can build the whole chain at once and submit it together. Mempool
policy allows chains of 25 unconfirmed transactions, and each transaction is
limited to 400,000 WU (standard) with a varops budget of weight × 10,000.

Sizing: bitcoin-circle-stark's Plonk verifier is 72 parts and 3.31 MB of script
with 8-bit table multiplication, and 414 KB (12.5%) with native 64-bit
multiplication and modulo, which GSR provides. At 400,000 WU per transaction
that suggests a handful of steps, including the proof data. This is an
estimate, not a measurement. The timeout N must cover proof generation plus
all steps.

### 4.2 The placeholder until then

`Franker` checks, off chain, what the circuit checks that does not depend on
the L2's internals: the DA data is canonical and matches H, and R and W are the
split tree of its withdrawal list. It then signs the whole completion
(BIP 340, SIGHASH_DEFAULT, i.e. all inputs and outputs), and the completion leaf
checks that signature against the franker key baked into P. Without
CHECKSIGFROMSTACK a signature can only cover a transaction, and the transaction
fixes every statement field. To switch to the real verifier, replace this
signature check with the steps of §4.1; the statement fields are already on the
completion leaf's stack.

## 5. Open items

- Rewards and fee reimbursement rules (per-template byte quotas at a reference fee rate).
- Chunked DA publication across several steps (the H format already allows it).
- Transaction introspection: the vault's scripts currently authenticate the
  spending transaction with the CAT/Schnorr trick. Moving to OP_TX (implemented
  in jmoik/bitcoin `gsr-full`) is under evaluation; it does not change this
  interface.
