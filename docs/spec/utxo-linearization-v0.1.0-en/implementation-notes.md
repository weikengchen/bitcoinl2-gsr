# Implementation Mapping and Research Tasks

Applies to *UTXO Linearization with Caboose State*, v0.1.0. This file is informative. The normative rules in the specification take precedence if a conflict arises.

## 1. Pinned Reference Revision

Repository: [Bitcoin-Wildlife-Sanctuary/covenants-gadgets](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets).

Commit: `93e057f2abdac14760b6a8ff82ee4a613a263153` (2025-05-04; message: `fix bugs`). Descriptions here follow the actual code. The earlier counter/randomizer layout described in the README should not override the current implementation.

## 2. Code-to-Specification Mapping

| Reference | Existing capability | Rules | Required work |
|---|---|---|---|
| [`lib.rs`: caboose generation](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/lib.rs#L265-L289) | Wraps a 32-byte state hash and 4-byte r in P2WSH | STATE, CAB | Hash the canonical envelope; enforce the trailing position |
| [`bitcoin_script.rs`: steps 1–6](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/bitcoin_script.rs#L16-L271) | CAT/Schnorr introspection of the current transaction | INT | Change 0x81 to 0x01; add complete input vectors and actual input_index validation |
| [`tap_csv_preimage.rs`](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/wizards/tap_csv_preimage.rs) | Message-construction components for several signature modes | INT-1–3 | Turn constant-data construction into a constrained validator for actual witnesses |
| [`bitcoin_script.rs`: steps 7–9](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/bitcoin_script.rs#L274-L410) | Reconstructs the parent and compares its authenticated txid | AUTH-2 | Extend role checks; authenticate Q and add branch selection |
| [`tx.rs`](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/wizards/tx.rs) | Reconstructs non-witness transaction serialization | AUTH-2–3, RES | Validate dynamic-field boundaries, counts, and resource limits at runtime |
| [`tx_in.rs`](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/wizards/tx_in.rs#L17-L33) | Empty-scriptSig input model | TX, RES-2 | Preserve the native SegWit baseline; reject unsupported ancestor formats |
| [`lib.rs`: Taproot construction](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/lib.rs#L128-L159) | Unknown-discrete-log internal point and a covenant prefix on every leaf | ENV-2 | Inspect the complete deployed script tree, not one successful path |
| [`counter.rs`](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/examples/counter.rs) | Example state openings and action validation | STATE-2, Init / First / Step | Add the identity layer and replace counter semantics with the target application |
| [`test.rs`: initialization](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-gadgets/blob/93e057f2abdac14760b6a8ff82ee4a613a263153/src/test.rs#L54-L80) | Unconditionally inserts an initial transaction into the simulator database | GEN, INIT | Construct an actually valid funding chain and test rejection of counterfeit genesis states |

## 3. Implementation Misreadings to Avoid

- **An output index is not an input index.** An outpoint.vout of 0 does not prove that the current input has index 0. ANYONECANPAY lacks the complete input-position commitment required here.
- **Committed data is not directly readable.** Fields such as sha_prevouts require openings and recomputation. Their preimages cannot be recovered from the hashes.
- **The same program is not the same identity.** Checking the expected P still leaves the origin and expected value of genesis_id to be authenticated.
- **The parent does not contain the predecessor script.** T's input lists an outpoint. The actual output in Q determines the non-main-program or same-main-program branch.
- **A caboose has a P2WSH wrapper.** OP_RETURN appears inside the hashed witnessScript. A direct OP_RETURN output is not the same byte format.
- **Known G does not prevent a key-path bypass.** G is used only for the Schnorr trick. The actual Taproot internal point and every spending path require separate review.
- **A two-generation backtrace is not a proof of arbitrary history.** It relies on actual spending relationships, consensus-valid ancestors, and complete recursive constraints.
- **An output commitment does not ensure data availability.** Losing state data or proofs can still prevent the program from advancing.

## 4. Suggested Implementation Sequence

1. Implement state-envelope parsing, caboose construction, and vector checks. Establish consistent byte order and lengths first.
2. Implement complete SIGHASH_ALL introspection of the current transaction. Verify the main-input index and role partition independently.
3. Bind parent T and grandparent Q, then implement the mutually exclusive genesis and continuation branches.
4. Use a minimal application to validate actual T0 → T1 → T2 transactions. Do not let unconditional insertion of an initial state hide entry-point failures.
5. Add counterfeit ACTIVE outputs, copied ids, incorrect ancestors, second main programs, and incorrect indices as adversarial cases.
6. Integrate vault authorization, fee accounting, and auxiliary contracts. Measure actual script size, witness size, grinding effort, and execution cost.

## 5. Deployment Description to Complete

| Parameter | Required definition |
|---|---|
| Target-chain context | Network and validated view; an external identity may be represented as `(chain_context, genesis_id)` |
| Taproot deployment | Internal point, all script leaves, construction rules, and expected P |
| Main-program set M | At least P; recognition of additional main programs must be explicit |
| app_root semantics | State encoding, root computation, or proof-validation rules |
| Init | Valid initial state, initial vault, and permitted funding sources |
| First / Step | Initial and ordinary actions, authorizations, and transition relations |
| Auxiliary input roles | Deposits, fee funding, auxiliary contracts, and authentication of their assigned roles |
| Auxiliary output roles | Withdrawals, change, recipients, amounts, and authorization |
| c and fee allocation | Who pays the caboose amount; miner-fee bounds or authorization |
| Data availability | Storage, publication, and recovery of data, proofs, and r |
| Resources | Further bounds on counts, proofs, and script budgets within R1 |

The actual spending logic must enforce these parameters. Publishing a client configuration file does not establish protocol enforcement.

## 6. Existing Validation Record

On 2026-09-07, `cargo test --lib` was run against the pinned reference commit: **18 passed, 0 failed**. The counter test performed 100 simulated transitions. The reference repository's source code was not modified.

The repository does not commit Cargo.lock. Dependencies were resolved within its declared ranges; principal versions were bitcoin `0.32.102`, bitcoin-script `2f2510ab`, bitcoin-scriptexec `fe203d2a`, and bitcoin-simulator `16b73cfa`. These details describe the test environment, not a published reference implementation of this draft.

This package separately verifies state-envelope and caboose encoding vectors. The new lineage authentication, resource boundaries, key-path or alternate-leaf bypass cases, and auxiliary-contract interactions have not completed actual Script testing.

## 7. Core Questions for Reviewers

Prioritize the following falsifiable claims: an arbitrarily created P output cannot enter a valid lineage with a copied ACTIVE identity; Q unambiguously authenticates T's actual predecessor script; every P spending path preserves the same inductive constraints; complete role checks cannot omit inputs or outputs; and every newly created successor satisfies the format and resource conditions needed for reflection at its next spend.
