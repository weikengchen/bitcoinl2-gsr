# bitcoinl2-gsr

Research code for a Bitcoin L2 whose L1 vault is a covenant UTXO line, assuming
Great Script Restoration (BIP 440 varops budget, BIP 441 tapleaf 0xc2) plus
OP_TX for transaction introspection.

## Layout

| Path | Contents |
|---|---|
| `docs/design.md` | Design decisions and open questions (Chinese, newer entries in English) |
| `docs/dev-plan.md` | Development plan and status (Chinese, newer entries in English) |
| `docs/verifier.md` | The withdrawal proof: statement, rules and on-chain verification |
| `docs/spec/` | UTXO linearization draft v0.1.0 handoff package (the vault component) |
| `scriptexec/` | Bitcoin Script executor with tapscript v2 (0xc2) and OP_TX support |
| `simulator/` | Local ledger simulator (Rust + SQLite) that validates 0xc2 spends |
| `gadgets/` | Covenant gadgets for 0xc2: OP_TX field readers, txid reflection, canonical transaction parsing (and the older SIGHASH_ALL + Schnorr-trick introspection) |
| `vault/` | The vault (a UTXO line per the draft spec), program a (deposits: merge and fold) and program b (withdrawals: split tree) |

## Provenance

`scriptexec/` and `simulator/` are modified copies of:

| Directory | Upstream | Commit | License |
|---|---|---|---|
| `scriptexec/` | [Bitcoin-Wildlife-Sanctuary/rust-bitcoin-scriptexec](https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-scriptexec) | `fac1401` | CC0-1.0 |
| `simulator/` | [Bitcoin-Wildlife-Sanctuary/bitcoin-simulator](https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-simulator) | `16b73cf` (tag 1.1.0) | MIT |

The first commit touching each directory imports the upstream tree verbatim;
later commits carry the changes. Tapscript v2 semantics and costs follow the
BIP 440/441 reference implementation, jmoik/bitcoin `gsr-inquisition` at
`8384b7a`, whose JSON conformance vectors are copied into
`scriptexec/tests/data/`. OP_TX (0xbd) follows jmoik/bitcoin `gsr-full` at
`d279905` (`src/script/op_tx.cpp`), including its fixed per-call cost; its
reference vectors are copied into the same directory.

## Test

```sh
cargo test
```

## License

MIT (see `LICENSE`), except `scriptexec/` (CC0-1.0) and `simulator/` (MIT),
which keep their upstream licenses.
