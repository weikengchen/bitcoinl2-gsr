# UTXO Linearization Research Package · v0.1.0

For developer research and review. Delivery date: 2026-09-08. English edition; protocol definitions and encoding vectors are unchanged from v0.1.0.

This package specifies how a single main program holds vault funds, commits to application state through a caboose, and preserves a permanent identity derived from its genesis txid. It is an unsubmitted BIP-style research draft, not a deployed protocol or complete reference implementation.

## Suggested Reading Order

1. Open the **[offline reading edition](read.html)** for the specification and three diagrams. Styles and figures are embedded; reading the specification requires no network connection.
2. Use the **[Markdown specification](bip-utxo-linearization.md)** for technical review, version control, or further editing.
3. Consult the **[implementation notes](implementation-notes.md)** for reusable components in the reference repository and the remaining implementation work.
4. Use the **[verification cases](verification-cases.md)** and **[encoding vectors](vectors/encoding-vectors.json)** to establish an implementation-validation plan.

## Files

| Path | Purpose |
|---|---|
| `bip-utxo-linearization.md` | Specification: rules, state encoding, validation algorithm, conditional arguments, and scope |
| `read.html` | Offline edition of the complete specification; printable from a browser |
| `implementation-notes.md` | Pinned code revision, implementation gaps, suggested research sequence, and validation record |
| `verification-cases.md` | Positive and negative scenarios with corresponding rule identifiers |
| `figures/*.svg` | Scalable lifecycle, caboose, and authentication diagrams |
| `figures/*.mmd` | Mermaid sources for the same concepts, for further editing |
| `vectors/encoding-vectors.json` | Three valid encodings plus malformed-encoding, altered-commitment, and identity-comparison cases |
| `vectors/verify_vectors.py` | Python 3 standard-library verifier for the encoding and commitment examples |
| `MANIFEST.sha256` | SHA256 checksums of every delivered file except the manifest itself |

## Run the Encoding Checks

From this directory:

```sh
python3 vectors/verify_vectors.py
```

No additional libraries are required. The verifier checks state envelopes, caboose bytes, and hash relationships. It does not execute Bitcoin Script or establish consensus validity of transactions or identity lineages.

## Choices Made in This Version

The main program is fixed at input and output 0. The caboose is the last output. State envelopes are 41 or 73 bytes. Introspection uses SIGHASH_ALL without ANYONECANPAY. Direct txid reflection uses the 520-byte R1 profile.

These choices make the draft explicit and are documented in the specification. Application transitions, auxiliary roles, the main-program recognition set, caboose amount, and vault-fee policy must be defined and enforced by each application configuration.

## Maturity

The pinned reference repository passed its 18 existing library tests. This package provides reproducible byte-encoding examples. Complete identity-validation scripts, adversarial tests of two-generation backtracing, and end-to-end OP_CAT transaction validation remain to be implemented.

No BIP number has been assigned. The rights holder must determine public licensing and author attribution. The specification links to the reference code and external standards; the package does not duplicate the full repository or its build dependencies.
