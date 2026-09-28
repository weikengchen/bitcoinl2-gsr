# Verification-Case Matrix

Applies to v0.1.0. Except for cases explicitly identified as encoding examples, this is a test plan for implementers, not a record of executed or passing tests.

“Accept” means acceptance by the protocol's identity layer only. The complete transaction must also satisfy Bitcoin consensus and application authorization and transition checks. Unless stated otherwise, assume main program P, set M, a valid target-chain context, and a Taproot construction with no bypass path.

## 1. Genesis and Identity

| Case | Construction or change | Expected result | Principal rules |
|---|---|---|---|
| G01 | One permitted ordinary funding input; P at output 0; trailing caboose commits to valid GENESIS; first transition writes T0's txid | Accept | GEN, INIT |
| G02 | Genesis has two ordinary funding inputs | Reject the first transition | GEN-1, INIT-1 |
| G03 | Ordinary funds create P directly, but the caboose is ACTIVE with a copied known id | Reject the first transition | AUTH-4, INIT-2 |
| G04 | As G03, with an arbitrarily chosen id instead of a copied id | Reject the first transition | INIT-2 |
| G05 | First spend of valid GENESIS writes a txid other than its parent's | Reject | INIT-3 |
| G06 | First spend of valid GENESIS produces another GENESIS state | Reject | INIT-3 |
| G07 | A real P predecessor exists, but the old state is GENESIS to attempt an identity reset | Reject | NEXT-2 |
| G08 | A valid ACTIVE transition changes any bit of the id | Reject | NEXT-2 |
| G09 | A valid ACTIVE transition preserves the id and changes app_root as authorized | Accept | NEXT-2–3 |
| G10 | Clone P and use independent ordinary funds to create another valid GENESIS | Allow a new instance; its first id differs from the expected old id unless the cryptographic assumptions fail | INIT-3, VERIFY-1 |
| G11 | The predecessor belongs to M but is not P | Reject | REJECT-1 |
| G12 | GENESIS bytes are correct but the application Init predicate fails | Reject | INIT-2 |

## 2. Positions, Roles, and Outputs

| Case | Construction or change | Expected result | Principal rules |
|---|---|---|---|
| L01 | Move the main-program input from index 0 to 1 | Reject | LIN-2, INT-3 |
| L02 | Change the spent main-program output's vout from 0 to 1 | Reject | LIN-2 |
| L03 | Add a second input whose main-program script belongs to M | Reject | LIN-1 |
| L04 | Add a second output whose main-program script belongs to M | Reject | LIN-1 |
| L05 | Remove the main-program successor | Reject | TX-1, LIN-1–3 |
| L06 | Replace output 0 with another P2TR script | Reject | LIN-1 |
| L07 | Put the claimed caboose at a non-final index | Reject | CAB-1 |
| L08 | Add an output with the same caboose_spk as the valid trailing caboose | Reject | CAB-4 |
| L09 | Add an input or output not covered by any role | Reject | ROLE-1–2 |
| L10 | Assign one input to both deposit and fee-funding roles to count it twice | Reject ambiguous or overlapping role assignment | ROLE-1, VALUE-2 |
| L11 | Supply only a subset of the input vectors to introspection | Reject commitment mismatch | INT-2 |
| L12 | Exhaustive, disjoint funding, withdrawal, and change roles; retain unique P and trailing caboose | Identity layer accepts; application authorization still required | ROLE, VALUE |

## 3. Ancestor Authentication

| Case | Construction or change | Expected result | Principal rules |
|---|---|---|---|
| A01 | Substitute parent T while retaining the original referenced txid | Reject | AUTH-2 |
| A02 | Change T's amount or caboose without changing the txid referenced by the actual input | Reject | AUTH-2 |
| A03 | Present another output script from Q as the output indexed by k | Reject | AUTH-3 |
| A04 | Forge a Q containing P while retaining the original q | Reject | AUTH-3 |
| A05 | k is outside Q's output range | Reject | AUTH-3 |
| A06 | Omit Q and assert in the witness that the predecessor is P | Reject | AUTH-3–4 |
| A07 | Supply raw transaction bytes that look like a continuation, without an actual spending relationship or chain-validity anchor | Must not serve as external identity authentication | ENV-4, VERIFY-1 / 5 |
| A08 | For the current spend of a valid long chain, supply only T, Q, and this step's required state proofs | Accept when recursive premises hold; proof depth does not grow with history | AUTH, NEXT |

## 4. Encoding, Signatures, and Resources

| Case | Construction or change | Expected result | Principal rules |
|---|---|---|---|
| E01 | Incorrect magic, version, phase, total length, or trailing bytes | Reject; encoding examples included | STATE-1 |
| E02 | An ACTIVE id contains 31 or 33 bytes | Reject; encoding examples included | STATE-1 |
| E03 | The envelope is correct, but app_root disagrees with the application opening or proof | Reject | STATE-2 |
| E04 | Change the state envelope without updating the caboose | Reject commitment mismatch; byte example included | CAB-1, AUTH-2 / 5 |
| E05 | Change r without updating the caboose | Reject commitment mismatch; byte example included | CAB-1 / 3 |
| E06 | Change r, update all commitments, and satisfy introspection and authorization | May accept; one application state permits different r values | CAB-3 |
| E07 | Use ALL\|ANYONECANPAY, NONE, or SINGLE for the introspection signature | Reject | INT-1 |
| E08 | An annex or an unsupported codesep_pos is present at introspection | Reject | INT-1 / 3 |
| E09 | Forge a challenge hash or signature hint not bound to the actual message | Reject | ENV-3, INT-4 |
| E10 | The simplified G/G construction's raw challenge integer is at least n-1 | Reject that candidate and grind again | INT-4 |
| E11 | Reflected T or Q, or a newly created protocol transaction, exceeds 520 bytes without witness | Reject under R1 | RES-1 |
| E12 | Ancestor Q has a nonempty scriptSig | Reject under R1 | RES-2 |
| E13 | A CAT intermediate exceeds its limit despite otherwise valid fields | Reject or fail execution | RES-1 |
| E14 | Non-minimal CompactSize or ambiguous field parsing | Reject | Section 4, RES-3 |
| E15 | Encode the example id in explorer display order instead of outpoint order | May remain parsable, but must fail comparison with the actual expected id | Section 4, INIT-3 / VERIFY-1 |

## 5. Vault, Spending Paths, and Auxiliary Contracts

| Case | Construction or change | Expected result | Principal rules |
|---|---|---|---|
| V01 | Preserve the correct id but convert vault funds into unauthorized miner fees | Reject | VALUE-1–3 |
| V02 | Combine a valid application proof with a falsified input amount | Reject the actual-amount commitment mismatch | INT-2, VALUE-1 |
| V03 | Accounting overflows or underflows | Reject | VALUE-3 |
| V04 | Another Taproot leaf can transfer the entire vault directly | Deployment is noncompliant; induction must not be used | ENV-2 |
| V05 | A key path has a known private key | Deployment is noncompliant | ENV-2 |
| V06 | An auxiliary contract verifies expected P and id and reads the authenticated new state | Accept if all inputs and application conditions succeed | VERIFY-3–4 |
| V07 | An auxiliary contract accepts any id or checks only the same P | Does not authenticate the intended instance | VERIFY-1 / 3 |
| V08 | An auxiliary contract uses an independent forged state witness while the main program uses the real one | Auxiliary contract must reject commitment mismatch | VERIFY-3 |
| V09 | Two independent main programs both require their own input index to be 0 | Cannot form a compliant joint transition | LIN-2, ROLE-3 |
| V10 | Claim current unspentness solely from a historical block-inclusion proof | Must not accept the claimed current-state conclusion | VERIFY-2 / 5 |

## 6. Operational Conditions That Are Not Execution Errors

| Condition | Interpretation |
|---|---|
| Two unconfirmed candidate transactions spend the same main program | Candidate conflicts do not contradict a unique lineage within a valid chain view |
| A reorganization removes a transition | Indexers must roll back; the old branch tip is no longer the current state |
| Nobody submits another transition | Linearization does not guarantee liveness |
| State data or proof material is lost | Commitment authenticity remains, but a successor witness may no longer be constructible |

The encoding examples and their verifier do not cover most Script or consensus scenarios in this matrix. Implementation reports should record the environment, construction, expectation, observed result, and failure location for each case. The existence of a matching test name is not evidence that validation is complete.
