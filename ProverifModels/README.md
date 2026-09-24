# Birthmark Protocol — ProVerif Formal Verification

This folder contains the ProVerif models supporting the privacy and integrity claims made
in "The Birthmark Protocol: Achieving Semantic Non-Assembly in Media Provenance." Each
model is self-contained and independently runnable; none depends on any other file in
this folder.

For the architecture these models formalize — the capture device, the credential
processor (C), the credential validator, the three gatekeepers and their paired match
boards, the two content-channel servers, and the registry — see the paper itself. This
README indexes what each model tests and what result to expect; it isn't a substitute
for reading the paper.

## Running a model

Each file is a complete ProVerif specification. With ProVerif installed:

```
proverif BM_Baseline_Noncorrelation.pv
```

(or `proverif.exe` on Windows). No arguments or build steps beyond that.

## What each model tests

| File | Establishes | Tests | Result |
|---|---|---|---|
| `BM_Baseline_Noncorrelation.pv` | Properties A, B, C | No compromise: can a passive observer tell which content a given device authenticated, or identify a device from the registry, or from the content channel alone? | Observational equivalence is true |
| `BM_CredentialProcessor_Compromise.pv` | Property D | C's relay-terminus key leaked alone — does that reveal which device produced which content? | Observational equivalence is true |
| `BM_Validator_Compromise.pv` | Property E | Validator's key leaked alone — same question | Observational equivalence is true |
| `BM_ContentServer_Compromise.pv` | Property F | A content-channel server's key leaked alone — same question | Observational equivalence is true |
| `BM_Posting_Forgery.pv` | Property G | Can anyone other than the validator produce a signature the match board would accept? | `not attacker(v_token_sk)` is true |
| `BM_Registry_Convergence.pv` | Property H | Can one compromised content-channel server alone produce both signatures the registry requires? | `not attacker(i_device_sk)` is true |
| `BM_Quorum_Forgery.pv` | Property I (one gatekeeper compromised) | Can a quorum be reached without a genuine validator approval preceding it? | Correspondence query holds |
| `BM_Quorum_Collusion.pv` | Property I (two gatekeepers compromised) | Same question, with two of the three gatekeepers' keys leaked instead of one | Correspondence query holds |

## Reading the results

Three different proof techniques are used, and they answer different kinds of questions:

- **Observational equivalence** (Properties A–F): the model runs two scenarios side by
  side — e.g., a device authenticating one piece of content versus another — and asks
  whether any adversary, given everything it's allowed to observe or leak in that model,
  can tell which scenario it's in. "True" means it can't: the property holds.
- **Secrecy query, `not attacker(X)`** (Properties G, H): asks whether a specific key
  ever becomes derivable by the adversary. "True" means it never does, which is what
  makes forging a signature without that key infeasible.
- **Correspondence query** (Property I): asks whether one event can only occur after
  another has already occurred — specifically, whether a `quorum_reached` event is
  always preceded by a `validator_approved` event for the same value. "True" means
  quorum can't be forged even by a gatekeeper (or, for the collusion model, two of the
  three) who never held that approval.

## Naming

Each file's key variables follow the paper's own terms, lowercased and with underscores
in place of hyphens (ProVerif identifiers can't contain hyphens): `packethash` for
PacketHash, `v_token_pk`/`v_token_sk` for the validator's keypair, `c_device_pk`/
`c_device_sk` for C's relay-terminus key, `c_sign_pk`/`c_sign_sk` for C's own
submission-server signing key, `f_device_sk`/`i_device_sk` for the two content-channel
servers' keys, `blindshare_key` for BlindShare_key, and `g1_sk`/`g1_sign_sk`,
`g2_sk`/`g2_sign_sk`, `g3_sk`/`g3_sign_sk` for the three gatekeepers' terminus and
signing keys respectively.

"Gatekeeper" in these models always means one of the three verify-and-post nodes, never
C. C was previously called the "gatekeeper server" in an earlier revision of both the
paper and this folder; `BM_CredentialProcessor_Compromise.pv` is the current name for
what was once `BM_Gatekeeper_Compromise.pv`, testing the same property (D) under the
current terminology. If a file by the old name is still present in this folder, it's
stale and should be removed rather than treated as a second copy of Property D.

Property and file names are otherwise independent of each other by design: a file is
named for what it tests, not for a letter, so that the mapping in the table above is the
only place that pairing needs to be looked up.

