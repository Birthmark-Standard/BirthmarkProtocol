# Birthmark Protocol — ProVerif Formal Verification

This folder contains the ProVerif models supporting the privacy and integrity claims made
in "The Birthmark Protocol: Achieving Semantic Non-Assembly in Media Provenance." Each
model is self-contained and independently runnable; none depends on any other file in
this folder.

For the architecture these models formalize — the capture device, the gatekeeper server,
the credential validator, the content-channel servers, the match board, and the
registry — see the paper itself. This README indexes what each model tests and what
result to expect; it isn't a substitute for reading the paper.

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
| `BM_Gatekeeper_Compromise.pv` | Property D | Gatekeeper server's key leaked alone — does that reveal which device produced which content? | Observational equivalence is true |
| `BM_Validator_Compromise.pv` | Property E | Validator's key leaked alone — same question | Observational equivalence is true |
| `BM_ContentServer_Compromise.pv` | Property F | A content-channel server's key leaked alone — same question | Observational equivalence is true |
| `BM_Posting_Forgery.pv` | Property G | Can anyone other than the validator produce a signature the match board would accept? | `not attacker(v_token_sk)` is true |
| `BM_Registry_Convergence.pv` | Property H | Can one compromised content-channel server alone produce both signatures the registry requires? | `not attacker(i_device_sk)` is true |

## Reading the results

Two different proof techniques are used, and they answer different questions:

- **Observational equivalence** (Properties A–F): the model runs two scenarios side by
  side — e.g., a device authenticating one piece of content versus another — and asks
  whether any adversary, given everything it's allowed to observe or leak in that model,
  can tell which scenario it's in. "True" means it can't: the property holds.
- **Secrecy query, `not attacker(X)`** (Properties G, H): asks whether a specific key
  ever becomes derivable by the adversary. "True" means it never does, which is what
  makes forging a signature without that key infeasible.

## Naming

Each file's key variables follow the paper's own terms, lowercased and with underscores
in place of hyphens (ProVerif identifiers can't contain hyphens): `packethash` for
PacketHash, `v_token_pk`/`v_token_sk` for the validator's keypair, `c_device_pk`/
`c_device_sk` for the gatekeeper server's relay-terminus key, `f_device_sk`/`i_device_sk`
for the two content-channel servers' keys, and `blindshare_key` for BlindShare_key.

Property and file names are otherwise independent of each other by design: a file is
named for what it tests, not for a letter, so that the mapping in the table above is the
only place that pairing needs to be looked up.
