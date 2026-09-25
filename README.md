# Birthmark Protocol

The Birthmark Protocol is a two-channel provenance architecture for media authentication. It separates a capture device's credential from its content's identifying hash across disjoint delivery paths and encryption boundaries, so that no single component's compromise (including the credential validator's) is sufficient to determine which device produced which content. Correlation requires coordinated compromise across multiple components.

The architecture formalizes the privacy property this separation targets as Semantic Non-Assembly (SNA): a structural privacy property, built from established separation and information-hiding strategies but given a precise, executable threshold, characterized by the information yield of component exposure rather than the difficulty of achieving it. Full definitions, the threat model, and the formal privacy properties are in the paper (see Citation, below).

## Repository contents

- `ProverifModels/`: the ProVerif formal verification models establishing the protocol's privacy and integrity properties, with a README indexing what each model tests and how to run it.
- `GPAExperiment/level3/`: an empirical evaluation of traffic-analysis resistance against a passive network observer holding no cryptographic keys. Complements the formal models, which do not reason about timing or packet size.
- `InsiderCompromiseExperiment/`: an empirical evaluation of the same question against a different adversary: a single compromised network element holding its own real keys and exact knowledge of its own event timing. Tests a combination the threat model permits (network monitoring together with single-component key access) that the formal models, being timing-blind, cannot evaluate on their own.

This repository holds the protocol's formal architecture, its formal verification artifacts, and its empirical evaluations. The formal models establish what no coalition of compromised components can do cryptographically. The empirical experiments measure what a passive or key-holding observer can do statistically, a different kind of question the formal models are not built to answer. The reference deployment for photographic media (the Birthmark Standard) is documented separately; the protocol here is deployment-agnostic and does not assume any particular capture hardware or media type.

## Citation

Sam Ryan. "The Birthmark Protocol: Achieving Semantic Non-Assembly in Media Provenance."

[Full venue, date, and DOI/arXiv identifier to be added once available. The paper is currently in peer review. This repository's formal verification artifacts (`ProverifModels/`) and empirical evaluations (`GPAExperiment/`, `InsiderCompromiseExperiment/`) are complete and citable independent of that process.]

## License

Released under Apache 2.0. This work is published as prior art: the architecture and its verification are intended as public infrastructure, open for anyone to build on, rather than a position any single organization can enclose.

## Status

The formal properties in `ProverifModels/` are stable and independently verifiable with ProVerif. The empirical evaluations in `GPAExperiment/` and `InsiderCompromiseExperiment/` are complete. Their results are measured and reported directly in each experiment's `RESULTS.md`, including residual findings that remain open. The paper itself may still change during peer review; this repository is updated to stay consistent with whatever the current version claims.
