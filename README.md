# Birthmark Protocol

The Birthmark Protocol is a two-channel provenance architecture for media authentication.
It separates a capture device's credential from its content's identifying hash across
disjoint delivery paths and encryption boundaries, so that no single component's
compromise — including the credential validator's — is sufficient to determine which
device produced which content. Correlation requires coordinated compromise across
components, not just one.

The architecture formalizes the privacy property this separation targets as **Semantic
Non-Assembly (SNA)**: a class of privacy guarantee characterized by the information yield
of component exposure, not the difficulty of achieving it. Full definitions, the threat
model, and the formal privacy properties are in the paper (see Citation, below).

## Repository contents

- **`ProverifModels/`** — the ProVerif formal verification models establishing the
  protocol's privacy and integrity properties, with a README indexing what each model
  tests and how to run it.

This repository holds the protocol's formal architecture and its verification artifacts.
The reference deployment for photographic media — the Birthmark Standard — is
documented separately; the protocol here is deployment-agnostic and does not assume any
particular capture hardware or media type.

## Citation

Sam Ryan. "The Birthmark Protocol: Achieving Semantic Non-Assembly in Media
Provenance."

*[Full venue, date, and DOI/arXiv identifier to be added once available. The paper is
currently in peer review; this repository's formal verification artifacts are already
final and citable independent of that process.]*

## License

Released under Apache 2.0. This work is published as prior art: the architecture and its
formal verification are intended as public infrastructure, open for anyone to build on,
rather than a position any single organization can enclose.

## Status

Active. The formal properties in `ProverifModels/` are stable and independently
verifiable with ProVerif. The paper itself may still change during peer review;
this repository is updated to stay consistent with whatever the current version claims.
