# Insider-compromise experiment

Does a single compromised network element (F, I or C), holding its own real keys and knowing
its own events exactly, gain a pairing capability beyond what the ProVerif models already rule
out cryptographically?

The build spec is [`Birthmark_Insider_Compromise_Catalog.xlsx`](Birthmark_Insider_Compromise_Catalog.xlsx).
Its *Insider Experiment Design* tab specifies the design changes tested here (B3 to B7). Its
*Insider Results* tab records the original design, before those changes (numbers in
`results/first_run/`); the results use it as a comparison point at the same L. The system tabs
(Leg Catalog, Simulation Parameters, Size Verification) match the GPA experiment's workbook.
Results are in [`RESULTS.md`](RESULTS.md).

The GPA experiment ([`../GPAExperiment/level3/`](../GPAExperiment/level3/)) tests an adversary
with no keys. This one holds one node's keys.

## Layout

| Path | What it is |
|---|---|
| `insider/core.py` | The compromised node's view, the Monte Carlo model, and the F/I and C scenarios |
| `insider/run.py` | The sweep runner (resumable, parallel, paired seeds across configurations) |
| `insider/report.py` | Aggregation into `results/summary.json` and `results/summary.csv` |
| `insider/gpa_check.py` | The outside observer's sequencing attack under the redesign, with and without the gatekeeper hold |
| `insider/clock_check.py` | Direct measurement that the gatekeeper hold clocks are independent |
| `insider/control.py` | Isolating control for the gatekeeper hold (every other lottery hold off) |
| `tests/test_insider.py` | Role rules, gatekeeper exclusion, ring signature, model fit, positive controls, hold clock independence |

The shared code lives in `../GPAExperiment/level3/birthmark_l3`, and this experiment imports it:
- the simulator, lottery and clock mechanics, and padding;
- the measured TLS/DNS pools;
- the observation model;
- the assignment, calibration and bootstrap code;
- the ring signature (`ring_sig.py`).

## Running

```
pip install -r ../GPAExperiment/level3/requirements.txt
python -m pytest -q tests                  # ~45 s
python -m insider.run                      # ~2 h on 4 cores (four configurations)
python -m insider.gpa_check                # ~3 min per configuration
python -m insider.clock_check
python -m insider.control
python -m insider.report
```

## Configuration

These are the adopted GPA settings:
- node-wide relay clock;
- per-channel device phase;
- F/I hold before posting, on each server's own node clock;
- no CV-1/2 hold;
- 25 background clients per node;
- record type read by the observer.

On top of those come the Insider Experiment Design changes (`role_rules="insider_v2"` in the
shared simulator) and the gatekeeper posting hold:
- **Gatekeepers (B4, B5).** One active set of three gatekeepers per run, used by every
  submission. The rotation period is not specified; one set per 90-minute run treats rotation as
  slower than a run. C fans out to all three, and quorum is 2 of 3.
- **Role pools (B3, B4).** C, F and I are distinct and drawn from the 17 nodes outside the
  gatekeeper set. First hops A, D and G are distinct and never C, F or I (device-table routing),
  so no insider in these roles sees a device IP. Gatekeepers remain eligible for relay hops.
- **Random hops (B3).** B is never A, E is never D, and H is never G. B, E and H may coincide with
  C, F and I. When they do, the hop holds in the lottery as usual and delivers locally, with no leg
  on the wire. The insider does not use that coincidence (B3).
- **Ring signature (B6).** `ring_sig=True` makes C's signature an Abe–Ohkubo–Suzuki
  1-out-of-n Schnorr ring signature over the 17-node C-candidate pool. It is built on libsodium's
  Ed25519 group operations via PyNaCl, and is unlinkable (no key image). Verifiers learn that a pool
  member signed, and not which one. The signature is 576 B, so the GK leg grows to 801 B raw (measured
  with real keys). It is padded in its own size class, 820–860 B, which is 842–882 B on the wire;
  every other leg keeps 420–460 B. The gatekeepers' countersignatures are unchanged.
- **Gatekeeper posting hold.** `gk_hold="gatekeeper"` makes each gatekeeper hold C's GK leg in
  the lottery (10-second ticks, 8.33% release per tick, 5-minute cap) before countersigning and
  posting to its own match board. Each gatekeeper has a dedicated hold clock whose phase is drawn
  once per run, independently of its relay clock, the other gatekeepers' hold clocks, C's fan-out
  clock and the F/I hold clocks. `gk_hold="fresh"` draws a new phase for every held post instead.
  The hold is governed by this setting alone, so it stays on when the rest of the lottery is off.

## Configurations and sweep

The adopted configuration:
- **Redesign + gatekeeper hold** (`ring_sig=True, gk_hold="gatekeeper"`): B3 to B6 plus the hold.

Comparison configurations:
- **Redesign** (`ring_sig=True`): B3 to B6, without the hold.
- **Exclusion only** (`ring_sig=False`): B3 to B5, with C's plain signature.
- **Fresh-phase check** (`ring_sig=True, gk_hold="fresh"`): the hold with a new phase per post.

Each configuration runs scenarios F, I and C at 80, 240 and 400 devices, with the interval held at
20 minutes (L = 8, 24, 40; B7). That is 200 runs per cell, on seeds paired across all
configurations.

Comparison points share L, and so submission rate:

| This experiment | Original design | Published GPA |
|---|---|---|
| 80 devices | 40/10 | `main_80_20` (the same point) |
| 240 devices | 120/10 | 120/10 |
| 400 devices | 200/10 | 200/10 |

## The adversary

The adversary is the level3 global passive observer plus one compromised pool node X, drawn at
random per run. Roles rotate per submission, so a scenario scores the submissions where X holds
that scenario's role. The gatekeeper exclusion means X is never a gatekeeper in a scored
submission.

The level3 observer already sees exact timestamps on every link. Beyond that, X adds:
- **Labels for its own events.** Its content terminals (as F/I), its credential terminals and the
  GK legs it sent (as C).
- **Internal events.** The quorum-detection poll tick at F/I, and the quorum C computes from its own
  GK legs.
- **What the board records show F/I.** The posting gatekeepers, which are the public active set,
  and, without the ring signature, the node that acted as C.

## The attacks

Success criterion and calibration are the GPA experiment's:
- accuracy against 1/L and against random assignment over the same feasible pairs;
- the top-vs-runner-up score gap;
- accuracy in the top 10% of gaps.

**F or I compromised.** Each of X's content items is paired with a credential transaction (a
validator's reply arriving at some C):
- *timing*: X's quorum-detection tick and content arrival, scored against every validator reply
  with a Monte Carlo likelihood.
- *full*: everything X knows. Without the ring signature, candidates are C's own validator
  replies. With it, C is unknown, so every candidate's sender is searched for GK legs to the three
  active gatekeepers. The quorum those legs imply must agree with X's own detection tick. Candidates
  are scored on the legs' hop likelihood, on that agreement, and on content-arrival timing. The
  random-assignment baseline of this variant measures what the identity disclosure gives on its own.
  When the gatekeepers hold, the quorum those legs imply is uncertain, so agreement is scored as
  the Monte Carlo probability that the held quorum falls in X's detection window.
- *legs*: the GK-leg search and the quorum agreement alone, without content-arrival timing. It
  isolates the leg pathway.

**C compromised.** Each of X's credential transactions is paired with the registry-gossip bursts
of F and I, with the quorum computed from X's own GK legs.

The Monte Carlo models come from the shared simulator, built under the same configuration as the
system being evaluated, on seeds disjoint from the evaluation seeds. Each bootstrap interval is
seeded by its own cell name, so intervals do not depend on which configurations are aggregated.
