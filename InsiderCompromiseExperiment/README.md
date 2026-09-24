# Insider-compromise experiment

Does a single compromised network element (F, I or C), holding its own real keys and knowing
its own events exactly, gain a pairing capability beyond what the ProVerif models already rule
out cryptographically?

The build spec is [`Birthmark_Insider_Compromise_Catalog.xlsx`](Birthmark_Insider_Compromise_Catalog.xlsx),
*Insider Experiment Design* tab. Its system tabs (Leg Catalog, Simulation Parameters, Size
Verification) match the GPA experiment's workbook. Results are in [`RESULTS.md`](RESULTS.md).

This is a separate question from the GPA experiment
([`../GPAExperiment/level3/`](../GPAExperiment/level3/)). That experiment's adversary holds no
keys. This one holds one node's keys.

## Layout

| Path | What it is |
|---|---|
| `insider/core.py` | The compromised node's view, the Monte Carlo model, and the F/I and C scenarios |
| `insider/run.py` | Tier 1 and Tier 2 runner (resumable, parallel) |
| `insider/report.py` | Aggregation into `results/summary.json`, `results/summary.csv` and the Tier 2 trigger |
| `tests/test_insider.py` | Role rules, detection-tick placement, model-vs-simulation fit, positive control |

Everything else is imported from `../GPAExperiment/level3/birthmark_l3`:
- the simulator, lottery and clock mechanics, and padding;
- the measured TLS/DNS pools;
- the observation model: signature mask, grid estimation and gossip-origin detection;
- the assignment step, and the calibration and bootstrap code.

## Running

```
pip install -r ../GPAExperiment/level3/requirements.txt
python -m pytest -q tests                  # ~20 s
python -m insider.run --tier 1             # ~4 min on 4 cores
python -m insider.report                   # writes results/tier1_trigger.json
python -m insider.run --tier 2             # only scenarios Tier 1 flagged
python -m insider.report
```

## Configuration

All settings are the adopted GPA settings:
- node-wide relay clock;
- per-channel device phase;
- F/I hold before posting, on each server's own node clock;
- no CV-1/2 hold;
- 25 background clients per node;
- record type read by the observer.

The one difference is the role-assignment rule (`role_rules="catalog"` in the shared
simulator), which follows Leg Catalog K3 as clarified by the protocol owner:
- C, F and I are distinct.
- First hops A, D and G are distinct and never C, F or I (device-table routing), so the
  insider never sees a device IP.
- Each Random hop excludes only its own first hop and destination (B excludes A and C, E excludes
  D and F, H excludes G and I). So F or I can be the B hop on the same submission's credential chain.
- The three gatekeepers are any three nodes. When C is one of them, C posts to its own board with
  no leg on the wire, and that self-signed record does not count toward quorum. F and I then need
  the other two boards.

The published GPA sweep used a stricter rule (nine distinct nodes, C never a gatekeeper).
`gpa_anchor_L4` re-runs the GPA attacks at L = 4 under the catalog rule on the published seeds, so
every comparison here is like for like.

## The adversary

The level3 global passive observer plus one compromised pool node X. X is drawn at random per run.

Roles rotate per submission, so X serves as F for some submissions, as I for others, and as C,
relay or gatekeeper for others. A scenario scores the submissions where X holds that scenario's
role. About 1 in 20 submissions is scored per run: roughly 780 per scenario over 200 runs at L = 4.

The level3 observer already sees exact timestamps on every link. X's exact self-knowledge adds
three things beyond that:
- **Labels for its own events.** Which arrivals at X are its content terminals (as F/I) or its
  credential terminals (as C), and which GK legs it sent (as C).
- **Internal events that never reach the wire.** The quorum-detection poll tick at F/I, and the
  quorum C can compute from the GK legs it sent.
- **Identities it verifies or decrypts.** F and I verify C's signature under each gatekeeper's
  board record (paper §3.3), which identifies the node that acted as C and the gatekeepers that
  posted. When X is also one of the submission's gatekeepers, it receives C's GK leg directly.

X holds no other party's keys and learns no device IP.

Relay-role overlap is simulated, and X holds that knowledge, but no attack feature uses it. A node's
chance of relaying a given credential chain is independent of whether it is F for that submission,
so its own relayed packets say nothing about which chain belongs to its content.

## The attacks

Success criterion and calibration are the GPA experiment's:
- accuracy against 1/L and against random assignment over the same feasible pairs;
- the top-vs-runner-up score gap;
- accuracy in the top 10% of gaps.

**F or I compromised.** Each of X's content items is paired with a credential transaction: a
validator's reply (CV-2) arriving at some C, visible on the wire. Two variants separate the
timing gain from the identity disclosure:
- *timing*: X's quorum-detection tick and content arrival only. It is scored with a Monte Carlo
  likelihood of both, relative to the CV-2 arrival, split by whether detection was the first poll
  after the content arrived.
- *full*: everything X legitimately knows. The candidates are restricted to CV-2 arrivals at the
  node that acted as C. For each candidate, the GK legs from C to the posting gatekeepers are found
  on the wire, or taken directly when X was one of them. Candidates are then scored on the
  hop likelihood of those legs, on whether the quorum they imply agrees with X's own detection
  tick, and on the content-arrival timing. The random-assignment baseline for this variant
  measures the identity disclosure on its own.

**C compromised.** Each of X's credential transactions is paired with the registry-gossip
origination bursts of F and I (the pooled setup of the GPA sequencing attack). The quorum is
computed from X's own GK legs, which removes the gatekeeper lottery from the timing. C learns no
identity on the content side, so the two variants coincide.

The Monte Carlo models come from the shared simulator, run on seeds separate from the
evaluation seeds. `test_model_matches_fresh_simulation` checks the fit.

## Tiers

- **Tier 1:** each scenario at L = 4 (40 devices, 20-minute interval), 200 runs.
- **Tier 2 trigger:** a scenario goes to Tier 2 when either variant's 95% CI lower bound exceeds
  12.2%, the strongest figure the GPA experiment found at L = 4 (its perfect-chains bound). It also
  triggers when predictions are confident: at least one score gap of 2 nats or more, and top-decile
  accuracy with its CI above overall accuracy.
- **Tier 2:** L = 8, 16, 24 and 40 (40/10, 80/10, 120/10 and 200/10), 200 runs each.
