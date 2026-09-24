# Level 3 traffic-analysis experiment

Can a global passive observer, with no compromised nodes, link a device's credential
submission to its content submission from network timing and size alone?

The build spec is `../Birthmark_Traffic_Analysis_Catalog.xlsx`. The copy in this repo is the corrected version: it takes in this experiment's findings and records its outcome on a new *Level 3 Results* tab. The paper
(`../../Docs/Birthmark_Protocol_v58.docx`) was used only to resolve the workbook's section
citations. Results are in [`RESULTS.md`](RESULTS.md).

## Layout

| Path | What it is |
|---|---|
| `birthmark_l3/params.py` | Every numeric input, tagged `[WB cell]`, `[PAPER §]`, `[DECISION]` or `[DEFAULT]` |
| `birthmark_l3/crypto_legs.py` | Byte-exact construction of every Leg Catalog leg with real ECIES / AES-GCM / Ed25519. A test checks it against the corrected Size Verification tab (relay legs 146–235 B, GK 289 B) |
| `birthmark_l3/wire_pools.py` | Wire-size pools measured from real traffic: 360 TLS sessions run through Python `ssl` (OpenSSL 3), 600 DNSSEC-signed EDNS0 responses (dnspython), and Birthmark packets pushed through real TLS 1.3 |
| `birthmark_l3/lottery.py` | The "chance of transit" lottery and the Monte Carlo likelihoods |
| `birthmark_l3/refsim.py` | Reference simulator: a literal discrete-event network. Every node holds packets and rolls the lottery on every tick. Every packet is a real ciphertext, opened and re-sealed hop by hop. The full protocol runs through validator, gatekeepers, boards and registry gossip |
| `birthmark_l3/fastsim.py` | The same process, vectorised so that 3,000 runs are feasible. Tested against `refsim` |
| `birthmark_l3/attack.py` | The observer's attacks (below) |
| `birthmark_l3/sweep.py`, `report.py` | The sweep runner and the aggregation of results |
| `tests/test_level3.py` | Workbook conformance, reference-vs-fast equivalence, positive controls |
| `pools/pools.json` | The measured pools (regenerate with `python -m birthmark_l3.wire_pools`) |
| `results/` | `summary.json`, `summary.csv`, `sweep.png`. Raw per-run output goes in `results/raw/` (not committed) |

## Running

```
pip install -r requirements.txt
python -m pytest -q tests                        # ~1 min
python -m birthmark_l3.sweep --jobs all          # ~70 min on 4 cores; resumable
python -m birthmark_l3.sweep --jobs harden     # optional: sequencing-attack comparisons (~50 min)
python -m birthmark_l3.report
```

## What is simulated

**Network.** The network is a 20-node pool, fully connected. Every node can fill every role (relay, C, F, I, gatekeeper, registry node). There are 4 validators, and devices are split evenly across them. Each submission picks nine distinct nodes for C, F, I, A, B, D, E, G and H. This keeps first hops and intermediaries disjoint across channels (G6) and satisfies the Leg Catalog's exclusion rules. The three gatekeepers are any three nodes other than C.

**Legs.** Every leg in the Leg Catalog is emitted:
- Cred-1/2/3, ContA-1/2/3 and ContB-1/2/3.
- CV-1/CV-2. No lottery hold. A hold here was tested and rejected (Level 3 Experiment Design!B6).
- GK-1/2/3. Each leg is held by its own lottery draw at C.
- Post-1/2/3. These are internal: they appear only as board-post times and never on an observed link.
- Reg-1/Reg-2. F and I post after the adopted lottery hold. The posts appear as gossipsub v1.1 traffic: the origin flood-publishes to every peer, then each node forwards on first receipt to its 6 mesh peers.

**Padding.** Every leg except Reg is padded *to* a target drawn uniformly from 420–460 B, with the padding inside the transit encryption. It then travels as one TLS 1.3 application-data record, which measures at 442–482 B on the wire.

**Lottery.** 10 s ticks, 8.33% release per tick, forced release at tick 30. There is one draw per hop traversed, including the device's own hold before the first hop.

**Background.** 25 clients per node (500 total). 90% are casual: one transaction, then a pause of U[1, 60] s. 10% are high-frequency: back-to-back request/response on a persistent connection. 80% of their transactions replay a real TLS session from the pool, and 20% are DNS lookups the contacted node makes. 20% of clients are other pool nodes, representing server-to-server traffic.

**Non-blending traffic.** Large bulk transfers of about 1 MB (median), carried as maximum-size 16,406 B records, in both external↔node and node↔node directions. Also HTTP/2-PING-sized keepalives (39 B) on every persistent connection.

## Decisions settled with the experiment owner

| Question | Decision |
|---|---|
| Whose clock do the 10 s ticks follow? | **Node-wide clock** with a random phase per node, so a release carries no trace of the packet's arrival phase. This is now the spec: Level 3 Experiment Design!B13. A per-packet-timer probe measures the phase leak it avoids. |
| Device-side clock | **Independent, freshly drawn random phase per channel** (Level 3 Experiment Design!B4, B13). A probe with one shared device clock measures the leak this avoids. |
| Is the observer told which arrivals are terminal? | **No oracle.** The observer sees (link, time, size) and must discover chains itself: Stage 1 reconstructs 3-hop chains, and Stage 2 groups them by origin time. |
| TLS record type / protocol | **The observer reads it** in the sweep, because a real GPA can. Blend-in is also reported with it ignored. |
| External sources | **All ingress is anonymised.** Devices and background clients both appear as "external → node". Device IPs are used only in the separate origin-anchored section. |
| Background volume | 25 clients per node. Sensitivity checked at 0, 5 and 100. |
| When do F and I post to the registry? | They poll the boards on their own 10 s tick. Once 2-of-3 have posted and their content has arrived, each **holds the posting in the lottery on its own node clock**, and F's and I's clocks are independent of each other. This is **adopted** (Level 3 Experiment Design!B6, B13; Leg Catalog K26/K27). The polling interval itself is still an assumption. |
| Hold at CV-1/2? | **No. Rejected** (Level 3 Experiment Design!B6): a hold there strengthens the sequencing signal. It is kept only as a labelled comparison. |
| Real TLS | Byte sizes come from real `ssl` output. Timing is virtual. The pools are diverse (360 distinct session size signatures, 48 distinct ClientHello sizes, 252 distinct DNS response sizes), not one canonical capture reused. |

## Flagged defaults (not in the workbook)

Latencies:
- One-way external↔node: U[10, 120] ms.
- Node↔node: U[5, 80] ms.
- Per-packet jitter: exponential, mean 2 ms.
- Processing: U[0.5, 3] ms.

Other defaults:
- Validator processing: U[5, 50] ms. Gatekeeper verify-and-post: U[1, 10] ms.
- gossipsub envelope: about 168 B.
- Bulk and keepalive rates: see `params.py`.
- Run window: 20 min warm-up, then 40 min in which submissions are scored, then 30 min cooldown.
- The Little's-law L column is used as printed. The lottery's actual mean hold is 111 s, not the 120 s behind the table.

## The attacks

All of them use `scipy.optimize.linear_sum_assignment` and Monte Carlo likelihoods of the lottery process, built under the same clock model the system runs.

**Stage 1: per-hop matching.**
- The observer first estimates each node's release grid from the phase of its relay-class departures. With a node-wide clock the grid is recovered to within about 1 ms.
- At each node, departures are matched to arrivals by hop log-likelihood ratio.
- The hop positions this matching implies (ingress = 1; a departure matched to a validator's reply = gatekeeper leg) are fed back. That rules out forwarding an arrival that must be terminal. The matching is then re-solved until it is stable.
- A departure from a node with no detected grid may stay unmatched, if nothing beats chance.

**Stage 2: grouping by origin time.**
- Credential chains are recognised from the traffic itself: C contacts a validator milliseconds after the chain terminates.
- The other complete chains are pooled as content candidates.
- Credential and content chains are paired by the likelihood of their origin-time difference.
- A pairing succeeds when the credential chain's terminal (Cred-3) is paired with the same submission's ContA-3 or ContB-3.

**Sequencing attack.** CV-2 arrivals at C are paired with registry-gossip origination bursts (detected as flood-publish bursts). The score is the likelihood of the delay from quorum formation, through the board poll, to the post.

**Origin-anchored trace (separate section).** Uses the same Stage 1 matching, but starts from each device's IP-visible first hops.

**Baselines and bounds.**
- **1/L**: as specified in the workbook.
- **Empirical chance**: the same assignment step run on random scores over the same feasible pairs.
- **Two diagnostic bounds**. These are not attacks, because they use ground truth the observer lacks:
  - *perfect chains*: Stage 2 given the true chains.
  - *true terminal labels*: the workbook's original terminal-timing attack.

**Calibration.** For each prediction, the gap between the top and runner-up scores. Reported as accuracy in the top 10% of gaps and at fixed gaps (≥ 1, 2 and 3 nats), plus a reliability table of the attacker's own posterior.

**Sequencing-attack comparisons.** The adopted F/I hold is the default. The `harden_*` jobs run only the sequencing attack across the sweep, with every flag pinned so their results keep their meaning:
- `none`: no hold anywhere. This is the original protocol, and the "before" comparison.
- `cv`: CV-1/2 hold only. Tested and rejected.
- `both`: the F/I hold plus the CV-1/2 hold.
- `fresh`: the F/I hold with a new random phase per posting, which checks the clock wording.

The attacker's model is rebuilt for each variant. See RESULTS.md.
