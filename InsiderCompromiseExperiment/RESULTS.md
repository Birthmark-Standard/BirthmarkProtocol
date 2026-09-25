# Insider-compromise results

## Configurations

**Adopted configuration: redesign + gatekeeper hold.** The adopted GPA settings (node-wide relay
clock, per-channel device phase, F/I hold on each server's own clock, no CV-1/2 hold, 25
background clients per node), with the Insider Experiment Design changes and the gatekeeper
posting hold:
- the corrected role rules (B3);
- one active set of three gatekeepers per run, never C, F or I (B4);
- C fans out to all three gatekeepers, with a 2-of-3 quorum (B5);
- the ring signature on C's signature (B6);
- each gatekeeper holds C's GK leg in the lottery (10-second ticks, 8.33% release per tick,
  5-minute cap) before countersigning and posting to its match board. Each gatekeeper runs its
  own dedicated hold clock, with its phase drawn once and independently of its relay clock, the
  other gatekeepers' hold clocks, C's fan-out clock and the F/I hold clocks.

**Comparison configurations**, on the same paired seeds:
- **Redesign without the hold:** B3 to B6.
- **Exclusion only:** B3 to B5, with C's plain signature.
- **Fresh-phase check:** the adopted configuration, with a fresh hold phase drawn for every held
  post in place of a dedicated clock per gatekeeper.

Scenarios F, I and C ran at 80, 240 and 400 devices with a 20-minute interval (L = 8, 24, 40),
200 runs per scenario, device count and configuration: 7,200 runs in all.

**Original design.** The first insider run tested the design before the Insider Experiment
Design changes (workbook *Insider Results*; numbers in `results/first_run/`). Its results appear
as a further comparison column at the same L. Methods are in [`README.md`](README.md).

## Headline

**The gatekeeper hold narrows the GK-leg timing search and leaves a residual, so the pathway
stays open.** Under the redesign without the hold, the search is what keeps a compromised F or I
above 1/L. With the hold added:
- **The insider falls below 1/L everywhere.** Every accuracy interval, in every scenario and
  variant at every L, lies below 1/L. The full variant reaches 6.3–6.6% at L = 8 (1/L = 12.5%),
  1.9% at L = 24 (1/L = 4.2%) and 1.2–1.4% at L = 40 (1/L = 2.5%).
- **Combining the search with timing gains nothing measurable.** On paired runs (F and I pooled),
  full minus timing-only is +0.3, −0.1 and 0.0 points at L = 8, 24, 40, and every 95% interval
  contains zero. Under the redesign without the hold, the full variant was 3.0–3.2× timing-only
  at L = 8 and 24.
- **On its own, the search still carries information.** Scored alone (the legs variant: GK legs
  and quorum agreement, no content-arrival timing), it finds the true pairing 2.7–2.9× as often
  as random assignment over the same candidates: 5.1% against 1.8% at L = 8, 1.5% against 0.6%
  at L = 24, 1.0% against 0.4% at L = 40 (F and I pooled). It stays below 1/L and at or below
  timing-only. Since combining it with timing gains nothing, it adds no measurable information to
  timing alone.
- **Calibration collapses.** Top-decile accuracy is 9–13% at L = 8, with intervals that include
  1/L, and about 2% at L = 40. Items with a score gap of 2 nats or more fall from 400–800 per
  scenario to 0–14.

The hold also lowers the timing-only variant (paired, F and I pooled: 1.6, 0.4 and 0.4 points
lower at L = 8, 24, 40, all intervals excluding zero) and a compromised C's attack (8.5% to 4.5%
at L = 8). Both attacks depend on the gap between C's send and the quorum, and the hold adds
independent jitter to that gap.

The outside observer's sequencing attack is essentially unchanged by the hold (4.3%, 1.3% and
0.8% at L = 8, 24, 40) and stays below 1/L.

The dedicated per-gatekeeper clock and the fresh-phase check give the same results: every paired
difference has a 95% interval containing zero.

## The pathway the hold targets: the redesign without the hold

**The redesign without the hold leaves the pairing open.** A compromised F or I links its
content to the credential transaction above 1/L at every tested L:
- 24–25% at L = 8 (1/L = 12.5%);
- 7.3–7.5% at L = 24 (1/L = 4.2%);
- 3.1–3.2% at L = 40 (1/L = 2.5%).

Every 95% interval lies above 1/L. The predictions are partly calibrated. At L = 8, the top 10% of
score gaps is 60% correct against 24% overall, and over 400 predictions per scenario carry a gap
of 2 nats or more.

The remaining signal comes from the GK legs on the wire. Every C sends its three GK legs to
the same three active gatekeepers, and each leg carries C as its sender. A compromised F knows
its own quorum-detection tick exactly. It can search every sender for a set of GK legs whose
implied quorum falls inside its detection window, and that recovers C from timing alone, with no
use of the signature. Scored on its own, the search reaches 22% at L = 8, 6.1–6.2% at L = 24 and
2.5–2.6% at L = 40, close to the full variant. The positive control (lottery off) confirms the
search: it pins over 90% of pairings with the ring signature in place.

**Without the hold, timing alone stays below 1/L in every scenario, and a compromised C stays
below 1/L on every point estimate.** At L = 24, C's interval [3.2–4.4] reaches 1/L (4.2%).

### Against the stated predictions

The stated predictions held for the identity pathway and missed for the result as a whole:
- **The ring signature removes the identity disclosure.** Guessing among the remaining
  candidates falls from 28–29% (exclusion only) to 1.3–1.9% at L = 8, well below 1/L.
- **The full variant stays above the timing-only floor.** It is 3.0–3.2× timing-only at L = 8
  and 24, and 1.8–1.9× at L = 40.

| Prediction (Insider Experiment Design!B9) | Measured |
|---|---|
| The gatekeeper exclusion removes the gatekeeper-overlap contribution. | The exclusion-only full variant sits 12–17 points below the original design's no-overlap items at the same L (for example 60% vs 74% at L = 8). That is more than the overlap itself contributed on average (a 6–17 point gain on the 14–17% of items that had an overlap). The same step also fixes one active gatekeeper set for every transaction, so the posting gatekeepers' identities no longer narrow the GK-leg search, and it applies the corrected role rules. The exclusion-only configuration changes all three at once, so their separate contributions remain unmeasured. |
| The ring signature removes the identity-disclosure contribution. | Confirmed. Guessing among candidates falls from 28–29% to 1.3–1.9% at L = 8, and from 5.4–5.6% to 0.3–0.4% at L = 40. |
| Together, the full variant collapses toward the timing-only floor, under 1/L. | Not met. The redesign's full variant is 1.25–2.0× 1/L and 1.8–3.2× timing-only, through the GK-leg timing search. |

## F and I compromised

### Adopted configuration

Columns:
- **Hold: full:** the headline figure, with its random-assignment baseline.
- **Hold: legs:** the GK-leg search alone (legs and quorum agreement, no content-arrival timing).
- **Redesign:** the redesign without the hold, same variants, on the same seeds.
- **Fresh-phase check:** the full variant with a fresh hold phase per post.

| Role | Devices | L | 1/L | **Hold: full** | Hold full: random assignment | Hold full: top-decile accuracy | Hold full: gap ≥ 2 nats | Hold: legs | Hold legs: random assignment | Hold: timing only | Redesign: full | Redesign: legs | Redesign: timing only | Fresh-phase check: full |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F | 80 | 8 | 12.5% | **6.3% [5.1–7.6]** | 1.7% | 13.0% | 14 of 1,610 | 4.9% [3.9–6.0] | 1.8% | 7.1% [6.0–8.3] | 24.2% | 22.0% | 7.6% | 6.6% [5.6–7.8] |
| F | 240 | 24 | 4.2% | **1.9% [1.6–2.3]** | 0.6% | 3.7% | 3 of 4,877 | 1.6% [1.3–2.0] | 0.5% | 2.1% [1.7–2.5] | 7.5% | 6.1% | 2.4% | 2.3% [1.8–2.7] |
| F | 400 | 40 | 2.5% | **1.2% [1.0–1.5]** | 0.4% | 1.8% | 0 of 7,930 | 1.0% [0.8–1.2] | 0.3% | 1.4% [1.1–1.7] | 3.1% | 2.6% | 1.7% | 1.3% [1.1–1.6] |
| I | 80 | 8 | 12.5% | **6.6% [5.4–7.7]** | 1.8% | 9.4% | 11 of 1,597 | 5.3% [4.2–6.4] | 1.8% | 5.3% [4.1–6.5] | 25.0% | 22.4% | 7.9% | 6.1% [4.9–7.4] |
| I | 240 | 24 | 4.2% | **1.9% [1.6–2.3]** | 0.4% | 3.4% | 3 of 4,754 | 1.5% [1.1–1.8] | 0.6% | 2.0% [1.6–2.4] | 7.3% | 6.2% | 2.5% | 2.3% [1.9–2.7] |
| I | 400 | 40 | 2.5% | **1.4% [1.1–1.6]** | 0.3% | 1.9% | 0 of 8,062 | 1.1% [0.9–1.3] | 0.5% | 1.3% [1.0–1.5] | 3.2% | 2.5% | 1.7% | 1.4% [1.2–1.7] |

### Comparison configurations

Columns:
- **Redesign: full,** with its random-assignment baseline (guessing among candidates).
- **Exclusion only:** the full variant without the ring signature, with its own random baseline.
- **Original design:** the full variant at the same L, overall and for items with no
  gatekeeper overlap.

| Role | Devices | L | 1/L | Redesign: full | Redesign: guessing among candidates | Redesign full: top-decile accuracy | Redesign full: gap ≥ 2 nats | Exclusion only: full | Exclusion only: guessing | Timing only | Original design: full | Original design: full, no overlap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F | 80 | 8 | 12.5% | 24.2% [22.1–26.3] | 1.9% | 59.6% | 435 of 1,610 | 60.2% [57.6–62.6] | 28.3% | 7.6% [6.3–8.9] | 75.4% | 74.3% |
| F | 240 | 24 | 4.2% | 7.5% [6.8–8.3] | 0.7% | 17.6% | 810 of 4,877 | 30.1% [28.9–31.3] | 10.5% | 2.4% [2.0–2.9] | 47.9% | 45.9% |
| F | 400 | 40 | 2.5% | 3.1% [2.7–3.5] | 0.4% | 6.8% | 748 of 7,930 | 18.0% [17.1–18.9] | 5.4% | 1.7% [1.5–2.0] | 32.6% | 30.3% |
| I | 80 | 8 | 12.5% | 25.0% [22.8–27.2] | 1.3% | 59.4% | 443 of 1,597 | 60.0% [57.6–62.3] | 29.1% | 7.9% [6.6–9.2] | 76.5% | 74.5% |
| I | 240 | 24 | 4.2% | 7.3% [6.6–8.0] | 0.6% | 17.6% | 785 of 4,754 | 28.3% [27.2–29.5] | 9.5% | 2.5% [2.0–2.9] | 47.6% | 45.5% |
| I | 400 | 40 | 2.5% | 3.2% [2.8–3.7] | 0.3% | 7.1% | 808 of 8,062 | 18.4% [17.5–19.3] | 5.6% | 1.7% [1.4–2.0] | 33.2% | 30.7% |

Timing-only results are identical under exclusion only and the redesign: the variant uses no
identity, and the runs are paired.

## C compromised

| Devices | L | 1/L | **Hold** | Hold: random assignment | Hold: top-decile accuracy | Fresh-phase check | Redesign | Redesign: random assignment | Redesign: top-decile accuracy | Original design, same L | GPA sequencing, same L |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 80 | 8 | 12.5% | **4.5% [3.5–5.6]** | 1.2% | 4.4% | 4.7% [3.8–5.8] | 8.5% [6.9–10.0] | 1.1% | 8.9% | 9.2% | 4.2% |
| 240 | 24 | 4.2% | **1.3% [1.0–1.6]** | 0.4% | 1.1% | 1.4% [1.1–1.7] | 3.8% [3.2–4.4] | 0.5% | 3.8% | 2.7% | 1.5% |
| 400 | 40 | 2.5% | **0.8% [0.6–1.0]** | 0.2% | 0.8% | 0.9% [0.7–1.1] | 1.8% [1.6–2.2] | 0.3% | 1.8% | 1.6% | 0.8% |

No prediction in any C configuration carries a score gap of 2 nats or more. C's attack uses only
its own GK legs and the registry gossip, so the ring signature does not affect it, and the
exclusion-only results match the redesign within noise. The gatekeeper hold lowers it at every L
(paired differences of 4.0, 2.5 and 1.0 points, all intervals excluding zero), because the quorum
C computes from its own GK legs no longer fixes when the gatekeepers post.

## The outside observer

The ring-signed GK leg travels in its own size class (842–882 B on the wire). The GPA sequencing
attack, on 200 runs per point:

| Devices | L | GPA sequencing, redesign + gatekeeper hold | GPA sequencing, redesign | GPA sequencing, published |
|---|---|---|---|---|
| 80 | 8 | 4.3% [4.1–4.5] | 4.3% [4.1–4.5] | 4.2% |
| 240 | 24 | 1.3% [1.2–1.4] | 1.4% [1.3–1.5] | 1.5% |
| 400 | 40 | 0.8% [0.7–0.8] | 0.8% [0.8–0.9] | 0.8% |

The size class gives the observer with no keys nothing measurable. The gatekeeper hold leaves
the observer's sequencing attack almost where it was: 4.29% with and without the hold at L = 8,
1.39% to 1.30% at L = 24, and 0.82% to 0.77% at L = 40. With and without the hold, the attack
stays below 1/L and above random assignment (1.2%, 0.3% and 0.2% at L = 8, 24, 40), matching the
published GPA results.

## Gatekeeper hold clocks: independence

`python -m insider.clock_check` measures the hold clocks directly on 150 runs at 400 devices
(`results/clock_check.json`). Each phase comparison uses one pair per run, so the samples in each
test are independent. A uniform phase difference across runs means the two clocks are unrelated.

| Check (dedicated per-gatekeeper clock) | Result |
|---|---|
| Posts on their own gatekeeper's hold-clock grid (within gatekeeper processing time) | 100.0% of posts |
| Hold phase against the same gatekeeper's relay clock | uniform, KS p = 0.14 |
| Hold phase between two gatekeepers of the active set | uniform, KS p = 0.53 |
| Hold phase against C's fan-out clock | uniform, KS p = 0.69 |
| Hold phase against F's or I's clock | uniform, KS p = 0.27 |
| Hold lengths of the three gatekeepers within a submission (Spearman p-values over 450 pairs) | uniform, KS p = 0.82 |
| Mean hold | 106 s |

In the fresh-phase check, each gatekeeper's post phases spread uniformly, with no shared grid
(KS p = 0.12 on the per-gatekeeper p-values). Hold lengths within a submission are again
uncorrelated (KS p = 0.14), and the mean hold is 106 s.

## Gatekeeper hold: isolating control

`python -m insider.control` switches every other lottery hold off (relay hops, C fan-out, F/I
hold) and keeps the ring signature, so the two arms differ only in the gatekeeper hold. It runs F
compromised at 40 devices (L = 4), 10 runs, with every node taking a turn as X (807 items per
arm; `results/control.json`).

| Variant | No hold: accuracy | No hold: random assignment | Hold only: accuracy | Hold only: random assignment |
|---|---|---|---|---|
| legs | 78.2% | 79.9% | 20.1% | 8.7% |
| timing | 93.9% | 96.2% | 96.5% | 95.8% |
| full | 96.5% | 79.6% | 97.5% | 9.9% |

The legs row is the isolating comparison. With the lottery off, content-arrival timing alone pins
almost every pairing whether or not the gatekeepers hold, so the timing and full variants stay at
94–98% in both arms and cannot show the hold's effect. The legs variant scores only the GK-leg
search and its quorum agreement.

Without the hold, the search's detection window leaves about one candidate per item: random
assignment is already 79.9%, and the search reaches 78.2%. Adding only the gatekeeper hold forces
the window to cover the hold. Random assignment over that wider window falls to 8.7%, and the
search reaches 20.1%, about 2.3× random. The hold on its own removes most of the pathway and
leaves a residual above random, the same pattern as in the full sweep.

## Device count and L

Every attack here scores pairings of submissions, and its inputs depend on the submission rate
(devices ÷ interval), which is what L tracks. None of these attacks uses the number of devices
per validator. So the coupled sweep (interval fixed, device count varied) measures the pairing
fully. Varying device count and L independently would only matter for identifying the device
within its validator's population, a question outside the scored pairing.
