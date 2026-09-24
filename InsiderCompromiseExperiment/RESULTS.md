# Insider-compromise results (corrected design)

**Configuration:** the adopted GPA settings (node-wide relay clock, per-channel device phase, F/I
hold on each server's own clock, no CV-1/2 hold, 25 background clients per node) with the
Insider Experiment Design changes:
- the corrected role rules (B3);
- one active set of three gatekeepers per run, never C, F or I (B4);
- C fans out to all three gatekeepers, with a 2-of-3 quorum (B5);
- the ring signature on C's signature (B6).

Scenarios F, I and C ran at 80, 240 and 400 devices with a 20-minute interval (L = 8, 24, 40),
200 runs each. Each ran twice on paired seeds:
- **Exclusion only:** B3 to B5, with C's plain signature.
- **Redesign:** B3 to B6, adding the ring signature.

That is 3,600 runs. The first run's results (workbook *Insider Results*; numbers in
`results/first_run/`) are the baseline. Methods are in [`README.md`](README.md).

## Headline

**The redesign does not close the pairing.** Under the full redesign, a compromised F or I still
links its content to the credential transaction above 1/L at every tested L:
- 24–25% at L = 8 (1/L = 12.5%);
- 7.3–7.5% at L = 24 (1/L = 4.2%);
- 3.1–3.2% at L = 40 (1/L = 2.5%).

Every 95% interval lies above 1/L. The predictions are partly calibrated. At L = 8, the top 10% of
score gaps is 60% correct against 24% overall, and over 400 predictions per scenario carry a gap
of 2 nats or more.

The stated prediction held for the identity pathway and missed for the result as a whole:
- **The ring signature removes the identity disclosure.** Guessing among the remaining
  candidates falls from 28–29% (exclusion only) to 1.3–1.9% at L = 8, well below 1/L.
- **The full variant does not collapse to the timing-only floor.** It stays 3.0–3.2× above
  timing-only at L = 8 and 24, and 1.8–1.9× at L = 40.

The remaining signal comes from the GK legs on the wire. Every C sends its three GK legs to
the same three active gatekeepers, and each leg carries C as its sender. A compromised F knows
its own quorum-detection tick exactly. It can search every sender for a set of GK legs whose
implied quorum falls inside its detection window, and that recovers C by timing instead of by
signature. The positive control (lottery off) confirms the search: it pins over 90% of pairings
with the ring signature in place.

**Timing alone stays below 1/L in every scenario, and a compromised C stays below 1/L on
every point estimate.** At L = 24, C's interval [3.2–4.3] reaches 1/L (4.2%).

## F and I compromised

Columns:
- **Redesign: full:** the headline figure.
- **Redesign: guessing among candidates:** the full variant's random-assignment baseline.
- **Exclusion only:** the full variant without the ring signature, with its own random baseline.
- **First run:** the first run's full variant at the same L, overall and for items with no
  gatekeeper overlap.

| Role | Devices | L | 1/L | **Redesign: full** | Redesign: guessing among candidates | Redesign full: top-decile accuracy | Redesign full: gap ≥ 2 nats | Exclusion only: full | Exclusion only: guessing | Timing only | First run: full | First run: full, no overlap |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F | 80 | 8 | 12.5% | **24.2% [22.2–26.2]** | 1.9% | 59.6% | 435 of 1,610 | 60.2% [57.8–62.7] | 28.3% | 7.6% [6.3–8.9] | 75.4% | 74.3% |
| F | 240 | 24 | 4.2% | **7.5% [6.8–8.3]** | 0.7% | 17.6% | 810 of 4,877 | 30.1% [28.9–31.3] | 10.5% | 2.4% [2.0–2.9] | 47.9% | 45.9% |
| F | 400 | 40 | 2.5% | **3.1% [2.7–3.5]** | 0.4% | 6.8% | 748 of 7,930 | 18.0% [17.1–19.0] | 5.4% | 1.7% [1.5–2.0] | 32.6% | 30.3% |
| I | 80 | 8 | 12.5% | **25.0% [22.9–27.3]** | 1.3% | 59.4% | 443 of 1,597 | 60.0% [57.4–62.3] | 29.1% | 7.9% [6.6–9.2] | 76.5% | 74.5% |
| I | 240 | 24 | 4.2% | **7.3% [6.7–8.0]** | 0.6% | 17.6% | 785 of 4,754 | 28.3% [27.1–29.5] | 9.5% | 2.5% [2.0–2.9] | 47.6% | 45.5% |
| I | 400 | 40 | 2.5% | **3.2% [2.8–3.6]** | 0.3% | 7.1% | 808 of 8,062 | 18.4% [17.5–19.3] | 5.6% | 1.7% [1.5–2.0] | 33.2% | 30.7% |

Timing-only results are identical in both configurations: the variant uses no identity, and the
runs are paired.

## Against the stated predictions

| Prediction (Insider Experiment Design!B9) | Measured |
|---|---|
| The gatekeeper exclusion removes the gatekeeper-overlap contribution. | The exclusion-only full variant sits 12–17 points below the first run's no-overlap items at the same L (for example 60% vs 74% at L = 8). That is more than the overlap itself contributed on average (a 6–17 point gain on the 14–17% of items that had an overlap). The same step also fixes one active gatekeeper set for every transaction, so the posting gatekeepers' identities no longer narrow the GK-leg search, and it applies the corrected role rules. This run does not separate those three effects. |
| The ring signature removes the identity-disclosure contribution. | Confirmed. Guessing among candidates falls from 28–29% to 1.3–1.9% at L = 8, and from 5.4–5.6% to 0.3–0.4% at L = 40. |
| Together, the full variant collapses toward the timing-only floor, under 1/L. | Not met. The redesign's full variant is 1.25–2.0× 1/L and 1.8–3.2× timing-only, through the GK-leg timing search. |

## C compromised

| Devices | L | 1/L | Redesign | Random assignment | Top-decile accuracy | Gap ≥ 2 nats | First run, same L | GPA sequencing, same L |
|---|---|---|---|---|---|---|---|---|
| 80 | 8 | 12.5% | 8.5% [7.0–10.0] | 1.1% | 8.9% | 0 | 9.2% | 4.2% |
| 240 | 24 | 4.2% | 3.8% [3.2–4.3] | 0.5% | 3.8% | 0 | 2.7% | 1.5% |
| 400 | 40 | 2.5% | 1.8% [1.5–2.2] | 0.3% | 1.8% | 0 | 1.6% | 0.8% |

C's attack uses only its own GK legs and the registry gossip, so the ring signature does not
affect it. The exclusion-only results match within noise.

## The outside observer under the redesign

The ring-signed GK leg travels in its own size class (842–882 B on the wire). The GPA sequencing
attack under the redesign, on 200 runs per point:

| Devices | L | GPA sequencing, redesign | GPA sequencing, published |
|---|---|---|---|
| 80 | 8 | 4.3% [4.1–4.5] | 4.2% |
| 240 | 24 | 1.4% [1.3–1.5] | 1.5% |
| 400 | 40 | 0.8% [0.8–0.9] | 0.8% |

The size class gives the observer with no keys nothing measurable.

## Device count and L

Every attack here scores pairings of submissions, and its inputs depend on the submission rate
(devices ÷ interval), which is what L tracks. None of these attacks uses the number of devices
per validator. So the coupled sweep (interval fixed, device count varied) measures the pairing
fully. Varying device count and L independently would only matter for a question about
identifying the device within its validator's population, which this experiment does not score.
