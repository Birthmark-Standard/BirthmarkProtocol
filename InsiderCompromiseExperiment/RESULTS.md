# Insider-compromise results

**Configuration:** the adopted GPA settings (node-wide relay clock, per-channel device phase, F/I
hold on each server's own clock, no CV-1/2 hold, 25 background clients per node), with the Leg
Catalog role rules. Tier 1 ran each scenario at L = 4 for 200 runs. All three scenarios met the
Tier 2 bar, so each also ran at L = 8, 16, 24 and 40 for 200 runs apiece (3,200 runs in total,
plus 200 GPA-anchor runs). Methods are in [`README.md`](README.md); per-row numbers are in
`results/summary.csv`.

## Headline

**A compromised F or I, combined with the network view, links its content to the credential
transaction that produced it, confidently and far above 1/L at every tested L.**
- Accuracy runs from 85% at L = 4 to 33% at L = 40, which is 3.4× to 13× the 1/L baseline.
- At L = 4 and 8, every prediction in the top 10% of score gaps is correct. Hundreds of
  predictions per setting carry a score gap of 2 nats or more.

Two parts drive this result:
- **Identity disclosure.** F and I verify C's signature under each gatekeeper's board record
  (paper §3.3). That tells them which node acted as C, which cuts the candidates to C's own
  validator exchanges. Guessing among those alone scores 50% at L = 4 and 5.4% at L = 40.
- **The insider's own timing.** F's quorum-detection tick, set against the GK legs visible on the
  wire from that C, singles out the right exchange. This multiplies the identity-only accuracy by
  1.7× at L = 4, rising to 6.1× at L = 40. As L grows, the disclosure narrows less and the timing
  carries more of the result.

**Timing on its own stays below 1/L in every scenario.**
- A compromised F or I that ignores the identities reaches 1.5–2.2× the GPA sequencing attack at
  the same L.
- A compromised C reaches 1.8–2.1× it.
- Both are uncalibrated: across all settings, only two predictions carry a score gap of 2 nats.

This combined adversary sits inside the paper's own threat model. A_PRIV (§4.1) has network
monitoring and access to any single system component at the same time. The ProVerif models
operate on a symbolic model with no packet timing (§4.1, Appendix A.5), so they do not cover
this combination.

## What a correct pairing gives the insider

The pairing target is the validator's reply (CV-2) arriving at C. On the wire, that reply comes
from the validator, so a correct pairing tells the insider which validator authenticated the
device behind its content. Validators are the manufacturers (paper §6.2), and in this simulation
the devices are split evenly across four of them.

The device itself remains protected by two things:
- **Token encryption.** Only the validator can open the device token (§3.2).
- **Relay mixing.** Tracing the credential chain back to its first hop fails at the relays, at
  1.4–2.2% per hop in the GPA experiment.

A correct pairing also gives the credential chain's terminal and the C node that processed it.

## F and I compromised

The Monte Carlo model fits both roles, and they produce matching results: F and I are symmetric
roles in the protocol.

- **Full:** everything the node legitimately knows.
- **Identity only:** the full variant's random-assignment baseline over C's candidates.
- **Overlap:** the full variant's accuracy when the compromised node was also one of that
  submission's gatekeepers, against when it was not.
- **Timing only:** no identities.
- **GPA sequencing, same L:** the GPA anchor under the same role rules at L = 4. At other L it is
  the published GPA sweep, which used the stricter distinct-node rule. At L = 4 the two differ by
  0.1 point (9.0% vs 9.1%).

| Role | L | 1/L | **Full** | Identity only | Full: top-decile accuracy | Full: predictions with gap ≥ 2 nats | Full with / without gatekeeper overlap | Timing only | Timing only: random assignment | GPA sequencing, same L |
|---|---|---|---|---|---|---|---|---|---|---|
| F | 4 | 25.0% | **85.6% [83.1–88.2]** | 50.1% | 100.0% | 563 of 773 | 90.8% / 84.6% | 14.6% [12.1–17.2] | 8.4% | 9.0% |
| F | 8 | 12.5% | **75.4% [73.3–77.4]** | 31.9% | 100.0% | 865 of 1,591 | 80.8% / 74.3% | 7.8% [6.6–9.0] | 4.2% | 4.3% |
| F | 16 | 6.2% | **60.1% [58.3–61.8]** | 15.1% | 95.2% | 1,117 of 3,144 | 70.7% / 58.4% | 4.6% [3.8–5.3] | 2.3% | 2.2% |
| F | 24 | 4.2% | **47.9% [46.4–49.6]** | 10.4% | 77.5% | 1,220 of 4,798 | 59.5% / 45.9% | 2.5% [2.0–2.9] | 1.1% | 1.5% |
| F | 40 | 2.5% | **32.6% [31.6–33.6]** | 5.4% | 49.2% | 1,599 of 7,947 | 46.8% / 30.3% | 1.7% [1.4–2.0] | 0.7% | 0.8% |
| I | 4 | 25.0% | **84.9% [82.3–87.5]** | 52.4% | 100.0% | 562 of 776 | 90.2% / 83.9% | 13.8% [11.3–16.3] | 8.1% | 9.0% |
| I | 8 | 12.5% | **76.5% [74.3–78.7]** | 30.7% | 100.0% | 811 of 1,535 | 88.1% / 74.5% | 8.5% [7.2–9.7] | 3.6% | 4.3% |
| I | 16 | 6.2% | **60.3% [58.6–62.1]** | 15.5% | 96.4% | 1,071 of 3,021 | 69.2% / 58.7% | 4.3% [3.6–5.0] | 2.1% | 2.2% |
| I | 24 | 4.2% | **47.6% [46.0–49.0]** | 9.9% | 75.6% | 1,196 of 4,746 | 59.1% / 45.5% | 2.8% [2.3–3.2] | 1.3% | 1.5% |
| I | 40 | 2.5% | **33.2% [32.2–34.2]** | 5.7% | 50.3% | 1,519 of 8,006 | 47.4% / 30.7% | 1.8% [1.5–2.1] | 0.7% | 0.8% |

- **Gatekeeper overlap** (the compromised node is also one of the submission's gatekeepers, 14–17% of items) adds 6 to 17 points. The node then holds C's GK leg directly, with exact timing.
- **Without overlap** the full variant still reaches 30–85%, so the board-record disclosure plus network timing is enough on its own.

## C compromised

C knows its own GK legs, so it computes the quorum time directly, without the gatekeeper lottery.
Its candidates are the registry-gossip bursts of F and I, pooled as in the GPA sequencing attack.
Nothing on the content side is disclosed to C, so C has no identity variant.

| L | 1/L | C compromised | Random assignment | Top-decile accuracy | Predictions with gap ≥ 2 nats | GPA sequencing, same L | GPA perfect-chains bound, same L |
|---|---|---|---|---|---|---|---|
| 4 | 25.0% | 15.9% [13.2–18.6] | 2.8% | 16.5% | 0 | 9.0% | 12.4% |
| 8 | 12.5% | 9.2% [7.8–10.6] | 1.3% | 13.9% | 0 | 4.3% | 6.7% |
| 16 | 6.2% | 4.3% [3.7–4.9] | 0.7% | 4.9% | 0 | 2.2% | 3.5% |
| 24 | 4.2% | 2.7% [2.3–3.2] | 0.4% | 3.8% | 0 | 1.5% | 2.3% |
| 40 | 2.5% | 1.6% [1.3–1.9] | 0.2% | 1.1% | 0 | 0.8% | 1.4% |

A compromised C sits at 1.8–2.1× the GPA sequencing attack. It stays below 1/L at every L, and its
most confident predictions are no more accurate than the rest.

## GPA anchor at L = 4

Under the Leg Catalog role rules on the published seeds, the GPA attacks at L = 4 give:
- main attack: 0.05%;
- sequencing attack: 9.0% [8.6–9.4];
- perfect-chains bound: 12.4%;
- true-terminal bound: 5.4%.

The published sweep (strict role rule) gives 0.10%, 9.1%, 12.2% and 5.8% at the same point. The
role rule does not change the GPA results beyond run-to-run noise.

## Where the signal comes from

Four observations taken together produce the pairing:
1. The board record names C.
2. The GK legs from that C to the posting gatekeepers are visible on the wire, and F knows which
   gatekeepers posted.
3. F knows its own quorum-detection tick exactly.
4. The quorum implied by those GK legs must agree with that tick.

Remove the identities (the timing-only variant) and the result falls below 1/L. The accuracy
comes from the combination: the board-record disclosure, the network view, and the node's own
detection timing.
