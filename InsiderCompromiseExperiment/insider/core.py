"""The compromised insider's view and attacks.

The adversary is the level3 global passive observer plus one compromised pool node X. X holds
its own keys and knows its own events exactly. Roles rotate per submission, so X serves as F
for some submissions, I for others, C for others, and as relay or gatekeeper for more. A
scenario ("F", "I" or "C") scores the submissions where X holds that role.

What X adds to the level3 observer's view:
  * labels for its own events: which arrivals at X are its content terminals (as F/I) or its
    credential terminals (as C), and which GK legs it sent (as C);
  * internal events that never reach the wire: the quorum-detection poll tick (as F/I), and
    the gatekeeper legs it sent together with the quorum they imply (as C);
  * identities it decrypts or verifies: as F/I, the board records show which node acted as C
    (C's signature under each gatekeeper record, paper §3.3) and which gatekeepers posted; as a
    gatekeeper for the same submission, it receives C's GK leg itself.
It never learns a device IP (first-hop ingress stays anonymised) and holds no other party's
keys.

Two variants per F/I scenario, so the timing gain is separated from the identity disclosure:
  timing  own-event timing only (content arrival, detection tick), no identities
  full    everything X legitimately knows, including C and gatekeeper identities and, when X is
          also a gatekeeper for the same submission, the GK leg it received
For C, no identity about the content side is disclosed to C, so the two variants coincide.

The likelihoods are Monte-Carlo estimates built by running the shared simulator itself on
seeds disjoint from the evaluation seeds.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from . import LEVEL3  # noqa: F401  (puts birthmark_l3 on the path)
from birthmark_l3 import attack as A
from birthmark_l3 import fastsim as FS
from birthmark_l3 import lottery as LT
from birthmark_l3 import params as P
from birthmark_l3.wire_pools import Pools

GK_PROC_MEAN_S = sum(P.GATEKEEPER_PROC_MS) / 2 / 1000
INCONSISTENT = -30.0       # log-penalty when a candidate contradicts X's own detection tick


def adopted_config(devices: int, interval_min: float, **kw) -> P.Config:
    """Adopted GPA settings (node clock, per-channel device phase, F/I hold, no CV hold,
    25 background clients per node) with the Leg Catalog role rules."""
    return P.Config(devices=devices, interval_min=interval_min, role_rules="catalog", **kw)


# =========================================================================== MC model
@dataclass
class InsiderModel:
    # F/I: detection tick and content arrival, relative to the CV-2 arrival at C
    p_cens: float
    d1_unc: LT.EmpiricalLogPDF      # detection - cv2, content arrived before the previous poll
    d2_unc: LT.EmpiricalLogPDF      # arrival - cv2, same case
    d2_cens: LT.EmpiricalLogPDF     # arrival - cv2, detection was the first poll after arrival
    # C: registry-gossip origin relative to the quorum C can compute from its own GK legs
    seq_c: LT.EmpiricalLogPDF
    d_max: float
    seq_max: float


def _content_features(run, role):
    s, ev, ph = run.subs, run.events, run.phase
    node = s[role]
    arr, det = s["arr_f" if role == "F" else "arr_i"], s["det_f" if role == "F" else "det_i"]
    cv2 = ev["t_arr"][s["ev_cv2"]]
    cens = np.abs(det - LT.next_tick(arr, ph[node])) < 1e-6
    return det - cv2, arr - cv2, cens


def quorum_from_legs(run):
    """Quorum as C can compute it from its own GK legs (arrival + mean gatekeeper processing).
    A self-signed record (C as its own gatekeeper) does not count."""
    s, ev = run.subs, run.events
    ids = s["ev_gk"]
    t = np.where(ids >= 0, ev["t_arr"][np.maximum(ids, 0)] + GK_PROC_MEAN_S, np.inf)
    return np.sort(t, axis=1)[:, 1]


def build_model(pools: Pools, n_runs=40, seed0=900_000) -> InsiderModel:
    d1u, d2u, d2c, seqc, nc, nt = [], [], [], [], 0, 0
    for k in range(n_runs):
        cfg = adopted_config(200, 10, bg_clients_per_node=0, nonblending_enabled=False)
        run = FS.simulate(cfg, seed0 + k, pools)
        for role in ("F", "I"):
            d1, d2, cens = _content_features(run, role)
            d1u.append(d1[~cens]); d2u.append(d2[~cens]); d2c.append(d2[cens])
            nc += int(cens.sum()); nt += cens.size
        q = quorum_from_legs(run)
        ev, s = run.events, run.subs
        for key in ("ev_reg_f", "ev_reg_i"):
            seqc.append(ev["t_send"][s[key]] - q)
    cat = np.concatenate
    d1u, d2u, d2c, seqc = cat(d1u), cat(d2u), cat(d2c), cat(seqc)
    return InsiderModel(
        p_cens=nc / nt,
        d1_unc=LT.EmpiricalLogPDF(d1u, 0.5), d2_unc=LT.EmpiricalLogPDF(d2u, 2.0),
        d2_cens=LT.EmpiricalLogPDF(d2c, 2.0), seq_c=LT.EmpiricalLogPDF(seqc, 0.5),
        d_max=float(max(np.abs(d2u).max(), np.abs(d2c).max(), d1u.max())) + 5.0,
        seq_max=float(seqc.max()) + 5.0)


# =========================================================================== helpers
def _scored_mask(run, subs_idx):
    t0 = run.subs["t0"][subs_idx]
    return (t0 >= P.WARMUP_S) & (t0 < P.WARMUP_S + P.MEASURE_S)


def _evaluate(W, row_sub, col_sub, scored, rng):
    col, gap, post = A.assign(W)
    ok = (col >= 0) & (col_sub[np.maximum(col, 0)] == row_sub)
    Wr = np.where(np.isfinite(W), rng.random(W.shape), -np.inf)
    colr, _, _ = A.assign(Wr)
    okr = (colr >= 0) & (col_sub[np.maximum(colr, 0)] == row_sub)
    feas = np.isfinite(W).sum(1)
    return dict(correct=ok[scored].astype(np.int8), gap=gap[scored].astype(np.float32),
                post=post[scored].astype(np.float32), chance=int(okr[scored].sum()),
                feasible=feas[scored].astype(np.int32))


def _cv2_events(ev, sig):
    src, dst = ev["src"].astype(int), ev["dst"].astype(int)
    return np.nonzero(sig & (src >= FS.VAL0) & (src < FS.VAL0 + P.N_VALIDATORS) & (dst < P.N_NODES))[0]


# =========================================================================== F / I scenario
def content_scenario(run, pools, lik, model: InsiderModel, role: str, X: int, rng):
    """X serves as F (or I) for some submissions. Pair each of X's content items with the
    credential transaction (the validator reply at C) that produced it."""
    s, ev = run.subs, run.events
    items = np.nonzero(s[role] == X)[0]
    scored = _scored_mask(run, items)
    sig = A.signature_mask(ev, run.cfg.attacker_reads_record_type, pools.tls13_overhead)
    cols = _cv2_events(ev, sig)
    t_v, c_node, col_sub = ev["t_arr"][cols], ev["dst"][cols].astype(int), ev["sub"][cols]
    arr = s["arr_f" if role == "F" else "arr_i"][items]
    det = s["det_f" if role == "F" else "det_i"][items]
    cens = np.abs(det - LT.next_tick(arr, run.phase[X])) < 1e-6

    # ---- timing variant: X's own detection tick and content arrival, nothing else
    d1 = det[:, None] - t_v[None, :]
    d2 = arr[:, None] - t_v[None, :]
    lu = np.log(1 - model.p_cens) + model.d1_unc(d1) + model.d2_unc(d2)
    lc = np.log(model.p_cens) + model.d2_cens(d2)
    W_t = np.where(cens[:, None], lc, lu)
    W_t = np.where((d1 > 0) & np.isfinite(W_t), W_t, -np.inf)

    # ---- full variant: + C and gatekeeper identities from the board records, + own GK leg
    W_f = np.full_like(W_t, -np.inf)
    src, dst = ev["src"].astype(int), ev["dst"].astype(int)
    overlap = np.zeros(items.size, bool)
    for r, sidx in enumerate(items):
        C = int(s["C"][sidx])
        gks = [int(g) for g, v in zip(s["gk"][sidx], s["gk_valid"][sidx]) if v]
        own_leg = None
        if X in gks:
            overlap[r] = True
            j = int(np.nonzero(s["gk"][sidx] == X)[0][0])
            own_leg = int(s["ev_gk"][sidx, j])
        cand = np.nonzero((c_node == C) & (d1[r] > 0))[0]
        legs = {g: np.nonzero(sig & (src == C) & (dst == g))[0] for g in gks}
        for ci in cand:
            tv, total, arrivals, ok = t_v[ci], 0.0, [], True
            for g in gks:
                e = np.array([own_leg]) if (g == X and own_leg is not None) else legs[g]
                dd = ev["t_send"][e] - tv
                w = np.where((dd > 0) & (dd < lik.hop_max), lik.hop(np.clip(dd, 0, lik.hop_max)), -np.inf)
                if not np.isfinite(w).any():
                    ok = False
                    break
                b = int(np.argmax(w))
                total += w[b]
                arrivals.append(ev["t_arr"][e[b]] + GK_PROC_MEAN_S)
            if not ok:
                continue
            q = sorted(arrivals)[1]
            tol = 0.006
            consistent = (q <= det[r] + tol) and (cens[r] or q > det[r] - P.TICK_S - tol)
            term = model.d2_cens(d2[r, ci]) if cens[r] else model.d2_unc(d2[r, ci])
            W_f[r, ci] = total + (0.0 if consistent else INCONSISTENT) + (term if np.isfinite(term) else -10.0)

    row_sub = items
    out = dict(timing=_evaluate(W_t, row_sub, col_sub, scored, rng),
               full=_evaluate(W_f, row_sub, col_sub, scored, rng),
               overlap=overlap[scored].astype(np.int8), n_scored=int(scored.sum()))
    return out


# =========================================================================== C scenario
def credential_scenario(run, pools, lik, model: InsiderModel, X: int, rng):
    """X serves as C for some submissions. Pair each of X's credential transactions with the
    registry posts (F's or I's gossip origination) of the same submission."""
    s, ev = run.subs, run.events
    items = np.nonzero(s["C"] == X)[0]
    scored = _scored_mask(run, items)
    q = quorum_from_legs(run)[items]
    cols = A.gossip_origins(ev, run.cfg.attacker_reads_record_type, pools.gossip_wire)
    col_sub = np.where(np.isin(ev["leg"][cols], [FS.REG_F_ORIGIN, FS.REG_I_ORIGIN]), ev["sub"][cols], -1)
    d = ev["t_send"][cols][None, :] - q[:, None]
    W = np.where((d > 0) & (d < model.seq_max), model.seq_c(np.clip(d, 0, model.seq_max)), -np.inf)
    res = _evaluate(W, items, col_sub, scored, rng)
    return dict(timing=res, full=res, overlap=np.zeros(int(scored.sum()), np.int8), n_scored=int(scored.sum()))


def run_scenario(scenario: str, cfg: P.Config, seed: int, pools, lik, model):
    run = FS.simulate(cfg, seed, pools)
    rng = np.random.default_rng(seed ^ 0x5EED)
    X = int(rng.integers(0, P.N_NODES))        # the one compromised node
    if scenario in ("F", "I"):
        out = content_scenario(run, pools, lik, model, scenario, X, rng)
    else:
        out = credential_scenario(run, pools, lik, model, X, rng)
    out["X"] = X
    return out
