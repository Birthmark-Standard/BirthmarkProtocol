"""The compromised insider's view and attacks (Insider Experiment Design, corrected run).

The adversary is the level3 global passive observer plus one compromised pool node X. X holds
its own keys and knows its own events exactly. Roles rotate per submission, so X serves as F
for some submissions, I for others, C for others, and as a relay for more. A scenario ("F", "I"
or "C") scores the submissions where X holds that role. The three active gatekeepers are never
C, F or I, so X is never a gatekeeper in a scored submission.

What X adds to the level3 observer's view:
  * labels for its own events: which arrivals at X are its content terminals (as F/I) or its
    credential terminals (as C), and which GK legs it sent (as C);
  * internal events that never reach the wire: the quorum-detection poll tick (as F/I), and the
    quorum C can compute from its own GK legs;
  * what the board records disclose to F/I: the gatekeepers that posted (the public active set)
    and, without the ring signature, the node that acted as C.
X never learns a device IP and holds no other party's keys. When X is the Random hop for its
own submission (B = C, E = F, H = I) it does not use that coincidence (Insider Experiment
Design!B3).

Two variants per F/I scenario:
  timing  X's detection tick and content arrival, scored against every validator reply
  full    everything X knows. Without the ring signature, candidates are C's own validator
          replies. With it, every candidate's sender is searched for GK legs to the three active
          gatekeepers whose implied quorum agrees with X's own detection tick.
For C, nothing on the content side is disclosed, so the two variants coincide.

The likelihoods are Monte-Carlo estimates from the shared simulator on seeds disjoint from the
evaluation seeds.
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


def adopted_config(devices: int, interval_min: float, ring_sig: bool = True, **kw) -> P.Config:
    """Adopted GPA settings (node clock, per-channel device phase, F/I hold, no CV hold,
    25 background clients per node) with the Insider Experiment Design role rules, the gatekeeper
    exclusion and, unless ring_sig=False, the ring-signed C signature."""
    return P.Config(devices=devices, interval_min=interval_min, role_rules="insider_v2", ring_sig=ring_sig, **kw)


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


def build_model(pools: Pools, n_runs=40, seed0=900_000, **cfg_kw) -> InsiderModel:
    """Monte Carlo of the protocol under the same settings the evaluated system runs (the attacker
    knows the protocol's configuration); cfg_kw overrides them, e.g. for the positive control."""
    d1u, d2u, d2c, seqc, nc, nt = [], [], [], [], 0, 0
    for k in range(n_runs):
        cfg = adopted_config(400, 20, bg_clients_per_node=0, nonblending_enabled=False, **cfg_kw)
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
def _hold_samples(cfg, rng, m=2000):
    """Monte Carlo draws of (gatekeeper posting hold + processing) for the three gatekeepers. The
    gatekeepers' hold-clock phases are not observable, so the first tick is uniform in [0, 10) s."""
    t = rng.uniform(0, 1000, (m, 3))
    ph = rng.uniform(0, P.TICK_S, (m, 3))
    rel = LT.release_time(rng, t.ravel(), ph.ravel(), "node", True).reshape(m, 3)
    return rel - t + rng.uniform(*P.GATEKEEPER_PROC_MS, (m, 3)) / 1000



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

    # ---- full variant: everything X legitimately knows. The three active gatekeepers are public.
    # Without the ring signature, the board record names C, so candidates are restricted to C's
    # own validator replies. With it, X does not learn C and searches every candidate's sender.
    ring = run.cfg.ring_sig
    lo, hi = P.PAD_GK_RING if ring else (P.PAD_MIN, P.PAD_MAX)
    gk_mask = (ev["size"] >= lo + pools.tls13_overhead) & (ev["size"] <= hi + pools.tls13_overhead)
    if run.cfg.attacker_reads_record_type:
        gk_mask &= ev["rtype"] == P.RT_APPDATA
    src, dst = ev["src"].astype(int), ev["dst"].astype(int)
    gks = [int(g) for g in s["gk"][0]]
    assert X not in gks or not items.size, "gatekeeper exclusion: a gatekeeper is never F or I"
    legs = {(c, g): np.nonzero(gk_mask & (src == c) & (dst == g))[0] for c in range(P.N_NODES) for g in gks}
    W_f = np.full_like(W_t, -np.inf)
    W_l = np.full_like(W_t, -np.inf)       # the GK-leg search alone: legs + quorum agreement
    held = _hold_samples(run.cfg, rng) if run.cfg.gk_hold else None
    for r, sidx in enumerate(items):
        base = (d1[r] > 0) & (d1[r] < model.d_max)     # plain time window, independent of the model
        cand = np.nonzero(base & (c_node == int(s["C"][sidx])))[0] if not ring else np.nonzero(base)[0]
        for ci in cand:
            c, tv, total, arrivals, ok = int(c_node[ci]), t_v[ci], 0.0, [], True
            for g in gks:
                e = legs[(c, g)]
                dd = ev["t_send"][e] - tv
                w = np.where((dd > 0) & (dd < lik.hop_max), lik.hop(np.clip(dd, 0, lik.hop_max)), -np.inf)
                if not np.isfinite(w).any():
                    ok = False
                    break
                b = int(np.argmax(w))
                total += w[b]
                arrivals.append(ev["t_arr"][e[b]])
            if not ok:
                continue
            tol = 0.006
            if held is None:
                q = sorted(arrivals)[1] + GK_PROC_MEAN_S
                consistent = (q <= det[r] + tol) and (cens[r] or q > det[r] - P.TICK_S - tol)
                agree = 0.0 if consistent else INCONSISTENT
            else:
                # gatekeeper posting hold: probability that the held 2-of-3 quorum lands where X's
                # own detection tick says it did
                q = np.sort(np.asarray(arrivals)[None, :] + held, axis=1)[:, 1]
                pr = np.mean((q <= det[r] + tol) & (cens[r] | (q > det[r] - P.TICK_S - tol)))
                agree = float(np.log(max(pr, 1.0 / held.shape[0])))
            term = model.d2_cens(d2[r, ci]) if cens[r] else model.d2_unc(d2[r, ci])
            W_f[r, ci] = total + agree + (term if np.isfinite(term) else -10.0)
            W_l[r, ci] = total + agree

    row_sub = items
    out = dict(timing=_evaluate(W_t, row_sub, col_sub, scored, rng),
               full=_evaluate(W_f, row_sub, col_sub, scored, rng),
               legs=_evaluate(W_l, row_sub, col_sub, scored, rng), n_scored=int(scored.sum()))
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
    return dict(timing=res, full=res, legs=res, n_scored=int(scored.sum()))


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
