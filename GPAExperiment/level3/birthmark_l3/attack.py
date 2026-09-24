"""The global passive observer's attacks.

The observer sees, for every message on every link: (t_send, t_arr, src, dst, size) and, in
the main sweep, the plaintext TLS record type / protocol. External hosts are all labelled EXT:
devices and background clients alike. It is never told which messages are Birthmark legs,
which are terminal arrivals, or which channel anything belongs to.

Main attack (two stages, both scored with Monte-Carlo likelihoods of the lottery process):
  Stage 1  per-node hop matching. At each node, observed departures are matched to observed
           arrivals with scipy.optimize.linear_sum_assignment, maximising the summed hop
           log-likelihood. Hop positions implied by the matching (ingress=1, then 2, 3; a
           departure matched to a validator's reply = gatekeeper leg) are fed back to rule out
           forwarding an arrival that must be terminal, and the matching is re-solved until
           stable. Following matches from each ingress arrival gives candidate 3-hop chains.
  Stage 2  chains are grouped by common origin time. Credential chains are recognised from the
           traffic (the credential processor contacts a validator milliseconds after the chain
           terminates), the other complete chains are pooled as content candidates, and
           linear_sum_assignment pairs them by the likelihood of their origin-time difference.
  Success: the credential chain's terminal (Cred-3 at C) is paired with a chain whose terminal
           is the same submission's ContA-3 or ContB-3.

Sequencing attack (same report): validator replies (CV-2 at C) vs registry-gossip origination
bursts (Reg-1/Reg-2 at F/I), paired by linear_sum_assignment on a Monte-Carlo likelihood of the
quorum -> board poll -> post delay.

Origin-anchored trace (separate section): same Stage 1 output, but read from each device's
known IP at the first hop.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import linear_sum_assignment

from . import lottery as LT
from . import params as P
from .fastsim import (CA3, CB3, CRED3, CV2, EXT, K_BIRTHMARK, K_BLEND, K_BULK, K_KEEPALIVE,
                      REG_F_ORIGIN, REG_I_ORIGIN, VAL0)

BIG = 1e9
GRID_TOL_S = 0.004
CV1_WINDOW_S = 0.050
POS_GK = 9


# =========================================================================== likelihoods
@dataclass
class Likelihoods:
    hop: LT.EmpiricalLogPDF
    origin: LT.EmpiricalLogPDF
    seq: LT.EmpiricalLogPDF
    term: LT.EmpiricalLogPDF      # diagnostic bound only: Cred-3 arrival minus ContX-3 arrival
    hop_max: float
    origin_max: float
    seq_max: float
    term_max: float
    seq_samples: np.ndarray = None   # kept for tests: the Monte-Carlo draws behind `seq`


def _lat(rng, rng_ms, n):
    return rng.uniform(*rng_ms, n) / 1000


def _proc(rng, n):
    return rng.uniform(*P.PROC_MS, n) / 1000


def _jit(rng, n):
    return rng.exponential(P.JITTER_MS / 1000, n)


def build_likelihoods(cfg: P.Config, n=1_000_000, seed=12345) -> Likelihoods:
    """Monte-Carlo the lottery process under the same clock model the system runs."""
    rng = np.random.default_rng(seed)
    on = cfg.lottery_enabled

    def relay(t):
        return LT.release_time(rng, t, rng.uniform(0, P.TICK_S, t.shape[0]), cfg.relay_clock, on) + _proc(rng, t.shape[0])

    def device(t0, shared_phase):
        return LT.device_release(rng, t0, shared_phase, cfg.device_clock, on) + _proc(rng, t0.shape[0])

    # hop: departure time minus arrival time at one node
    t_in = rng.uniform(0, 1000, n)
    hop = relay(t_in) - t_in

    # origin: first-hop arrival difference between two channels of one submission
    t0 = rng.uniform(0, 1000, n)
    ph = rng.uniform(0, P.TICK_S, n)
    a = device(t0, ph) + _lat(rng, P.LAT_EXT_MS, n) + _jit(rng, n)
    b = device(t0, ph) + _lat(rng, P.LAT_EXT_MS, n) + _jit(rng, n)
    origin = a - b

    # sequencing: registry-gossip origin at F minus CV-2 arrival at C
    def chain(t0):
        t = device(t0, rng.uniform(0, P.TICK_S, n)) + _lat(rng, P.LAT_EXT_MS, n) + _jit(rng, n)
        for _ in range(2):
            t = relay(t) + _lat(rng, P.LAT_INT_MS, n) + _jit(rng, n)
        return t
    t0 = np.zeros(n)
    arr_c = chain(t0)
    cv1 = relay(arr_c) if cfg.cv_hold else arr_c + _proc(rng, n)
    cv2 = cv1 + _lat(rng, P.LAT_INT_MS, n) + _jit(rng, n) + rng.uniform(*P.VALIDATOR_PROC_MS, n) / 1000
    if cfg.cv_hold:
        cv2 = relay(cv2)
    cv2 = cv2 + _lat(rng, P.LAT_INT_MS, n) + _jit(rng, n)
    ph_c = rng.uniform(0, P.TICK_S, n)
    posts = np.stack([LT.release_time(rng, cv2, ph_c, cfg.relay_clock, on) + _proc(rng, n)
                      + _lat(rng, P.LAT_INT_MS, n) + _jit(rng, n) + rng.uniform(*P.GATEKEEPER_PROC_MS, n) / 1000
                      for _ in range(3)], 1)
    if cfg.role_rules == "catalog":   # C is one of the gatekeepers 3 times in 20: its record doesn't count
        posts[:, 0] = np.where(rng.random(n) < 3 / P.N_NODES, np.inf, posts[:, 0])
    quorum = np.sort(posts, 1)[:, 1]
    ph_f = rng.uniform(0, P.TICK_S, n)
    reg = LT.next_tick(np.maximum(quorum, chain(t0)), ph_f)
    if cfg.reg_hold:
        ph_h = rng.uniform(0, P.TICK_S, n) if cfg.reg_hold_phase == "fresh" else ph_f
        reg = LT.release_time(rng, reg, ph_h, cfg.relay_clock, on)
    reg = reg + _proc(rng, n)
    seq = reg - cv2
    term = arr_c - chain(t0)

    fine = cfg.relay_clock == "packet" or not on
    hop_bw = 1e-4 if not on else (0.002 if fine else 0.25)
    org_bw = 0.002 if (cfg.device_clock == "shared" or not on) else 0.25
    return Likelihoods(
        hop=LT.EmpiricalLogPDF(hop, hop_bw),
        origin=LT.EmpiricalLogPDF(origin, org_bw),
        seq=LT.EmpiricalLogPDF(seq, 0.5 if on else 0.05),
        term=LT.EmpiricalLogPDF(term, 0.5 if on else 0.002),
        hop_max=float(hop.max()) + 1.0, origin_max=float(np.abs(origin).max()) + 1.0,
        seq_max=float(seq.max()) + 5.0, term_max=float(np.abs(term).max()) + 1.0,
        seq_samples=seq[:20_000])


# =========================================================================== observation
def signature_mask(ev, reads_record_type: bool, tls_overhead: int):
    """The published relay size class on the wire (padding range + measured TLS 1.3 overhead)."""
    lo, hi = P.PAD_MIN + tls_overhead, P.PAD_MAX + tls_overhead
    m = (ev["size"] >= lo) & (ev["size"] <= hi)
    if reads_record_type:
        m &= ev["rtype"] == P.RT_APPDATA
    return m


def estimate_grids(ev, sig):
    """Per node: does its relay-class traffic leave on a 10 s grid, and at what phase?"""
    is_node_src = ev["src"] < P.N_NODES
    phase = np.full(P.N_NODES, np.nan)
    for n in range(P.N_NODES):
        t = ev["t_send"][sig & is_node_src & (ev["src"] == n) & (ev["dst"] < P.N_NODES)]
        if t.size < 20:
            continue
        h = np.bincount((np.mod(t, P.TICK_S) * 1000).astype(int), minlength=10_000)
        sm = np.convolve(np.concatenate([h[-5:], h, h[:5]]), np.ones(5), "same")[5:-5]
        peak = int(sm.argmax())
        expected = t.size * 5 / 10_000        # 5 ms window under a uniform (grid-free) phase
        if sm[peak] >= max(10.0, 30.0 * expected):
            phase[n] = peak / 1000.0
    return phase


def on_grid(ev, phase):
    src = ev["src"].astype(int)
    ok = np.zeros(ev["src"].shape[0], bool)
    node = src < P.N_NODES
    ph = np.where(node, phase[np.minimum(src, P.N_NODES - 1)], np.nan)
    has = node & ~np.isnan(ph)
    d = np.mod(ev["t_send"][has] - ph[has] + P.TICK_S / 2, P.TICK_S) - P.TICK_S / 2
    ok[has] = np.abs(d) <= GRID_TOL_S
    ok[node & np.isnan(ph)] = True             # no grid detected -> can't filter by phase
    return ok


# =========================================================================== stage 1
def stage1(ev, sig, lik: Likelihoods, max_iter=4):
    n_ev = ev["src"].shape[0]
    src, dst = ev["src"].astype(int), ev["dst"].astype(int)
    phase = estimate_grids(ev, sig)
    grid = on_grid(ev, phase)
    n2n = sig & (src < P.N_NODES) & (dst < P.N_NODES) & grid
    ingress = sig & (src == EXT) & (dst < P.N_NODES)
    cv2 = sig & (src >= VAL0) & (src < VAL0 + P.N_VALIDATORS) & (dst < P.N_NODES)
    t_send, t_arr = ev["t_send"], ev["t_arr"]

    pos = np.zeros(n_ev, np.int8)
    pos[ingress] = 1
    pos[cv2] = POS_GK
    forwardable = ingress | n2n
    pred = np.full(n_ev, -1, np.int64)
    by_src = {n: np.nonzero(n2n & (src == n))[0] for n in range(P.N_NODES)}
    col_base = {n: np.nonzero((ingress | n2n) & (dst == n))[0] for n in range(P.N_NODES)}
    cv2_at = {n: np.nonzero(cv2 & (dst == n))[0] for n in range(P.N_NODES)}

    for _ in range(max_iter):
        new_pred = np.full(n_ev, -1, np.int64)
        for n in range(P.N_NODES):
            R = by_src[n]
            if R.size == 0:
                continue
            cb = col_base[n]
            Cc = np.concatenate([cb[forwardable[cb]], np.repeat(cv2_at[n], 3)])
            if Cc.size == 0:
                continue
            d = t_send[R][:, None] - t_arr[Cc][None, :]
            # log-likelihood ratio against an unrelated (uniform-in-window) pairing
            w = np.where((d > 0) & (d < lik.hop_max),
                         lik.hop(np.clip(d, 0, lik.hop_max)) + np.log(lik.hop_max), -np.inf)
            cost = np.where(np.isfinite(w), -w, BIG)
            # "no predecessor" option at LLR 0, only for departures with no grid evidence that
            # they are relay outputs (a node whose traffic shows no 10 s grid)
            dummy = np.full((R.size, R.size), BIG)
            if np.isnan(phase[n]):
                np.fill_diagonal(dummy, 0.0)
            cost = np.hstack([cost, dummy])
            ri, ci = linear_sum_assignment(cost)
            ok = (cost[ri, ci] < BIG) & (ci < Cc.size)
            new_pred[R[ri[ok]]] = Cc[ci[ok]]
        # hop positions implied by the matching
        newpos = pos.copy()
        rows = np.nonzero(n2n)[0]
        newpos[rows] = 0
        for _ in range(4):
            p = new_pred[rows]
            has = p >= 0
            pp = np.where(has, newpos[np.maximum(p, 0)], 0)
            newpos[rows] = np.where(~has, 0, np.where(pp == POS_GK, POS_GK,
                                     np.where(pp == 0, 0, np.minimum(pp + 1, 4))))
        new_fwd = ingress | (n2n & ((newpos == 2) | (newpos == 0)))
        stable = np.array_equal(new_pred, pred)
        pred, pos, forwardable = new_pred, newpos, new_fwd
        if stable:
            break
    return dict(pred=pred, pos=pos, n2n=n2n, ingress=ingress, cv2=cv2, phase=phase)


def successors(pred, n_ev):
    succ = np.full(n_ev, -1, np.int64)
    rows = np.nonzero(pred >= 0)[0]
    succ[pred[rows]] = rows      # CV-2 duplicates: last write wins; never followed forward
    return succ


# =========================================================================== stage 2
def cred_terminals(ev, sig, s1):
    """Arrivals at a node followed within milliseconds by that node contacting a validator."""
    src, dst = ev["src"].astype(int), ev["dst"].astype(int)
    cv1 = np.nonzero(sig & (src < P.N_NODES) & (dst >= VAL0) & (dst < VAL0 + P.N_VALIDATORS))[0]
    arrivals = s1["n2n"]
    out = []
    for n in range(P.N_NODES):
        a = np.nonzero(arrivals & (dst == n))[0]
        if a.size == 0:
            continue
        ta = ev["t_arr"][a]
        o = np.argsort(ta)
        a, ta = a[o], ta[o]
        c = cv1[src[cv1] == n]
        k = np.searchsorted(ta, ev["t_send"][c], side="right") - 1
        good = (k >= 0) & (ev["t_send"][c] - ta[np.maximum(k, 0)] <= CV1_WINDOW_S)
        out.append(a[k[good]])
    return np.unique(np.concatenate(out)) if out else np.zeros(0, np.int64)


def build_chains(ev, sig, s1):
    pred, n_ev = s1["pred"], ev["src"].shape[0]
    succ = successors(pred, n_ev)
    term = cred_terminals(ev, sig, s1)
    ing = s1["ingress"]
    # credential chains: trace back from each detected terminal
    e2 = pred[term]
    ok2 = e2 >= 0
    ok2[ok2] &= s1["n2n"][e2[ok2]]
    e1 = np.where(ok2, pred[np.maximum(e2, 0)], -1)
    ok1 = ok2 & (e1 >= 0)
    ok1[ok1] &= ing[e1[ok1]]
    cred = dict(term=term, origin_ev=e1, ok=ok1)
    # content candidates: trace forward from every ingress arrival
    starts = np.nonzero(ing)[0]
    s2 = succ[starts]
    s3 = np.where(s2 >= 0, succ[np.maximum(s2, 0)], -1)
    good = (s2 >= 0) & (s3 >= 0)
    good[good] &= s1["pos"][s3[good]] == 3
    cred_origin_set = set(e1[ok1].tolist())
    cred_term_set = set(term.tolist())
    good &= ~np.isin(starts, list(cred_origin_set)) & ~np.isin(s3, list(cred_term_set))
    cont = dict(origin_ev=starts[good], mid=s2[good], term=s3[good])
    return cred, cont, succ


def assign(weights):
    """linear_sum_assignment maximising summed log-likelihood; -inf = infeasible.
    Returns col index per row (-1 if unassigned), gap top-vs-runner-up, max posterior."""
    nr = weights.shape[0]
    col = np.full(nr, -1, np.int64)
    gap = np.full(nr, np.nan)
    post = np.full(nr, np.nan)
    if nr == 0 or weights.shape[1] == 0:
        return col, gap, post
    cost = np.where(np.isfinite(weights), -weights, BIG)
    ri, ci = linear_sum_assignment(cost)
    ok = cost[ri, ci] < BIG
    col[ri[ok]] = ci[ok]
    srt = -np.sort(-np.where(np.isfinite(weights), weights, -np.inf), axis=1)
    top = srt[:, 0]
    second = srt[:, 1] if weights.shape[1] > 1 else np.full(nr, -np.inf)
    with np.errstate(invalid="ignore"):
        gap = np.where(np.isfinite(top), top - np.where(np.isfinite(second), second, top - 50.0), np.nan)
    fin = np.isfinite(weights)
    wmax = np.where(np.isfinite(top), top, 0.0)[:, None]
    ew = np.where(fin, np.exp(np.where(fin, weights, 0.0) - wmax), 0.0)
    z = ew.sum(1)
    chosen = np.where(col >= 0, ew[np.arange(nr), np.maximum(col, 0)], 0.0)
    post = np.where(z > 0, chosen / np.maximum(z, 1e-300), np.nan)
    return col, gap, post


def stage2(ev, cred, cont, lik: Likelihoods):
    oc = ev["t_arr"][np.maximum(cred["origin_ev"], 0)]
    ox = ev["t_arr"][cont["origin_ev"]]
    d = oc[:, None] - ox[None, :]
    w = np.where(np.abs(d) < lik.origin_max, lik.origin(np.clip(d, -lik.origin_max, lik.origin_max)), -np.inf)
    w[~cred["ok"]] = -np.inf
    return w


# =========================================================================== sequencing attack
def gossip_origins(ev, reads_record_type: bool, gossip_wire: int):
    m = (np.abs(ev["size"] - gossip_wire) <= 4) & (ev["src"] < P.N_NODES)
    if reads_record_type:
        m &= ev["rtype"] == P.RT_NOISE
    idx = np.nonzero(m)[0]
    out = []
    for n in range(P.N_NODES):
        e = idx[ev["src"][idx] == n]
        if e.size == 0:
            continue
        t = ev["t_send"][e]
        o = np.argsort(t)
        e, t = e[o], t[o]
        brk = np.concatenate([[True], np.diff(t) > 0.002])
        cid = np.cumsum(brk) - 1
        size = np.bincount(cid)
        first = e[brk]
        out.append(first[size >= 10])
    return np.sort(np.concatenate(out)) if out else np.zeros(0, np.int64)


# =========================================================================== one run
def _scored(run):
    t0 = run.subs["t0"]
    return np.nonzero((t0 >= P.WARMUP_S) & (t0 < P.WARMUP_S + P.MEASURE_S))[0]


def _pack(correct, gap, post):
    return dict(correct=correct.astype(np.int8), gap=gap.astype(np.float32), post=post.astype(np.float32))


def attack_run(run, lik: Likelihoods, pools, rng_seed=0, diagnostics=True):
    ev, subs, cfg = run.events, run.subs, run.cfg
    sig = signature_mask(ev, cfg.attacker_reads_record_type, pools.tls13_overhead)
    s1 = stage1(ev, sig, lik)
    cred, cont, succ = build_chains(ev, sig, s1)
    W = stage2(ev, cred, cont, lik)
    col, gap, post = assign(W)

    sc = _scored(run)
    S = subs["t0"].shape[0]
    leg, sub_of = ev["leg"], ev["sub"]
    # map each scored submission to its credential row (if its Cred-3 was detected)
    row_of_sub = np.full(S, -1, np.int64)
    term_is_cred3 = leg[cred["term"]] == CRED3
    row_of_sub[sub_of[cred["term"][term_is_cred3]]] = np.nonzero(term_is_cred3)[0]
    cont_term_sub = np.where(np.isin(leg[cont["term"]], [CA3, CB3]), sub_of[cont["term"]], -1)
    r = row_of_sub[sc]
    has = r >= 0
    chosen = np.where(has, col[np.maximum(r, 0)], -1)
    correct = has & (chosen >= 0) & (np.where(chosen >= 0, cont_term_sub[np.maximum(chosen, 0)], -2) == sc)
    g = np.where(has, gap[np.maximum(r, 0)], np.nan)
    p = np.where(has, post[np.maximum(r, 0)], np.nan)
    out = {"main": _pack(correct, g, p)}

    # empirical chance baseline: random scores on exactly the same feasibility mask
    rng = np.random.default_rng(rng_seed)
    Wr = np.where(np.isfinite(W), rng.random(W.shape), -np.inf)
    colr, _, _ = assign(Wr)
    chosen_r = np.where(has, colr[np.maximum(r, 0)], -1)
    out["chance_correct"] = int((has & (chosen_r >= 0) &
                                 (np.where(chosen_r >= 0, cont_term_sub[np.maximum(chosen_r, 0)], -2) == sc)).sum())
    feas = np.isfinite(W[np.maximum(r[has], 0)]).sum(1) if has.any() else np.zeros(0)
    out["feasible_candidates_mean"] = float(feas.mean()) if feas.size else 0.0

    # ---- sequencing attack: CV-2 arrivals vs gossip origination bursts
    out.update(sequencing(run, lik, pools, sc, rng))

    # ---- origin-anchored trace (device IP visible at the first hop) - separate section
    def trace_ok(first, last):
        s2 = succ[first]
        s3 = np.where(s2 >= 0, succ[np.maximum(s2, 0)], -1)
        return s3 == last
    ca = trace_ok(subs["ev_ca"][sc, 0], subs["ev_ca"][sc, 2])
    cb = trace_ok(subs["ev_cb"][sc, 0], subs["ev_cb"][sc, 2])
    cr = trace_ok(subs["ev_cred"][sc, 0], subs["ev_cred"][sc, 2])
    dev, t0 = subs["dev"], subs["t0"]
    alone = np.ones(sc.shape[0], bool)            # device has no other submission within +-5 min
    order = np.lexsort((t0, dev))
    same = dev[order][1:] == dev[order][:-1]
    close = same & (np.diff(t0[order]) < P.MAX_TICKS * P.TICK_S)
    crowded = np.zeros(S, bool)
    crowded[order[1:][close]] = True
    crowded[order[:-1][close]] = True
    alone = ~crowded[sc]
    out["origin"] = dict(content_either=int((ca | cb).sum()), content_channel=int(ca.sum() + cb.sum()),
                         cred=int(cr.sum()), cred_and_content=int((cr & (ca | cb)).sum()),
                         first_hop_unambiguous=int(alone.sum()))

    out["n_scored"] = int(sc.shape[0])
    if diagnostics:
        out["diag"] = _diagnostics(run, ev, sig, s1, cred, cont, sc, lik)
    return out


def sequencing(run, lik: Likelihoods, pools, sc, rng):
    """CV-2 arrivals at C vs registry-gossip origination bursts, paired by linear_sum_assignment."""
    ev, cfg = run.events, run.cfg
    S = run.subs["t0"].shape[0]
    leg, sub_of = ev["leg"], ev["sub"]
    sig = signature_mask(ev, cfg.attacker_reads_record_type, pools.tls13_overhead)
    src, dst = ev["src"].astype(int), ev["dst"].astype(int)
    rows = np.nonzero(sig & (src >= VAL0) & (src < VAL0 + P.N_VALIDATORS) & (dst < P.N_NODES))[0]
    cols = gossip_origins(ev, cfg.attacker_reads_record_type, pools.gossip_wire)
    d = ev["t_send"][cols][None, :] - ev["t_arr"][rows][:, None]
    Ws = np.where((d > 0) & (d < lik.seq_max), lik.seq(np.clip(d, 0, lik.seq_max)), -np.inf)
    cs, gs, ps = assign(Ws)
    row_sub = np.full(S, -1, np.int64)
    rs = leg[rows] == CV2
    row_sub[sub_of[rows[rs]]] = np.nonzero(rs)[0]
    col_sub = np.where(np.isin(leg[cols], [REG_F_ORIGIN, REG_I_ORIGIN]), sub_of[cols], -1)
    rr = row_sub[sc]
    hs = rr >= 0
    ch = np.where(hs, cs[np.maximum(rr, 0)], -1)
    corr = hs & (ch >= 0) & (np.where(ch >= 0, col_sub[np.maximum(ch, 0)], -2) == sc)
    Wsr = np.where(np.isfinite(Ws), rng.random(Ws.shape), -np.inf)
    csr, _, _ = assign(Wsr)
    chr_ = np.where(hs, csr[np.maximum(rr, 0)], -1)
    chance = int((hs & (chr_ >= 0) & (np.where(chr_ >= 0, col_sub[np.maximum(chr_, 0)], -2) == sc)).sum())
    return {"seq": _pack(corr, np.where(hs, gs[np.maximum(rr, 0)], np.nan), np.where(hs, ps[np.maximum(rr, 0)], np.nan)),
            "seq_chance_correct": chance}


def sequencing_only_run(run, lik: Likelihoods, pools, rng_seed=0):
    """Hardening checks: the sequencing attack alone, plus whether credential terminals are
    still detectable from the CV-1 timing rule the main attack relies on."""
    ev = run.events
    sc = _scored(run)
    out = sequencing(run, lik, pools, sc, np.random.default_rng(rng_seed))
    sig = signature_mask(ev, run.cfg.attacker_reads_record_type, pools.tls13_overhead)
    grid = on_grid(ev, estimate_grids(ev, sig))
    n2n = sig & (ev["src"] < P.N_NODES) & (ev["dst"] < P.N_NODES) & grid
    term = cred_terminals(ev, sig, {"n2n": n2n})
    out["cred_terminal_detect"] = float(np.isin(run.subs["ev_cred"][sc, 2], term).mean())
    out["cred_terminal_false"] = float(np.mean(ev["leg"][term] != CRED3)) if term.size else 0.0
    out["n_scored"] = int(sc.shape[0])
    return out


def _diagnostics(run, ev, sig, s1, cred, cont, sc, lik):
    subs, kind, pred = run.subs, ev["kind"], s1["pred"]
    # Stage 1 per-hop accuracy on the true relay departures of scored submissions
    true_pairs = []
    for key in ("ev_cred", "ev_ca", "ev_cb"):
        e = subs[key][sc]
        true_pairs += [(e[:, 1], e[:, 0]), (e[:, 2], e[:, 1])]
    hop_ok = np.concatenate([pred[a] == b for a, b in true_pairs])
    chain_ok = {}
    for key in ("ev_cred", "ev_ca", "ev_cb"):
        e = subs[key][sc]
        chain_ok[key] = float(np.mean((pred[e[:, 2]] == e[:, 1]) & (pred[e[:, 1]] == e[:, 0])))
    cred3 = subs["ev_cred"][sc, 2]
    detected = np.isin(cred3, cred["term"])
    chain_events = np.concatenate([cred["term"], cred["origin_ev"][cred["ok"]], cont["origin_ev"], cont["mid"], cont["term"]])
    contam = np.bincount(kind[chain_events], minlength=4)
    # oracle-chain Stage 2 (perfect Stage 1): how much the origin-time grouping alone leaks
    allsub = np.arange(subs["t0"].shape[0])
    oc = ev["t_arr"][subs["ev_cred"][allsub, 0]]
    ox = np.concatenate([ev["t_arr"][subs["ev_ca"][allsub, 0]], ev["t_arr"][subs["ev_cb"][allsub, 0]]])
    xs = np.concatenate([allsub, allsub])
    d = oc[:, None] - ox[None, :]
    Wo = np.where(np.abs(d) < lik.origin_max, lik.origin(np.clip(d, -lik.origin_max, lik.origin_max)), -np.inf)
    co, go, po = assign(Wo)
    oracle_ok = (co[sc] >= 0) & (xs[np.maximum(co[sc], 0)] == sc)
    # oracle-terminal bound: the workbook's original terminal-timing attack given TRUE terminal
    # labels (which the observer does not have) - how much pairing signal terminal timing holds
    tc = ev["t_arr"][subs["ev_cred"][allsub, 2]]
    tx = np.concatenate([ev["t_arr"][subs["ev_ca"][allsub, 2]], ev["t_arr"][subs["ev_cb"][allsub, 2]]])
    d = tc[:, None] - tx[None, :]
    Wt = np.where(np.abs(d) < lik.term_max, lik.term(np.clip(d, -lik.term_max, lik.term_max)), -np.inf)
    ct, gt, pt = assign(Wt)
    term_ok = (ct[sc] >= 0) & (xs[np.maximum(ct[sc], 0)] == sc)
    window = signature_mask(ev, True, 22)
    window_any = signature_mask(ev, False, 22)
    ingress = ev["src"] == EXT
    return dict(
        hop_acc=float(hop_ok.mean()), chain_acc=chain_ok, cred_terminal_detect=float(detected.mean()),
        n_cred_rows=int(cred["term"].shape[0]), n_cred_rows_ok=int(cred["ok"].sum()),
        n_content_candidates=int(cont["term"].shape[0]),
        content_candidates_true=float(np.mean(np.isin(ev["leg"][cont["term"]], [CA3, CB3]))) if cont["term"].size else 0.0,
        chain_events_by_kind=dict(birthmark=int(contam[K_BIRTHMARK]), blend=int(contam[K_BLEND]),
                                  bulk=int(contam[K_BULK]), keepalive=int(contam[K_KEEPALIVE])),
        oracle_stage2=_pack(oracle_ok, go[sc], po[sc]),
        oracle_terminal=_pack(term_ok, gt[sc], pt[sc]),
        grid_detected=int(np.sum(~np.isnan(s1["phase"]))),
        grid_phase_err_ms=float(np.nanmax(np.abs(((s1["phase"] - run.phase + 5) % 10) - 5)) * 1000)
        if np.any(~np.isnan(s1["phase"])) else float("nan"),
        ingress_in_window_rt=np.bincount(kind[window & ingress], minlength=4).tolist(),
        ingress_in_window_size_only=np.bincount(kind[window_any & ingress], minlength=4).tolist(),
    )
