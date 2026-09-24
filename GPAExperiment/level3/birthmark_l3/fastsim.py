"""Vectorised generator of one run's complete wire trace.

Implements the same process as refsim.py (the literal per-tick, real-crypto reference
simulator) but draws each packet's lottery outcome directly instead of rolling it tick by
tick, which is what makes 3,000 runs feasible. tests/test_equivalence.py checks the two
against each other statistically.

Output: an event table (one row per message on a link, as a GPA would see it) plus the
hidden ground truth needed to score attacks. Every Birthmark leg in the Leg Catalog is
emitted, including the internal ones the GPA cannot see (Post-1/2/3 are generated as
board-post times only - they never appear on an observed link).
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from . import lottery as LT
from . import params as P
from .crypto_legs import raw_size_table
from .wire_pools import Pools

EXT = 99                 # every external host (device or background client) as the GPA labels it
VAL0 = P.N_NODES         # validators are ids 20..23

# leg codes (truth only)
CRED1, CRED2, CRED3, CA1, CA2, CA3, CB1, CB2, CB3 = range(1, 10)
CV1, CV2, GK1, GK2, GK3, REG_F_ORIGIN, REG_I_ORIGIN, REG_RELAY = range(10, 18)
LEG_NAMES = {0: "-", CRED1: "Cred-1", CRED2: "Cred-2", CRED3: "Cred-3", CA1: "ContA-1",
             CA2: "ContA-2", CA3: "ContA-3", CB1: "ContB-1", CB2: "ContB-2", CB3: "ContB-3",
             CV1: "CV-1", CV2: "CV-2", GK1: "GK-1", GK2: "GK-2", GK3: "GK-3",
             REG_F_ORIGIN: "Reg-1 gossip (origin)", REG_I_ORIGIN: "Reg-2 gossip (origin)",
             REG_RELAY: "Reg gossip (relay)"}
# kind codes (truth only)
K_BIRTHMARK, K_BLEND, K_BULK, K_KEEPALIVE = 0, 1, 2, 3

_RAW = None


def raw_sizes():
    global _RAW
    if _RAW is None:
        _RAW = raw_size_table()
    return _RAW


class _Events:
    """Column buffers; finalised into one table sorted by send time."""
    COLS = ("t_send", "t_arr", "src", "dst", "size", "rtype", "kind", "leg", "sub", "ext_src", "ext_dst")
    DT = dict(t_send=np.float64, t_arr=np.float64, src=np.int16, dst=np.int16, size=np.int32,
              rtype=np.int16, kind=np.int8, leg=np.int8, sub=np.int32, ext_src=np.int32, ext_dst=np.int32)

    def __init__(self):
        self.parts = {c: [] for c in self.COLS}
        self.n = 0

    def add(self, t_send, t_arr, src, dst, size, rtype, kind, leg=0, sub=-1, ext_src=-1, ext_dst=-1):
        t_send = np.asarray(t_send, dtype=float)
        n = t_send.shape[0]
        if n == 0:
            return np.zeros(0, dtype=np.int64)
        vals = dict(t_send=t_send, t_arr=t_arr, src=src, dst=dst, size=size, rtype=rtype, kind=kind,
                    leg=leg, sub=sub, ext_src=ext_src, ext_dst=ext_dst)
        for c in self.COLS:
            self.parts[c].append(np.broadcast_to(np.asarray(vals[c]), (n,)).astype(self.DT[c]))
        ids = np.arange(self.n, self.n + n)
        self.n += n
        return ids

    def finalize(self):
        cols = {c: np.concatenate(self.parts[c]) for c in self.COLS}
        order = np.argsort(cols["t_send"], kind="stable")
        rank = np.empty_like(order)
        rank[order] = np.arange(order.shape[0])
        return {c: v[order] for c, v in cols.items()}, rank


@dataclass
class Run:
    cfg: P.Config
    events: dict            # observed columns + truth columns (kind/leg/sub/ext_*)
    subs: dict              # per-submission truth; event references are row indices into events
    phase: np.ndarray       # node clock phases (truth; the attacker estimates its own)
    horizon: float


class World:
    def __init__(self, cfg: P.Config, seed: int, pools: Pools):
        self.cfg, self.pools = cfg, pools
        self.rng = np.random.default_rng(seed)
        r = self.rng
        n_int = P.N_NODES + P.N_VALIDATORS
        base = r.uniform(*P.LAT_INT_MS, size=(n_int, n_int)) / 1000
        self.lat_int = (base + base.T) / 2
        self.phase = r.uniform(0, P.TICK_S, P.N_NODES)
        self.dev_phase = r.uniform(0, P.TICK_S, cfg.devices)
        self.lat_dev = r.uniform(*P.LAT_EXT_MS, size=(cfg.devices, P.N_NODES)) / 1000
        self.ev = _Events()

    def jit(self, n):
        return self.rng.exponential(P.JITTER_MS / 1000, n)

    def proc(self, n):
        return self.rng.uniform(*P.PROC_MS, n) / 1000

    def relay_size(self, leg_family: str, n):
        if not self.cfg.padding_enabled:
            return np.full(n, raw_sizes()[leg_family] + self.pools.tls13_overhead)
        target = self.rng.integers(P.PAD_MIN, P.PAD_MAX + 1, n)
        return target + self.pools.tls13_overhead      # measured: one TLS 1.3 record per packet


# --------------------------------------------------------------------------- Birthmark legs
def _chain(w: World, t0, dev, first, second, dest, legs, fam, sub):
    cfg, n = w.cfg, t0.shape[0]
    dep = LT.device_release(w.rng, t0, w.dev_phase[dev], cfg.device_clock, cfg.lottery_enabled) + w.proc(n)
    arr = dep + w.lat_dev[dev, first] + w.jit(n)
    ids = [w.ev.add(dep, arr, EXT, first, w.relay_size(fam[0], n), P.RT_APPDATA, K_BIRTHMARK, legs[0], sub,
                    ext_src=dev)]
    cur = first
    for nxt, leg, f in ((second, legs[1], fam[1]), (dest, legs[2], fam[2])):
        rel = LT.release_time(w.rng, arr, w.phase[cur], cfg.relay_clock, cfg.lottery_enabled) + w.proc(n)
        arr = rel + w.lat_int[cur, nxt] + w.jit(n)
        ids.append(w.ev.add(rel, arr, cur, nxt, w.relay_size(f, n), P.RT_APPDATA, K_BIRTHMARK, leg, sub))
        cur = nxt
    return arr, ids


def _gossip(w: World, origin, t_origin, sub, origin_leg, mesh):
    """Reg gossip: gossipsub v1.1 flood-publishes the node's own message to every peer; each
    peer then forwards on first receipt to its mesh peers (not back to the source/origin)."""
    r, N = w.rng, P.N_NODES
    size = w.pools.gossip_wire
    origin_ids = np.full(origin.shape[0], -1, dtype=np.int64)
    for o in range(N):
        sel = np.nonzero(origin == o)[0]
        if sel.size == 0:
            continue
        others = np.array([v for v in range(N) if v != o])
        ts = t_origin[sel][:, None] + r.uniform(0, 1e-3, (sel.size, others.size))
        ta = ts + w.lat_int[o, others][None, :] + w.jit(ts.size).reshape(ts.shape)
        ids = w.ev.add(ts.ravel(), ta.ravel(), o, np.tile(others, sel.size), size, P.RT_NOISE, K_BIRTHMARK,
                       np.repeat(origin_leg[sel], others.size), np.repeat(sub[sel], others.size))
        origin_ids[sel] = ids.reshape(sel.size, others.size)[:, 0]
        for j, v in enumerate(others):
            fwd = np.array([u for u in mesh[v] if u != o])
            if fwd.size == 0:
                continue
            tf = ta[:, j][:, None] + r.uniform(*P.GOSSIP_VALIDATE_MS, (sel.size, 1)) / 1000 \
                + r.uniform(0, 1e-3, (sel.size, fwd.size))
            tfa = tf + w.lat_int[v, fwd][None, :] + w.jit(tf.size).reshape(tf.shape)
            w.ev.add(tf.ravel(), tfa.ravel(), v, np.tile(fwd, sel.size), size, P.RT_NOISE, K_BIRTHMARK,
                     REG_RELAY, np.repeat(sub[sel], fwd.size))
    return origin_ids


def _mesh(rng):
    """6-regular gossip mesh: circulant i±1,±2,±3 over a random node ordering."""
    order = rng.permutation(P.N_NODES)
    pos = np.empty_like(order)
    pos[order] = np.arange(P.N_NODES)
    half = P.GOSSIP_MESH_D // 2
    return {v: [int(order[(pos[v] + k) % P.N_NODES]) for k in list(range(1, half + 1)) + list(range(-half, 0))]
            for v in range(P.N_NODES)}


def gen_birthmark(w: World):
    cfg, r, H = w.cfg, w.rng, w.cfg.horizon_s
    rate = 1.0 / (cfg.interval_min * 60.0)
    counts = r.poisson(rate * H, cfg.devices)
    dev = np.repeat(np.arange(cfg.devices), counts)
    t0 = r.uniform(0, H, dev.shape[0])
    o = np.argsort(t0)
    t0, dev = t0[o], dev[o]
    S = t0.shape[0]
    sub = np.arange(S)
    val = VAL0 + dev % P.N_VALIDATORS
    # role slots: nine distinct nodes so no intermediary or first hop is shared across
    # channels (G6), and A != C, B not in {A, C} etc. as the Leg Catalog requires.
    perm = np.argsort(r.random((S, P.N_NODES)), axis=1)
    C, F, I, A, B, D, E, G, Hh = perm[:, :9].T
    gkr = r.random((S, P.N_NODES))
    gkr[sub, C] = 2.0
    gk = np.argsort(gkr, axis=1)[:, :3]

    arr_c, cred_ids = _chain(w, t0, dev, A, B, C, (CRED1, CRED2, CRED3), ("Cred-1", "Cred-2", "Cred-3"), sub)
    arr_f, ca_ids = _chain(w, t0, dev, D, E, F, (CA1, CA2, CA3), ("ContA-1", "ContA-2", "ContA-3"), sub)
    arr_i, cb_ids = _chain(w, t0, dev, G, Hh, I, (CB1, CB2, CB3), ("ContA-1", "ContA-2", "ContA-3"), sub)

    # C <-> validator round trip (no lottery: the workbook applies it to relay hops + GK only)
    # (hardening check only: optional lottery hold at C before CV-1 and at the validator
    # before CV-2. Extra random draws happen only when enabled, so the sweep's seeds are unchanged.)
    val_phase = r.uniform(0, P.TICK_S, P.N_VALIDATORS) if cfg.cv_hold else None
    cv1_s = arr_c
    if cfg.cv_hold:
        cv1_s = LT.release_time(r, arr_c, w.phase[C], cfg.relay_clock, cfg.lottery_enabled)
    cv1_s = cv1_s + w.proc(S)
    cv1_a = cv1_s + w.lat_int[C, val] + w.jit(S)
    cv1_id = w.ev.add(cv1_s, cv1_a, C, val, w.relay_size("CV-1", S), P.RT_APPDATA, K_BIRTHMARK, CV1, sub)
    cv2_s = cv1_a + r.uniform(*P.VALIDATOR_PROC_MS, S) / 1000
    if cfg.cv_hold:
        cv2_s = LT.release_time(r, cv2_s, val_phase[val - VAL0], cfg.relay_clock, cfg.lottery_enabled) + w.proc(S)
    cv2_a = cv2_s + w.lat_int[val, C] + w.jit(S)
    cv2_id = w.ev.add(cv2_s, cv2_a, val, C, w.relay_size("CV-2", S), P.RT_APPDATA, K_BIRTHMARK, CV2, sub)

    # gatekeeper fan-out: staggered, each leg its own lottery draw at C
    posts, gk_ids = np.empty((S, 3)), []
    for j in range(3):
        rel = LT.release_time(r, cv2_a, w.phase[C], cfg.relay_clock, cfg.lottery_enabled) + w.proc(S)
        arr = rel + w.lat_int[C, gk[:, j]] + w.jit(S)
        gk_ids.append(w.ev.add(rel, arr, C, gk[:, j], w.relay_size("GK", S), P.RT_APPDATA, K_BIRTHMARK,
                               GK1 + j, sub))
        posts[:, j] = arr + r.uniform(*P.GATEKEEPER_PROC_MS, S) / 1000   # Post-j: internal, unobserved
    quorum = np.sort(posts, axis=1)[:, 1]

    # F and I poll the boards on their own 10 s tick and post once 2-of-3 AND content are in
    # [DECISION: polling default, flagged as an assumption]
    reg_f = LT.next_tick(np.maximum(quorum, arr_f), w.phase[F])
    reg_i = LT.next_tick(np.maximum(quorum, arr_i), w.phase[I])
    if cfg.reg_hold:   # hardening check only: hold the posting in F's / I's own lottery
        reg_f = LT.release_time(r, reg_f, w.phase[F], cfg.relay_clock, cfg.lottery_enabled)
        reg_i = LT.release_time(r, reg_i, w.phase[I], cfg.relay_clock, cfg.lottery_enabled)
    reg_f = reg_f + w.proc(S)
    reg_i = reg_i + w.proc(S)
    mesh = _mesh(r)
    origin = np.concatenate([F, I])
    t_org = np.concatenate([reg_f, reg_i])
    legs = np.concatenate([np.full(S, REG_F_ORIGIN), np.full(S, REG_I_ORIGIN)])
    oids = _gossip(w, origin, t_org, np.concatenate([sub, sub]), legs, mesh)

    subs = dict(t0=t0, dev=dev, val=val, C=C, F=F, I=I, A=A, B=B, D=D, E=E, G=G, H=Hh, gk=gk,
                quorum=quorum, reg_f=reg_f, reg_i=reg_i, arr_c=arr_c, arr_f=arr_f, arr_i=arr_i,
                ev_cred=np.stack(cred_ids, 1), ev_ca=np.stack(ca_ids, 1), ev_cb=np.stack(cb_ids, 1),
                ev_cv1=cv1_id, ev_cv2=cv2_id, ev_gk=np.stack(gk_ids, 1),
                ev_reg_f=oids[:S], ev_reg_i=oids[S:])
    return subs


# --------------------------------------------------------------------------- background
def _pool_arrays(pools: Pools):
    """Flatten the session pool for vectorised expansion."""
    sess = pools.tls_sessions
    off = np.cumsum([0] + [s.shape[0] for s in sess])
    flat = np.concatenate(sess)
    # app-phase request/response pairs for persistent-connection (high-frequency) clients
    pairs = []
    for s in sess:
        app = s[s[:, 4] == 1]
        for f in np.unique(app[:, 1]):
            fl = app[app[:, 1] == f]
            if fl[0, 0] == 0:
                nxt = app[(app[:, 1] == f + 1) & (app[:, 0] == 1)]
                pairs.append(np.concatenate([fl, nxt]) if nxt.size else fl)
    poff = np.cumsum([0] + [p.shape[0] for p in pairs])
    pflat = np.concatenate(pairs)
    # renumber flights within each pair to 0/1
    pflat = pflat.copy()
    pflat[:, 1] = pflat[:, 0]
    nfl = np.array([s[:, 1].max() + 1 for s in sess])
    return off, flat, nfl, poff, pflat


def _expand(tx_start, tx_rec_off, tx_rec_cnt, flat, lat, think):
    """Expand transactions into record rows. Flight k is sent at start + k*(lat+1ms), plus the
    server think time for server-side application flights."""
    n_rec = tx_rec_cnt.sum()
    tx_of = np.repeat(np.arange(tx_start.shape[0]), tx_rec_cnt)
    within = np.arange(n_rec) - np.repeat(np.cumsum(tx_rec_cnt) - tx_rec_cnt, tx_rec_cnt)
    rec = flat[np.repeat(tx_rec_off, tx_rec_cnt) + within]
    direction, flight, rtype, size, app = rec.T
    step = lat[tx_of] + 0.001
    t_send = tx_start[tx_of] + flight * step + np.where((direction == 1) & (app == 1), think[tx_of], 0.0) \
        + within * 1e-5
    return tx_of, direction, rtype, size, t_send


def gen_background(w: World, pools: Pools, arrays):
    cfg, r, H = w.cfg, w.rng, w.cfg.horizon_s
    n_cl = cfg.bg_clients_per_node * P.N_NODES
    if n_cl == 0 or not cfg.background_enabled:
        return
    off, flat, nfl, poff, pflat = arrays
    n_int = int(round(n_cl * P.BG_INTERNAL_FRACTION))
    internal_host = np.full(n_cl, -1)
    internal_host[:n_int] = r.integers(0, P.N_NODES, n_int)
    hifreq = np.zeros(n_cl, bool)
    hifreq[r.permutation(n_cl)[: int(round(n_cl * (1 - P.BG_CASUAL_FRACTION)))]] = True
    lat_cl = r.uniform(*P.LAT_EXT_MS, size=(n_cl, P.N_NODES)) / 1000
    for c in range(n_cl):
        host = internal_host[c]
        if hifreq[c]:
            n = int(H / 0.25) + 50
            kind_pairs = True
            pause = r.uniform(*P.BG_HIFREQ_PAUSE_S, n)
        else:
            n = int(H / 25.0) + 20
            kind_pairs = False
            pause = r.uniform(*P.BG_CASUAL_PAUSE_S, n)
        server = r.integers(0, P.N_NODES, n)
        if host >= 0:
            server = np.where(server == host, (server + 1) % P.N_NODES, server)
            lat = w.lat_int[host, server]
        else:
            lat = lat_cl[c, server]
        is_dns = r.random(n) < P.BG_DNS_FRACTION
        think = r.uniform(0.001, 0.050, n)
        if kind_pairs:   # persistent connection, one request/response per transaction
            pidx = r.integers(0, poff.shape[0] - 1, n)
            rec_off, rec_cnt, nflight = poff[pidx], np.diff(poff)[pidx], np.full(n, 2)
            src_flat = pflat
        else:            # fresh session each transaction (handshake + exchanges)
            sidx = r.integers(0, off.shape[0] - 1, n)
            rec_off, rec_cnt, nflight = off[sidx], np.diff(off)[sidx], nfl[sidx]
            src_flat = flat
        dur = np.where(is_dns, 2 * lat + 0.015, nflight * (lat + 0.001) + think)
        start = np.cumsum(dur + pause) - (dur + pause)[0] + r.uniform(0, 60)
        keep = start < H
        start, server, lat, think, is_dns = start[keep], server[keep], lat[keep], think[keep], is_dns[keep]
        rec_off, rec_cnt = rec_off[keep], rec_cnt[keep]
        # HTTPS transactions
        h = ~is_dns
        tx_of, d, rt, sz, ts = _expand(start[h], rec_off[h], rec_cnt[h], src_flat, lat[h], think[h])
        srv = server[h][tx_of]
        ta = ts + lat[h][tx_of] + w.jit(ts.shape[0])
        if host >= 0:
            src = np.where(d == 0, host, srv)
            dst = np.where(d == 0, srv, host)
            w.ev.add(ts, ta, src, dst, sz, rt, K_BLEND)
        else:
            cid = 1_000_000 + c
            w.ev.add(ts, ta, np.where(d == 0, EXT, srv), np.where(d == 0, srv, EXT), sz, rt, K_BLEND,
                     ext_src=np.where(d == 0, cid, -1), ext_dst=np.where(d == 0, -1, cid))
        # DNS lookups the contacted node makes (node -> external resolver -> node), UDP/53
        dn = np.nonzero(is_dns)[0]
        if dn.size:
            k = r.integers(0, pools.dns_query.shape[0], dn.size)
            rl = r.uniform(*P.LAT_EXT_MS, dn.size) / 1000
            qs = start[dn]
            w.ev.add(qs, qs + rl, server[dn], EXT, pools.dns_query[k], P.RT_DNS, K_BLEND, ext_dst=2_000_000)
            rs = qs + 2 * rl + r.uniform(0.001, 0.030, dn.size)
            w.ev.add(rs, rs + rl, EXT, server[dn], pools.dns_resp[k], P.RT_DNS, K_BLEND, ext_src=2_000_000)


def gen_nonblending(w: World, pools: Pools):
    """Large bulk transfers (unpadded, far outside the window) and tiny keepalives."""
    if not w.cfg.nonblending_enabled:
        return
    r, H, N = w.rng, w.cfg.horizon_s, P.N_NODES
    rec_sz = pools.bulk_record_wire
    payload = rec_sz - pools.tls13_overhead

    def transfers(n, src_of, dst_of, ext_src, ext_dst, lat):
        sizes = np.exp(np.log(P.BULK_MEDIAN_BYTES) + r.normal(0, 1, n)).astype(np.int64)
        nrec = sizes // payload + 1
        start = r.uniform(0, H, n)
        tx = np.repeat(np.arange(n), nrec)
        within = np.arange(nrec.sum()) - np.repeat(np.cumsum(nrec) - nrec, nrec)
        last = within == nrec[tx] - 1
        size = np.where(last, sizes[tx] % payload + pools.tls13_overhead, rec_sz)
        ts = start[tx] + within * 0.0013          # ~100 Mbit/s serialisation
        w.ev.add(ts, ts + lat[tx], src_of[tx], dst_of[tx], size, P.RT_APPDATA, K_BULK,
                 ext_src=ext_src[tx] if ext_src is not None else -1,
                 ext_dst=ext_dst[tx] if ext_dst is not None else -1)

    n = r.poisson(P.BULK_EXT_RATE_PER_NODE * H * N)
    node = r.integers(0, N, n)
    up = r.random(n) < 0.3
    cid = 3_000_000 + np.arange(n)
    transfers(n, np.where(up, EXT, node), np.where(up, node, EXT), np.where(up, cid, -1), np.where(up, -1, cid),
              r.uniform(*P.LAT_EXT_MS, n) / 1000)
    n = r.poisson(P.BULK_INT_RATE_PER_NODE * H * N)
    a = r.integers(0, N, n)
    b = (a + r.integers(1, N, n)) % N
    transfers(n, a, b, None, None, w.lat_int[a, b])
    # keepalives on every persistent connection: node<->node and node<->validator
    ends = [(i, j) for i in range(N) for j in range(N + P.N_VALIDATORS) if i != j]
    ends += [(j, i) for i in range(N) for j in range(N, N + P.N_VALIDATORS)]
    ends = np.array(ends)
    k = int(H / P.KEEPALIVE_PERIOD_S) + 1
    ph = r.uniform(0, P.KEEPALIVE_PERIOD_S, len(ends))
    ts = (ph[:, None] + P.KEEPALIVE_PERIOD_S * np.arange(k)[None, :] + r.uniform(-1, 1, (len(ends), k))).ravel()
    s, d = np.repeat(ends[:, 0], k), np.repeat(ends[:, 1], k)
    ok = (ts > 0) & (ts < H)
    w.ev.add(ts[ok], ts[ok] + w.lat_int[s[ok], d[ok]], s[ok], d[ok], pools.keepalive_wire, P.RT_APPDATA,
             K_KEEPALIVE)


# --------------------------------------------------------------------------- run
_ARRAYS_CACHE = {}


def simulate(cfg: P.Config, seed: int, pools: Pools) -> Run:
    key = id(pools)
    if key not in _ARRAYS_CACHE:
        _ARRAYS_CACHE[key] = _pool_arrays(pools)
    w = World(cfg, seed, pools)
    subs = gen_birthmark(w)
    gen_background(w, pools, _ARRAYS_CACHE[key])
    gen_nonblending(w, pools)
    events, rank = w.ev.finalize()
    for k, v in subs.items():
        if k.startswith("ev_"):
            subs[k] = np.where(v >= 0, rank[np.maximum(v, 0)], -1)
    return Run(cfg=cfg, events=events, subs=subs, phase=w.phase, horizon=cfg.horizon_s)
