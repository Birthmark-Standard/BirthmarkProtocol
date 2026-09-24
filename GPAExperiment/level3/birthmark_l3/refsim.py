"""Reference simulator: a literal discrete-event network with real cryptography.

This is the slow, obviously-correct version of the process fastsim.py generates in bulk:
  * every node runs its own 10 s clock; every packet it holds rolls the 8.33% release lottery
    on each tick and is force-released on the 30th (relay_clock="node"), or each packet runs
    its own 10 s timer from arrival (relay_clock="packet");
  * every packet is a real ciphertext built by crypto_legs: transit layers are opened and
    re-sealed hop by hop, the Addressed hop reads and discards the routing code, the Random hop
    consumes it, C runs the BlindShare round trip with the validator and checks the signature,
    gatekeepers verify both signatures and post to their boards, F/I recompute PacketHash, poll
    the boards on their tick and post a signed registry entry that is gossiped.
It records observed events in the same schema as fastsim so the two can be compared, and it
checks protocol correctness (every submission finalises with two valid registry postings).

The workbook suggests asyncio; a heap-ordered event queue in virtual time is the same
semantics (one task per held packet, woken each tick) without wall-clock waiting.
"""
from __future__ import annotations

import hashlib
import heapq
import itertools
from collections import defaultdict

import numpy as np

from . import crypto_legs as X
from . import lottery as LT
from . import params as P
from .fastsim import (CA1, CA3, CB1, CRED1, CRED3, CV1, CV2, EXT, GK1, REG_F_ORIGIN,
                      REG_I_ORIGIN, REG_RELAY, VAL0, _mesh)


class RefSim:
    def __init__(self, cfg: P.Config, seed: int, tls_overhead: int = 22, gossip_wire: int = 282):
        self.cfg = cfg
        self.rng = np.random.default_rng(seed)
        self.q, self.seq, self.now = [], itertools.count(), 0.0
        self.tls_overhead, self.gossip_wire = tls_overhead, gossip_wire
        N = P.N_NODES
        self.keys = [X.ServerKeys.new() for _ in range(N)]
        self.vkeys = [X.ValidatorKeys.new() for _ in range(P.N_VALIDATORS)]
        self.route_table = {X.routing_code(i): i for i in range(N)}
        self.phase = self.rng.uniform(0, P.TICK_S, N)
        base = self.rng.uniform(*P.LAT_INT_MS, (N + P.N_VALIDATORS,) * 2) / 1000
        self.lat_int = (base + base.T) / 2
        self.lat_dev = self.rng.uniform(*P.LAT_EXT_MS, (cfg.devices, N)) / 1000
        self.dev_phase = self.rng.uniform(0, P.TICK_S, cfg.devices)
        self.held = defaultdict(list)            # node -> [packet dict]
        self.held_posts = defaultdict(list)      # node -> [registry postings in the adopted F/I hold]
        self.boards = [defaultdict(set) for _ in range(N)]   # gatekeeper node's board: PacketHash -> posts
        self.registry_seen = defaultdict(set)
        self.pending_content = defaultdict(list)  # node -> [(packet_hash, content_hash, sub, leg)]
        self.cstate = {}                          # C-side per-transaction state
        self.events, self.subs, self.registry = [], [], defaultdict(list)
        self.mesh = _mesh(self.rng)
        for n in range(N):
            self._at(self.phase[n], self._node_tick, n)

    # ------------------------------------------------------------------ plumbing
    def _at(self, t, fn, *args):
        heapq.heappush(self.q, (t, next(self.seq), fn, args))

    def run(self, until):
        while self.q and self.q[0][0] <= until:
            self.now, _, fn, args = heapq.heappop(self.q)
            fn(*args)

    def _jit(self):
        return self.rng.exponential(P.JITTER_MS / 1000)

    def _proc(self):
        return self.rng.uniform(*P.PROC_MS) / 1000

    def _target(self):
        return X.draw_target(self.rng) if self.cfg.padding_enabled else None

    def _send(self, src, dst, blob, leg, sub, kind, lat, ext_src=-1, rtype=P.RT_APPDATA, extra=None):
        t_send = self.now
        t_arr = t_send + lat + self._jit()
        size = len(blob) + (self.tls_overhead if rtype == P.RT_APPDATA else 0)
        self.events.append((t_send, t_arr, src, dst, size, rtype, leg, sub, ext_src))
        self._at(t_arr, self._receive, dst, src, blob, leg, sub, kind, extra)

    # ------------------------------------------------------------------ devices
    def submit(self, t0, dev):
        self._at(t0, self._device_submit, dev)

    def _device_submit(self, dev):
        r = self.rng
        sub = len(self.subs)
        V = self.vkeys[dev % P.N_VALIDATORS]
        s = X.new_submission(hashlib.sha256(b"dev" + dev.to_bytes(4, "big")).digest(), V)
        perm = r.permutation(P.N_NODES)
        C, F, I, A, B, D, E, G, H = (int(v) for v in perm[:9])
        self.subs.append(dict(t0=self.now, dev=dev, C=C, F=F, I=I, content_hash=s.content_hash,
                              packet_hash=s.packet_hash, finalized=None))
        chans = [(A, C, X.cred_payload(s, self.keys[C]), CRED1, B),
                 (D, F, X.content_payload(s, self.keys[F]), CA1, E),
                 (G, I, X.content_payload(s, self.keys[I]), CB1, H)]
        for first, dest, payload, leg, _ in chans:
            pkt = X.first_hop(payload, dest, self.keys[first], self._target())
            phase = self.dev_phase[dev] if self.cfg.device_clock == "shared" else r.uniform(0, P.TICK_S)
            self._device_hold(dev, pkt, first, leg, sub, LT.next_tick(self.now, phase), 1)
        self.cstate[sub] = dict(V=dev % P.N_VALIDATORS, mid=None)

    def _device_hold(self, dev, pkt, first, leg, sub, tick_t, k):
        """Device-side lottery for one channel, rolled literally tick by tick."""
        def roll():
            if not self.cfg.lottery_enabled or k >= P.MAX_TICKS or self.rng.random() < P.RELEASE_P:
                self.now += self._proc()
                self._send(EXT, first, pkt, leg, sub, "relay", self.lat_dev[dev, first], ext_src=dev)
            else:
                self._device_hold(dev, pkt, first, leg, sub, tick_t + P.TICK_S, k + 1)
        if not self.cfg.lottery_enabled:
            self._at(self.now, roll)
        else:
            self._at(tick_t, roll)

    # ------------------------------------------------------------------ nodes
    def _hold(self, node, item):
        if not self.cfg.lottery_enabled:
            self._release(node, item)
            return
        item["ticks"] = 0
        if self.cfg.relay_clock == "node":
            self.held[node].append(item)
        else:
            self._at(self.now + P.TICK_S, self._packet_tick, node, item)

    def _packet_tick(self, node, item):
        item["ticks"] += 1
        if item["ticks"] >= P.MAX_TICKS or self.rng.random() < P.RELEASE_P:
            self._release(node, item)
        else:
            self._at(self.now + P.TICK_S, self._packet_tick, node, item)

    def _node_tick(self, node):
        keep = []
        for item in self.held[node]:
            item["ticks"] += 1
            if item["ticks"] >= P.MAX_TICKS or self.rng.random() < P.RELEASE_P:
                self._release(node, item)
            else:
                keep.append(item)
        self.held[node] = keep
        keep = []
        for item in self.held_posts[node]:
            if self.now <= item["since"] + 1e-9:          # first roll is the tick AFTER quorum was seen
                keep.append(item)
                continue
            item["ticks"] += 1
            if item["ticks"] >= P.MAX_TICKS or self.rng.random() < P.RELEASE_P:
                self._post_registry(node, item["c"])
            else:
                keep.append(item)
        self.held_posts[node] = keep
        self._at(self.now + P.TICK_S, self._node_tick, node)

    def _release(self, node, item):
        t = self.now
        self.now = t + self._proc()
        self._send(node, item["dst"], item["blob"], item["leg"], item["sub"], item["kind"],
                   self.lat_int[node, item["dst"]])
        self.now = t

    def _receive(self, node, src, blob, leg, sub, kind, extra):
        me = self.keys[node] if node < P.N_NODES else None
        padded = self.cfg.padding_enabled
        if kind == "relay":
            if src == EXT:                                     # Addressed hop
                nxt = self._role(sub, leg)
                out = X.addressed_hop_forward(blob, me, self.keys[nxt], self._target(), padded)
                self._hold(node, dict(dst=nxt, blob=out, leg=leg + 1, sub=sub, kind="relay"))
                return
            inner = X.transit_unwrap(me.transit, blob, padded)
            try:                                               # terminal: payload opens under my terminus key
                plain = X.ecies_decrypt(me.terminus, inner)
                self._terminal(node, plain, leg, sub)
                return
            except Exception:
                pass
            dest = self.route_table[inner[:X.ROUTING_CODE_LEN]]   # Random hop consumes routing code
            out = X.transit_wrap(self.keys[dest].transit.pk, inner[X.ROUTING_CODE_LEN:], self._target())
            self._hold(node, dict(dst=dest, blob=out, leg=leg + 1, sub=sub, kind="relay"))
        elif kind == "cv1":
            vi = node - VAL0
            V = self.vkeys[vi]
            reply = X.cv2(blob, V, self.keys[src], self._target(), padded)
            self.now += self.rng.uniform(*P.VALIDATOR_PROC_MS) / 1000
            self._send(node, src, reply, CV2, sub, "cv2", self.lat_int[node, src])
        elif kind == "cv2":
            st = self.cstate[sub]
            inner = X.transit_unwrap(me.transit, blob, padded)
            wrapped, vsig = inner[4:52], inner[52:116]
            self.vkeys[st["V"]].sign.public_key().verify(vsig, wrapped)
            assert X.blindshare_decrypt(st["bsk"], wrapped) == st["ph"]   # C's own check
            gks = [int(g) for g in self.rng.permutation([v for v in range(P.N_NODES) if v != node])[:3]]
            pkts, _ = X.gk_fanout(st["ph"], wrapped, vsig, st["bsk"], me, [self.keys[g] for g in gks],
                                  [self._target() for _ in gks])
            del st["bsk"]                                        # BlindShare_key discarded
            for j, (g, p) in enumerate(zip(gks, pkts)):
                self._hold(node, dict(dst=g, blob=p, leg=GK1 + j, sub=sub, kind="gk", C=node))
        elif kind == "gk":
            body = X.transit_unwrap(me.transit, blob, padded)
            ph, wrapped, vsig, bsk, csig = body[:32], body[32:80], body[80:144], body[144:176], body[176:240]
            V = self.vkeys[self.cstate[sub]["V"]]
            V.sign.public_key().verify(vsig, wrapped)
            assert X.blindshare_decrypt(bsk, wrapped) == ph
            self.keys[self.cstate[sub]["C"]].sign.public_key().verify(csig, ph)
            me.sign.sign(csig)                                   # Post-j: internal, never on an observed link
            t_post = self.now + self.rng.uniform(*P.GATEKEEPER_PROC_MS) / 1000
            self._at(t_post, lambda: self.boards[node][ph].add(t_post))
        elif kind == "gossip":
            origin, first = extra
            if first and node not in self.registry_seen[(sub, origin)]:
                self.registry_seen[(sub, origin)].add(node)
                t = self.now + self.rng.uniform(*P.GOSSIP_VALIDATE_MS) / 1000
                for u in self.mesh[node]:
                    if u != origin:
                        self._at(t + self.rng.uniform(0, 1e-3), self._gossip_send, node, u, blob, sub, origin)

    def _gossip_send(self, node, u, blob, sub, origin):
        self._send(node, u, blob, REG_RELAY, sub, "gossip", self.lat_int[node, u], rtype=P.RT_NOISE,
                   extra=(origin, False))
        self.events[-1] = self.events[-1][:4] + (self.gossip_wire,) + self.events[-1][5:]

    def _terminal(self, node, plain, leg, sub):
        if leg == CRED3:
            enc_token, ph = plain[:81], plain[89:121]
            pkt, bsk = X.cv1(enc_token, ph, self.vkeys[self.cstate[sub]["V"]], self._target())
            self.cstate[sub].update(bsk=bsk, ph=ph, C=node)
            self.now += self._proc()
            v = VAL0 + self.cstate[sub]["V"]
            self._send(node, v, pkt, CV1, sub, "cv1", self.lat_int[node, v])
        else:
            ch, n = plain[:32], plain[32:48]
            ph = hashlib.sha256(ch + n).digest()                 # PacketHash' recomputed at F / I
            self.pending_content[node].append(dict(ph=ph, ch=ch, sub=sub,
                                                   leg=REG_F_ORIGIN if leg == CA3 else REG_I_ORIGIN))
            if not self.cstate.get(("poll", node)):
                self.cstate[("poll", node)] = True
                self._at(LT.next_tick(self.now, self.phase[node]), self._poll, node)

    def _poll(self, node):
        """F / I check the three boards on their own tick; post once 2-of-3 agree."""
        keep = []
        for c in self.pending_content[node]:
            votes = sum(1 for g in range(P.N_NODES) if c["ph"] in self.boards[g])
            if votes >= 2:
                self._hold_post(node, c)
            else:
                keep.append(c)
        self.pending_content[node] = keep
        if keep:
            self._at(self.now + P.TICK_S, self._poll, node)
        else:
            self.cstate[("poll", node)] = False

    def _hold_post(self, node, c):
        """Adopted F/I hold: the posting rolls the lottery on this node's own clock (or, for the
        "fresh" check, on a clock with a new random phase), starting at the next tick."""
        cfg = self.cfg
        if not (cfg.reg_hold and cfg.lottery_enabled):
            self._post_registry(node, c)
            return
        if cfg.relay_clock == "node" and cfg.reg_hold_phase == "node":
            self.held_posts[node].append(dict(c=c, ticks=0, since=self.now))
            return
        first = self.now + P.TICK_S if cfg.relay_clock == "packet" else \
            float(LT.next_tick(self.now, self.rng.uniform(0, P.TICK_S)))
        self._at(first, self._post_timer, node, dict(c=c, ticks=0))

    def _post_timer(self, node, item):
        item["ticks"] += 1
        if item["ticks"] >= P.MAX_TICKS or self.rng.random() < P.RELEASE_P:
            self._post_registry(node, item["c"])
        else:
            self._at(self.now + P.TICK_S, self._post_timer, node, item)

    def _post_registry(self, node, c):
        entry = X.reg_posting(c["ch"], self.keys[node])
        self.registry[c["ch"]].append((node, entry))
        if len({n for n, _ in self.registry[c["ch"]]}) == 2 and self.subs[c["sub"]]["finalized"] is None:
            self.subs[c["sub"]]["finalized"] = self.now
        self.registry_seen[(c["sub"], node)].add(node)
        t = self.now + self._proc()
        for u in range(P.N_NODES):
            if u != node:
                self._at(t + self.rng.uniform(0, 1e-3), self._gossip_origin_send, node, u, entry, c)

    def _gossip_origin_send(self, node, u, entry, c):
        self._send(node, u, entry, c["leg"], c["sub"], "gossip", self.lat_int[node, u], rtype=P.RT_NOISE,
                   extra=(node, True))
        self.events[-1] = self.events[-1][:4] + (self.gossip_wire,) + self.events[-1][5:]

    # ------------------------------------------------------------------ routing
    def _role(self, sub, leg):
        s = self.subs[sub]
        if "B" not in s:
            used = {s["C"], s["F"], s["I"]}
            free = [v for v in range(P.N_NODES) if v not in used]
            # the Random hop is chosen by the Addressed hop, independent of the routing table,
            # excluding every other role in this submission (G6)
            pick = self.rng.permutation(free)
            s["B"], s["E"], s["H"] = int(pick[0]), int(pick[1]), int(pick[2])
        return {CRED1: s["B"], CA1: s["E"], CB1: s["H"]}[leg]

    # ------------------------------------------------------------------ verification
    def verify_registry(self) -> dict:
        ok = bad = 0
        for ch, posts in self.registry.items():
            for node, entry in posts:
                try:
                    self.keys[node].sign.public_key().verify(entry[32:], entry[:32])
                    ok += 1
                except Exception:
                    bad += 1
        return dict(valid_postings=ok, invalid_postings=bad,
                    finalized=sum(1 for s in self.subs if s["finalized"] is not None),
                    submissions=len(self.subs))

    def event_table(self):
        a = np.array(self.events, dtype=float)
        cols = ("t_send", "t_arr", "src", "dst", "size", "rtype", "leg", "sub", "ext_src")
        return {c: a[:, i] for i, c in enumerate(cols)}


def simulate(cfg: P.Config, seed: int, horizon_s: float):
    sim = RefSim(cfg, seed)
    rate = 1.0 / (cfg.interval_min * 60.0)
    for d in range(cfg.devices):
        for t in np.sort(sim.rng.uniform(0, horizon_s, sim.rng.poisson(rate * horizon_s))):
            sim.submit(float(t), d)
    sim.run(horizon_s + 40 * 60)
    return sim
