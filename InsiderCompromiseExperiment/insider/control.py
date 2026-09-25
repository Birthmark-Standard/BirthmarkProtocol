"""Isolating control for the gatekeeper posting hold.

Every other lottery hold is off (relay hops, C fan-out, F/I hold), the ring signature is on, and
the only change between the two arms is the gatekeeper posting hold. 40 devices, 20-minute
interval (L = 4). With the lottery off, the timing variant alone already pins most pairings, so
the arms are compared on the legs variant, which scores only the GK-leg search and the quorum
agreement with no content-arrival timing. The full and timing variants are recorded as well.

    python -m insider.control
"""
from __future__ import annotations

import json

import numpy as np

from . import LEVEL3  # noqa: F401
from birthmark_l3 import attack as A
from birthmark_l3 import fastsim as FS
from birthmark_l3 import params as P
from birthmark_l3.wire_pools import Pools
from . import core as K
from .run import ROOT

DEVICES, SEEDS = 40, range(700, 710)


def measure(pools=None):
    pools = pools or Pools()
    out = {}
    for gk in ("", "gatekeeper"):
        cfg = K.adopted_config(DEVICES, 20, lottery_enabled=False, ring_sig=True, gk_hold=gk)
        lik = A.build_likelihoods(cfg, n=200_000)
        model = K.build_model(pools, n_runs=5, lottery_enabled=False, gk_hold=gk)
        acc = {v: [0, 0, 0.0] for v in ("timing", "full", "legs")}   # hits, n, chance
        for seed in SEEDS:
            run = FS.simulate(cfg, seed, pools)
            for X in range(P.N_NODES):
                o = K.content_scenario(run, pools, lik, model, "F", X, np.random.default_rng(seed))
                for v in acc:
                    acc[v][0] += int(o[v]["correct"].sum())
                    acc[v][1] += o["n_scored"]
                    acc[v][2] += o[v]["chance"]
        out[gk or "no_hold"] = {v: dict(accuracy=h / n, random_assignment=c / n, n=n)
                                for v, (h, n, c) in acc.items()}
    out["L"] = DEVICES / 20 * 2.0
    return out


if __name__ == "__main__":
    r = measure()
    (ROOT / "results" / "control.json").write_text(json.dumps(r, indent=1))
    print(json.dumps(r, indent=1))
