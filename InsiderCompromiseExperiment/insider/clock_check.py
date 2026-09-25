"""Direct measurement that the gatekeeper posting hold runs on independent clocks.

For the "gatekeeper" mode (one dedicated hold clock per gatekeeper, phase drawn once), across many
runs and submissions:
  1. every post sits on its own gatekeeper's hold-clock grid (within gatekeeper processing time);
  2. each hold-clock phase is independent of that gatekeeper's relay clock, of the other two
     gatekeepers' hold clocks, of C's fan-out clock and of F's and I's clocks (phase differences
     uniform across runs);
  3. the three gatekeepers' hold lengths within one submission are uncorrelated.
For the "fresh" mode (new phase per held post), posts of one gatekeeper do not share a grid, and
hold lengths are again uncorrelated.

    python -m insider.clock_check
"""
from __future__ import annotations

import json
from itertools import combinations

import numpy as np
from scipy.stats import kstest, spearmanr

from . import LEVEL3  # noqa: F401
from birthmark_l3 import fastsim as FS
from birthmark_l3 import lottery as LT
from birthmark_l3 import params as P
from birthmark_l3.wire_pools import Pools
from . import core as K
from .run import ROOT

PROC_MAX_S = P.GATEKEEPER_PROC_MS[1] / 1000


def _circ(x):
    return np.mod(x, P.TICK_S) / P.TICK_S


def measure(n_runs=150, devices=400, seed0=770_000, pools=None):
    """Phase comparisons use ONE pair per run, so the samples fed to each KS test are independent
    (the three pairwise differences within a run are linked, and all of a run's C nodes share the
    same three hold phases)."""
    pools = pools or Pools()
    pick = np.random.default_rng(1)
    out = {}
    for mode in ("gatekeeper", "fresh"):
        on_grid, d_relay, d_between, d_c, d_fi, corr_p, hold_mean, grid_share = [], [], [], [], [], [], [], []
        for k in range(n_runs):
            cfg = K.adopted_config(devices, 20, gk_hold=mode, bg_clients_per_node=0, nonblending_enabled=False)
            run = FS.simulate(cfg, seed0 + k, pools)
            s, ph = run.subs, run.phase
            gks = s["gk"][0]
            ticks = np.empty((s["t0"].size, 3))
            for j, g in enumerate(gks):
                post, arr = s["posts"][:, j], s["gk_arr"][:, j]
                if mode == "gatekeeper":
                    hp = s["gk_hold_phase"][g]
                    off = np.mod(post - hp, P.TICK_S)
                    on_grid.append(np.mean(off <= PROC_MAX_S + 1e-9))
                    ticks[:, j] = np.round((post - LT.next_tick(arr, hp)) / P.TICK_S) + 1
                    d_relay.append(_circ(hp - ph[g]))
                else:
                    # a shared grid would concentrate post phases; fresh phases spread them uniformly
                    grid_share.append(kstest(_circ(post), "uniform").pvalue)
                    ticks[:, j] = np.ceil((post - arr - PROC_MAX_S) / P.TICK_S)
                hold_mean.append(float(np.mean(post - arr)))
            if mode == "gatekeeper":
                hp3 = s["gk_hold_phase"][gks]
                a, b = pick.choice(3, 2, replace=False)
                d_between.append(_circ(hp3[a] - hp3[b]))
                g = pick.integers(3)
                d_c.append(_circ(hp3[g] - ph[pick.choice(np.unique(s["C"]))]))
                d_fi.append(_circ(hp3[g] - ph[pick.choice(np.unique(np.concatenate([s["F"], s["I"]])))]))
            for a, b in combinations(range(3), 2):
                corr_p.append(spearmanr(ticks[:, a], ticks[:, b])[1])
        res = dict(runs=n_runs, mean_hold_s=float(np.mean(hold_mean)),
                   hold_length_corr_pvalues_uniform_p=float(kstest(corr_p, "uniform").pvalue),
                   min_hold_corr_p=float(np.min(corr_p)))
        if mode == "gatekeeper":
            res.update(
                posts_on_own_hold_grid=float(np.min(on_grid)),
                hold_vs_own_relay_clock_uniform_p=float(kstest(d_relay, "uniform").pvalue),
                hold_between_gatekeepers_uniform_p=float(kstest(d_between, "uniform").pvalue),
                hold_vs_C_fanout_clock_uniform_p=float(kstest(d_c, "uniform").pvalue),
                hold_vs_F_I_clocks_uniform_p=float(kstest(d_fi, "uniform").pvalue))
        else:
            res["post_phases_uniform_pvalues_uniform_p"] = float(kstest(grid_share, "uniform").pvalue)
        out[mode] = res
    return out


if __name__ == "__main__":
    r = measure()
    (ROOT / "results" / "clock_check.json").write_text(json.dumps(r, indent=1))
    print(json.dumps(r, indent=1))
