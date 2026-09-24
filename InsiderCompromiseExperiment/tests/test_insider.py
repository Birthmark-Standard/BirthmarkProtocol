"""Run from InsiderCompromiseExperiment/:   python -m pytest -q tests"""
import re
from pathlib import Path

import numpy as np
import pytest
from scipy.stats import ks_2samp

from insider import core as K
from birthmark_l3 import attack as A
from birthmark_l3 import lottery as LT
from birthmark_l3 import params as P
from birthmark_l3 import fastsim as FS
from birthmark_l3.wire_pools import Pools


@pytest.fixture(scope="module")
def pools():
    return Pools()


def test_insider_never_reads_device_identity_or_truth_labels_as_observations():
    """The insider's scoring code must not use device IPs (ext_src) or ground-truth kind/leg
    labels for events it could not label itself. Truth columns appear only in evaluation."""
    src = (Path(K.__file__)).read_text()
    assert "ext_src" not in src
    scoring = src.split("def _evaluate")[0] + src.split("def content_scenario")[1]
    for bad in ('ev["kind"]',):
        assert bad not in scoring


def test_catalog_role_rules(pools):
    run = FS.simulate(K.adopted_config(200, 10, bg_clients_per_node=0, nonblending_enabled=False), 3, pools)
    s = run.subs
    C, F, I, A_, B, D, E, G, H = (s[k] for k in "C F I A B D E G H".split())
    assert np.all((C != F) & (C != I) & (F != I))
    for x in (A_, D, G):
        assert np.all((x != C) & (x != F) & (x != I))
    assert np.all((B != A_) & (B != C) & (E != D) & (E != F) & (H != G) & (H != I))
    self_gk = ~s["gk_valid"]
    assert self_gk.any()                                         # C as its own gatekeeper happens
    assert np.all(s["ev_gk"][self_gk] == -1)                     # and then no leg is on the wire


def test_detection_tick_is_on_the_servers_own_grid(pools):
    run = FS.simulate(K.adopted_config(200, 10, bg_clients_per_node=0, nonblending_enabled=False), 4, pools)
    s = run.subs
    for role, key in (("F", "det_f"), ("I", "det_i")):
        off = np.mod(s[key] - run.phase[s[role]], P.TICK_S)
        assert np.all(np.minimum(off, P.TICK_S - off) < 1e-6)
        assert np.all(s["reg_f" if role == "F" else "reg_i"] > s[key])   # adopted hold comes after


def test_model_matches_fresh_simulation(pools):
    """The Monte-Carlo model describes simulations it was not built from."""
    model = K.build_model(pools, n_runs=6)
    run = FS.simulate(K.adopted_config(200, 10, bg_clients_per_node=0, nonblending_enabled=False), 77, pools)
    d1, d2, cens = K._content_features(run, "F")
    rng = np.random.default_rng(0)
    # sample from the model's histogram and compare with fresh data
    def sample(pdf, n):
        p = np.exp(pdf.logd); p /= p.sum()
        return pdf.lo + (rng.choice(p.size, n, p=p) + rng.random(n)) * pdf.bw
    assert ks_2samp(d1[~cens], sample(model.d1_unc, 5000)).pvalue > 0.001
    assert ks_2samp(d2[cens], sample(model.d2_cens, 5000)).pvalue > 0.001
    assert abs(cens.mean() - model.p_cens) < 0.05


def test_full_variant_is_near_perfect_without_lottery(pools):
    """Positive control: with the lottery off, the full insider view pins every pairing."""
    cfg = K.adopted_config(40, 20, lottery_enabled=False)
    lik = A.build_likelihoods(cfg, n=200_000)
    model = K.build_model(pools, n_runs=4)
    hits = n = 0
    for seed in range(6):
        run = FS.simulate(cfg, 500 + seed, pools)
        for X in range(P.N_NODES):
            o = K.content_scenario(run, pools, lik, model, "F", X, np.random.default_rng(seed))
            hits += int(o["full"]["correct"].sum()); n += o["n_scored"]
    assert n > 50 and hits / n > 0.95
