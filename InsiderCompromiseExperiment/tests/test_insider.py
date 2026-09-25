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


def test_corrected_role_rules_and_gatekeeper_exclusion(pools):
    """Insider Experiment Design!B3-B5: one active gatekeeper set, never C/F/I; B/E/H may be
    C/F/I (self-delivered, no wire leg); fan-out always reaches all three gatekeepers."""
    run = FS.simulate(K.adopted_config(400, 20, bg_clients_per_node=0, nonblending_enabled=False), 3, pools)
    s = run.subs
    C, F, I, A_, B, D, E, G, H = (s[k] for k in "C F I A B D E G H".split())
    gks = set(s["gk"][0].tolist())
    assert np.all(s["gk"] == s["gk"][0]) and len(gks) == 3
    assert not (set(C.tolist()) | set(F.tolist()) | set(I.tolist())) & gks
    assert np.all((C != F) & (C != I) & (F != I))
    for x in (A_, D, G):
        assert np.all((x != C) & (x != F) & (x != I))
    assert np.all((B != A_) & (E != D) & (H != G))
    assert (B == C).any() and (E == F).any()
    assert np.all(s["ev_cred"][B == C, 2] == -1) and np.all(s["ev_ca"][E == F, 2] == -1)
    assert np.all(s["ev_gk"] >= 0)


def test_ring_signature():
    import os
    from birthmark_l3 import ring_sig as RS
    keys = [RS.RingKey() for _ in range(17)]
    ring = [k.pk for k in keys]
    m = os.urandom(32)
    sigs = [RS.sign(m, ring, i, keys[i]) for i in range(17)]
    assert all(RS.verify(m, ring, x) for x in sigs) and len(sigs[0]) == RS.size(17) == 576
    assert not RS.verify(os.urandom(32), ring, sigs[0])
    assert not RS.verify(m, [RS.RingKey().pk] + ring[1:], sigs[4])


def test_ring_gk_leg_size_class(pools):
    from birthmark_l3.crypto_legs import ring_gk_raw_size
    assert ring_gk_raw_size() == 801 <= P.PAD_GK_RING[0]
    run = FS.simulate(K.adopted_config(80, 20, bg_clients_per_node=0, nonblending_enabled=False), 5, pools)
    sz = run.events["size"][run.subs["ev_gk"].ravel()]
    assert sz.min() >= P.PAD_GK_RING[0] + 22 and sz.max() <= P.PAD_GK_RING[1] + 22


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
    run = FS.simulate(K.adopted_config(400, 20, bg_clients_per_node=0, nonblending_enabled=False), 77, pools)
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
    """Positive control: with the lottery off, the full insider view pins every pairing, with and
    without the ring signature."""
    cfg = K.adopted_config(40, 20, lottery_enabled=False)
    lik = A.build_likelihoods(cfg, n=200_000)
    model = K.build_model(pools, n_runs=4, lottery_enabled=False)
    hits = n = 0
    for seed in range(6):
        run = FS.simulate(cfg, 500 + seed, pools)
        for X in range(P.N_NODES):
            o = K.content_scenario(run, pools, lik, model, "F", X, np.random.default_rng(seed))
            hits += int(o["full"]["correct"].sum()); n += o["n_scored"]
    assert n > 50 and hits / n > 0.95
    # and with the ring signature (C unknown), the GK-leg search still pins it with no lottery
    cfg = K.adopted_config(40, 20, lottery_enabled=False, ring_sig=True)
    hits = n = 0
    for seed in range(3):
        run = FS.simulate(cfg, 600 + seed, pools)
        for X in range(P.N_NODES):
            o = K.content_scenario(run, pools, lik, model, "F", X, np.random.default_rng(seed))
            hits += int(o["full"]["correct"].sum()); n += o["n_scored"]
    assert n > 50 and hits / n > 0.9


def test_gatekeeper_hold_clocks_are_independent(pools):
    """Each gatekeeper's posting hold runs on its own clock: posts on its own hold grid, phases
    independent of its relay clock, of the other gatekeepers, of C's and of F/I's clocks, and hold
    lengths uncorrelated across the three gatekeepers (Insider Experiment Design, gatekeeper hold)."""
    from insider.clock_check import measure
    r = measure(n_runs=40, devices=200, pools=pools)
    g = r["gatekeeper"]
    assert g["posts_on_own_hold_grid"] == 1.0
    for k in ("hold_vs_own_relay_clock_uniform_p", "hold_between_gatekeepers_uniform_p",
              "hold_vs_C_fanout_clock_uniform_p", "hold_vs_F_I_clocks_uniform_p",
              "hold_length_corr_pvalues_uniform_p"):
        assert g[k] > 0.001, k
    assert r["fresh"]["post_phases_uniform_pvalues_uniform_p"] > 0.001
    assert 100 < g["mean_hold_s"] < 112


def test_gatekeeper_hold_alone_breaks_the_leg_search(pools):
    """Isolating control. With every other lottery off, the GK-leg search (legs + quorum agreement,
    no content-arrival timing) pins the pairing; adding only the gatekeeper hold breaks it."""
    res = {}
    for gk in ("", "gatekeeper"):
        cfg = K.adopted_config(40, 20, lottery_enabled=False, ring_sig=True, gk_hold=gk)
        lik = A.build_likelihoods(cfg, n=200_000)
        model = K.build_model(pools, n_runs=3, lottery_enabled=False, gk_hold=gk)
        hits = n = 0
        for seed in range(2):
            run = FS.simulate(cfg, 600 + seed, pools)
            for X in range(P.N_NODES):
                o = K.content_scenario(run, pools, lik, model, "F", X, np.random.default_rng(seed))
                hits += int(o["legs"]["correct"].sum()); n += o["n_scored"]
        res[gk] = hits / n
    # measured: about 0.79 without the hold, about 0.24 with it
    assert res[""] > 0.7 and res["gatekeeper"] < 0.5 * res[""]
