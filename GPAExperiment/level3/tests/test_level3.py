"""Checks that the simulator implements the workbook and that the attack is not broken.

Run from GPAExperiment/level3:   python -m pytest -q tests
"""
import numpy as np
import pytest
from scipy.stats import ks_2samp

from birthmark_l3 import attack as A
from birthmark_l3 import crypto_legs as X
from birthmark_l3 import fastsim as F
from birthmark_l3 import lottery as LT
from birthmark_l3 import params as P
from birthmark_l3 import refsim as R
from birthmark_l3.wire_pools import Pools


@pytest.fixture(scope="module")
def pools():
    return Pools()


# ------------------------------------------------------------------ lottery
def test_lottery_matches_workbook():
    rng = np.random.default_rng(0)
    k = LT.draw_ticks(rng, 2_000_000)
    assert k.min() == 1 and k.max() == P.MAX_TICKS          # forced release at 30 ticks
    assert abs(np.mean(k == 1) - P.RELEASE_P) < 0.001       # 8.33% on the first tick
    assert abs(np.mean(k) * P.TICK_S - LT.lottery_mean_s()) < 0.5
    assert 110 < LT.lottery_mean_s() < 112                 # 111 s, not the nominal 120 s


def test_node_clock_releases_on_grid():
    rng = np.random.default_rng(1)
    t = rng.uniform(0, 1e4, 10_000)
    rel = LT.release_time(rng, t, 3.21, "node")
    r = np.mod(rel - 3.21, P.TICK_S)
    assert np.all(np.minimum(r, P.TICK_S - r) < 1e-6)
    assert np.all(rel > t) and np.all(rel - t <= P.MAX_TICKS * P.TICK_S)


# ------------------------------------------------------------------ payloads and padding
def test_every_leg_fits_under_padding_floor():
    for leg, wb, measured, _ in X.size_verification_report():
        assert measured < P.PAD_MIN, leg


def test_padding_makes_size_independent_of_leg(pools):
    run = F.simulate(P.Config(devices=40, interval_min=10, bg_clients_per_node=0, nonblending_enabled=False), 3, pools)
    e = run.events
    sizes = {}
    for leg in (F.CRED1, F.CRED3, F.CA3, F.CV1, F.CV2, F.GK1):
        sizes[leg] = e["size"][e["leg"] == leg]
    ref = sizes[F.CRED1]
    for leg, s in sizes.items():
        assert s.min() >= P.PAD_MIN + 22 and s.max() <= P.PAD_MAX + 22
        assert ks_2samp(ref, s).pvalue > 0.001, F.LEG_NAMES[leg]


# ------------------------------------------------------------------ measured pools are diverse
def test_pools_are_diverse(pools):
    s = pools.summary()
    assert s["tls_sessions"] >= 300 and s["distinct_session_size_signatures"] >= 300
    assert s["distinct_clienthello_sizes"] >= 20
    assert s["distinct_dns_response_sizes"] >= 100
    assert s["tls13_record_overhead"] == 22


# ------------------------------------------------------------------ reference vs fast simulator
def _timings(ev, leg_a, leg_b):
    """Per submission: send time of leg_b minus arrival time of leg_a."""
    a = {int(s): t for s, t, l in zip(ev["sub"], ev["t_arr"], ev["leg"]) if l == leg_a}
    b = {int(s): t for s, t, l in zip(ev["sub"], ev["t_send"], ev["leg"]) if l == leg_b}
    return np.array([b[s] - a[s] for s in a if s in b])


@pytest.mark.parametrize("clock", ["node", "packet"])
def test_fastsim_matches_reference(pools, clock):
    cfg = P.Config(devices=40, interval_min=10, relay_clock=clock, bg_clients_per_node=0, nonblending_enabled=False)
    ref = R.simulate(cfg, 21, 3 * 3600)
    assert ref.verify_registry()["invalid_postings"] == 0
    assert ref.verify_registry()["finalized"] == ref.verify_registry()["submissions"]
    re = ref.event_table()
    fe = F.simulate(cfg, 22, pools).events
    for a, b in [(F.CRED1, F.CRED2), (F.CRED2, F.CRED3), (F.CA1, F.CA2), (F.CB2, F.CB3), (F.CV2, F.GK1)]:
        x, y = _timings(re, a, b), _timings(fe, a, b)
        assert ks_2samp(x, y).pvalue > 0.001, (F.LEG_NAMES[a], F.LEG_NAMES[b])
    # end to end: registry gossip origination after the Cred-1 departure
    x = _timings(re, F.CRED1, F.REG_F_ORIGIN)
    y = _timings(fe, F.CRED1, F.REG_F_ORIGIN)
    assert ks_2samp(x, y).pvalue > 0.001


# ------------------------------------------------------------------ the attack is not broken
def test_positive_control_attack_succeeds(pools):
    """With the lottery switched off, the same attack code must link nearly everything."""
    cfg = P.Config(devices=80, interval_min=15, lottery_enabled=False)
    out = A.attack_run(F.simulate(cfg, 4, pools), A.build_likelihoods(cfg, n=300_000), pools)
    assert out["main"]["correct"].mean() > 0.9
    assert out["diag"]["hop_acc"] > 0.95


def test_phase_leak_probe_breaks_stage1(pools):
    cfg = P.Config(devices=80, interval_min=15, relay_clock="packet")
    out = A.attack_run(F.simulate(cfg, 5, pools), A.build_likelihoods(cfg, n=300_000), pools)
    assert out["diag"]["hop_acc"] > 0.9


def test_shared_device_clock_probe_breaks_stage2(pools):
    cfg = P.Config(devices=80, interval_min=15, device_clock="shared")
    out = A.attack_run(F.simulate(cfg, 6, pools), A.build_likelihoods(cfg, n=300_000), pools)
    assert out["diag"]["oracle_stage2"]["correct"].mean() > 0.4


def test_nonblending_traffic_never_enters_chains(pools):
    cfg = P.Config(devices=80, interval_min=15)
    out = A.attack_run(F.simulate(cfg, 7, pools), A.build_likelihoods(cfg, n=300_000), pools)
    assert out["diag"]["chain_events_by_kind"]["keepalive"] == 0
    assert out["diag"]["grid_detected"] == P.N_NODES
    assert out["diag"]["grid_phase_err_ms"] < 5
