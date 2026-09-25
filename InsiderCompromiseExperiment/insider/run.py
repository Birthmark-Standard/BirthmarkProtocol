"""Run the insider experiment (Insider Experiment Design, corrected run).

    python -m insider.run          # both configurations, F / I / C, 80 / 240 / 400 devices
    python -m insider.report

Configurations (Insider Experiment Design):
  excl          corrected role rules + gatekeeper exclusion + 3-way fan-out; C's plain signature
  ring          the same, with C's signature ring-signed over the 17-node C-candidate pool
  gkhold        ring + each gatekeeper holds before countersigning and posting, on its own
                dedicated hold clock (phase drawn once per gatekeeper)
  gkhold_fresh  ring + the same hold with a fresh phase for every held post (check)
Interval is held at 20 minutes, so L = 8, 24, 40 (Insider Experiment Design!B7, flagged assumption).

Raw per-run results are appended to results/raw/<job>.pkl.gz; re-running resumes. Runs are
paired across all configurations (same seed per scenario, device count and run index).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import pickle
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from . import LEVEL3  # noqa: F401
from birthmark_l3 import params as P

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "results" / "raw"
RUNS = P.RUNS_PER_SETTING                       # 200, matching the GPA experiment
INTERVAL_MIN = 20
DEVICES = (80, 240, 400)
# name -> adopted_config overrides. Seeds are paired across all configurations.
CONFIGS = {"excl": dict(ring_sig=False),
           "ring": dict(ring_sig=True),
           "gkhold": dict(ring_sig=True, gk_hold="gatekeeper"),          # redesign + gatekeeper hold
           "gkhold_fresh": dict(ring_sig=True, gk_hold="fresh")}         # check: fresh phase per post
SCENARIOS = ("F", "I", "C")                     # priority order


def L_of(devices, interval=INTERVAL_MIN):
    return devices / interval * 2.0             # Little's law with the workbook's 2-minute mean jitter


def jobs():
    return [(f"{c}_{s}_{d}", c, s, d) for c in CONFIGS for s in SCENARIOS for d in DEVICES]


def seed_for(scenario, devices, k):
    return int.from_bytes(hashlib.sha256(f"insider-v2:{scenario}:{devices}:{k}".encode()).digest()[:4], "big")


_W = {}


def _worker(job, config, scenario, devices, k):
    from birthmark_l3 import attack as A
    from birthmark_l3.wire_pools import Pools
    from . import core as K
    if "pools" not in _W:
        _W["pools"] = Pools()
    kw = CONFIGS[config]
    cfg = K.adopted_config(devices, INTERVAL_MIN, **kw)
    key = kw.get("gk_hold", "")           # the attacker's models follow the protocol being attacked
    if key not in _W:
        _W[key] = (K.build_model(_W["pools"], gk_hold=key), A.build_likelihoods(cfg))
    model, lik = _W[key]
    t = time.time()
    out = K.run_scenario(scenario, cfg, seed_for(scenario, devices, k), _W["pools"], lik, model)
    out["run"], out["seconds"] = k, time.time() - t
    return job, out


def load(job):
    p = RAW / f"{job}.pkl.gz"
    res = []
    if p.exists():
        with gzip.open(p, "rb") as f:
            while True:
                try:
                    res.append(pickle.load(f))
                except (EOFError, OSError, pickle.UnpicklingError):
                    break
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    a = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    J = jobs()
    tasks = []
    for job, c, s, d in J:
        done = {r["run"] for r in load(job)}
        tasks += [(job, c, s, d, k) for k in range(RUNS) if k not in done]
    tasks.sort(key=lambda t: (t[4], t[0]))
    print(f"{len(tasks)} runs across {len(J)} jobs", flush=True)
    handles, t0 = {}, time.time()
    with ProcessPoolExecutor(a.workers) as ex:
        futs = [ex.submit(_worker, *t) for t in tasks]
        for n, f in enumerate(as_completed(futs), 1):
            job, out = f.result()
            if job not in handles:
                handles[job] = gzip.open(RAW / f"{job}.pkl.gz", "ab")
            pickle.dump(out, handles[job])
            handles[job].flush()
            if n % 100 == 0 or n == len(futs):
                print(f"{n}/{len(futs)} done, {(time.time() - t0) / 60:.1f} min", flush=True)
    for h in handles.values():
        h.close()


if __name__ == "__main__":
    main()
