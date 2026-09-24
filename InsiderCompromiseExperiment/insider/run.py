"""Run the insider experiment.

    python -m insider.run --tier 1          # F, I, C at L = 4, plus the GPA anchor at L = 4
    python -m insider.run --tier 2          # follow-up sweep for scenarios Tier 1 flagged
    python -m insider.report

Raw per-run results are appended to results/raw/<job>.pkl.gz; re-running resumes.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import pickle
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from . import LEVEL3  # noqa: F401
from birthmark_l3 import params as P
from birthmark_l3.sweep import seed_for as gpa_seed_for

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "results" / "raw"
RUNS = P.RUNS_PER_SETTING                       # 200, matching the GPA experiment
TIER1_POINT = (40, 20)                          # L = 4 in the workbook's Little's-law table
TIER2_POINTS = [(40, 10), (80, 10), (120, 10), (200, 10)]   # L = 8, 16, 24, 40
L_OF = {(d, i): L for d, i, L in P.SWEEP}
SCENARIOS = ("F", "I", "C")                     # priority order


def tier1_jobs():
    d, i = TIER1_POINT
    J = [(f"t1_{s}", s, d, i) for s in SCENARIOS]
    J.append(("gpa_anchor_L4", "GPA", d, i))
    return J


def tier2_jobs(scenarios):
    return [(f"t2_{s}_{d}_{i}", s, d, i) for s in scenarios for d, i in TIER2_POINTS]


def seed_for(job, k):
    if job == "gpa_anchor_L4":                  # paired with the published GPA runs at L = 4
        return gpa_seed_for(f"main_{TIER1_POINT[0]}_{TIER1_POINT[1]}", k)
    return int.from_bytes(hashlib.sha256(f"insider:{job}:{k}".encode()).digest()[:4], "big")


_W = {}


def _worker(job, scenario, devices, interval, k):
    from birthmark_l3 import attack as A
    from birthmark_l3 import fastsim as FS
    from birthmark_l3.wire_pools import Pools
    from . import core as K
    if "pools" not in _W:
        _W["pools"] = Pools()
        _W["model"] = K.build_model(_W["pools"])
    cfg = K.adopted_config(devices, interval)
    if "lik" not in _W:
        _W["lik"] = A.build_likelihoods(cfg)
    t = time.time()
    if scenario == "GPA":
        out = A.attack_run(FS.simulate(cfg, seed_for(job, k), _W["pools"]), _W["lik"], _W["pools"], rng_seed=k)
    else:
        out = K.run_scenario(scenario, cfg, seed_for(job, k), _W["pools"], _W["lik"], _W["model"])
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


def triggered_scenarios():
    path = ROOT / "results" / "tier1_trigger.json"
    return json.loads(path.read_text())["triggered"] if path.exists() else []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", type=int, required=True)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    a = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    J = tier1_jobs() if a.tier == 1 else tier2_jobs(triggered_scenarios())
    tasks = []
    for job, scn, d, i in J:
        done = {r["run"] for r in load(job)}
        tasks += [(job, scn, d, i, k) for k in range(RUNS) if k not in done]
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
