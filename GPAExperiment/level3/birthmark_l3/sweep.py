"""Run the Level 3 sweep and probes.

    python -m birthmark_l3.sweep --jobs all --workers 4
    python -m birthmark_l3.sweep --jobs main --runs 20      # quick look

Every run's compact result is appended to results/raw/<job>.pkl.gz; re-running resumes.
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

import numpy as np

from . import params as P

RAW = Path(__file__).resolve().parent.parent / "results" / "raw"
PROBE_SETTING = (80, 15)        # L = 10.7 in the workbook table: mid-low, where leaks show first
SENS_SETTING = (120, 15)        # L = 16: mid-sweep


def jobs(runs_main: int, runs_probe: int, runs_sens: int):
    J = []
    for dev, iv, L in P.SWEEP:
        J.append((f"main_{dev}_{iv}", P.Config(devices=dev, interval_min=iv), runs_main, L))
    d, iv = PROBE_SETTING
    L = dict(((a, b), c) for a, b, c in P.SWEEP)[(d, iv)]
    base = P.Config(devices=d, interval_min=iv)
    J += [
        ("probe_packet_clock", base.with_(relay_clock="packet"), runs_probe, L),
        ("probe_shared_device_clock", base.with_(device_clock="shared"), runs_probe, L),
        ("probe_both_leaks", base.with_(relay_clock="packet", device_clock="shared"), runs_probe, L),
        ("control_no_lottery", base.with_(lottery_enabled=False), runs_probe, L),
    ]
    d, iv = SENS_SETTING
    L = dict(((a, b), c) for a, b, c in P.SWEEP)[(d, iv)]
    base = P.Config(devices=d, interval_min=iv)
    for bg in (0, 5, 100):     # 25 = the main sweep's own runs at this setting
        J.append((f"bg_{bg}", base.with_(bg_clients_per_node=bg), runs_sens, L))
    J.append(("record_type_ignored", base.with_(attacker_reads_record_type=False), runs_sens, L))
    return J


def seed_for(job: str, i: int) -> int:
    # background/bg-sensitivity jobs share seeds with the main run at the same setting so the
    # comparison is paired; everything else gets its own stream
    key = job
    if job.startswith("bg_") or job == "record_type_ignored":
        key = f"main_{SENS_SETTING[0]}_{SENS_SETTING[1]}"
    return int.from_bytes(hashlib.sha256(f"{key}:{i}".encode()).digest()[:4], "big")


_W = {}


def _worker(job, cfg, i):
    from . import attack as A
    from . import fastsim as F
    from .wire_pools import Pools
    if "pools" not in _W:
        _W["pools"] = Pools()
    key = (cfg.relay_clock, cfg.device_clock, cfg.lottery_enabled)
    if key not in _W:
        _W[key] = A.build_likelihoods(cfg)
    t = time.time()
    run = F.simulate(cfg, seed_for(job, i), _W["pools"])
    out = A.attack_run(run, _W[key], _W["pools"], rng_seed=i)
    out["run"] = i
    out["seconds"] = time.time() - t
    return job, out


def load(job: str) -> list[dict]:
    p = RAW / f"{job}.pkl.gz"
    if not p.exists():
        return []
    res = []
    with gzip.open(p, "rb") as f:
        while True:
            try:
                res.append(pickle.load(f))
            except (EOFError, OSError, pickle.UnpicklingError):   # tail of an interrupted append
                break
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", default="all", help="all | main | probes | comma list of job names")
    ap.add_argument("--runs", type=int, default=P.RUNS_PER_SETTING)
    ap.add_argument("--probe-runs", type=int, default=20)
    ap.add_argument("--sens-runs", type=int, default=50)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    a = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    J = jobs(a.runs, a.probe_runs, a.sens_runs)
    if a.jobs == "main":
        J = [j for j in J if j[0].startswith("main_")]
    elif a.jobs == "probes":
        J = [j for j in J if not j[0].startswith("main_")]
    elif a.jobs != "all":
        want = set(a.jobs.split(","))
        J = [j for j in J if j[0] in want]
    tasks = []
    for name, cfg, n, _ in J:
        done = {r["run"] for r in load(name)}
        tasks += [(name, cfg, i) for i in range(n) if i not in done]
    # interleave settings so partial results cover the whole sweep early
    tasks.sort(key=lambda t: (t[2], t[0]))
    print(f"{len(tasks)} runs to do across {len(J)} jobs", flush=True)
    t0, handles = time.time(), {}
    with ProcessPoolExecutor(a.workers) as ex:
        futs = [ex.submit(_worker, *t) for t in tasks]
        for k, f in enumerate(as_completed(futs), 1):
            job, out = f.result()
            if job not in handles:
                handles[job] = gzip.open(RAW / f"{job}.pkl.gz", "ab")
            pickle.dump(out, handles[job])
            handles[job].flush()
            if k % 50 == 0 or k == len(futs):
                el = time.time() - t0
                print(f"{k}/{len(futs)} done, {el/60:.1f} min elapsed, ~{el/k*(len(futs)-k)/60:.1f} min left", flush=True)
    for h in handles.values():
        h.close()


if __name__ == "__main__":
    main()
