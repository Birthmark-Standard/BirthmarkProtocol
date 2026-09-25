"""Aggregate the corrected insider run into results/summary.json and results/summary.csv.

    python -m insider.report

Comparison points share L (and so submission rate) with this run's device counts:
  80 devices / 20 min  (L = 8)   first run: 40 / 10    GPA: main_80_20 (same point)
  240 devices / 20 min (L = 24)  first run: 120 / 10   GPA: main_120_10
  400 devices / 20 min (L = 40)  first run: 200 / 10   GPA: main_200_10
"""
from __future__ import annotations

import csv
import hashlib
import json

import numpy as np

from . import LEVEL3
from birthmark_l3 import report as R
from .run import CONFIGS, DEVICES, ROOT, SCENARIOS, L_of, load

OUT = ROOT / "results"
FIRST_RUN = OUT / "first_run" / "summary.json"
GPA_SUMMARY = LEVEL3 / "results" / "summary.json"
FIRST_RUN_KEY = {80: "40_10", 240: "120_10", 400: "200_10"}
GPA_KEY = {80: "main_80_20", 240: "main_120_10", 400: "main_200_10"}


def _block(runs, variant, L, key):
    # each block's bootstrap is seeded by its own name, so intervals do not depend on which
    # configurations are aggregated alongside it
    rng = np.random.default_rng(int.from_bytes(hashlib.sha256(key.encode()).digest()[:4], "big"))
    recs = [dict(x=r[variant], n_scored=r["n_scored"], x_chance=r[variant]["chance"]) for r in runs]
    b = R._attack_block(recs, "x", "x_chance", L, rng)
    feas = np.concatenate([r[variant]["feasible"] for r in runs])
    b["feasible_candidates_mean"] = float(feas.mean()) if feas.size else float("nan")
    return b


def summarize():
    first = json.loads(FIRST_RUN.read_text())["tier2"] if FIRST_RUN.exists() else {}
    gpa = json.loads(GPA_SUMMARY.read_text())["jobs"] if GPA_SUMMARY.exists() else {}
    out = {"runs": {}, "first_run": {}, "gpa": {}}
    for c in CONFIGS:
        for s in SCENARIOS:
            for d in DEVICES:
                runs = load(f"{c}_{s}_{d}")
                if not runs:
                    continue
                L = L_of(d)
                rec = dict(config=c, scenario=s, devices=d, interval_min=20, L=L, runs=len(runs),
                           timing=_block(runs, "timing", L, f"{s}_{d}_timing"))
                if s in ("F", "I"):
                    rec["full"] = _block(runs, "full", L, f"{c}_{s}_{d}_full")
                    if all("legs" in r for r in runs):
                        rec["legs"] = _block(runs, "legs", L, f"{c}_{s}_{d}_legs")
                out["runs"][f"{c}_{s}_{d}"] = rec
    for d in DEVICES:
        for s in SCENARIOS:
            f = first.get(f"{s}_{FIRST_RUN_KEY[d]}")
            if f:
                out["first_run"][f"{s}_{d}"] = dict(
                    timing=f["timing"]["accuracy"],
                    full=f.get("full", {}).get("accuracy"),
                    identity_only=f.get("full", {}).get("empirical_chance"),
                    full_without_overlap=(f.get("full_overlap_split") or {}).get("without_overlap", {}).get("accuracy"))
        g = gpa.get(GPA_KEY[d])
        if g:
            out["gpa"][str(d)] = dict(L=g["L_workbook"], sequencing=g["sequencing"]["accuracy"],
                                      sequencing_chance=g["sequencing"]["empirical_chance"],
                                      bound_perfect_chains=g["bound_oracle_chains"]["accuracy"])
    (OUT / "summary.json").write_text(json.dumps(out, indent=1, default=float))
    _csv(out)
    return out


def _csv(out):
    rows = []
    for rec in out["runs"].values():
        d, s = rec["devices"], rec["scenario"]
        fr = out["first_run"].get(f"{s}_{d}", {})
        g = out["gpa"].get(str(d), {})
        for v in ("timing", "full", "legs"):
            if v not in rec:
                continue
            b, c = rec[v], rec[v]["calibration"]
            rows.append(dict(
                config=rec["config"], scenario=s, variant=v, devices=d, interval_min=20, L=rec["L"],
                inv_L=round(1 / rec["L"], 4), runs=rec["runs"], n_scored=b["n_scored"],
                accuracy=round(b["accuracy"], 4), ci_lo=round(b["ci95"][0], 4), ci_hi=round(b["ci95"][1], 4),
                above_inv_L=b["above_inv_L"], random_assignment=round(b["empirical_chance"], 4),
                feasible_candidates=round(b["feasible_candidates_mean"], 2),
                top_decile_accuracy=round(c.get("top_decile", {}).get("accuracy", float("nan")), 4),
                n_gap_ge_2=c.get("gap_ge_2", {}).get("n", 0),
                first_run_same_L=fr.get(v) if fr.get(v) is None else round(fr[v], 4),
                gpa_sequencing_same_L=round(g.get("sequencing", float("nan")), 4)))
    if rows:
        with open(OUT / "summary.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    s = summarize()
    for k, r in s["runs"].items():
        for v in ("timing", "full", "legs"):
            if v in r:
                b = r[v]
                print(f"{k:12s} {v:6s} acc={b['accuracy']:.3f} [{b['ci95'][0]:.3f},{b['ci95'][1]:.3f}] "
                      f"1/L={1 / r['L']:.3f} rand={b['empirical_chance']:.3f} n={b['n_scored']}")
