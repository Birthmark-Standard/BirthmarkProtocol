"""Aggregate insider results into results/summary.json, results/summary.csv and the Tier 2 trigger.

    python -m insider.report
"""
from __future__ import annotations

import csv
import json

import numpy as np

from . import LEVEL3
from birthmark_l3 import report as R
from .run import L_OF, ROOT, SCENARIOS, TIER1_POINT, TIER2_POINTS, load

OUT = ROOT / "results"
GPA_SUMMARY = LEVEL3 / "results" / "summary.json"
STRONGEST_KNOWN_L4 = 0.122        # GPA perfect-chains bound at L = 4 (strongest known figure there)


def _block(runs, variant, L, rng):
    """Adapt insider records to birthmark_l3.report._attack_block (bootstrap CI + calibration)."""
    recs = [dict(x=r[variant], n_scored=r["n_scored"], x_chance=r[variant]["chance"]) for r in runs]
    b = R._attack_block(recs, "x", "x_chance", L, rng)
    feas = np.concatenate([r[variant]["feasible"] for r in runs])
    b["feasible_candidates_mean"] = float(feas.mean()) if feas.size else float("nan")
    return b


def _overlap_split(runs):
    ok = np.concatenate([r["full"]["correct"] for r in runs]).astype(bool)
    ov = np.concatenate([r["overlap"] for r in runs]).astype(bool)
    return {"with_gatekeeper_overlap": dict(n=int(ov.sum()), accuracy=float(ok[ov].mean()) if ov.any() else None),
            "without_overlap": dict(n=int((~ov).sum()), accuracy=float(ok[~ov].mean()) if (~ov).any() else None)}


def _confident(b):
    c = b["calibration"]
    n2 = c.get("gap_ge_2", {}).get("n", 0)
    td = c.get("top_decile", {})
    top_clear = td.get("ci95", [0, 0])[0] > b["accuracy"] if td else False
    return n2 > 0 and top_clear


def summarize():
    rng = np.random.default_rng(0)
    out = {"tier1": {}, "tier2": {}, "gpa_anchor_L4": None}
    d, i = TIER1_POINT
    L4 = L_OF[TIER1_POINT]
    for s in SCENARIOS:
        runs = load(f"t1_{s}")
        if not runs:
            continue
        rec = dict(scenario=s, devices=d, interval_min=i, L=L4, runs=len(runs),
                   timing=_block(runs, "timing", L4, rng))
        if s in ("F", "I"):
            rec["full"] = _block(runs, "full", L4, rng)
            rec["full_overlap_split"] = _overlap_split(runs)
        trig = {v: (rec[v]["ci95"][0] > STRONGEST_KNOWN_L4) or _confident(rec[v]) for v in ("timing", "full") if v in rec}
        rec["tier2_trigger"] = trig
        out["tier1"][s] = rec
    anchor = load("gpa_anchor_L4")
    if anchor:
        out["gpa_anchor_L4"] = dict(
            runs=len(anchor), role_rules="catalog",
            main=R._attack_block(anchor, "main", "chance_correct", L4, rng),
            sequencing=R._attack_block(anchor, "seq", "seq_chance_correct", L4, rng),
            bound_perfect_chains=R._attack_block(anchor, None, None, L4, rng, sub="oracle_stage2"),
            bound_true_terminals=R._attack_block(anchor, None, None, L4, rng, sub="oracle_terminal"))
    gpa = json.loads(GPA_SUMMARY.read_text())["jobs"] if GPA_SUMMARY.exists() else {}
    out["gpa_published"] = {k: dict(L=v["L_workbook"], main=v["main"]["accuracy"], sequencing=v["sequencing"]["accuracy"],
                                     sequencing_chance=v["sequencing"]["empirical_chance"],
                                     bound_perfect_chains=v["bound_oracle_chains"]["accuracy"],
                                     bound_true_terminals=v["bound_oracle_terminals"]["accuracy"])
                            for k, v in gpa.items() if k.startswith("main_")}
    triggered = [s for s, r in out["tier1"].items() if any(r["tier2_trigger"].values())]
    (OUT / "tier1_trigger.json").write_text(json.dumps({"triggered": triggered, "bar": STRONGEST_KNOWN_L4}, indent=1))
    for s in SCENARIOS:
        for dd, ii in TIER2_POINTS:
            runs = load(f"t2_{s}_{dd}_{ii}")
            if not runs:
                continue
            L = L_OF[(dd, ii)]
            rec = dict(scenario=s, devices=dd, interval_min=ii, L=L, runs=len(runs), timing=_block(runs, "timing", L, rng))
            if s in ("F", "I"):
                rec["full"] = _block(runs, "full", L, rng)
                rec["full_overlap_split"] = _overlap_split(runs)
            out["tier2"][f"{s}_{dd}_{ii}"] = rec
    (OUT / "summary.json").write_text(json.dumps(out, indent=1, default=float))
    _csv(out)
    return out


def _csv(out):
    rows = []

    def add(tier, rec, variant):
        b = rec[variant]
        c = b["calibration"]
        key = f"main_{rec['devices']}_{rec['interval_min']}"
        g = out["gpa_published"].get(key, {})
        rows.append(dict(
            tier=tier, scenario=rec["scenario"], variant=variant, devices=rec["devices"],
            interval_min=rec["interval_min"], L=rec["L"], inv_L=round(1 / rec["L"], 4), runs=rec["runs"],
            n_scored=b["n_scored"], accuracy=round(b["accuracy"], 4), ci_lo=round(b["ci95"][0], 4),
            ci_hi=round(b["ci95"][1], 4), above_inv_L=b["above_inv_L"],
            random_assignment=round(b["empirical_chance"], 4),
            feasible_candidates=round(b["feasible_candidates_mean"], 2),
            top_decile_accuracy=round(c.get("top_decile", {}).get("accuracy", float("nan")), 4),
            n_gap_ge_2=c.get("gap_ge_2", {}).get("n", 0),
            gpa_sequencing_same_L=round(g.get("sequencing", float("nan")), 4),
            gpa_bound_perfect_chains_same_L=round(g.get("bound_perfect_chains", float("nan")), 4)))
    for s, rec in out["tier1"].items():
        for v in ("timing", "full"):
            if v in rec:
                add(1, rec, v)
    for rec in out["tier2"].values():
        for v in ("timing", "full"):
            if v in rec:
                add(2, rec, v)
    if rows:
        with open(OUT / "summary.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    s = summarize()
    for sc, r in s["tier1"].items():
        for v in ("timing", "full"):
            if v in r:
                b = r[v]
                print(f"T1 {sc} {v:6s} acc={b['accuracy']:.3f} [{b['ci95'][0]:.3f},{b['ci95'][1]:.3f}] "
                      f"chance={b['empirical_chance']:.3f} n={b['n_scored']} trigger={r['tier2_trigger'][v]}")
    for k, r in s["tier2"].items():
        for v in ("timing", "full"):
            if v in r:
                print(f"T2 {k} {v} acc={r[v]['accuracy']:.3f} 1/L={1 / r['L']:.3f}")
