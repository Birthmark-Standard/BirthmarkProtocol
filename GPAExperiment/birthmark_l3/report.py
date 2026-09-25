"""Aggregate raw sweep results into results/summary.json, results/*.csv and figures.

    python -m birthmark_l3.report
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np

from . import params as P
from .sweep import HARDENING, PROBE_SETTING, SENS_SETTING, hardening_jobs, jobs, load
from .wire_pools import Pools
from .crypto_legs import size_verification_report

OUT = Path(__file__).resolve().parent.parent / "results"
HIGH_CONF_GAPS = (1.0, 2.0, 3.0)      # nats: likelihood ratio e, 7.4, 20 between top and runner-up
BOOT = 2000


def _boot_ci(correct_per_run, n_per_run, rng):
    c, n = np.asarray(correct_per_run, float), np.asarray(n_per_run, float)
    if n.sum() == 0:
        return (np.nan, np.nan)
    idx = rng.integers(0, c.size, (BOOT, c.size))
    acc = c[idx].sum(1) / np.maximum(n[idx].sum(1), 1)
    return (float(np.percentile(acc, 2.5)), float(np.percentile(acc, 97.5)))


def _wilson(k, n, z=1.96):
    if n == 0:
        return (np.nan, np.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (float(c - h), float(c + h))


def _attack_block(runs, key, chance_key, L, rng, sub=None):
    get = (lambda r: r[key]) if sub is None else (lambda r: r["diag"][sub])
    corr = [int(get(r)["correct"].sum()) for r in runs]
    n = [r["n_scored"] for r in runs]
    tot, N = sum(corr), sum(n)
    acc = tot / N if N else np.nan
    gap = np.concatenate([get(r)["gap"] for r in runs]).astype(float)
    post = np.concatenate([get(r)["post"] for r in runs]).astype(float)
    ok = np.concatenate([get(r)["correct"] for r in runs]).astype(bool)
    blk = dict(accuracy=acc, ci95=_boot_ci(corr, n, rng), inv_L=1.0 / L,
               ratio_to_inv_L=acc * L if N else np.nan, n_scored=N, n_correct=tot)
    blk["above_inv_L"] = bool(blk["ci95"][0] > 1.0 / L)
    if chance_key:
        ch = sum(r[chance_key] for r in runs)
        blk["empirical_chance"] = ch / N if N else np.nan
    # calibration: accuracy among high-confidence predictions (top-vs-runner-up score gap)
    has = ~np.isnan(gap)
    cal = {}
    if has.sum():
        q90 = float(np.nanpercentile(gap[has], 90))
        sel = has & (gap >= q90)
        cal["top_decile_gap_threshold"] = q90
        cal["top_decile"] = dict(n=int(sel.sum()), accuracy=float(ok[sel].mean()) if sel.sum() else np.nan,
                                 ci95=_wilson(int(ok[sel].sum()), int(sel.sum())))
        for g in HIGH_CONF_GAPS:
            sel = has & (gap >= g)
            cal[f"gap_ge_{g:g}"] = dict(n=int(sel.sum()), share_of_scored=float(sel.sum() / max(N, 1)),
                                        accuracy=float(ok[sel].mean()) if sel.sum() else np.nan,
                                        ci95=_wilson(int(ok[sel].sum()), int(sel.sum())))
        # reliability of the attacker's own posterior
        hp = ~np.isnan(post)
        bins = np.array([0, .05, .1, .2, .4, .6, .8, 1.0001])
        rel = []
        for lo, hi in zip(bins[:-1], bins[1:]):
            s = hp & (post >= lo) & (post < hi)
            if s.sum():
                rel.append(dict(lo=float(lo), hi=float(min(hi, 1)), n=int(s.sum()),
                                mean_posterior=float(post[s].mean()), accuracy=float(ok[s].mean())))
        cal["reliability"] = rel
        cal["ece"] = float(sum(b["n"] * abs(b["mean_posterior"] - b["accuracy"]) for b in rel) / max(hp.sum(), 1))
    blk["calibration"] = cal
    return blk


def _diag_block(runs):
    d = [r["diag"] for r in runs]
    kinds = {k: int(sum(x["chain_events_by_kind"][k] for x in d)) for k in ("birthmark", "blend", "bulk", "keepalive")}
    rt = np.sum([x["ingress_in_window_rt"] for x in d], 0)
    so = np.sum([x["ingress_in_window_size_only"] for x in d], 0)
    return dict(
        stage1_hop_accuracy=float(np.mean([x["hop_acc"] for x in d])),
        chain_reconstructed=dict(cred=float(np.mean([x["chain_acc"]["ev_cred"] for x in d])),
                                 contA=float(np.mean([x["chain_acc"]["ev_ca"] for x in d])),
                                 contB=float(np.mean([x["chain_acc"]["ev_cb"] for x in d]))),
        cred_terminal_detected=float(np.mean([x["cred_terminal_detect"] for x in d])),
        content_pool_true_terminal_share=float(np.mean([x["content_candidates_true"] for x in d])),
        feasible_candidates_per_cred_row=float(np.mean([r["feasible_candidates_mean"] for r in runs])),
        grids_detected_mean=float(np.mean([x["grid_detected"] for x in d])),
        grid_phase_error_ms_max=float(np.nanmax([x["grid_phase_err_ms"] for x in d])),
        chain_events_by_kind=kinds,
        ingress_window_records_per_run_by_kind=dict(
            record_type_read=dict(zip(("birthmark", "blend", "bulk", "keepalive"), (rt / len(d)).round(1).tolist())),
            size_only=dict(zip(("birthmark", "blend", "bulk", "keepalive"), (so / len(d)).round(1).tolist()))),
        seconds_per_run=float(np.mean([r["seconds"] for r in runs])),
    )


def _origin_block(runs):
    N = sum(r["n_scored"] for r in runs)
    s = lambda k: sum(r["origin"][k] for r in runs)
    return dict(n_scored=N,
                first_hop_linked_by_ip_unambiguous=s("first_hop_unambiguous") / N,
                device_to_content_terminal_either_channel=s("content_either") / N,
                device_to_content_terminal_per_channel=s("content_channel") / (2 * N),
                device_to_cred_terminal=s("cred") / N,
                device_to_cred_and_content_terminals=s("cred_and_content") / N)


def summarize():
    rng = np.random.default_rng(0)
    out = {"jobs": {}}
    for name, cfg, nruns, L in jobs(P.RUNS_PER_SETTING, 20, 50):
        runs = load(name)
        if not runs:
            continue
        out["jobs"][name] = dict(
            devices=cfg.devices, interval_min=cfg.interval_min, L_workbook=L, runs=len(runs),
            config={k: getattr(cfg, k) for k in ("relay_clock", "device_clock", "bg_clients_per_node",
                                                  "attacker_reads_record_type", "lottery_enabled")},
            main=_attack_block(runs, "main", "chance_correct", L, rng),
            sequencing=_attack_block(runs, "seq", "seq_chance_correct", L, rng),
            bound_oracle_chains=_attack_block(runs, None, None, L, rng, sub="oracle_stage2"),
            bound_oracle_terminals=_attack_block(runs, None, None, L, rng, sub="oracle_terminal"),
            stages=_diag_block(runs),
            origin_anchored=_origin_block(runs))
    out["hardening"] = {}
    for name, cfg, nruns, L in hardening_jobs(P.RUNS_PER_SETTING, 50):
        runs = load(name)
        if not runs:
            continue
        out["hardening"][name] = dict(
            variant=name.split("_")[1], devices=cfg.devices, interval_min=cfg.interval_min, L_workbook=L,
            runs=len(runs), sequencing=_attack_block(runs, "seq", "seq_chance_correct", L, rng),
            cred_terminal_detected=float(np.mean([r["cred_terminal_detect"] if "cred_terminal_detect" in r
                                                   else r["diag"]["cred_terminal_detect"] for r in runs])))
    pools = Pools()
    out["wire_pools"] = pools.summary()
    out["size_verification"] = [dict(leg=l, workbook=w, measured=m, note=n) for l, w, m, n in size_verification_report()]
    OUT.mkdir(exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(out, indent=1, default=float))
    _csv(out)
    _figures(out)
    return out


def _csv(out):
    rows = []
    for name, j in out["jobs"].items():
        m, s = j["main"], j["sequencing"]
        rows.append(dict(
            job=name, devices=j["devices"], interval_min=j["interval_min"], L=j["L_workbook"], runs=j["runs"],
            n_scored=m["n_scored"], inv_L=round(1 / j["L_workbook"], 4),
            main_acc=round(m["accuracy"], 4), main_ci_lo=round(m["ci95"][0], 4), main_ci_hi=round(m["ci95"][1], 4),
            main_chance_empirical=round(m["empirical_chance"], 4),
            main_top_decile_acc=round(m["calibration"].get("top_decile", {}).get("accuracy", np.nan), 4),
            seq_acc=round(s["accuracy"], 4), seq_ci_lo=round(s["ci95"][0], 4), seq_ci_hi=round(s["ci95"][1], 4),
            seq_chance_empirical=round(s["empirical_chance"], 4),
            seq_top_decile_acc=round(s["calibration"].get("top_decile", {}).get("accuracy", np.nan), 4),
            seq_gap3_acc=round(s["calibration"].get("gap_ge_3", {}).get("accuracy", np.nan), 4),
            seq_gap3_share=round(s["calibration"].get("gap_ge_3", {}).get("share_of_scored", np.nan), 4),
            bound_oracle_chains=round(j["bound_oracle_chains"]["accuracy"], 4),
            bound_oracle_terminals=round(j["bound_oracle_terminals"]["accuracy"], 4),
            stage1_hop_acc=round(j["stages"]["stage1_hop_accuracy"], 4),
            origin_content_either=round(j["origin_anchored"]["device_to_content_terminal_either_channel"], 4),
        ))
    with open(OUT / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def _figures(out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    main = {k: v for k, v in out["jobs"].items() if k.startswith("main_")}
    if not main:
        return
    Ls = np.array([v["L_workbook"] for v in main.values()])
    o = np.argsort(Ls)
    names = np.array(list(main.keys()))[o]
    Ls = Ls[o]
    plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False, "axes.edgecolor": "#9a9993",
                         "axes.labelcolor": "#0b0b0b", "xtick.color": "#52514e", "ytick.color": "#52514e",
                         "grid.color": "#e6e5e0", "font.size": 9})
    fig, ax = plt.subplots(1, 2, figsize=(12, 4.6), sharey=False, facecolor="#fcfcfb")
    for a in ax:
        a.set_facecolor("#fcfcfb")
        a.grid(True, axis="y", lw=0.6)
    series = [("main", "Main attack (Stage 1+2)", "#2a78d6"), ("sequencing", "Quorum-to-registry sequencing", "#eb6834"),
              ("bound_oracle_terminals", "Bound: true terminal labels", "#52514e"),
              ("bound_oracle_chains", "Bound: perfect chains", "#9a9993")]
    for key, label, col in series:
        acc = np.array([main[n][key]["accuracy"] for n in names])
        lo = np.array([main[n][key]["ci95"][0] for n in names])
        hi = np.array([main[n][key]["ci95"][1] for n in names])
        ls = "-" if key in ("main", "sequencing") else "--"
        ax[0].errorbar(Ls, acc, yerr=[acc - lo, hi - acc], fmt="o" + ls, color=col, label=label, ms=5, capsize=2, lw=2,
                       mec="#fcfcfb", mew=1)
    xs = np.linspace(Ls.min(), Ls.max(), 100)
    ax[0].plot(xs, 1 / xs, color="black", lw=1, ls=":", label="1/L chance baseline")
    ax[0].set_xlabel("L (workbook Little's-law anonymity set)")
    ax[0].set_ylabel("Pairing accuracy")
    ax[0].set_title("Raw pairing accuracy vs 1/L (200 runs per point, 95% CI)")
    ax[0].legend(fontsize=8)
    ax[0].set_yscale("log")
    for key, label, col in series[:2]:
        acc = np.array([main[n][key]["calibration"].get("top_decile", {}).get("accuracy", np.nan) for n in names])
        ax[1].plot(Ls, acc, "o-", color=col, label=label + ": top-decile gap", ms=5, lw=2, mec="#fcfcfb", mew=1)
    ax[1].plot(xs, 1 / xs, color="black", lw=1, ls=":", label="1/L")
    ax[1].set_xlabel("L")
    ax[1].set_ylabel("Accuracy among high-confidence predictions")
    ax[1].set_title("Calibration: accuracy in the top 10% score gap")
    ax[1].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "sweep.png", dpi=150)
    plt.close(fig)
    _hardening_figure(out, main, names, Ls, xs, plt)


def _hardening_figure(out, main, names, Ls, xs, plt):
    H = out.get("hardening", {})
    if not H:
        return
    fig, ax = plt.subplots(1, 2, figsize=(12, 4.6), facecolor="#fcfcfb")
    for a in ax:
        a.set_facecolor("#fcfcfb")
        a.grid(True, axis="y", lw=0.6)
    series = [("ADOPTED: F/I hold, own node clocks", None, "#eb6834"),
              ("before: no hold anywhere", "none", "#8a938f"),
              ("rejected: hold at CV-1/2 (no F/I hold)", "cv", "#2a78d6"),
              ("F/I hold + CV-1/2 hold", "both", "#eda100"),
              ("check: F/I hold, fresh phase per posting", "fresh", "#1baf7a")]
    for label, v, col in series:
        blocks = [main[n]["sequencing"] if v is None else H.get(f"harden_{v}_{n[5:]}", {}).get("sequencing")
                  for n in names]
        if any(b is None for b in blocks):
            continue
        acc = np.array([b["accuracy"] for b in blocks])
        lo = np.array([b["ci95"][0] for b in blocks])
        hi = np.array([b["ci95"][1] for b in blocks])
        ch = np.array([b["empirical_chance"] for b in blocks])
        ax[0].errorbar(Ls, acc, yerr=[acc - lo, hi - acc], fmt="o-", color=col, label=label, ms=5, lw=2,
                       capsize=2, mec="#fcfcfb", mew=1)
        ax[1].plot(Ls, acc / ch, "o", color=col, label=label, ms=6, mec="#fcfcfb", mew=1)
    ax[0].plot(xs, 1 / xs, color="black", lw=1, ls=":", label="1/L")
    ax[0].set_yscale("log")
    ax[0].set_xlabel("L (workbook Little's-law anonymity set)")
    ax[0].set_ylabel("Sequencing-attack pairing accuracy")
    ax[0].set_title("Sequencing attack: adopted configuration vs comparisons (95% CI)")
    ax[0].legend(fontsize=8)
    ax[1].axhline(1.0, color="black", lw=1, ls=":", label="random assignment (= 1x)")
    ax[1].set_ylim(bottom=0)
    ax[1].set_xlabel("L")
    ax[1].set_ylabel("Accuracy / random-assignment baseline")
    ax[1].set_title("Residual signal above true chance (one point per setting)")
    ax[1].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "hardening.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    s = summarize()
    for name, j in s["jobs"].items():
        print(f"{name:28s} L={j['L_workbook']:5.1f} main={j['main']['accuracy']:.4f} "
              f"seq={j['sequencing']['accuracy']:.4f} 1/L={1/j['L_workbook']:.4f} "
              f"hop={j['stages']['stage1_hop_accuracy']:.3f} runs={j['runs']}")
