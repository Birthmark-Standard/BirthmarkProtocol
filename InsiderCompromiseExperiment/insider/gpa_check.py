"""The outside (GPA) observer's sequencing attack under the redesign and under the redesign with
the gatekeeper posting hold, at this run's three points.

The ring-signed GK leg travels in its own size class (842-882 B on the wire), which makes GK
legs identifiable by size. This checks what that does for the observer with no keys, against
the published GPA sequencing results at the same L.

    python -m insider.gpa_check
"""
from __future__ import annotations

import json
import os
from concurrent.futures import ProcessPoolExecutor

import numpy as np

from . import LEVEL3  # noqa: F401
from birthmark_l3 import report as R
from .run import CONFIGS, DEVICES, INTERVAL_MIN, ROOT, RUNS, L_of, seed_for

_W = {}


def _one(args):
    config, d, k = args
    from birthmark_l3 import attack as A
    from birthmark_l3 import fastsim as FS
    from birthmark_l3.wire_pools import Pools
    from . import core as K
    if "pools" not in _W:
        _W["pools"] = Pools()
    cfg = K.adopted_config(d, INTERVAL_MIN, **CONFIGS[config])
    if config not in _W:           # the observer's likelihood follows the protocol being attacked
        _W[config] = A.build_likelihoods(cfg)
    run = FS.simulate(cfg, seed_for("GPA", d, k), _W["pools"])
    return config, d, A.sequencing_only_run(run, _W[config], _W["pools"], rng_seed=k)


CHECKED = ("ring", "gkhold")


def main():
    path = ROOT / "results" / "gpa_check.json"
    summary = json.loads(path.read_text()) if path.exists() else {}
    if summary and "ring" not in summary:          # earlier layout: keyed by device count only
        summary = {"ring": summary}
    todo = [c for c in CHECKED if c not in summary]
    tasks = [(c, d, k) for c in todo for d in DEVICES for k in range(RUNS)]
    res = {(c, d): [] for c in todo for d in DEVICES}
    with ProcessPoolExecutor(os.cpu_count()) as ex:
        for c, d, out in ex.map(_one, tasks, chunksize=4):
            res[(c, d)].append(out)
    rng = np.random.default_rng(0)
    for c in todo:
        summary[c] = {str(d): R._attack_block(res[(c, d)], "seq", "seq_chance_correct", L_of(d), rng) for d in DEVICES}
    path.write_text(json.dumps(summary, indent=1, default=float))
    for c in CHECKED:
        for d, b in summary[c].items():
            print(c, d, round(b["accuracy"], 4), [round(x, 4) for x in b["ci95"]], "1/L", round(1 / L_of(int(d)), 4))


if __name__ == "__main__":
    main()
