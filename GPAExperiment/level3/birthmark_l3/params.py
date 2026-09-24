"""Every numeric input to the Level 3 experiment, with its provenance.

Tags used below:
  [WB <sheet>!<cell>]  taken from GPAExperiment/Birthmark_Traffic_Analysis_Catalog.xlsx
  [PAPER §x]           taken from Docs/Birthmark_Protocol_v58.docx where the workbook is silent
  [DECISION]           settled with the experiment owner during the build (see README)
  [DEFAULT]            a modelling default the workbook does not specify; flagged in the
                       report, and cheap to change here
"""
from dataclasses import dataclass, replace

# ---------------------------------------------------------------------------
# Lottery ("chance of transit")                     [WB Level 3!B4; clock model Level 3!B13]
# ---------------------------------------------------------------------------
TICK_S = 10.0              # 10-second ticks
RELEASE_P = 0.0833         # 8.33% release probability per tick
MAX_TICKS = 30             # forced release at 30 ticks (5 min cap)
# Simulation Parameters!C2 describes the same thing as "truncated exponential, window
# [0, 5 min], mean 2 min".  The lottery is its discrete form; its actual mean is
# 10 s * sum_{k<30} (1-p)^k = 111 s, not 120 s.  The Little's-law L column below uses
# 2 min as the workbook does; the report also shows the measured anonymity set.

# ---------------------------------------------------------------------------
# Padding                                           [WB Simulation Parameters!C3]
# ---------------------------------------------------------------------------
PAD_MIN, PAD_MAX = 420, 460   # draw a TARGET total size uniformly, pad raw payload up to it
PAD_GK_RING = (820, 860)      # [DECISION] own size class for the ring-signed GK leg (801 B raw)

# ---------------------------------------------------------------------------
# Topology                                          [WB Level 3!B8]
# ---------------------------------------------------------------------------
N_NODES = 20               # fully connected pool supplying every submission-server role
N_VALIDATORS = 4           # fixed across the sweep; devices split evenly across them
N_GATEKEEPERS = 3          # [WB Leg Catalog GK-1/2/3]
GOSSIP_MESH_D = 6          # [DEFAULT] gossipsub v1.1 default mesh degree D=6
# Origin publishes with gossipsub v1.1 "flood publish" (to all peers) - library default.

# ---------------------------------------------------------------------------
# Sweep                                             [WB Level 3!A17:C31]
# ---------------------------------------------------------------------------
SWEEP = [  # (devices, mean interval minutes, L as printed in the workbook)
    (40, 10, 8.0), (40, 15, 5.3), (40, 20, 4.0),
    (80, 10, 16.0), (80, 15, 10.7), (80, 20, 8.0),
    (120, 10, 24.0), (120, 15, 16.0), (120, 20, 12.0),
    (160, 10, 32.0), (160, 15, 21.3), (160, 20, 16.0),
    (200, 10, 40.0), (200, 15, 26.7), (200, 20, 20.0),
]
RUNS_PER_SETTING = 200     # [WB Level 3!B9]

# ---------------------------------------------------------------------------
# Background traffic                                [WB Simulation Parameters!C4, Level 3!B3]
# ---------------------------------------------------------------------------
BG_CASUAL_FRACTION = 0.90          # 90% casual / 10% high-frequency
BG_CASUAL_PAUSE_S = (1.0, 60.0)    # casual: transact, then pause U[1,60] s
BG_HIFREQ_PAUSE_S = (0.0, 0.5)     # [DEFAULT] "minimal pause" for back-to-back clients
BG_CLIENTS_PER_NODE = 25           # [DECISION] main sweep; sensitivity at 0/5/25/100
BG_INTERNAL_FRACTION = 0.2         # [DEFAULT] share of background clients that are other pool
                                   #   nodes (server-to-server API calls) rather than external hosts
BG_DNS_FRACTION = 0.2              # [DEFAULT] share of background transactions that are DNS
                                   #   lookups (node -> external resolver) rather than HTTPS

# Non-blending traffic                              [WB Level 3!B2]
BULK_EXT_RATE_PER_NODE = 1 / 60.0  # [DEFAULT] large downloads per node per second
BULK_INT_RATE_PER_NODE = 1 / 120.0 # [DEFAULT] node-to-node bulk sync per node per second
BULK_MEDIAN_BYTES = 1_000_000      # [DEFAULT] lognormal(median 1 MB, sigma 1)
KEEPALIVE_PERIOD_S = 30.0          # [DEFAULT] per ordered node pair on persistent connections

# ---------------------------------------------------------------------------
# Network timing                                    [DEFAULT] - none of these are in the workbook
# ---------------------------------------------------------------------------
LAT_EXT_MS = (10.0, 120.0)   # one-way base latency external<->node, fixed per pair per run
LAT_INT_MS = (5.0, 80.0)     # node<->node and node<->validator
JITTER_MS = 2.0              # per-packet exponential jitter, mean
PROC_MS = (0.5, 3.0)         # per-packet processing before a send
VALIDATOR_PROC_MS = (5.0, 50.0)
GATEKEEPER_PROC_MS = (1.0, 10.0)   # verify + post to own board (board post itself is internal)
GOSSIP_VALIDATE_MS = (5.0, 50.0)   # gossip relay validate-then-forward

# ---------------------------------------------------------------------------
# Run window
# ---------------------------------------------------------------------------
WARMUP_S = 20 * 60           # [DEFAULT] submissions start at 0; scoring starts after steady state
MEASURE_S = 40 * 60          # [DEFAULT] submissions whose t0 falls here are scored
COOLDOWN_S = 30 * 60         # [DEFAULT] keep simulating so every scored chain completes

# ---------------------------------------------------------------------------
# Record-type codes carried in observed events
# ---------------------------------------------------------------------------
RT_HANDSHAKE = 0x16
RT_APPDATA = 0x17
RT_DNS = 53          # UDP/53 - not TLS at all
RT_NOISE = 1         # libp2p Noise transport frame: no TLS header at all (2-byte length only)


@dataclass(frozen=True)
class Config:
    """One experiment configuration. Defaults = the main sweep."""
    devices: int = 120
    interval_min: float = 15.0
    relay_clock: str = "node"          # [WB Level 3!B13] "node" (spec) | "packet" (probe only)
    device_clock: str = "per_channel"  # [WB Level 3!B13] "per_channel" (spec) | "shared" (probe only)
    bg_clients_per_node: int = BG_CLIENTS_PER_NODE
    attacker_reads_record_type: bool = True   # [DECISION] yes in sweep; both in blend-in report
    lottery_enabled: bool = True       # False = positive control (immediate forwarding)
    reg_hold: bool = True              # [WB Level 3!B6, B13; Leg Catalog K26/K27] ADOPTED: F and I
                                       #   each hold their registry posting in the lottery after seeing
                                       #   the 2-of-3 quorum. False = the "before" comparison.
    reg_hold_phase: str = "node"       # [WB Level 3!B13] "node": F's and I's own node clocks,
                                       #   independent of each other (spec). "fresh": a new random phase
                                       #   per posting (check run only, to settle the wording).
    role_rules: str = "distinct"       # "distinct": nine distinct nodes per submission, gatekeepers drawn
                                       #   per submission and never C (the published GPA sweep).
                                       #   "insider_v2": Insider Experiment Design!B3-B5. One active set of 3
                                       #   gatekeepers per run [DECISION: rotation slower than a run], used by
                                       #   every submission; C, F, I drawn from the other 17; A, D, G distinct
                                       #   and never C, F or I; B != A, E != D, H != G, and B/E/H may coincide
                                       #   with C/F/I (the hop then self-delivers: lottery hold, no wire leg).
    ring_sig: bool = False             # Insider Experiment Design!B6: C's signature is an AOS ring signature
                                       #   over the 17-node C-candidate pool (ring_sig.py). F/I learn that a
                                       #   pool member signed, not which one. The GK leg then carries 576 B of
                                       #   signature and is padded in its own size class.
    cv_hold: bool = False              # [WB Level 3!B6] REJECTED: a hold at CV-1/2 strengthens the
                                       #   sequencing signal. True only to reproduce that comparison.
    padding_enabled: bool = True       # False = positive control (raw sizes on the wire)
    background_enabled: bool = True
    nonblending_enabled: bool = True

    @property
    def horizon_s(self) -> float:
        return WARMUP_S + MEASURE_S + COOLDOWN_S

    def with_(self, **kw) -> "Config":
        return replace(self, **kw)
