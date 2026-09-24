"""Insider-compromise experiment. Builds on GPAExperiment/level3 (imported, not copied)."""
import sys
from pathlib import Path

LEVEL3 = Path(__file__).resolve().parents[2] / "GPAExperiment" / "level3"
if str(LEVEL3) not in sys.path:
    sys.path.insert(0, str(LEVEL3))
