"""Phase registry. Phases run in ascending `number` order.

Add new phases here one at a time as they are implemented:
  2 = scanning/enumeration, 3 = vuln assessment, 4 = (gated) exploitation,
  5 = reporting, 6 = retest.
"""
from .base import Phase, PhaseContext
from .recon import ReconPhase
from .scanning import ScanPhase

PHASES: list[type[Phase]] = [
    ReconPhase,
    ScanPhase,
]

__all__ = ["Phase", "PhaseContext", "PHASES", "ReconPhase", "ScanPhase"]
