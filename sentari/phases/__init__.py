"""Phase registry. Phases run in ascending `number` order.

Add new phases here one at a time as they are implemented:
  2 = scanning/enumeration, 3 = vuln assessment / client-side DAST,
  4 = verification; gated exploitation / post-exploitation stay off the list.
"""
from .base import Phase, PhaseContext
from .osint import OSINTPhase
from .recon import ReconPhase
from .scanning import ScanPhase
from .vuln import VulnPhase
from .browser import BrowserPhase
from .verify import VerifyPhase

PHASES: list[type[Phase]] = [
    OSINTPhase,
    ReconPhase,
    ScanPhase,
    VulnPhase,
    BrowserPhase,
    VerifyPhase,
]

__all__ = ["Phase", "PhaseContext", "PHASES",
           "OSINTPhase", "ReconPhase", "ScanPhase", "VulnPhase", "BrowserPhase",
           "VerifyPhase"]
