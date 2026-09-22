# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase registry. Phases run in ascending `number` order.

Add new phases here one at a time as they are implemented:
  2 = scanning/enumeration / SAST, 3 = vuln assessment / client-side DAST / API tests,
  4 = verification; gated exploitation / post-exploitation stay off the list.
"""
from .base import Phase, PhaseContext
from .osint import OSINTPhase
from .recon import ReconPhase
from .scanning import ScanPhase
from .sast import SASTPhase
from .cloudaudit import CloudAuditPhase
from .vuln import VulnPhase
from .apitest import APITestPhase
from .accesscontrol import AccessControlPhase
from .injection import InjectionPhase
from .workflow_phase import WorkflowPhase
from .proxy_ingest import ProxyIngestPhase
from .browser import BrowserPhase
from .verify import VerifyPhase

PHASES: list[type[Phase]] = [
    OSINTPhase,
    ReconPhase,
    ScanPhase,
    SASTPhase,
    CloudAuditPhase,
    VulnPhase,
    APITestPhase,
    AccessControlPhase,
    InjectionPhase,
    WorkflowPhase,
    ProxyIngestPhase,
    BrowserPhase,
    VerifyPhase,
]

__all__ = ["Phase", "PhaseContext", "PHASES",
           "OSINTPhase", "ReconPhase", "ScanPhase", "SASTPhase", "CloudAuditPhase",
           "VulnPhase", "APITestPhase", "AccessControlPhase", "InjectionPhase",
           "WorkflowPhase", "ProxyIngestPhase", "BrowserPhase", "VerifyPhase"]
