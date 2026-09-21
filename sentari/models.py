"""Core data model for Sentari.

The central design rule of Sentari: a Finding may only exist if it is backed by
Evidence: the real output of a real command that actually ran. Nothing in this
codebase should ever construct a Finding from a hardcoded string or from an LLM's
imagination. Evidence is the ground truth; everything else describes it.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


@dataclass
class Evidence:
    """The proof behind a finding: exactly what command ran and what it returned.

    An Evidence object is produced only by the ToolRunner after a real process
    exits. A Finding without at least one Evidence id is not permitted.
    """
    id: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    ended_at: str
    duration_sec: float
    tool: str
    cwd: Optional[str] = None

    def summary(self) -> str:
        cmd = " ".join(self.command)
        return f"[{self.tool}] `{cmd}` -> exit {self.returncode} ({self.duration_sec:.2f}s)"


@dataclass
class Finding:
    """A single observation. MUST cite at least one Evidence id."""
    title: str
    severity: Severity
    description: str
    evidence_ids: list[str]
    target: str
    phase: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    location: Optional[str] = None          # e.g. port 443/tcp, URL, header name
    recommendation: Optional[str] = None
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise ValueError(
                f"Finding {self.title!r} has no evidence: this is forbidden. "
                "Every finding must reference the command output that produced it."
            )
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)


@dataclass
class PhaseResult:
    phase: str
    started_at: str
    ended_at: str
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    tools_available: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [
            {**asdict(f), "severity": f.severity.value} for f in self.findings
        ]
        return d
