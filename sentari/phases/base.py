# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase framework.

Each phase receives a PhaseContext, runs real tools through the shared
ToolRunner, and returns a PhaseResult whose findings all cite evidence. Phases
are added one at a time and registered in PHASES (see __init__.py); the engine
runs them in order.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..models import PhaseResult
from ..runner import ToolRunner


@dataclass
class PhaseContext:
    target: str
    runner: ToolRunner
    safe_mode: bool = True
    options: dict[str, Any] = field(default_factory=dict)
    shared: dict[str, Any] = field(default_factory=dict)  # data passed between phases


class Phase(ABC):
    name: str = "phase"
    number: int = 0
    description: str = ""

    @abstractmethod
    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        """Do the work: run tools via ctx.runner, append Findings to result."""

    def run(self, ctx: PhaseContext) -> PhaseResult:
        result = PhaseResult(
            phase=self.name,
            started_at=datetime.now(timezone.utc).isoformat(),
            ended_at="",
        )
        try:
            self.execute(ctx, result)
        except Exception as e:  # a phase failure must never fabricate results
            result.error = f"{type(e).__name__}: {e}"
        # attach every piece of evidence the runner produced during this phase
        result.evidence = ctx.runner.evidence
        result.ended_at = datetime.now(timezone.utc).isoformat()
        return result
