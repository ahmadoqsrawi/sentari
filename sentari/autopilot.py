"""AI autopilot: let an LLM drive the assessment flow, safely.

At each step the model sees what has run and what was found, then picks the next
phase to run or decides to stop. That is the only thing it controls. It cannot
change the target, invent a finding, or run an arbitrary command:

  * The target is fixed to the authorized target and never comes from the model.
  * The action must be one of the known phase names (or "stop"); anything else
    is rejected and the loop falls back to the next phase in order.
  * Findings still come only from the phases, each backed by real evidence.
  * Scope and safe mode are enforced exactly as in a normal run.

So the worst a hostile target (via prompt injection in a response body) can do is
nudge the phase order or an early stop. It cannot escalate into command
execution or fabricated results.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from .authorization import AuditLog, Scope, authorize
from .models import PhaseResult
from .phases import PHASES, PhaseContext
from .runner import ToolRunner

_PHASE_ORDER = [c.name for c in sorted(PHASES, key=lambda c: c.number)]
_PHASE_BY_NAME = {c.name: c for c in PHASES}

_SYSTEM = (
    "You are orchestrating a security assessment. You do not perform it and you "
    "do not report vulnerabilities. Your only job is to choose the next phase to "
    "run, from the given list, or to stop. Base the choice on what has already "
    "run and what was found. Respond with ONLY JSON: "
    '{"action": "<phase name or stop>", "reason": "<short>"}.'
)


@dataclass
class Decision:
    step: int
    action: str
    reason: str
    source: str  # "llm" or "fallback"


@dataclass
class AutopilotRun:
    results: list[PhaseResult] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    provider: str = ""
    note: Optional[str] = None


def _state(results: list[PhaseResult], done: list[str]) -> str:
    counts: dict[str, int] = {}
    titles = []
    for r in results:
        for f in r.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            if len(titles) < 12:
                titles.append(f"{f.severity.value}: {f.title}")
    return json.dumps({"phases_run": done, "finding_counts": counts,
                       "sample_findings": titles})


def _next_fallback(done: list[str]) -> Optional[str]:
    for name in _PHASE_ORDER:
        if name not in done:
            return name
    return None


def run_autopilot(
    target: str,
    scope: Scope,
    authorized: bool,
    audit: AuditLog,
    provider,
    *,
    safe_mode: bool = True,
    timeout: int = 120,
    dry_run: bool = False,
    options: Optional[dict] = None,
    max_steps: int = 8,
    apply_compliance: bool = True,
    apply_anomaly: bool = True,
) -> AutopilotRun:
    authorize(target, scope, authorized, audit)
    out = AutopilotRun(provider=getattr(provider, "name", "none"))

    usable = False
    if provider is not None:
        ok, reason = provider.available()
        usable = ok
        if not ok:
            out.note = f"AI provider unavailable ({reason}); running phases in order."

    ctx = PhaseContext(target=target, runner=ToolRunner(timeout, dry_run),
                       safe_mode=safe_mode, options=options or {})
    done: list[str] = []

    for step in range(1, max_steps + 1):
        action, source, why = _decide(provider, usable, out.results, done)
        if action == "stop" or action is None:
            out.decisions.append(Decision(step, "stop", why or "nothing left to run", source))
            audit.record("autopilot.stop", target=target, step=step)
            break

        out.decisions.append(Decision(step, action, why or "", source))
        audit.record("autopilot.step", target=target, step=step, action=action, source=source)

        cls = _PHASE_BY_NAME[action]
        ctx.runner = ToolRunner(timeout, dry_run)
        result = cls().run(ctx)
        ctx.shared.setdefault("prior_findings", []).extend(result.findings)
        out.results.append(result)
        done.append(action)

        if all(name in done for name in _PHASE_ORDER):
            break

    if apply_compliance:
        from . import compliance
        compliance.apply(out.results)
    if apply_anomaly:
        from . import anomaly
        anomaly.apply(out.results)
    return out


def _decide(provider, usable: bool, results: list[PhaseResult],
            done: list[str]) -> tuple[Optional[str], str, str]:
    """Return (action, source, reason). Falls back to phase order on any doubt."""
    if not usable:
        return _next_fallback(done), "fallback", "provider unavailable"

    remaining = [n for n in _PHASE_ORDER if n not in done]
    if not remaining:
        return "stop", "fallback", "all phases run"

    user = (f"Phases available (not yet run): {remaining}\n"
            f"State so far: {_state(results, done)}\n"
            "Pick the next phase to run, or stop.")
    try:
        raw = provider.complete(_SYSTEM, user, max_tokens=200)
        obj = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
        action = str(obj.get("action", "")).strip()
        reason = str(obj.get("reason", ""))[:200]
    except Exception:
        return _next_fallback(done), "fallback", "unparseable model reply"

    if action == "stop":
        return "stop", "llm", reason
    if action in _PHASE_BY_NAME and action not in done:
        return action, "llm", reason
    # model picked something invalid or already-run: ignore it, stay grounded
    return _next_fallback(done), "fallback", f"rejected model action {action!r}"
