# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""The function-calling agent loop.

The model plans and calls tools one at a time; the dispatcher runs each against
the real target and returns an observation. The model may author findings, but
only through record_finding with a real evidence_id, and a verifier pass then
drops any model-authored finding the cited evidence does not support. Tool-
created facts (DNS, open ports, nuclei matches) are kept as they are.

With no usable provider it runs a fixed recon sequence, so it still does real
work without inventing anything.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..authorization import AuditLog, Scope, authorize
from ..models import PhaseResult
from ..runner import ToolRunner
from .tools import TOOL_SPECS, ToolDispatcher


@dataclass
class AgentRun:
    results: list[PhaseResult] = field(default_factory=list)
    transcript: list[dict] = field(default_factory=list)
    provider: str = ""
    note: Optional[str] = None


def _system(safe_mode: bool) -> str:
    tools = "\n".join(f"- {t['name']}({', '.join(t['args'])}): {t['desc']}" for t in TOOL_SPECS)
    msg = ("You are an autonomous security assessment agent working against one fixed "
           "target. Call one tool per step. To claim a finding you MUST call "
           "record_finding with an evidence_id returned by an earlier tool; never assert "
           "a vulnerability without evidence. When done, call finish. Respond with ONLY "
           'JSON: {"tool":"<name>","args":{...}}.\nTools:\n' + tools)
    if safe_mode:
        msg += "\n(safe mode is ON; intrusive tools are disabled)"
    return msg


def _result(disp: ToolDispatcher, runner: ToolRunner) -> PhaseResult:
    ts = datetime.now(timezone.utc).isoformat()
    return PhaseResult(phase="agent", started_at=ts, ended_at=ts,
                       findings=disp.findings, evidence=runner.evidence)


def run_agent(target: str, scope: Scope, authorized: bool, audit: AuditLog, provider,
              *, goal: Optional[str] = None, safe_mode: bool = True, timeout: int = 120,
              max_steps: int = 14, verify: bool = True,
              max_budget: Optional[float] = None) -> AgentRun:
    authorize(target, scope, authorized, audit)
    from ..ai import providers as _providers
    _providers.reset_spend()
    runner = ToolRunner(timeout)
    disp = ToolDispatcher(runner, target, safe_mode)
    out = AgentRun(provider=getattr(provider, "name", "none"))

    ok, reason = provider.available() if provider is not None else (False, "no provider")
    if not ok:
        out.note = f"AI provider unavailable ({reason}); ran a fixed recon sequence."
        for tool, args in [("dns_lookup", {}), ("port_scan", {}),
                           ("http_get", {"path": "/"}), ("run_nuclei", {})]:
            obs = disp.dispatch(tool, args)
            out.transcript.append({"tool": tool, "args": args, "observation": obs})
        out.results = [_result(disp, runner)]
        return out

    if provider.supports_tools():
        try:
            _run_native(provider, disp, audit, target, goal, safe_mode, max_steps, out,
                        max_budget)
        except Exception as e:
            out.note = f"native tool-calling failed ({e}); used the JSON protocol instead."
            _run_json(provider, disp, audit, target, goal, safe_mode, max_steps, out,
                      max_budget)
    else:
        _run_json(provider, disp, audit, target, goal, safe_mode, max_steps, out, max_budget)

    if verify and disp.findings:
        _verify(provider, disp, runner, audit, target)
    out.results = [_result(disp, runner)]
    return out


def _over_budget(max_budget, out) -> bool:
    if not max_budget:
        return False
    from ..ai import providers as _providers
    if _providers.spent_cost() >= max_budget:
        from .. import events
        note = f"budget reached (est. ${_providers.spent_cost():.4f} >= ${max_budget})"
        out.note = ((out.note + "; ") if out.note else "") + note
        events.emit("note", "budget", note)
        return True
    return False


def _run_json(provider, disp, audit, target, goal, safe_mode, max_steps, out,
              max_budget=None) -> None:
    """Provider-agnostic loop: the model returns a JSON action each step."""
    convo: list[str] = []
    if goal:
        convo.append(f"Goal: {goal}")
    from .. import events
    for step in range(1, max_steps + 1):
        if events.should_cancel() or _over_budget(max_budget, out):
            break
        user = "\n".join(convo[-30:]) + "\n\nNext action as JSON:"
        try:
            raw = provider.complete(_system(safe_mode), user, max_tokens=400)
            obj = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
            tool = str(obj.get("tool", ""))
            args = obj.get("args", {}) or {}
        except Exception:
            out.transcript.append({"step": step, "error": "unparseable model reply"})
            break
        from .. import events
        audit.record("agent.step", target=target, step=step, tool=tool)
        if tool == "finish":
            out.transcript.append({"step": step, "tool": "finish", "args": args})
            events.emit("thinking", "agent", "finished")
            break
        events.emit("agent_step", "agent", f"{tool}({json.dumps(args)[:80]})", step=step)
        obs = disp.dispatch(tool, args)
        events.emit("observation", tool, str(obs)[:160])
        out.transcript.append({"step": step, "tool": tool, "args": args, "observation": obs})
        convo.append(f"[{step}] {tool}({json.dumps(args)}) -> {obs}")


def _run_native(provider, disp, audit, target, goal, safe_mode, max_steps, out,
                max_budget=None) -> None:
    """Native function-calling loop (OpenAI / Anthropic tool APIs)."""
    from .schema import OPENAI_TOOLS
    system = _system(safe_mode)
    messages = [{"role": "user",
                 "content": (f"Goal: {goal}\n" if goal else "") +
                            "Assess the target using the tools. Call finish when done."}]
    from .. import events
    for step in range(1, max_steps + 1):
        if events.should_cancel() or _over_budget(max_budget, out):
            break
        turn = provider.tool_turn(system, messages, OPENAI_TOOLS, max_tokens=800)
        if turn.get("text"):
            events.emit("thinking", "agent", str(turn["text"])[:200])
        calls = turn.get("tool_calls") or []
        if not calls:
            out.transcript.append({"step": step, "text": (turn.get("text") or "")[:200]})
            break
        messages.append({"role": "assistant", "content": turn.get("text"), "tool_calls": calls})
        finished = False
        for c in calls:
            audit.record("agent.step", target=target, step=step, tool=c["name"])
            if c["name"] == "finish":
                out.transcript.append({"step": step, "tool": "finish", "args": c["args"]})
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": "ok"})
                events.emit("thinking", "agent", "finished")
                finished = True
                continue
            events.emit("agent_step", "agent",
                        f"{c['name']}({json.dumps(c['args'])[:80]})", step=step)
            obs = disp.dispatch(c["name"], c["args"])
            events.emit("observation", c["name"], str(obs)[:160])
            out.transcript.append({"step": step, "tool": c["name"], "args": c["args"],
                                   "observation": obs})
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": obs})
        if finished:
            break


def _verify(provider, disp: ToolDispatcher, runner: ToolRunner,
            audit: AuditLog, target: str) -> None:
    """Drop model-authored findings the cited evidence does not support."""
    evidence = {e.id: e for e in runner.evidence}
    kept, dropped = [], 0
    for f in disp.findings:
        if (f.metadata or {}).get("authored_by") != "agent":
            kept.append(f)   # tool-created facts stay
            continue
        e = evidence.get(f.evidence_ids[0]) if f.evidence_ids else None
        snippet = e.stdout[:800] if e else ""
        q = (f"Evidence:\n{snippet}\n\nClaim: [{f.severity.value}] {f.title} - "
             f"{f.description}\nDoes the evidence support this claim? Answer YES or NO.")
        try:
            ans = provider.complete(
                "You are a strict verifier. Answer YES only if the evidence clearly "
                "supports the claim, otherwise NO.", q, max_tokens=5)
            if ans.strip().upper().startswith("YES"):
                f.metadata = {**f.metadata, "verified": True}
                kept.append(f)
            else:
                dropped += 1
        except Exception:
            kept.append(f)   # on verifier error, keep rather than silently drop
    disp.findings[:] = kept
    if dropped:
        audit.record("agent.verify", target=target, dropped=dropped)
