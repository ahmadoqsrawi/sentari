# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Orchestration view for the live monitor (--threat-model --live).

Frames a run as a root agent that plans, keeps a todo checklist, and spawns
skill-scoped assessors (the threat-model assessors), surfaced live as an agent
tree. It does this by subscribing to the real phase events and mapping each
phase to the assessor that owns it, then emitting `agent` and `todo` events the
TUI renders. No fabricated activity: the plan is a stated plan, and every
assessor status change is driven by a real phase actually starting/finishing.
For real LLM "thinking", combine with --agent (the model's own reasoning streams
in); without a model, the plan is shown as a plan, not as invented thought.
"""
from __future__ import annotations

from typing import Optional

from . import events, threatmodel
from .authorization import AuditLog, Scope

# Assessors dispatched as reasoning LLM sub-agents (Verification is a final,
# deterministic step, not a sub-agent). Authorization is added only when
# credentials are supplied.
_DISPATCH = ["Recon & Perimeter Mapper", "Known-Vulnerability Assessor",
             "Auth & API Assessor", "Injection Assessor", "Framework/SPA Assessor",
             "Client-side Assessor"]


def attach(bus: events.EventBus, target: str, options: dict | None = None) -> None:
    """Register the orchestration mapping on a live event bus."""
    assessors = threatmodel.ASSESSORS
    todo = [{"name": a["name"], "status": "pending"} for a in assessors]

    bus.emit(events.Event("plan", "root",
             f"Planning a black-box assessment of {target}: reconnaissance and "
             "attack-surface mapping first, then specialized assessors (known-vuln, "
             "auth/API, authorization/IDOR, injection, framework/SPA, client-side), "
             "then reconcile coverage and findings."))
    bus.emit(events.Event("todo", "root", "", {"items": [dict(t) for t in todo]}))
    bus.emit(events.Event("agent", "Root Agent", "orchestrator", {"status": "running"}))
    for a in assessors:
        bus.emit(events.Event("agent", a["name"], ", ".join(a["skills"]),
                              {"status": "pending"}))

    def _set_todo(name: str, status: str) -> None:
        for t in todo:
            if t["name"] == name:
                t["status"] = status
        bus.emit(events.Event("todo", "root", "", {"items": [dict(t) for t in todo]}))

    started: set = set()

    def on(ev: events.Event) -> None:
        if ev.kind == "phase_start":
            a = threatmodel.assessor_for_phase(ev.source)
            if a and a["name"] not in started:
                started.add(a["name"])
                bus.emit(events.Event("spawn", a["name"], a.get("mandate", "")))
                bus.emit(events.Event("agent", a["name"], "", {"status": "running"}))
                _set_todo(a["name"], "running")
        elif ev.kind == "phase_done":
            a = threatmodel.assessor_for_phase(ev.source)
            # mark the assessor done when its last-defined phase finishes
            if a and ev.source == a["phases"][-1]:
                bus.emit(events.Event("agent", a["name"], "", {"status": "done"}))
                _set_todo(a["name"], "done")
        elif ev.kind == "run_done":
            # flip any still-running assessor (partial phase selection) to done
            for a in assessors:
                if a["name"] in started:
                    bus.emit(events.Event("agent", a["name"], "", {"status": "done"}))
                    _set_todo(a["name"], "done")
            bus.emit(events.Event("agent", "Root Agent", "", {"status": "done"}))

    bus.subscribe(on)


def run_llm(target: str, scope: Scope, authorized: bool, audit: AuditLog, provider,
            *, options: Optional[dict] = None, safe_mode: bool = True,
            timeout: int = 120, max_steps: int = 6, max_budget: Optional[float] = None):
    """True multi-agent orchestration: a root model plans, then dispatches each
    assessor as its own reasoning LLM sub-agent that runs real tools and streams
    its thinking. Returns an AgentRun (results + transcript). Requires a provider;
    every finding a sub-agent claims still needs evidence (grounding guard)."""
    from .agent.loop import AgentRun, run_agent
    from .ai import providers as _providers

    options = options or {}
    _providers.reset_spend()
    events.emit("run_start", "engine", target)
    out = AgentRun(provider=getattr(provider, "name", "none"))

    # Root plan: a real model completion, not a canned string.
    try:
        plan = provider.complete(
            "You are the lead of an authorized black-box web application penetration "
            "test. You do not test hands-on; you plan and delegate to specialized "
            "assessors. Be concise and concrete.",
            f"Target: {target}. In 4-6 sentences, give your plan: which specialized "
            "assessors you will dispatch, in what order, and why recon comes first.",
            max_tokens=350).strip()
    except Exception as e:
        plan = f"(planning call failed: {type(e).__name__}: {e})"
    events.emit("thinking", "Root Agent", plan)

    dispatch = [a for a in threatmodel.ASSESSORS if a["name"] in _DISPATCH]
    if options.get("identities"):
        auth = next((a for a in threatmodel.ASSESSORS
                     if a["name"] == "Authorization Assessor"), None)
        if auth:
            dispatch.append(auth)

    todo = [{"name": a["name"], "status": "pending"} for a in dispatch]

    def _set_todo(name, status):
        for t in todo:
            if t["name"] == name:
                t["status"] = status
        events.emit("todo", "root", "", items=[dict(t) for t in todo])

    _set_todo("", "")  # emit the initial checklist
    events.emit("agent", "Root Agent", "orchestrator", status="running")
    for a in dispatch:
        events.emit("agent", a["name"], ", ".join(a["skills"]), status="pending")

    shared: list[str] = []
    for a in dispatch:
        if events.should_cancel():
            out.note = ((out.note + "; ") if out.note else "") + "cancelled by user"
            break
        if max_budget and _providers.spent_cost() >= max_budget:
            events.emit("note", "budget",
                        f"budget reached (est. ${_providers.spent_cost():.4f}); "
                        "stopping further assessors")
            break
        events.emit("spawn", a["name"], a.get("mandate", ""))
        events.emit("agent", a["name"], "", status="running")
        _set_todo(a["name"], "running")
        goal = a.get("mandate", "")
        if shared:
            goal += " Context from earlier assessors (findings so far): " + \
                    "; ".join(shared[-10:])
        ar = run_agent(target, scope, authorized, audit, provider, goal=goal,
                       safe_mode=safe_mode, timeout=timeout, max_steps=max_steps,
                       max_budget=max_budget, verify=False, agent_name=a["name"],
                       reset_spend=False)
        for r in ar.results:
            out.results.append(r)
            for f in r.findings:
                shared.append(f.title)
        out.transcript.extend(ar.transcript)
        events.emit("agent", a["name"], "", status="done")
        _set_todo(a["name"], "done")

    events.emit("agent", "Root Agent", "", status="done")
    total = sum(len(r.findings) for r in out.results)
    events.emit("run_done", "engine", f"{total} finding(s) total")
    return out
