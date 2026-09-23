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

from . import events, threatmodel


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
