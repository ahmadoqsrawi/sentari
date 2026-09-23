# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""A tiny in-process event bus for live progress (the --live monitor).

Phases, the tool runner, the agent loop, and the AI providers publish real
events here as they happen (a phase starting, a command running and its exit
code, a finding, an agent step, token usage). A subscriber, such as the live
TUI, renders them. Everything published is a real observed event; nothing here
invents activity. When no bus is set, `emit` is a cheap no-op, so normal runs
pay nothing.

The current bus is stored per-thread via a ContextVar. The live monitor runs the
scan in a worker thread and calls `set_current(bus)` inside that thread so the
engine's emits reach the UI.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field

# event kinds: run_start, phase_start, phase_done, tool, finding, thinking,
# agent_step, observation, usage, note, error, run_done


@dataclass
class Event:
    kind: str
    source: str = ""
    text: str = ""
    data: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class EventBus:
    def __init__(self, maxlen: int = 5000) -> None:
        self._subs: list = []
        self._lock = threading.Lock()
        self.log: deque = deque(maxlen=maxlen)

    def subscribe(self, fn) -> None:
        with self._lock:
            self._subs.append(fn)

    def emit(self, ev: Event) -> None:
        with self._lock:
            self.log.append(ev)
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(ev)
            except Exception:
                pass


_current: ContextVar = ContextVar("sentari_event_bus", default=None)


def set_current(bus: EventBus | None) -> None:
    _current.set(bus)


def get_current() -> EventBus | None:
    return _current.get()


def emit(kind: str, source: str = "", text: str = "", **data) -> None:
    bus = _current.get()
    if bus is not None:
        bus.emit(Event(kind, source, text, data))
