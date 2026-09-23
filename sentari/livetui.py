# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Live terminal monitor for a running assessment (--live).

A multi-panel curses view fed by the real event bus (sentari.events):

  * Header/status: target, mode, model, elapsed time, requests, findings, and
    (for AI modes) token usage and an estimated cost.
  * Left: a live, color-coded transcript of phase/tool/finding events, and for
    agent runs the agent's steps, observations, and thinking.
  * Right: the roster of phases/assessors with a live status.
  * Footer: controls, and an input line that annotates the run log.

Everything shown is a real observed event; nothing is invented. Without a TTY it
streams the same events as plain lines. The scan runs in a worker thread; the
event bus is bound inside that thread so the engine's emits reach this view.
"""
from __future__ import annotations

import sys
import threading
import time
from collections import deque

from . import events


class _Monitor:
    def __init__(self, meta: dict) -> None:
        self.meta = meta
        self.start = time.time()
        self.transcript: deque = deque(maxlen=3000)
        self.roster: dict[str, dict] = {}
        self.order: list[str] = []
        self.requests = 0
        self.findings = 0
        self.tokens = 0
        self.cost = 0.0
        self.model = meta.get("model") or ""
        self.done = False
        self.cancelling = False
        self.cancel = None   # set to the bus cancel Event by run()
        self.orchestrated = False
        self.todos: list = []

    def _roster(self, name: str) -> dict:
        if name not in self.roster:
            self.roster[name] = {"status": "pending", "findings": 0}
            self.order.append(name)
        return self.roster[name]

    def on_event(self, ev) -> None:
        k = ev.kind
        if k == "tool":
            self.requests += 1
        elif k == "finding":
            self.findings += 1
            r = self._roster(ev.source)
            r["findings"] = r.get("findings", 0) + 1
        elif k == "usage":
            self.tokens += ev.data.get("total", 0)
            if ev.data.get("cost"):
                self.cost += ev.data["cost"]
            if ev.source:
                self.model = ev.source
        elif k == "agent":
            self.orchestrated = True
            self._roster(ev.source)["status"] = ev.data.get("status", "running")
        elif k == "todo":
            self.todos = ev.data.get("items", [])
        elif k == "phase_start":
            if not self.orchestrated:
                self._roster(ev.source)["status"] = "running"
        elif k == "phase_done":
            if not self.orchestrated:
                r = self._roster(ev.source)
                r["status"] = "failed" if ev.data.get("error") else "done"
                r["findings"] = ev.data.get("findings", r.get("findings", 0))
        elif k in ("agent_step", "observation") and not self.orchestrated:
            self._roster("agent")["status"] = "running"
        elif k == "run_done":
            self.done = True
            for r in self.roster.values():
                if r["status"] in ("running", "pending"):
                    r["status"] = "done"
        self.transcript.append(ev)

    def elapsed(self) -> str:
        s = int(time.time() - self.start)
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def run(run_callable, meta: dict, on_bus=None):
    """Run ``run_callable`` under the live monitor and return its result.

    ``on_bus(bus)`` is called after the bus is created, to attach extra
    subscribers (e.g. the orchestration view)."""
    bus = events.EventBus()
    mon = _Monitor(meta)
    mon.cancel = bus.cancel
    bus.subscribe(mon.on_event)
    if on_bus is not None:
        on_bus(bus)
    holder: dict = {}

    def worker():
        events.set_current(bus)
        try:
            holder["result"] = run_callable()
        except BaseException as e:  # capture to re-raise on the main thread
            holder["error"] = e
        finally:
            bus.emit(events.Event("run_done", "engine", ""))

    if not sys.stdout.isatty():
        bus.subscribe(_plain_printer(meta))
        t = threading.Thread(target=worker)
        t.start()
        t.join()
        _print_plain_summary(mon)
        if "error" in holder:
            raise holder["error"]
        return holder.get("result")

    import curses
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    try:
        curses.wrapper(_curses_loop, mon, t)
    except Exception:
        t.join()  # UI failed; still let the scan finish
    if t.is_alive():
        t.join()
    if "error" in holder:
        raise holder["error"]
    return holder.get("result")


# ---- plain (non-TTY) streaming -------------------------------------------
def _plain_printer(meta):
    print(f"[live] target={meta.get('target')} mode={meta.get('mode')} "
          f"model={meta.get('model') or '-'}")

    def _p(ev):
        if ev.kind in ("tool",):
            return  # too chatty for a plain stream
        prefix = {"phase_start": "==>", "phase_done": "  <", "finding": " !!",
                  "agent_step": "  >", "thinking": "  ~", "observation": "  <",
                  "usage": "  $", "run_start": "==", "run_done": "=="}.get(ev.kind, "  .")
        line = f"{prefix} [{ev.source}] {ev.text}".rstrip()
        print(line[:200], flush=True)
    return _p


def _print_plain_summary(mon: _Monitor) -> None:
    print(f"[live] done in {mon.elapsed()}  requests={mon.requests}  "
          f"findings={mon.findings}  tokens={mon.tokens}"
          + (f"  est.cost=${mon.cost:.4f}" if mon.cost else ""))


# ---- curses UI -----------------------------------------------------------
_KIND_COLOR = {
    "phase_start": 2, "phase_done": 2, "finding": 3, "thinking": 6, "plan": 6,
    "agent_step": 4, "observation": 0, "tool": 4, "usage": 5, "error": 3,
    "todo": 5, "agent": 4,
}


def _curses_loop(stdscr, mon: _Monitor, worker: threading.Thread) -> None:
    import curses
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(200)
    try:
        curses.start_color()
        curses.use_default_colors()
        for i, c in enumerate([curses.COLOR_WHITE, curses.COLOR_GREEN,
                               curses.COLOR_YELLOW, curses.COLOR_BLUE,
                               curses.COLOR_MAGENTA, curses.COLOR_CYAN], start=1):
            curses.init_pair(i, c, -1)
    except Exception:
        pass
    scroll = 0
    while True:
        try:
            _draw(stdscr, mon, scroll)
        except curses.error:
            pass
        ch = stdscr.getch()
        if ch == -1:
            continue
        if ch in (ord("q"), ord("Q"), ord("c"), ord("C"), 3):  # q / c / Ctrl-C
            if mon.done or not worker.is_alive():
                break                       # finished -> quit the viewer
            if mon.cancel is not None:      # running -> request cancel
                mon.cancel.set()
                mon.cancelling = True
        elif ch == curses.KEY_UP:
            scroll = min(scroll + 1, max(0, len(mon.transcript) - 1))
        elif ch == curses.KEY_DOWN:
            scroll = max(0, scroll - 1)
        elif ch == curses.KEY_PPAGE:
            scroll += 10
        elif ch == curses.KEY_NPAGE:
            scroll = max(0, scroll - 10)


def _draw(stdscr, mon: _Monitor, scroll: int) -> None:
    import curses
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if h < 6 or w < 40:
        stdscr.addstr(0, 0, "terminal too small")
        stdscr.refresh()
        return

    def cp(i):
        try:
            return curses.color_pair(i)
        except Exception:
            return 0

    try:
        from . import __version__ as _ver
    except Exception:
        _ver = "?"
    status = "DONE" if mon.done else ("CANCELLING" if mon.cancelling else "RUNNING")
    header1 = (f" target: {mon.meta.get('target','')}   mode: {mon.meta.get('mode','')}"
               f"   model: {mon.model or '-'}   v{_ver}")
    cost = f"  est.$ {mon.cost:.4f}" if mon.cost else ""
    header2 = (f" status: {status}  elapsed {mon.elapsed()}   requests: {mon.requests}"
               f"   findings: {mon.findings}   tokens: {mon.tokens}{cost}")
    stdscr.addstr(0, 0, header1[:w - 1], cp(6) | curses.A_BOLD)
    stdscr.addstr(1, 0, header2[:w - 1],
                  (cp(2) if mon.done else cp(3)) | curses.A_BOLD)
    stdscr.hline(2, 0, curses.ACS_HLINE, w)

    body_top, body_bottom = 3, h - 3
    right_w = min(40, max(24, w // 3))
    left_w = w - right_w - 1

    # left: transcript (agent/todo events drive the right panel, not the feed)
    lines = [e for e in mon.transcript if e.kind not in ("agent", "todo")]
    view_h = body_bottom - body_top
    end = len(lines) - scroll
    start = max(0, end - view_h)
    row = body_top
    for ev in lines[start:end]:
        prefix = {"phase_start": "==>", "phase_done": "  <", "finding": " !!",
                  "agent_step": "  >", "thinking": "  ~", "plan": " *", "observation": "  <",
                  "tool": "  .", "usage": "  $", "note": " >>"}.get(ev.kind, "  .")
        text = f"{prefix} [{ev.source}] {ev.text}"
        color = cp(_KIND_COLOR.get(ev.kind, 1))
        if ev.kind == "finding" and ev.data.get("severity") in ("critical", "high"):
            color = cp(3) | curses.A_BOLD
        stdscr.addstr(row, 0, text[:left_w], color)
        row += 1
        if row >= body_bottom:
            break

    # divider + right: agent tree (orchestrated) or phase roster, then todos
    for r in range(body_top, body_bottom):
        stdscr.addch(r, left_w, curses.ACS_VLINE)
    title = "AGENTS" if mon.orchestrated else "ROSTER"
    stdscr.addstr(body_top, left_w + 2, title, curses.A_BOLD)
    rrow = body_top + 1
    _mark = {"running": ("*", 3), "done": ("+", 2), "failed": ("x", 3),
             "pending": (".", 1), "spawning": ("*", 6)}
    for name in mon.order:
        if rrow >= body_bottom:
            break
        st = mon.roster[name]
        sym, col = _mark.get(st["status"], (".", 1))
        # indent spawned agents under Root Agent for a tree look
        indent = "" if name == "Root Agent" else "  "
        line = f"{indent}{sym} {name}"
        stdscr.addstr(rrow, left_w + 2, line[:right_w - 3], cp(col))
        rrow += 1

    if mon.todos and rrow < body_bottom - 1:
        rrow += 1
        stdscr.addstr(rrow, left_w + 2, "TODO", curses.A_BOLD)
        rrow += 1
        _tmark = {"done": "[x]", "running": "[~]", "pending": "[ ]"}
        for t in mon.todos:
            if rrow >= body_bottom:
                break
            box = _tmark.get(t.get("status"), "[ ]")
            stdscr.addstr(rrow, left_w + 2, f"{box} {t['name']}"[:right_w - 3],
                          cp(2) if t.get("status") == "done" else 0)
            rrow += 1

    # footer
    stdscr.hline(h - 2, 0, curses.ACS_HLINE, w)
    if mon.done:
        foot = " done.   [q] quit    [up/down] scroll"
    elif mon.cancelling:
        foot = " cancelling... stopping the current tool and skipping the rest"
    else:
        foot = " [c] or [q] cancel the scan    [up/down] scroll"
    stdscr.addstr(h - 1, 0, foot[:w - 1],
                  cp(3) | curses.A_BOLD if mon.cancelling else 0)
    stdscr.refresh()
