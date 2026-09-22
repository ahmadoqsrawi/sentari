# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Local terminal viewer for Sentari results.

An interactive, keyboard-driven browser over the findings of one or more runs,
built on the standard-library `curses` (no dependencies). It reads saved runs
(a --json report, a --runs-dir, or a --db) and shows findings by severity with
their evidence, so you can review a run without a browser or the web dashboard.

Falls back to a plain colored dump when there is no TTY (pipes, CI).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_LABEL = ["critical", "high", "medium", "low", "info"]
# ANSI colors for the non-curses fallback
_ANSI = {"critical": "\033[97;41m", "high": "\033[91m", "medium": "\033[93m",
         "low": "\033[94m", "info": "\033[90m"}
_RESET = "\033[0m"


def _flatten(runs: dict) -> tuple[list[dict], dict]:
    """Return (findings, evidence_by_id) across all runs."""
    findings, evmap = [], {}
    for run_id, payload in runs.items():
        results = payload.get("results", payload if isinstance(payload, list) else [])
        for r in results:
            for e in r.get("evidence", []):
                evmap[e.get("id")] = e
            for f in r.get("findings", []):
                f = dict(f)
                f["_run"] = run_id
                findings.append(f)
    findings.sort(key=lambda f: -_ORDER.get(f.get("severity", "info"), 0))
    return findings, evmap


def _counts(findings: list[dict]) -> dict:
    c = {s: 0 for s in _SEV_LABEL}
    for f in findings:
        c[f.get("severity", "info")] = c.get(f.get("severity", "info"), 0) + 1
    return c


def view(runs: dict) -> None:
    """Open the interactive viewer, or fall back to a plain dump without a TTY."""
    findings, evmap = _flatten(runs)
    if not sys.stdout.isatty():
        _plain(findings, evmap)
        return
    try:
        import curses
        curses.wrapper(_curses_main, findings, evmap)
    except Exception:
        _plain(findings, evmap)


def _plain(findings: list[dict], evmap: dict) -> None:
    c = _counts(findings)
    print("Sentari results  " + "  ".join(
        f"{_ANSI[s]}{c[s]} {s}{_RESET}" for s in _SEV_LABEL if c[s]))
    print("-" * 70)
    for f in findings:
        s = f.get("severity", "info")
        print(f"{_ANSI.get(s,'')}[{s.upper():5}]{_RESET} {f.get('title','')}")
        if f.get("location"):
            print(f"        where: {f['location']}")
        print(f"        {f.get('description','')}")
        for eid in f.get("evidence_ids", []):
            ev = evmap.get(eid)
            if ev:
                print(f"        evidence {eid}: {' '.join(ev.get('command', []))} "
                      f"-> exit {ev.get('returncode')}")
    print(f"\n{len(findings)} finding(s).")


def _curses_main(stdscr, findings, evmap) -> None:
    import curses
    curses.curs_set(0)
    curses.use_default_colors()
    pairs = {}
    for i, (s, fg) in enumerate([("critical", curses.COLOR_RED), ("high", curses.COLOR_RED),
                                 ("medium", curses.COLOR_YELLOW), ("low", curses.COLOR_BLUE),
                                 ("info", curses.COLOR_WHITE)], start=1):
        curses.init_pair(i, fg, -1)
        pairs[s] = curses.color_pair(i)

    idx, top, filt, detail, dscroll = 0, 0, None, False, 0
    while True:
        shown = [f for f in findings if filt is None or f.get("severity") == filt]
        if idx >= len(shown):
            idx = max(0, len(shown) - 1)
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        c = _counts(findings)
        header = "Sentari  " + "  ".join(f"{c[s]} {s}" for s in _SEV_LABEL if c[s])
        filt_txt = f"filter: {filt or 'all'}"
        stdscr.addnstr(0, 0, f"{header}   [{filt_txt}]", w - 1, curses.A_BOLD)
        stdscr.addnstr(h - 1, 0,
                       " up/down move  enter details  f filter  q quit", w - 1, curses.A_DIM)

        if detail and shown:
            _draw_detail(stdscr, shown[idx], evmap, pairs, dscroll, h, w)
        else:
            list_h = h - 3
            if idx < top:
                top = idx
            if idx >= top + list_h:
                top = idx - list_h + 1
            for row, f in enumerate(shown[top:top + list_h]):
                y = row + 2
                real = top + row
                sev = f.get("severity", "info")
                line = f"[{sev.upper():5}] {f.get('title','')}"
                attr = pairs.get(sev, 0) | (curses.A_REVERSE if real == idx else 0)
                stdscr.addnstr(y, 0, line.ljust(w - 1), w - 1, attr)
            if not shown:
                stdscr.addnstr(2, 0, "(no findings for this filter)", w - 1)
        stdscr.refresh()

        k = stdscr.getch()
        if k in (ord("q"), 27) and not detail:
            break
        elif k in (ord("q"), 27, curses.KEY_LEFT) and detail:
            detail, dscroll = False, 0
        elif k in (curses.KEY_DOWN, ord("j")):
            if detail:
                dscroll += 1
            else:
                idx = min(idx + 1, max(0, len(shown) - 1))
        elif k in (curses.KEY_UP, ord("k")):
            if detail:
                dscroll = max(0, dscroll - 1)
            else:
                idx = max(0, idx - 1)
        elif k in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT) and shown:
            detail, dscroll = True, 0
        elif k == ord("f"):
            opts = [None] + _SEV_LABEL
            filt = opts[(opts.index(filt) + 1) % len(opts)]
            idx, top = 0, 0


def _draw_detail(stdscr, f, evmap, pairs, dscroll, h, w) -> None:
    import curses
    import textwrap
    sev = f.get("severity", "info")
    lines = [(f"[{sev.upper()}] {f.get('title','')}", pairs.get(sev, 0))]
    if f.get("location"):
        lines.append((f"where: {f['location']}", 0))
    meta = f.get("metadata") or {}
    if (meta.get("cvss") or {}).get("score") is not None:
        lines.append((f"cvss: {meta['cvss']['score']}", 0))
    if meta.get("known_exploited"):
        lines.append(("KNOWN EXPLOITED (CISA KEV)", pairs.get("critical", 0)))
    if meta.get("candidate"):
        lines.append((f"candidate: {meta['candidate']}", 0))
    lines.append(("", 0))
    for para in (f.get("description", ""), f.get("recommendation", "")):
        for wl in textwrap.wrap(para, max(20, w - 2)):
            lines.append((wl, 0))
        if para:
            lines.append(("", 0))
    lines.append(("--- evidence ---", curses.A_BOLD))
    for eid in f.get("evidence_ids", []):
        ev = evmap.get(eid)
        if not ev:
            lines.append((f"{eid}: (not in this run)", 0))
            continue
        lines.append((f"{eid}  $ {' '.join(ev.get('command', []))}  -> exit {ev.get('returncode')}", 0))
        for wl in textwrap.wrap((ev.get("stdout") or "")[:600], max(20, w - 2))[:8]:
            lines.append(("  " + wl, curses.A_DIM))
    for row, (text, attr) in enumerate(lines[dscroll:dscroll + (h - 3)]):
        stdscr.addnstr(row + 2, 0, text, w - 1, attr)


def load(json_file: str | None, runs_dir: str | None, db: str | None) -> dict:
    """Load runs from a single --json file, a --runs-dir, or a --db."""
    if json_file:
        payload = json.loads(Path(json_file).read_text(encoding="utf-8"))
        return {Path(json_file).stem: payload}
    if db:
        from .db import RunStore
        store = RunStore(db)
        try:
            return store.all_runs()
        finally:
            store.close()
    from .web.server import _load_runs
    return _load_runs(Path(runs_dir or "runs"))
