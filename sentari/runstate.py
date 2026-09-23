# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Per-run checkpoint store, so a long run can be resumed after an interruption.

The engine writes the results-so-far after each phase to a named run's state
file. `--resume NAME` loads the completed phases and continues with the rest,
which matters for long assessments (a WAF-fronted injection sweep, an overnight
run) that get killed part way. State lives under ~/.sentari/state/<name>/ by
default, or a directory passed explicitly.
"""
from __future__ import annotations

import json
import re
from pathlib import Path


def _base(state_dir: str | None) -> Path:
    return Path(state_dir) if state_dir else (Path.home() / ".sentari" / "state")


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "run"


def state_file(run_name: str, state_dir: str | None = None) -> Path:
    return _base(state_dir) / _slug(run_name) / "results.json"


def save(run_name: str, payload: dict, state_dir: str | None = None) -> None:
    p = state_file(run_name, state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def load(run_name: str, state_dir: str | None = None) -> dict | None:
    p = state_file(run_name, state_dir)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def clear(run_name: str, state_dir: str | None = None) -> None:
    p = state_file(run_name, state_dir)
    try:
        p.unlink()
    except OSError:
        pass
