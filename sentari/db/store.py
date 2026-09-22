# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Run persistence.

A small store for completed runs, backing history, the dashboard, and DB-based
retest baselines. Defaults to SQLite (standard library, zero dependencies);
if the DSN is a postgres URL and psycopg2 is installed, it uses Postgres.

The schema is intentionally portable (TEXT ids, TEXT/JSON payload) so the same
SQL runs on both backends.
"""
from __future__ import annotations

import importlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

_SEVS = ["critical", "high", "medium", "low", "info"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summarize(payload: dict) -> tuple[int, dict[str, int]]:
    findings = [f for r in payload.get("results", []) for f in r.get("findings", [])]
    counts = {s: 0 for s in _SEVS}
    for f in findings:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1
    return len(findings), counts


class RunStore:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.is_pg = dsn.startswith(("postgres://", "postgresql://"))
        if self.is_pg:
            psycopg2 = importlib.import_module("psycopg2")
            self.conn = psycopg2.connect(dsn)
            self.ph = "%s"
        else:
            self.conn = sqlite3.connect(dsn)
            self.ph = "?"
        self._init()

    def _init(self) -> None:
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, target TEXT, created_at TEXT, findings INTEGER,
            critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, info INTEGER,
            payload TEXT)""")
        self.conn.commit()

    def save_run(self, target: str, payload: dict) -> str:
        total, c = _summarize(payload)
        rid = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        ph = self.ph
        cols = ("id,target,created_at,findings,critical,high,medium,low,info,payload")
        self.conn.cursor().execute(
            f"INSERT INTO runs ({cols}) VALUES ({','.join([ph]*10)})",
            (rid, target, _now(), total, c["critical"], c["high"], c["medium"],
             c["low"], c["info"], json.dumps(payload)))
        self.conn.commit()
        return rid

    def all_runs(self) -> dict[str, dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT id, payload FROM runs ORDER BY id DESC")
        return {row[0]: json.loads(row[1]) for row in cur.fetchall()}

    def get_run(self, rid: str) -> Optional[dict]:
        cur = self.conn.cursor()
        cur.execute(f"SELECT payload FROM runs WHERE id = {self.ph}", (rid,))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def latest_for_target(self, target: str) -> Optional[dict]:
        cur = self.conn.cursor()
        cur.execute(f"SELECT payload FROM runs WHERE target = {self.ph} "
                    f"ORDER BY id DESC LIMIT 1", (target,))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def close(self) -> None:
        self.conn.close()
