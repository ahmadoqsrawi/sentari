# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Store for platform users and their scans (tenant-isolated).

Backends: SQLite by default (a file path), or PostgreSQL when the DSN starts
with postgres:// or postgresql:// (needs psycopg2). Postgres lets Celery workers
on different machines share one store instead of a common volume. The public API
is identical for both.

Users authenticate with a per-user API token; only its SHA-256 hash is stored,
and the raw token is shown once at creation. Every scan/schedule row carries its
owner's user id, and every read is filtered by the authenticated user, so one
tenant can never see another's data.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    mode TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    findings INTEGER DEFAULT 0,
    confirmed INTEGER DEFAULT 0,
    error TEXT,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    target TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    options_json TEXT,
    mode TEXT,
    interval_sec INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    last_run REAL,
    next_run REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sched_user ON schedules(user_id);
"""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class User:
    id: str
    email: str
    role: str


class PlatformStore:
    def __init__(self, dsn: str = "sentari-platform.db") -> None:
        self._lock = threading.Lock()
        self.is_pg = dsn.startswith(("postgres://", "postgresql://"))
        if self.is_pg:
            import psycopg2
            import psycopg2.extras
            self._pg = psycopg2
            self._extras = psycopg2.extras
            self.conn = psycopg2.connect(dsn)
            self._integrity = (sqlite3.IntegrityError, psycopg2.IntegrityError)
        else:
            self.conn = sqlite3.connect(dsn, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._integrity = (sqlite3.IntegrityError,)
        with self._lock:
            self._script(_SCHEMA)

    # ---- backend-agnostic helpers ---------------------------------------
    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.is_pg else sql

    def _cursor(self):
        if self.is_pg:
            return self.conn.cursor(cursor_factory=self._extras.RealDictCursor)
        return self.conn.cursor()

    def _script(self, sql: str) -> None:
        if self.is_pg:
            cur = self._cursor()
            cur.execute(sql)          # psycopg2 runs multiple statements in one execute
            cur.close()
        else:
            self.conn.executescript(sql)  # sqlite needs executescript for multi-statement
        self.conn.commit()

    def _write(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._cursor()
            cur.execute(self._q(sql), params)
            rc = cur.rowcount
            self.conn.commit()
            cur.close()
            return rc

    def _one(self, sql: str, params: tuple = ()) -> dict | None:
        with self._lock:
            cur = self._cursor()
            cur.execute(self._q(sql), params)
            row = cur.fetchone()
            cur.close()
            return dict(row) if row else None

    def _all(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._cursor()
            cur.execute(self._q(sql), params)
            rows = cur.fetchall()
            cur.close()
            return [dict(r) for r in rows]

    # ---- users -----------------------------------------------------------
    def add_user(self, email: str, role: str = "user") -> tuple[User, str]:
        """Create a user; returns (user, raw_token). The token is shown once."""
        token = secrets.token_urlsafe(32)
        uid = uuid.uuid4().hex
        try:
            self._write(
                "INSERT INTO users(id,email,token_hash,role,created_at) VALUES(?,?,?,?,?)",
                (uid, email.strip().lower(), hash_token(token), role, time.time()))
        except self._integrity as e:
            raise ValueError(f"user already exists: {email}") from e
        return User(uid, email.strip().lower(), role), token

    def user_by_token(self, token: str) -> User | None:
        if not token:
            return None
        row = self._one("SELECT id,email,role FROM users WHERE token_hash=?",
                        (hash_token(token),))
        return User(row["id"], row["email"], row["role"]) if row else None

    def list_users(self) -> list[dict]:
        return self._all("SELECT id,email,role,created_at FROM users ORDER BY created_at")

    # ---- scans (always tenant-scoped) -----------------------------------
    def create_scan(self, user_id: str, target: str, mode: str | None = None) -> str:
        sid = uuid.uuid4().hex[:16]
        self._write(
            "INSERT INTO scans(id,user_id,target,status,mode,created_at) VALUES(?,?,?,?,?,?)",
            (sid, user_id, target, "queued", mode, time.time()))
        return sid

    def update_scan(self, scan_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self._write(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))

    def get_scan(self, user_id: str, scan_id: str) -> dict | None:
        d = self._one("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
        if not d:
            return None
        if d.get("payload_json"):
            try:
                d["payload"] = json.loads(d.pop("payload_json"))
            except (ValueError, TypeError):
                d.pop("payload_json", None)
        else:
            d.pop("payload_json", None)
        return d

    def list_scans(self, user_id: str) -> list[dict]:
        return self._all(
            "SELECT id,target,status,mode,created_at,finished_at,findings,confirmed,error "
            "FROM scans WHERE user_id=? ORDER BY created_at DESC", (user_id,))

    # ---- schedules (tenant-scoped) --------------------------------------
    def add_schedule(self, user_id: str, target: str, scope: list, interval_sec: int,
                     options: dict | None = None, mode: str | None = None) -> str:
        sid = uuid.uuid4().hex[:16]
        now = time.time()
        self._write(
            "INSERT INTO schedules(id,user_id,target,scope_json,options_json,mode,"
            "interval_sec,enabled,created_at,next_run) VALUES(?,?,?,?,?,?,?,1,?,?)",
            (sid, user_id, target, json.dumps(scope), json.dumps(options or {}),
             mode, int(interval_sec), now, now + int(interval_sec)))
        return sid

    def list_schedules(self, user_id: str) -> list[dict]:
        return self._all(
            "SELECT id,target,mode,interval_sec,enabled,created_at,last_run,next_run "
            "FROM schedules WHERE user_id=? ORDER BY created_at DESC", (user_id,))

    def get_schedule(self, user_id: str, sched_id: str) -> dict | None:
        return self._one("SELECT * FROM schedules WHERE id=? AND user_id=?",
                         (sched_id, user_id))

    def delete_schedule(self, user_id: str, sched_id: str) -> bool:
        return self._write("DELETE FROM schedules WHERE id=? AND user_id=?",
                           (sched_id, user_id)) > 0

    def due_schedules(self, now: float | None = None) -> list[dict]:
        now = now if now is not None else time.time()
        return self._all("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,))

    def mark_schedule_ran(self, sched_id: str, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        row = self._one("SELECT interval_sec FROM schedules WHERE id=?", (sched_id,))
        if row:
            self._write("UPDATE schedules SET last_run=?, next_run=? WHERE id=?",
                        (now, now + row["interval_sec"], sched_id))

    def close(self) -> None:
        with self._lock:
            self.conn.close()
