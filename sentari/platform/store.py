# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""SQLite store for platform users and their scans (tenant-isolated).

Users authenticate with a per-user API token; only its SHA-256 hash is stored,
and the raw token is shown once at creation. Every scan row carries its owner's
user id, and every read is filtered by the authenticated user, so one tenant can
never see or fetch another's scans. Stdlib sqlite3 only.
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
    payload_json TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
"""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class User:
    id: str
    email: str
    role: str


class PlatformStore:
    def __init__(self, path: str = "sentari-platform.db") -> None:
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(_SCHEMA)
            self.conn.commit()

    # ---- users -----------------------------------------------------------
    def add_user(self, email: str, role: str = "user") -> tuple[User, str]:
        """Create a user; returns (user, raw_token). The token is shown once."""
        token = secrets.token_urlsafe(32)
        uid = uuid.uuid4().hex
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO users(id,email,token_hash,role,created_at) VALUES(?,?,?,?,?)",
                    (uid, email.strip().lower(), hash_token(token), role, time.time()))
                self.conn.commit()
            except sqlite3.IntegrityError as e:
                raise ValueError(f"user already exists: {email}") from e
        return User(uid, email.strip().lower(), role), token

    def user_by_token(self, token: str) -> User | None:
        if not token:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT id,email,role FROM users WHERE token_hash=?",
                (hash_token(token),)).fetchone()
        return User(row["id"], row["email"], row["role"]) if row else None

    def list_users(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id,email,role,created_at FROM users ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    # ---- scans (always tenant-scoped) -----------------------------------
    def create_scan(self, user_id: str, target: str, mode: str | None = None) -> str:
        sid = uuid.uuid4().hex[:16]
        with self._lock:
            self.conn.execute(
                "INSERT INTO scans(id,user_id,target,status,mode,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (sid, user_id, target, "queued", mode, time.time()))
            self.conn.commit()
        return sid

    def update_scan(self, scan_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            self.conn.execute(f"UPDATE scans SET {cols} WHERE id=?",
                              (*fields.values(), scan_id))
            self.conn.commit()

    def get_scan(self, user_id: str, scan_id: str) -> dict | None:
        """Fetch a scan only if it belongs to this user (tenant isolation)."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM scans WHERE id=? AND user_id=?",
                (scan_id, user_id)).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("payload_json"):
            try:
                d["payload"] = json.loads(d.pop("payload_json"))
            except ValueError:
                d.pop("payload_json", None)
        else:
            d.pop("payload_json", None)
        return d

    def list_scans(self, user_id: str) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id,target,status,mode,created_at,finished_at,findings,confirmed,error "
                "FROM scans WHERE user_id=? ORDER BY created_at DESC",
                (user_id,)).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self.conn.close()
