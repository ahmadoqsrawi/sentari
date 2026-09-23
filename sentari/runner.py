# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""ToolRunner: the ONLY way findings get their ground truth.

Every external tool invocation goes through here. The runner records the exact
command, its output, exit code and timing as an Evidence object. Phases then
build Findings that reference those Evidence ids. Because Evidence can only be
created by actually running a process, a finding can never be fabricated.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import Evidence

# Extra directories to look in when a tool is not on PATH. Security scanners are
# often installed to a Go bin or a user bin that a non-login shell (a Celery
# worker, a systemd unit, a detached process) does not have on PATH, which would
# otherwise make a scanner look "missing" and silently degrade a phase to zero.
# Override or extend with the SENTARI_TOOLS_PATH env var (colon-separated).
_DEFAULT_TOOL_DIRS = [
    "/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin",
    "/snap/bin", "/opt/bin",
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/bin"),
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.cargo/bin"),
]


def _tool_search_dirs() -> list[str]:
    dirs = [d for d in os.environ.get("SENTARI_TOOLS_PATH", "").split(os.pathsep) if d]
    return dirs + _DEFAULT_TOOL_DIRS


def resolve_tool(name: str) -> Optional[str]:
    """Full path to an external tool, searching PATH and known install dirs.

    Independent of the caller's PATH, so a worker or detached process finds the
    same tools an interactive shell would. Returns None if not found anywhere."""
    found = shutil.which(name)
    if found:
        return found
    for d in _tool_search_dirs():
        cand = Path(d) / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


class ToolRunner:
    def __init__(self, default_timeout: int = 120, dry_run: bool = False,
                 sandbox=None) -> None:
        self.default_timeout = default_timeout
        self.dry_run = dry_run
        self.sandbox = sandbox  # optional Sandbox: run commands inside a container
        self._evidence: list[Evidence] = []

    def available(self, tool: str) -> bool:
        # In sandbox mode the tools live in the image, not on the host.
        if self.sandbox is not None:
            return True
        return resolve_tool(tool) is not None

    @property
    def evidence(self) -> list[Evidence]:
        return list(self._evidence)

    def record_internal(
        self,
        action: list[str],
        returncode: int,
        stdout: str,
        stderr: str = "",
        duration_sec: float = 0.0,
    ) -> Evidence:
        """Record a built-in probe (real socket/DNS/HTTP action performed by
        Sentari itself) as Evidence. Used when no external tool is required, but
        a real action still happened and produced a real result."""
        ts = datetime.now(timezone.utc).isoformat()
        ev = Evidence(
            id=uuid.uuid4().hex[:12], command=["sentari-builtin", *action],
            returncode=returncode, stdout=stdout, stderr=stderr,
            started_at=ts, ended_at=ts, duration_sec=duration_sec, tool="sentari-builtin",
        )
        self._evidence.append(ev)
        from . import events
        events.emit("tool", "builtin", " ".join(str(a) for a in action),
                    rc=returncode, duration=duration_sec)
        return ev

    def run(
        self,
        command: list[str],
        tool: Optional[str] = None,
        timeout: Optional[int] = None,
        sandbox_wrap: bool = True,
    ) -> Evidence:
        """Run a command and capture it as Evidence. Never raises on tool failure -
        a non-zero exit or timeout is itself recorded as evidence. Set
        sandbox_wrap=False for a command that already brings its own container."""
        tool = tool or command[0]
        timeout = timeout or self.default_timeout
        # In sandbox mode, rewrite the command to run inside a container. The
        # recorded evidence shows the actual command that ran (docker run ...).
        exec_command = command
        if self.sandbox is not None and sandbox_wrap:
            command = exec_command = self.sandbox.wrap(command)
        else:
            # Resolve the executable to a full path so it runs even when the
            # process PATH is minimal (worker/systemd/detached process). The
            # recorded evidence keeps the original command name for readability.
            resolved = resolve_tool(command[0])
            if resolved:
                exec_command = [resolved, *command[1:]]
        started = time.monotonic()
        started_at = datetime.now(timezone.utc).isoformat()

        if self.dry_run:
            ev = Evidence(
                id=uuid.uuid4().hex[:12], command=command, returncode=0,
                stdout="", stderr="[dry-run: not executed]",
                started_at=started_at, ended_at=started_at, duration_sec=0.0, tool=tool,
            )
            self._evidence.append(ev)
            return ev

        # Run via Popen and poll, so a user cancel (or the timeout) can kill the
        # in-flight tool immediately instead of waiting for it to finish.
        from . import events
        rc, out, err = 1, "", ""
        try:
            proc = subprocess.Popen(exec_command, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        except FileNotFoundError:
            rc, out, err = 127, "", f"tool not found: {command[0]}"
        except Exception as e:  # defensive: still record it
            rc, out, err = 1, "", f"{type(e).__name__}: {e}"
        else:
            while True:
                try:
                    o, e = proc.communicate(timeout=1.0)
                    out += o or ""
                    err += e or ""
                    rc = proc.returncode
                    break
                except subprocess.TimeoutExpired:
                    reason = None
                    if events.should_cancel():
                        reason, rc = " [cancelled by user]", 130
                    elif time.monotonic() - started > timeout:
                        reason, rc = f" [timeout after {timeout}s]", 124
                    if reason:
                        proc.kill()
                        try:
                            o, e = proc.communicate(timeout=5)
                            out += o or ""
                            err += e or ""
                        except Exception:
                            pass
                        err += reason
                        break

        dur = round(time.monotonic() - started, 3)
        ev = Evidence(
            id=uuid.uuid4().hex[:12], command=command, returncode=rc,
            stdout=out, stderr=err, started_at=started_at,
            ended_at=datetime.now(timezone.utc).isoformat(),
            duration_sec=dur, tool=tool,
        )
        self._evidence.append(ev)
        from . import events
        events.emit("tool", tool, f"{' '.join(command)} -> exit {rc} ({dur}s)",
                    rc=rc, duration=dur)
        return ev
