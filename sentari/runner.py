"""ToolRunner: the ONLY way findings get their ground truth.

Every external tool invocation goes through here. The runner records the exact
command, its output, exit code and timing as an Evidence object. Phases then
build Findings that reference those Evidence ids. Because Evidence can only be
created by actually running a process, a finding can never be fabricated.
"""
from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from .models import Evidence


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
        return shutil.which(tool) is not None

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
        return ev

    def run(
        self,
        command: list[str],
        tool: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Evidence:
        """Run a command and capture it as Evidence. Never raises on tool failure -
        a non-zero exit or timeout is itself recorded as evidence."""
        tool = tool or command[0]
        timeout = timeout or self.default_timeout
        # In sandbox mode, rewrite the command to run inside a container. The
        # recorded evidence shows the actual command that ran (docker run ...).
        if self.sandbox is not None:
            command = self.sandbox.wrap(command)
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

        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError:
            rc, out, err = 127, "", f"tool not found: {command[0]}"
        except subprocess.TimeoutExpired as e:
            rc, out = 124, (e.stdout or "") if isinstance(e.stdout, str) else ""
            err = f"timeout after {timeout}s"
        except Exception as e:  # defensive: still record it
            rc, out, err = 1, "", f"{type(e).__name__}: {e}"

        ev = Evidence(
            id=uuid.uuid4().hex[:12], command=command, returncode=rc,
            stdout=out, stderr=err, started_at=started_at,
            ended_at=datetime.now(timezone.utc).isoformat(),
            duration_sec=round(time.monotonic() - started, 3), tool=tool,
        )
        self._evidence.append(ev)
        return ev
