"""Custom proof-of-concept runtime (sandboxed).

Runs an operator-supplied Python PoC against the target inside a disposable
Docker container, and records the PoC's real output as evidence. A finding is
recorded only when the PoC itself prints the success marker, so Sentari never
decides on its own that an exploit worked.

The PoC receives the target as argv[1]. It signals success by printing the
marker `SENTARI_POC_SUCCESS` to stdout. This runs real code, so it is gated with
the other offensive features (--no-safe-mode + --exploit) and is for authorized,
non-production targets only.
"""
from __future__ import annotations

import os
from pathlib import Path

SUCCESS_MARKER = "SENTARI_POC_SUCCESS"
DEFAULT_IMAGE = "python:3-slim"


def docker_command(script: str, target: str, image: str = DEFAULT_IMAGE) -> list[str]:
    """Build the docker command that runs the PoC read-only inside a container."""
    abs_script = str(Path(script).resolve())
    return ["docker", "run", "--rm", "--network", "host",
            "-v", f"{abs_script}:/poc.py:ro", image, "python", "/poc.py", target]


def run_poc(runner, script: str, target: str, image: str = DEFAULT_IMAGE,
            timeout: int = 300) -> tuple[object, bool, str]:
    """Run the PoC in a container. Returns (evidence, success, note)."""
    if not Path(script).is_file():
        return None, False, f"PoC not found: {script}"
    cmd = docker_command(script, target, image)
    # sandbox_wrap=False: the command already brings its own container.
    ev = runner.run(cmd, tool="poc", timeout=timeout, sandbox_wrap=False)
    success = SUCCESS_MARKER in (ev.stdout or "")
    return ev, success, ""
