# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Docker sandbox for the gated offensive phases.

When enabled, the exploitation and post-exploitation tools run inside a
throwaway Docker container instead of on the host, so an exploit or a heavy
tool executes in an isolated, disposable environment. The container is removed
after each command (`--rm`).

This does not change what Sentari reports or loosen any gate: it only isolates
where the already-gated commands run. It is off by default and requires Docker.
"""
from __future__ import annotations

import shutil

# A default image that ships the common offensive toolchain (Metasploit, etc.).
# Operators can override it with --sandbox-image.
DEFAULT_IMAGE = "metasploitframework/metasploit-framework:latest"


class Sandbox:
    def __init__(self, image: str = DEFAULT_IMAGE, network: str = "host",
                 extra_args: list[str] | None = None) -> None:
        self.image = image
        self.network = network
        self.extra_args = extra_args or []

    @staticmethod
    def available() -> bool:
        return shutil.which("docker") is not None

    def wrap(self, command: list[str]) -> list[str]:
        """Return the command rewritten to run inside a disposable container."""
        return ["docker", "run", "--rm", "--network", self.network,
                *self.extra_args, self.image, *command]
