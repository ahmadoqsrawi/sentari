# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Declarative pentest spec (pentest.json): a reusable, schedulable setup.

A spec captures everything the "New Web App Pentest" wizard asks for: the
target and API specs, the scope (attackable and off-limits), source
repositories, access (test users and custom headers), and context
(instructions, documentation). It maps onto the existing CLI flags, so a spec
adds no new engine behavior and the evidence-first and authorization rules are
unchanged. ``--spec FILE`` loads one; the wizard writes one.
"""
from __future__ import annotations

import json
from pathlib import Path

TEMPLATE = {
    "mode": "web-pentest",              # or "code-review"
    "target": "https://app.example.com",
    "api_specs": [],                     # OpenAPI/Swagger/Postman files or URLs
    "scope": {"attack": ["app.example.com"], "exclude": []},
    "repositories": [],                  # git URLs; adds source review + deeper analysis
    "access": {
        "users": [                       # accounts to test what a logged-in user reaches
            # {"name": "alice", "header": "Cookie", "value": "session=..."}
        ],
        "headers": {                     # sent with every request
            # "Authorization": "Bearer ..."
        },
    },
    "context": {"instructions": "", "documentation": []},
    "oob": {"host": "127.0.0.1", "port": 0},   # 'auto' + a fixed port for external targets
    "safe_mode": True,
    "authorized": False,                 # set true only with written authorization
}


def load(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("spec must be a JSON object")
    return data


def save(path: str, spec: dict) -> None:
    Path(path).write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")


def _identity_specs(users: list[dict]) -> tuple[list[str], list[str]]:
    """Return (identity_flag_values, warnings)."""
    out: list[str] = []
    warns: list[str] = []
    for u in users or []:
        name = str(u.get("name") or u.get("email") or "user")
        header = u.get("header")
        value = u.get("value")
        if header and value is not None:
            out.append(f"{name}:{header}:{value}")
        else:
            warns.append(f"test user {name!r} has no header/value; "
                         "Sentari signs in via a header (e.g. Cookie), not a login form.")
    return out, warns


def apply(spec: dict, args) -> list[str]:
    """Map a spec onto an argparse Namespace. Returns human-readable notes about
    anything that was ignored or only partially supported. Call before
    _expand_presets so the workflow bundle is applied from the resulting args."""
    notes: list[str] = []
    mode = (spec.get("mode") or "web-pentest").strip()
    target = spec.get("target")

    repos = spec.get("repositories") or []
    if len(repos) > 1:
        notes.append(f"{len(repos)} repositories given; using the first ({repos[0]}).")

    if mode == "code-review":
        source = repos[0] if repos else spec.get("source")
        if not source:
            raise ValueError("code-review spec needs a repository or a 'source' path")
        args.code_review = source
    else:
        if not target:
            raise ValueError("web-pentest spec needs a 'target'")
        args.web_pentest = target
        if repos:
            # A repo alongside a live pentest enables source review in the same
            # run: the SAST phase runs next to the dynamic phases.
            args.sast = repos[0]

    scope = spec.get("scope") or {}
    if scope.get("attack"):
        args.scope = list(scope["attack"])
    if scope.get("exclude"):
        args.exclude = list(scope["exclude"])

    api_specs = spec.get("api_specs") or []
    if api_specs:
        args.openapi = api_specs[0]
        if len(api_specs) > 1:
            notes.append(f"{len(api_specs)} API specs given; using the first ({api_specs[0]}).")

    access = spec.get("access") or {}
    idents, warns = _identity_specs(access.get("users") or [])
    notes.extend(warns)
    if idents:
        args.identity = list(args.identity) + idents
    headers = access.get("headers") or {}
    if headers:
        args.header = list(args.header) + [f"{k}: {v}" for k, v in headers.items()]

    context = spec.get("context") or {}
    instr = (context.get("instructions") or "").strip()
    if instr and not args.goal:
        args.goal = instr
    if context.get("documentation"):
        notes.append("documentation files are informational; API specs belong in "
                     "'api_specs' so they become scan targets.")

    oob = spec.get("oob") or {}
    if oob.get("host"):
        args.oob_host = oob["host"]
    if oob.get("port"):
        args.oob_port = int(oob["port"])

    if spec.get("safe_mode") is False:
        args.no_safe_mode = True
    if spec.get("authorized") is True:
        args.authorized = True

    if spec.get("mcp") or (context.get("mcp")):
        notes.append("MCP/cloud connections: use --cloud-audit for deployment review.")

    return notes


def summary(spec: dict) -> str:
    """A compact, human-readable Review & Launch summary of a spec."""
    lines = []
    mode = spec.get("mode", "web-pentest")
    lines.append(f"Mode        : {mode}")
    if mode == "code-review":
        src = (spec.get("repositories") or [spec.get("source")])[0]
        lines.append(f"Source      : {src}")
    else:
        lines.append(f"Target      : {spec.get('target', '(none)')}")
    scope = spec.get("scope") or {}
    if scope.get("attack"):
        lines.append(f"Scope       : {', '.join(scope['attack'])}")
    if scope.get("exclude"):
        lines.append(f"Off-limits  : {', '.join(scope['exclude'])}")
    if spec.get("api_specs"):
        lines.append(f"API specs   : {', '.join(map(str, spec['api_specs']))}")
    if spec.get("repositories") and mode != "code-review":
        lines.append(f"Repositories: {', '.join(spec['repositories'])}")
    access = spec.get("access") or {}
    users = access.get("users") or []
    if users:
        lines.append("Test users  : " + ", ".join(
            str(u.get("name") or u.get("email") or "user") for u in users))
    if access.get("headers"):
        lines.append("Headers     : " + ", ".join(
            f"{k}: ***" for k in access["headers"]))
    oob = spec.get("oob") or {}
    if oob.get("host") and oob["host"] not in ("127.0.0.1", "localhost"):
        lines.append(f"OOB callback: {oob['host']}:{oob.get('port', 0)} (public)")
    instr = ((spec.get("context") or {}).get("instructions") or "").strip()
    if instr:
        lines.append(f"Instructions: {instr[:80]}")
    lines.append(f"Safe mode   : {spec.get('safe_mode', True)}")
    lines.append(f"Authorized  : {spec.get('authorized', False)}")
    return "\n".join(lines)
