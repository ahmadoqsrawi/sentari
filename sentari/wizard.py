# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Interactive "New Web App Pentest" setup: `sentari wizard`.

Walks the same five steps as a hosted pentest wizard (Target and APIs, Scope,
Repositories, Access, Context), shows a Review & Launch summary, saves a
reusable pentest.json spec, and launches the run. It only collects a spec and
hands it to the normal engine, so every authorization and evidence rule applies
exactly as if the flags had been typed by hand.
"""
from __future__ import annotations

import sys

from . import domainverify, spec as spec_mod

WEB_STEPS = ["Target & APIs", "Scope", "Repositories", "Access", "Context"]
CR_STEPS = ["Source", "Context"]


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return val or default


def _ask_yes(prompt: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        val = input(f"{prompt} ({d}): ").strip().lower()
    except EOFError:
        return default
    if not val:
        return default
    return val in ("y", "yes")


def _ask_list(prompt: str) -> list[str]:
    print(f"{prompt} (one per line, blank to finish):")
    out: list[str] = []
    while True:
        try:
            val = input("  > ").strip()
        except EOFError:
            break
        if not val:
            break
        out.append(val)
    return out


def _step_target(spec: dict) -> None:
    print("\n── Step 1/5  Target & APIs " + "─" * 30)
    spec["mode"] = "code-review" if _ask_yes(
        "Code review only (static, no live target)?", False) else "web-pentest"
    if spec["mode"] == "web-pentest":
        spec["target"] = _ask("Target URL or host", spec.get("target", ""))
        host = _host(spec["target"])
        if host and _ask_yes(f"Verify you control {host} via DNS TXT now?", False):
            _run_verify(host)
        spec["api_specs"] = _ask_list("API specs (OpenAPI/Swagger/Postman files or URLs)")
    else:
        spec["target"] = ""


def _step_scope(spec: dict) -> None:
    print("\n── Step 2/5  Scope " + "─" * 38)
    scope = spec.setdefault("scope", {})
    host = _host(spec.get("target", ""))
    attack = _ask_list("Attackable hosts/CIDRs (blank = the target host)")
    scope["attack"] = attack or ([host] if host else [])
    scope["exclude"] = _ask_list("Off-limits hosts/CIDRs (never touched)")


def _step_repos(spec: dict) -> None:
    print("\n── Step 3/5  Repositories " + "─" * 31)
    print("A git repo (GitHub/GitLab/Bitbucket) enables source review and deeper analysis.")
    print("Without one, testing is black-box only.")
    spec["repositories"] = _ask_list("Repository URLs")


def _step_access(spec: dict) -> None:
    print("\n── Step 4/5  Access " + "─" * 37)
    access = spec.setdefault("access", {"users": [], "headers": {}})
    access["users"] = []
    print("Test users: Sentari signs in via a header it sends (e.g. a session Cookie).")
    while _ask_yes("Add a test user?", False):
        name = _ask("  Name/email", "user")
        if _ask_yes("  Record the login through a browser and capture the session?", False):
            user = _record_login_user(name, spec.get("target", ""))
            if user:
                access["users"].append(user)
                continue
            print("  Falling back to entering the auth header manually.")
        header = _ask("  Auth header name", "Cookie")
        value = _ask("  Auth header value")
        access["users"].append({"name": name, "header": header, "value": value})
    access["headers"] = {}
    print("Custom headers sent with every request (API keys, JWTs, WAF-bypass tokens).")
    while _ask_yes("Add a header?", False):
        name = _ask("  Header name")
        value = _ask("  Header value")
        if name:
            access["headers"][name] = value


def _step_context(spec: dict) -> None:
    print("\n── Step 5/5  Context " + "─" * 36)
    ctx = spec.setdefault("context", {})
    ctx["instructions"] = _ask("Instructions (concerns, focus areas)",
                               ctx.get("instructions", ""))
    ctx["documentation"] = _ask_list("Reference docs (optional)")
    spec["safe_mode"] = not _ask_yes(
        "Enable active/intrusive checks (safe mode off)?", False)


def _cr_step_source(spec: dict) -> None:
    from . import repo
    print("\n── Step 1/2  Source " + "─" * 37)
    print("Connect a git repo (GitHub/GitLab/Bitbucket) or give a local path (an upload).")
    print("Code review is static: no live environment is touched.")
    current = (spec.get("repositories") or [spec.get("source", "")])
    src = _ask("Repository URL or local path", current[0] if current else "")
    if src and repo.is_repo_url(src):
        spec["repositories"] = [src]
        spec["source"] = ""
    else:
        spec["source"] = src
        spec["repositories"] = []


def _cr_step_context(spec: dict) -> None:
    print("\n── Step 2/2  Context " + "─" * 36)
    ctx = spec.setdefault("context", {})
    ctx["instructions"] = _ask(
        "Instructions (threats to focus on, parts to review, known issues)",
        ctx.get("instructions", ""))
    ctx["documentation"] = _ask_list("Reference docs / API specs (optional)")


_WEB_STEP_FNS = [_step_target, _step_scope, _step_repos, _step_access, _step_context]
_CR_STEP_FNS = [_cr_step_source, _cr_step_context]


def _host(target: str) -> str:
    if not target:
        return ""
    from .authorization import host_only
    return host_only(target)


def _record_login_user(name: str, target: str) -> dict | None:
    """Drive a browser login and return a test-user entry with the captured
    session cookie, or None if it could not be recorded."""
    from . import loginrec
    if not loginrec.available():
        print('  Playwright not installed (pip install "sentari[browser]" '
              "&& playwright install chromium).")
        return None
    login_url = _ask("  Login page URL", target)
    username = _ask("  Username/email", name if "@" in name else "")
    password = _ask("  Password")
    success = _ask("  Text shown after a successful login (optional, confirms it)")
    if not (login_url and username and password):
        return None
    print("  Recording login...")
    rec = loginrec.record_login(login_url, username, password,
                                success_text=success or None)
    if rec.error:
        print(f"  error: {rec.error}")
        return None
    print(f"  Login {'verified' if rec.verified else 'NOT verified'}: {rec.detail}")
    if rec.screenshot:
        print(f"  screenshot: {rec.screenshot}")
    if not rec.cookie_header:
        print("  no session cookies captured.")
        return None
    return {"name": name, "header": "Cookie", "value": rec.cookie_header,
            "login_verified": rec.verified}


def _run_verify(domain: str) -> None:
    res = domainverify.verify(domain)
    if res.verified:
        print(f"  ✓ {domain} verified (TXT record found).")
    else:
        print("  " + domainverify.instructions(domain, res.token).replace("\n", "\n  "))
        if res.error:
            print(f"  note: {res.error}")


def _mode_from_argv(argv: list[str]) -> str | None:
    if not argv:
        return None
    a = argv[0].strip().lower()
    if a in ("code-review", "code", "review", "cr"):
        return "code-review"
    if a in ("web-pentest", "web", "pentest", "wp"):
        return "web-pentest"
    return None


def _choose_mode() -> str:
    print("\nWhat do you want to set up?")
    print("  1. Web App Pentest  (live target)")
    print("  2. Code Review      (source only, no live environment)")
    return "code-review" if _ask("Choose", "1").strip() == "2" else "web-pentest"


def run(argv: list[str] | None = None) -> int:
    argv = argv or []
    print("Sentari: New Assessment")
    print("Answer each step; blank keeps the default. Ctrl-C to abort.")
    try:
        mode = _mode_from_argv(argv) or _choose_mode()
        if mode == "code-review":
            return _run_code_review()
        return _run_web_pentest()
    except KeyboardInterrupt:
        print("\nAborted.")
        return 1


def _run_web_pentest() -> int:
    print("\n[New Web App Pentest]")
    spec = {"mode": "web-pentest", "target": "", "api_specs": [],
            "scope": {"attack": [], "exclude": []}, "repositories": [],
            "access": {"users": [], "headers": {}},
            "context": {"instructions": "", "documentation": []},
            "safe_mode": True, "authorized": False}
    for fn in _WEB_STEP_FNS:
        fn(spec)
    return _review_and_launch(spec, WEB_STEPS, _WEB_STEP_FNS, "pentest.json")


def _run_code_review() -> int:
    print("\n[New Code Review]")
    # Static review of source you are authorized to read, so it is authorized
    # by default and touches no live environment.
    spec = {"mode": "code-review", "repositories": [], "source": "",
            "context": {"instructions": "", "documentation": []},
            "safe_mode": True, "authorized": True}
    for fn in _CR_STEP_FNS:
        fn(spec)
    return _review_and_launch(spec, CR_STEPS, _CR_STEP_FNS, "code-review.json")


def _review_and_launch(spec: dict, steps: list[str], step_fns: list,
                       save_name: str) -> int:
    while True:
        print("\n== Review & Launch " + "=" * 37)
        print(spec_mod.summary(spec))
        print("\n[Enter] launch   [e] edit a step   [s] save spec   [q] quit")
        try:
            choice = input("> ").strip().lower()
        except EOFError:
            choice = "q"
        if choice in ("", "l", "launch"):
            return _launch(spec, save_name)
        if choice in ("q", "quit"):
            print("Nothing launched.")
            return 0
        if choice in ("s", "save"):
            path = _ask("Save spec to", save_name)
            spec_mod.save(path, spec)
            print(f"Saved {path}. Re-run with: sentari --spec {path}")
        if choice in ("e", "edit"):
            for i, name in enumerate(steps, 1):
                print(f"  {i}. {name}")
            sel = _ask("Edit which step number")
            if sel.isdigit() and 1 <= int(sel) <= len(step_fns):
                step_fns[int(sel) - 1](spec)


def _launch(spec: dict, save_name: str) -> int:
    # A live pentest needs explicit authorization; code review of your own
    # source does not (it only reads local files).
    if spec.get("mode") != "code-review" and not spec.get("authorized"):
        if not _ask_yes(
                "I have explicit written authorization to test this target", False):
            print("Not launched: authorization is required. You can save the spec "
                  "and launch later with --spec once authorized.")
            return 0
        spec["authorized"] = True
    spec_mod.save(save_name, spec)
    print(f"\nSpec saved to {save_name}. Launching...\n")
    from .cli import main as cli_main
    return cli_main(["--spec", save_name])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run(sys.argv[1:]))
