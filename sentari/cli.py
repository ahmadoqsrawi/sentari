"""Sentari CLI: the engine that authorizes a target and runs phases in order."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .authorization import AuditLog, AuthorizationError, Scope
from .phases import PHASES
from .reporting import console

__version__ = "0.15.0"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentari",
        description="Sentari: evidence-grounded, authorized security assessment.",
    )
    p.add_argument("target", nargs="?", help="Target host, host:port, or URL")
    p.add_argument("--scope", action="append", default=[], metavar="HOST|CIDR",
                   help="Authorized target(s). Repeatable. Required to run.")
    p.add_argument("--authorized", action="store_true",
                   help="Attest you have explicit written authorization to test the target.")
    p.add_argument("--phases", default="all",
                   help="Comma-separated phase names to run, or 'all' (default).")
    p.add_argument("--list-phases", action="store_true", help="List available phases and exit.")
    p.add_argument("--no-safe-mode", action="store_true",
                   help="Allow more intrusive checks (default: safe mode on).")
    p.add_argument("--exploit", action="store_true",
                   help="Enable the gated exploitation phase (authorized targets only).")
    p.add_argument("--autonomous", action="store_true",
                   help="Autonomous run: full pipeline incl. gated exploitation, AI-driven, "
                        "authorized once at launch (needs --authorized, --no-safe-mode, --exploit-confirm).")
    p.add_argument("--exploit-module", action="append", default=[], metavar="MSF_MODULE",
                   help="Metasploit module to run (repeatable). Required for exploitation.")
    p.add_argument("--exploit-confirm", metavar="TEXT",
                   help="Exact acknowledgement string required to enable exploitation.")
    p.add_argument("--exfil-sim", action="store_true",
                   help="Bounded, redacted proof-of-impact read of confirmed exposures.")
    p.add_argument("--poc", action="append", default=[], metavar="SCRIPT",
                   help="Python PoC to run against the target in a sandbox container (repeatable, gated).")
    p.add_argument("--poc-image", metavar="IMAGE",
                   help="Docker image for --poc (default python:3-slim).")
    p.add_argument("--postexploit", action="store_true",
                   help="Enable gated post-exploitation (lateral movement, AD collection).")
    p.add_argument("--postexploit-confirm", metavar="TEXT",
                   help="Exact acknowledgement string required to enable post-exploitation.")
    p.add_argument("--postexploit-user", help="Credential username for post-exploitation.")
    p.add_argument("--postexploit-pass", help="Credential password for post-exploitation.")
    p.add_argument("--postexploit-domain", help="AD/SMB domain for post-exploitation.")
    p.add_argument("--postexploit-dc", help="Domain controller IP for BloodHound collection.")
    p.add_argument("--bloodhound", action="store_true",
                   help="Collect AD data with bloodhound-python during post-exploitation.")
    p.add_argument("--privesc", action="store_true",
                   help="Run read-only privilege-escalation enumeration over SSH (post-exploitation).")
    p.add_argument("--privesc-host", help="SSH host for privesc enumeration (default: the target).")
    p.add_argument("--privesc-key", help="SSH private key path for privesc enumeration.")
    p.add_argument("--privesc-port", type=int, default=22, help="SSH port for privesc (default 22).")
    p.add_argument("--openvas", action="store_true",
                   help="Pull results from a configured Greenbone/OpenVAS instance (GVM_* env).")
    p.add_argument("--nexpose", action="store_true",
                   help="Pull results from a configured Rapid7 Nexpose/InsightVM console (NEXPOSE_* env).")
    p.add_argument("--asset-value", choices=["low", "medium", "high", "critical"],
                   default="medium", help="Asset criticality for business-impact scoring.")
    p.add_argument("--correlate", action="store_true",
                   help="Report findings seen across more than one target in --db/--runs-dir, then exit.")
    p.add_argument("--trends", action="store_true",
                   help="Show how findings change across stored runs in --db/--runs-dir, then exit.")
    p.add_argument("--openapi", metavar="SRC",
                   help="OpenAPI/Swagger/Postman spec (file or URL); its endpoints become scan targets.")
    p.add_argument("--openapi-base-url",
                   help="Override the base URL for the ingested API endpoints.")
    p.add_argument("--proxy", type=int, metavar="PORT",
                   help="Start an mitmproxy capture on PORT (route traffic through it), then exit.")
    p.add_argument("--proxy-out", default="sentari-flows.jsonl",
                   help="Capture file for --proxy (default sentari-flows.jsonl).")
    p.add_argument("--proxy-ingest", metavar="FILE",
                   help="Analyze a captured mitmproxy JSONL or HAR file for issues.")
    p.add_argument("--proxy-web", type=int, metavar="PORT",
                   help="Launch mitmweb for interactive live request/response tampering, then exit.")
    p.add_argument("--tamper", metavar="FILE",
                   help="Replay a captured request (JSONL/HAR) with overrides and diff the response.")
    p.add_argument("--tamper-index", type=int, default=0,
                   help="Which captured request to tamper (default 0).")
    p.add_argument("--set-header", action="append", default=[], metavar="H=V",
                   help="Override a request header for --tamper (repeatable).")
    p.add_argument("--set-param", action="append", default=[], metavar="P=V",
                   help="Override a query parameter for --tamper (repeatable).")
    p.add_argument("--set-body", metavar="TEXT", help="Override the request body for --tamper.")
    p.add_argument("--fuzz-param", metavar="NAME", help="Parameter to fuzz on the --tamper request.")
    p.add_argument("--fuzz-values", metavar="FILE", help="Newline-separated values for --fuzz-param.")
    p.add_argument("--cloud-audit", choices=["aws", "azure", "gcp", "kubernetes"],
                   help="Audit cloud account configuration with Prowler.")
    p.add_argument("--sast", metavar="PATH",
                   help="Static analysis (SAST) over a source tree with semgrep.")
    p.add_argument("--sast-config", default="auto",
                   help="semgrep config/ruleset for --sast (default: auto).")
    p.add_argument("--injection", action="store_true",
                   help="Injection & logic tests: SSRF/XXE (OOB-confirmed), NoSQLi, mass assignment.")
    p.add_argument("--oob-host", default="127.0.0.1",
                   help="Address the target can reach for SSRF/XXE callbacks (default 127.0.0.1).")
    p.add_argument("--race-url", metavar="URL",
                   help="Fire concurrent requests at this URL to test for race conditions.")
    p.add_argument("--race-count", type=int, default=20, help="Concurrent requests for --race-url.")
    p.add_argument("--race-post", action="store_true", help="Use POST for --race-url (default GET).")
    p.add_argument("--session-fixation", metavar="LOGIN_URL",
                   help="Check whether the session id rotates on login at this URL.")
    p.add_argument("--login-data", metavar="BODY",
                   help="Form body for --session-fixation login (e.g. user=x&pass=y).")
    p.add_argument("--session-cookie", metavar="NAME",
                   help="Session cookie name for --session-fixation (auto-detected if omitted).")
    p.add_argument("--workflow", metavar="FILE",
                   help="Replay an operator-defined workflow spec (JSON) to test business logic.")
    p.add_argument("--access-control", action="store_true",
                   help="Broken-access-control / IDOR testing by comparing identities.")
    p.add_argument("--identity", action="append", default=[], metavar="NAME:HEADER:VALUE",
                   help="An identity for --access-control, e.g. alice:Cookie:session=abc (repeatable).")
    p.add_argument("--ac-url", action="append", default=[], metavar="URL",
                   help="Protected URL to test for access control (repeatable).")
    p.add_argument("--api-tests", action="store_true",
                   help="Read-only API-security checks (JWT audit, rate-limit, auth exposure).")
    p.add_argument("--jwt", metavar="TOKEN", help="Audit a specific JWT offline.")
    p.add_argument("--browser", action="store_true",
                   help="Client-side DAST: drive a headless browser (needs Playwright).")
    p.add_argument("--shell", action="store_true",
                   help="Open an interactive shell inside a disposable Docker container (exploit dev).")
    p.add_argument("--shell-image", metavar="IMAGE", default="alpine",
                   help="Docker image for --shell (default alpine; use a toolchain image as needed).")
    p.add_argument("--sandbox", action="store_true",
                   help="Run the gated offensive tools inside a disposable Docker container.")
    p.add_argument("--sandbox-image", metavar="IMAGE",
                   help="Docker image for --sandbox (default: a Metasploit toolchain image).")
    p.add_argument("--autofix", metavar="FILE",
                   help="Write a Markdown remediation guide built from the findings.")
    p.add_argument("--autofix-pr", action="store_true",
                   help="Open the remediation guide as a DRAFT pull request (needs gh + a repo).")
    p.add_argument("--autofix-repo", metavar="DIR", default=".",
                   help="Git repository for --autofix-pr / --suggest-patches (default: current directory).")
    p.add_argument("--suggest-patches", action="store_true",
                   help="Ask the AI for concrete code-fix diffs (validated, written to a patch file; not applied).")
    p.add_argument("--patch-out", metavar="FILE", default="SECURITY_FIXES.patch",
                   help="Where to write proposed patches (default SECURITY_FIXES.patch).")
    p.add_argument("--apply-fixes", action="store_true",
                   help="Apply the proposed patches into the working tree (uncommitted); needs --apply-confirm.")
    p.add_argument("--apply-confirm", metavar="TEXT",
                   help="Exact acknowledgement string required to apply patches to your code.")
    p.add_argument("--wordlist", help="Wordlist path for gobuster content discovery (Phase 2).")
    p.add_argument("--sqlmap-url", help="Explicit URL to test with sqlmap (Phase 3, gated).")
    p.add_argument("--dry-run", action="store_true", help="Show what would run; execute nothing.")
    p.add_argument("--timeout", type=int, default=120, help="Per-tool timeout seconds (default 120).")
    p.add_argument("--json", metavar="FILE", help="Write full results (with evidence) to JSON.")
    p.add_argument("--html", metavar="FILE", help="Write a self-contained HTML report.")
    p.add_argument("--xml", metavar="FILE", help="Write an XML report.")
    p.add_argument("--pdf", metavar="FILE", help="Write a PDF report (needs reportlab).")
    p.add_argument("--save-run", metavar="DIR",
                   help="Save this run as <dir>/<timestamp>-<target>.json for the dashboard.")
    p.add_argument("--db", metavar="DSN",
                   help="Persist/read runs in a DB: a SQLite file path or a postgres:// URL.")
    p.add_argument("--retest-latest", action="store_true",
                   help="Retest against this target's most recent run in --db.")
    p.add_argument("--enqueue", action="store_true",
                   help="Dispatch the scan to a Celery worker instead of running locally.")
    p.add_argument("--serve", action="store_true",
                   help="Start the read-only web dashboard instead of scanning.")
    p.add_argument("--port", type=int, default=8600, help="Dashboard port (default 8600).")
    p.add_argument("--host", default="127.0.0.1",
                   help="Dashboard bind address (default 127.0.0.1; use 0.0.0.0 in a container).")
    p.add_argument("--runs-dir", default="runs", help="Directory of saved runs (dashboard).")
    p.add_argument("--retest", metavar="BASELINE_JSON",
                   help="Compare this run against a prior --json baseline (fixed/still/new).")
    p.add_argument("--no-anomaly", action="store_true",
                   help="Do not flag unusual findings for manual review.")
    p.add_argument("--no-heuristics", action="store_true",
                   help="Do not flag error/leak patterns as candidates for manual review.")
    p.add_argument("--no-threatintel", action="store_true",
                   help="Do not correlate finding CVEs against the CISA KEV catalog.")
    p.add_argument("--no-compliance", action="store_true",
                   help="Do not tag findings with OWASP/CWE/NIST references.")
    p.add_argument("--graph", action="store_true",
                   help="Graph of agents: specialized nodes share a blackboard; targets run in parallel.")
    p.add_argument("--graph-target", action="append", default=[], metavar="TARGET",
                   help="Additional target(s) for --graph (repeatable). All must be in --scope.")
    p.add_argument("--autopilot", action="store_true",
                   help="Let the AI choose which phases to run (findings stay tool-backed).")
    p.add_argument("--autopilot-steps", type=int, default=8, help="Max autopilot steps (default 8).")
    p.add_argument("--agent", action="store_true",
                   help="Full AI agent: the model calls tools directly (findings stay evidence-anchored).")
    p.add_argument("--goal", help="Natural-language goal for the agent (e.g. 'focus on the API').")
    p.add_argument("--agent-steps", type=int, default=14, help="Max agent tool calls (default 14).")
    p.add_argument("--ai", action="store_true",
                   help="Grounded AI triage of the real findings (prioritize/chain/remediate).")
    p.add_argument("--ai-osint", action="store_true",
                   help="AI-assisted OSINT: the model proposes subdomain labels, DNS confirms them.")
    p.add_argument("--ai-provider", help="AI provider: openai, anthropic, google, openrouter, ollama.")
    p.add_argument("--ai-model", help="AI model id (provider-specific).")
    p.add_argument("--ai-base-url", help="Custom base URL (OpenAI-compatible / Ollama).")
    p.add_argument("--siem-url", help="Ship findings to a SIEM at this URL (or host:port for syslog).")
    p.add_argument("--siem-type", choices=["webhook", "splunk", "elasticsearch", "syslog"],
                   default="webhook", help="SIEM transport (default webhook).")
    p.add_argument("--siem-token", help="SIEM auth token (else read from SENTARI_SIEM_TOKEN).")
    p.add_argument("--list-models", action="store_true", help="List known AI models per provider and exit.")
    p.add_argument("--cloud", choices=["aws", "azure", "gcp"],
                   help="Discover internet-facing assets in your cloud account and exit.")
    p.add_argument("--audit-log", default="sentari-audit.log", help="Append-only audit log path.")
    p.add_argument("--version", action="version", version=f"sentari {__version__}")
    return p


def _print_analysis(a) -> None:
    print("\n" + "-" * 70)
    print(f"AI TRIAGE (grounded): provider={a.provider} model={a.model}")
    print("-" * 70)
    if a.error:
        print(f"  {a.error}")
        return
    if a.summary:
        print(a.summary)
    if a.prioritized:
        print("\n  Priority order (finding ids): " + ", ".join(a.prioritized))
    for ch in a.chains:
        print(f"\n  Attack chain: {ch['name']}")
        print(f"    findings: {', '.join(ch['finding_ids'])}")
        print(f"    {ch['rationale']}")
    if a.dropped_references:
        print(f"\n  [grounding guard] dropped {a.dropped_references} AI reference(s) "
              f"to findings that do not exist.")


def _analysis_to_dict(a) -> dict:
    return {"provider": a.provider, "model": a.model, "summary": a.summary,
            "prioritized": a.prioritized, "chains": a.chains,
            "remediation": a.remediation, "dropped_references": a.dropped_references,
            "error": a.error}


def _load_stored_runs(db: str | None, runs_dir: str | None) -> dict:
    """Load saved runs from a DB (preferred) or a runs directory."""
    if db:
        from .db import RunStore
        store = RunStore(db)
        try:
            return store.all_runs()
        finally:
            store.close()
    from .web.server import _load_runs
    return _load_runs(Path(runs_dir or "runs"))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.serve:
        from .web import serve
        serve(runs_dir=args.runs_dir, port=args.port, host=args.host, db=args.db)
        return 0

    if args.shell:
        import shutil
        import subprocess
        if not shutil.which("docker"):
            print("error: Docker not installed (needed for the sandboxed shell)", file=sys.stderr)
            return 5
        print(f"Opening a shell in a disposable {args.shell_image} container "
              "(host network). For authorized exploit development only.")
        return subprocess.run(["docker", "run", "--rm", "-it", "--network", "host",
                               args.shell_image, "/bin/sh"]).returncode

    if args.proxy_web:
        import shutil
        import subprocess
        from . import proxy as proxy_mod
        if not shutil.which("mitmweb"):
            print("error: mitmproxy not installed (pip install mitmproxy)", file=sys.stderr)
            return 5
        addon = str(Path(args.proxy_out).with_suffix(".addon.py"))
        proxy_mod.write_addon(addon)
        import os as _os
        env = {**_os.environ, "SENTARI_PROXY_OUT": args.proxy_out}
        print(f"Launching mitmweb on :{args.proxy_web} (interactive request/response editing).")
        print(f"Also capturing to {args.proxy_out}. Point your browser/app at the proxy; "
              "edit requests live in the web UI.")
        try:
            subprocess.run(["mitmweb", "-s", addon, "--listen-port", str(args.proxy_web)], env=env)
        except KeyboardInterrupt:
            print("\nstopped.")
        return 0

    if args.tamper:
        from . import proxy as proxy_mod
        from . import tamper as tamper_mod
        flows = proxy_mod._load(args.tamper)
        if not flows or args.tamper_index >= len(flows):
            print(f"error: no request at index {args.tamper_index} in {args.tamper} "
                  f"({len(flows)} captured)", file=sys.stderr)
            return 4
        req = tamper_mod.request_from_flow(flows[args.tamper_index])
        orig_resp = (flows[args.tamper_index].get("response", {}) or {}).get("content", "")

        def _kv(items):
            out = {}
            for it in items:
                k, _, v = it.partition("=")
                out[k.strip()] = v
            return out

        if args.fuzz_param:
            values = []
            if args.fuzz_values:
                values = [ln for ln in Path(args.fuzz_values).read_text().splitlines() if ln]
            rows = tamper_mod.fuzz(req, args.fuzz_param, values, timeout=args.timeout)
            print(f"Fuzzing '{args.fuzz_param}' on {req['url']} ({len(rows)} values):")
            for r in rows:
                print(f"  value={r['value']!r:30} status={r['status']} len={r['length']}")
            return 0

        mutated = tamper_mod.apply_mutations(
            req, set_headers=_kv(args.set_header), set_params=_kv(args.set_param),
            set_body=args.set_body)
        status, headers, body = tamper_mod.send(mutated, timeout=args.timeout)
        print(f"{mutated['method']} {mutated['url']}")
        print(f"-> HTTP {status}, {len(body)} bytes")
        d = tamper_mod.diff(orig_resp, body)
        if d:
            print("\n-- response diff (original vs tampered) --\n" + d)
        else:
            print("(no diff vs the captured response)")
        return 0

    if args.proxy:
        import shutil
        import subprocess
        from . import proxy as proxy_mod
        if not shutil.which("mitmdump"):
            print("error: mitmproxy not installed (pip install mitmproxy)", file=sys.stderr)
            return 5
        addon = str(Path(args.proxy_out).with_suffix(".addon.py"))
        proxy_mod.write_addon(addon)
        import os as _os
        env = {**_os.environ, "SENTARI_PROXY_OUT": args.proxy_out}
        print(f"Starting mitmproxy on :{args.proxy}. Route your browser/app through this proxy.")
        print(f"Capturing to {args.proxy_out}. Ctrl-C to stop, then analyze with:")
        print(f"  sentari <target> --scope <target> --authorized --proxy-ingest {args.proxy_out}")
        try:
            subprocess.run(["mitmdump", "-s", addon, "--listen-port", str(args.proxy)], env=env)
        except KeyboardInterrupt:
            print("\nstopped.")
        return 0

    if args.list_models:
        from .ai.catalog import list_models
        for provider, models in list_models().items():
            print(f"{provider}:")
            for m in models:
                print(f"  {m}")
        print("\nAny provider-specific model id also works via --ai-model.")
        return 0

    if args.cloud:
        from .cloud_assets import discover
        r = discover(args.cloud)
        if r.error:
            print(f"{r.provider}: {r.error}")
            return 0
        print(f"{r.provider}: {len(r.assets)} internet-facing asset(s)")
        for a in r.assets:
            print(f"  [{a.kind}] {a.identifier}" + (f" -> {a.endpoint}" if a.endpoint else ""))
        print("\nBring the endpoints you own into scope, then scan them with --scope.")
        return 0

    if args.correlate or args.trends:
        runs = _load_stored_runs(args.db, args.runs_dir)
        if not runs:
            print("No stored runs found (use --db or --runs-dir with saved runs).")
            return 0
        if args.correlate:
            from .correlation import correlate
            rows = correlate(runs)
            if not rows:
                print("No finding appears across more than one target.")
            for row in rows:
                print(f"[{row['severity']}] {row['finding']}  ->  {len(row['targets'])} targets: "
                      + ", ".join(row["targets"]))
        if args.trends:
            from .trends import render, trend_rows
            print(render(trend_rows(runs)))
        return 0

    if args.list_phases:
        for cls in sorted(PHASES, key=lambda c: c.number):
            print(f"  {cls.number}. {cls.name:12s} {cls.description}")
        return 0

    if not args.target:
        print("error: a target is required (or use --list-phases)", file=sys.stderr)
        return 2

    audit = AuditLog(Path(args.audit_log))
    scope = Scope.from_items(args.scope)
    selected = {s.strip() for s in args.phases.split(",")} if args.phases != "all" else None
    options = {}
    if args.wordlist:
        options["wordlist"] = args.wordlist
    if args.sqlmap_url:
        options["sqlmap_url"] = args.sqlmap_url
    if args.openvas:
        options["openvas"] = True
    if args.nexpose:
        options["nexpose"] = True
    if args.openapi:
        options["openapi"] = args.openapi
        if args.openapi_base_url:
            options["openapi_base_url"] = args.openapi_base_url
    if args.sast:
        options["sast_path"] = args.sast
        options["sast_config"] = args.sast_config
    if args.cloud_audit:
        options["cloud_audit"] = args.cloud_audit
    if args.proxy_ingest:
        options["proxy_ingest"] = args.proxy_ingest
    if args.injection or args.race_url:
        options["injection"] = True
        options["oob_host"] = args.oob_host
        if args.race_url:
            options["race_url"] = args.race_url
            options["race_count"] = args.race_count
            options["race_post"] = args.race_post
    if args.workflow:
        options["workflow_spec"] = args.workflow
    if args.session_fixation:
        options["session_fixation"] = {"login_url": args.session_fixation,
                                       "login_data": args.login_data or "",
                                       "cookie_name": args.session_cookie}
    if args.access_control:
        options["access_control"] = True
        idents = []
        for spec in args.identity:
            parts = spec.split(":", 2)
            if len(parts) == 3:
                idents.append({"name": parts[0], "headers": {parts[1]: parts[2]}})
            else:
                print(f"warning: ignoring --identity {spec!r} (want NAME:HEADER:VALUE)",
                      file=sys.stderr)
        options["identities"] = idents
        if args.ac_url:
            options["ac_urls"] = args.ac_url
    if args.api_tests:
        options["api_tests"] = True
    if args.jwt:
        options["jwt"] = args.jwt
    if args.browser:
        options["browser"] = True
    if args.sandbox:
        options["sandbox"] = {"image": args.sandbox_image} if args.sandbox_image else {}

    if args.exploit:
        from .phases.exploit import CONFIRM_STRING
        if not args.no_safe_mode:
            print("error: --exploit requires --no-safe-mode", file=sys.stderr)
            return 6
        if args.exploit_confirm != CONFIRM_STRING:
            print(f'error: --exploit requires --exploit-confirm "{CONFIRM_STRING}"',
                  file=sys.stderr)
            return 6
        print("!! EXPLOITATION ENABLED: authorized targets only; you are responsible for authorization and scope. !!",
              file=sys.stderr)
        options["exploit"] = {"modules": args.exploit_module, "exfil_sim": args.exfil_sim,
                              "poc_scripts": args.poc,
                              "poc_image": args.poc_image or "python:3-slim"}

    if args.postexploit:
        from .phases.postexploit import CONFIRM_STRING as PE_CONFIRM
        if not args.no_safe_mode:
            print("error: --postexploit requires --no-safe-mode", file=sys.stderr)
            return 6
        if args.postexploit_confirm != PE_CONFIRM:
            print(f'error: --postexploit requires --postexploit-confirm "{PE_CONFIRM}"',
                  file=sys.stderr)
            return 6
        if not args.postexploit_user:
            print("error: --postexploit requires --postexploit-user (and usually --postexploit-pass)",
                  file=sys.stderr)
            return 6
        print("!! POST-EXPLOITATION ENABLED: authorized targets only; you are responsible for authorization and scope. !!",
              file=sys.stderr)
        options["postexploit"] = {
            "username": args.postexploit_user, "password": args.postexploit_pass or "",
            "domain": args.postexploit_domain or "", "dc_ip": args.postexploit_dc or "",
            "bloodhound": args.bloodhound,
            "privesc": args.privesc, "privesc_host": args.privesc_host or "",
            "privesc_key": args.privesc_key or "", "privesc_port": args.privesc_port,
        }

    if args.autonomous:
        from .phases.exploit import CONFIRM_STRING as AUTO_CONFIRM
        if not (args.authorized and args.no_safe_mode and args.exploit_confirm == AUTO_CONFIRM):
            print('error: --autonomous requires --authorized, --no-safe-mode, and '
                  f'--exploit-confirm "{AUTO_CONFIRM}"', file=sys.stderr)
            return 6
        print("!! AUTONOMOUS RUN ENABLED. Full pipeline including gated exploitation. "
              "Authorized targets only; you are responsible for authorization and scope. !!",
              file=sys.stderr)
        options["injection"] = True
        options.setdefault("oob_host", args.oob_host)
        options["browser"] = True
        options["api_tests"] = True
        options.setdefault("exploit", {"modules": args.exploit_module, "exfil_sim": args.exfil_sim,
                                       "poc_scripts": args.poc, "poc_image": args.poc_image or "python:3-slim"})
        args.ai = True

    if args.ai_osint:
        if args.enqueue:
            print("note: --ai-osint runs locally; ignoring it for the enqueued run.",
                  file=sys.stderr)
        else:
            from .ai import get_provider
            options["ai_osint_provider"] = get_provider(
                args.ai_provider, args.ai_model, base_url=args.ai_base_url)

    if args.enqueue:
        from .tasks import HAVE_CELERY, run_assessment_task
        if not HAVE_CELERY:
            print("error: --enqueue needs Celery installed (pip install celery) and a "
                  "running broker; start a worker with: celery -A sentari.tasks worker",
                  file=sys.stderr)
            return 5
        async_result = run_assessment_task.delay(
            args.target, args.scope, args.authorized, options,
            not args.no_safe_mode, args.db)
        print(f"Dispatched to Celery. task id: {async_result.id}")
        print("Result will be persisted if --db was given; view via the dashboard.")
        return 0

    if args.graph:
        from . import graph as graph_mod
        targets = [args.target] + [t for t in args.graph_target if t]
        provider = None
        if args.ai:
            from .ai import get_provider
            provider = get_provider(args.ai_provider, args.ai_model, base_url=args.ai_base_url)
        try:
            graphs, correlated, coordination = graph_mod.run_graph_targets(
                targets, scope, args.authorized, audit,
                safe_mode=not args.no_safe_mode, timeout=args.timeout, options=options,
                provider=provider)
        except AuthorizationError as e:
            print(f"REFUSED: {e}", file=sys.stderr)
            return 3
        results = []
        for g in graphs:
            results.extend(g.results)
            summary = ", ".join(f"{n}:{c}" for n, c in g.node_summary.items())
            status = f"ERROR {g.error}" if g.error else summary
            print(f"[graph] {g.target}  nodes -> {status}")
        print(console.render(results))
        if correlated:
            print("\n" + "-" * 70 + "\nCROSS-ASSET CORRELATION\n" + "-" * 70)
            for row in correlated:
                print(f"[{row['severity']}] {row['finding']} -> "
                      + ", ".join(row["targets"]))
        if coordination is not None:
            _print_analysis(coordination)
        payload = {"results": [r.to_dict() for r in results]}
        if args.json:
            Path(args.json).write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                       encoding="utf-8")
            print(f"\nFull results written to {args.json}")
        if args.db:
            from .db import RunStore
            store = RunStore(args.db)
            for g in graphs:
                store.save_run(g.target, {"results": [r.to_dict() for r in g.results]})
            store.close()
            print(f"Runs persisted to db {args.db}")
        audit.record("graph.done", targets=len(graphs), correlated=len(correlated))
        return 0

    from .engine import run_assessment
    try:
        if args.agent:
            from .agent import run_agent
            from .ai import get_provider
            provider = get_provider(args.ai_provider, args.ai_model, base_url=args.ai_base_url)
            ar = run_agent(
                args.target, scope, args.authorized, audit, provider,
                goal=args.goal, safe_mode=not args.no_safe_mode, timeout=args.timeout,
                max_steps=args.agent_steps,
            )
            results = ar.results
            if not args.no_compliance:
                from . import compliance
                compliance.apply(results)
            if not args.no_anomaly:
                from . import anomaly
                anomaly.apply(results)
            if ar.note:
                print(ar.note)
            print("\n-- agent transcript --")
            for t in ar.transcript:
                if "error" in t:
                    print(f"  step {t.get('step')}: {t['error']}")
                else:
                    obs = t.get("observation", "")
                    print(f"  {t.get('step','-')}. {t['tool']} -> {obs[:120]}")
            audit.record("agent.done", target=args.target, steps=len(ar.transcript),
                         provider=ar.provider)
        elif args.autopilot:
            from .autopilot import run_autopilot
            from .ai import get_provider
            provider = get_provider(args.ai_provider, args.ai_model, base_url=args.ai_base_url)
            ap = run_autopilot(
                args.target, scope, args.authorized, audit, provider,
                safe_mode=not args.no_safe_mode, timeout=args.timeout, dry_run=args.dry_run,
                options=options, max_steps=args.autopilot_steps,
                apply_compliance=not args.no_compliance, apply_anomaly=not args.no_anomaly,
            )
            results = ap.results
            if ap.note:
                print(ap.note)
            print("\n-- autopilot decisions --")
            for d in ap.decisions:
                print(f"  {d.step}. {d.action} [{d.source}] {d.reason}")
            audit.record("autopilot.done", target=args.target,
                         steps=len(ap.decisions), provider=ap.provider)
        else:
            results = run_assessment(
                args.target, scope, args.authorized, audit,
                safe_mode=not args.no_safe_mode, phases=selected, timeout=args.timeout,
                dry_run=args.dry_run, options=options, apply_compliance=not args.no_compliance,
                apply_anomaly=not args.no_anomaly, apply_heuristics=not args.no_heuristics,
                apply_threatintel=not args.no_threatintel, asset_value=args.asset_value,
            )
    except AuthorizationError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 3

    print(console.render(results))

    analysis = None
    if args.ai:
        from .ai import GroundedAnalyst, get_provider
        provider = get_provider(args.ai_provider, args.ai_model, base_url=args.ai_base_url)
        analysis = GroundedAnalyst(provider).analyze(results)
        _print_analysis(analysis)
        audit.record("ai.triage", target=args.target, provider=analysis.provider,
                     error=analysis.error, dropped_refs=analysis.dropped_references)

    store = None
    if args.db:
        from .db import RunStore
        store = RunStore(args.db)

    if args.retest or args.retest_latest:
        from . import retest as retest_mod
        baseline, label = None, ""
        if args.retest_latest:
            if not store:
                print("error: --retest-latest requires --db", file=sys.stderr)
                return 4
            prev = store.latest_for_target(args.target)  # previous run (before this one is saved)
            baseline = retest_mod.findings_from_payload(prev) if prev else []
            label = f"latest in db ({'found' if prev else 'none yet'})"
        else:
            try:
                baseline = retest_mod.load_baseline(args.retest)
                label = args.retest
            except (OSError, ValueError) as e:
                print(f"error: could not read baseline {args.retest!r}: {e}", file=sys.stderr)
                return 4
        current = [f for r in results for f in r.findings]
        rr = retest_mod.compare(baseline, current)
        print(retest_mod.render(rr, label))
        audit.record("retest", target=args.target, fixed=len(rr.fixed),
                     still=len(rr.still_present), new=len(rr.new))

    payload = {"results": [r.to_dict() for r in results]}
    if analysis is not None:
        payload["ai_analysis"] = _analysis_to_dict(analysis)
    payload_json = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.json:
        Path(args.json).write_text(payload_json, encoding="utf-8")
        print(f"\nFull results written to {args.json}")

    if args.save_run:
        import re as _re
        from datetime import datetime as _dt
        d = Path(args.save_run); d.mkdir(parents=True, exist_ok=True)
        slug = _re.sub(r"[^A-Za-z0-9._-]", "_", args.target)[:40]
        run_file = d / f"{_dt.now().strftime('%Y%m%d-%H%M%S')}-{slug}.json"
        run_file.write_text(payload_json, encoding="utf-8")
        print(f"Run saved to {run_file} (view with: sentari --serve --runs-dir {args.save_run})")

    if store is not None:
        rid = store.save_run(args.target, payload)
        store.close()
        print(f"Run persisted to db as {rid} (view with: sentari --serve --db {args.db})")

    if args.siem_url:
        import os as _os
        from .siem import ship
        token = args.siem_token or _os.getenv("SENTARI_SIEM_TOKEN")
        sent, errors = ship(args.siem_type, args.siem_url, payload, args.target, token)
        print(f"SIEM ({args.siem_type}): {sent} event(s) sent" + (f", errors: {errors}" if errors else ""))
        audit.record("siem.export", target=args.target, type=args.siem_type, sent=sent, errors=errors)

    if args.html:
        from .reporting import html as html_report
        Path(args.html).write_text(html_report.render_html(results, args.target), encoding="utf-8")
        print(f"HTML report written to {args.html}")

    if args.xml:
        from .reporting import xml as xml_report
        Path(args.xml).write_text(xml_report.render_xml(results, args.target), encoding="utf-8")
        print(f"XML report written to {args.xml}")

    if args.pdf:
        from .reporting import pdf as pdf_report
        ok, msg = pdf_report.render_pdf(results, args.target, args.pdf)
        print(msg)

    if args.autofix or args.autofix_pr:
        from . import autofix
        report_md = autofix.build_report(
            results, _analysis_to_dict(analysis) if analysis is not None else None)
        if args.autofix:
            Path(args.autofix).write_text(report_md, encoding="utf-8")
            print(f"Remediation guide written to {args.autofix}")
        if args.autofix_pr:
            ok, msg = autofix.open_draft_pr(report_md, args.autofix_repo, args.target)
            print(f"Autofix PR: {msg}")

    if args.suggest_patches or args.apply_fixes:
        from . import patch as patch_mod
        from .ai import get_provider
        provider = get_provider(args.ai_provider, args.ai_model, base_url=args.ai_base_url)
        patches = patch_mod.propose(results, args.autofix_repo, provider)
        if not patches:
            print("No source-mapped findings produced a valid patch "
                  "(patches need findings with a file:line location, e.g. from --sast).")
            return 0
        Path(args.patch_out).write_text(patch_mod.combined_patch(patches), encoding="utf-8")
        print(f"\n{len(patches)} proposed patch(es) written to {args.patch_out}:")
        for p in patches:
            print(f"  - {p['file']}: {p['finding']}")
        print(f"Review them, then apply with: git -C {args.autofix_repo} apply {args.patch_out}")
        if args.apply_fixes:
            if args.apply_confirm != patch_mod.APPLY_CONFIRM:
                print(f'\nerror: --apply-fixes requires --apply-confirm "{patch_mod.APPLY_CONFIRM}"',
                      file=sys.stderr)
                return 6
            applied, failed = patch_mod.apply(patches, args.autofix_repo)
            print(f"\nApplied to the working tree (uncommitted): {len(applied)} file(s)."
                  + (f" Failed: {failed}" if failed else ""))
            print(f"Review with: git -C {args.autofix_repo} diff  |  then commit yourself, "
                  "and re-test to confirm the fix (see the retest skill).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
