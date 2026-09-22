"""Sentari CLI: the engine that authorizes a target and runs phases in order."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .authorization import AuditLog, AuthorizationError, Scope
from .phases import PHASES
from .reporting import console

__version__ = "0.1.0"


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
    p.add_argument("--wordlist", help="Wordlist path for gobuster content discovery (Phase 2).")
    p.add_argument("--sqlmap-url", help="Explicit URL to test with sqlmap (Phase 3, gated).")
    p.add_argument("--dry-run", action="store_true", help="Show what would run; execute nothing.")
    p.add_argument("--timeout", type=int, default=120, help="Per-tool timeout seconds (default 120).")
    p.add_argument("--json", metavar="FILE", help="Write full results (with evidence) to JSON.")
    p.add_argument("--html", metavar="FILE", help="Write a self-contained HTML report.")
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
    p.add_argument("--runs-dir", default="runs", help="Directory of saved runs (dashboard).")
    p.add_argument("--retest", metavar="BASELINE_JSON",
                   help="Compare this run against a prior --json baseline (fixed/still/new).")
    p.add_argument("--no-compliance", action="store_true",
                   help="Do not tag findings with OWASP/CWE/NIST references.")
    p.add_argument("--ai", action="store_true",
                   help="Grounded AI triage of the real findings (prioritize/chain/remediate).")
    p.add_argument("--ai-provider", help="AI provider: openai, anthropic, google, openrouter, ollama.")
    p.add_argument("--ai-model", help="AI model id (provider-specific).")
    p.add_argument("--ai-base-url", help="Custom base URL (OpenAI-compatible / Ollama).")
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.serve:
        from .web import serve
        serve(runs_dir=args.runs_dir, port=args.port, db=args.db)
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

    from .engine import run_assessment
    try:
        results = run_assessment(
            args.target, scope, args.authorized, audit,
            safe_mode=not args.no_safe_mode, phases=selected, timeout=args.timeout,
            dry_run=args.dry_run, options=options, apply_compliance=not args.no_compliance,
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

    if args.html:
        from .reporting import html as html_report
        Path(args.html).write_text(html_report.render_html(results, args.target), encoding="utf-8")
        print(f"HTML report written to {args.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
