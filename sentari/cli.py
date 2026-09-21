"""Sentari CLI: the engine that authorizes a target and runs phases in order."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .authorization import AuditLog, AuthorizationError, Scope, authorize
from .phases import PHASES, PhaseContext
from .reporting import console
from .runner import ToolRunner

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
    p.add_argument("--retest", metavar="BASELINE_JSON",
                   help="Compare this run against a prior --json baseline (fixed/still/new).")
    p.add_argument("--audit-log", default="sentari-audit.log", help="Append-only audit log path.")
    p.add_argument("--version", action="version", version=f"sentari {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_phases:
        for cls in sorted(PHASES, key=lambda c: c.number):
            print(f"  {cls.number}. {cls.name:12s} {cls.description}")
        return 0

    if not args.target:
        print("error: a target is required (or use --list-phases)", file=sys.stderr)
        return 2

    audit = AuditLog(Path(args.audit_log))
    scope = Scope.from_items(args.scope)
    try:
        authorize(args.target, scope, args.authorized, audit)
    except AuthorizationError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 3

    runner = ToolRunner(default_timeout=args.timeout, dry_run=args.dry_run)
    selected = {s.strip() for s in args.phases.split(",")} if args.phases != "all" else None

    options = {}
    if args.wordlist:
        options["wordlist"] = args.wordlist
    if args.sqlmap_url:
        options["sqlmap_url"] = args.sqlmap_url
    ctx = PhaseContext(target=args.target, runner=runner, safe_mode=not args.no_safe_mode,
                       options=options)
    results = []
    for cls in sorted(PHASES, key=lambda c: c.number):
        if selected is not None and cls.name not in selected:
            continue
        audit.record("phase.start", target=args.target, phase=cls.name)
        # each phase gets a fresh runner so its result carries only its own evidence
        ctx.runner = ToolRunner(default_timeout=args.timeout, dry_run=args.dry_run)
        result = cls().run(ctx)
        audit.record("phase.done", target=args.target, phase=cls.name,
                     findings=len(result.findings), error=result.error)
        results.append(result)

    print(console.render(results))

    if args.retest:
        from . import retest as retest_mod
        try:
            baseline = retest_mod.load_baseline(args.retest)
        except (OSError, ValueError) as e:
            print(f"error: could not read baseline {args.retest!r}: {e}", file=sys.stderr)
            return 4
        current = [f for r in results for f in r.findings]
        rr = retest_mod.compare(baseline, current)
        print(retest_mod.render(rr, args.retest))
        audit.record("retest", target=args.target, fixed=len(rr.fixed),
                     still=len(rr.still_present), new=len(rr.new))

    if args.json:
        Path(args.json).write_text(
            json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\nFull results written to {args.json}")

    if args.html:
        from .reporting import html as html_report
        Path(args.html).write_text(html_report.render_html(results, args.target), encoding="utf-8")
        print(f"HTML report written to {args.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
