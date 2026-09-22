# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Self-contained HTML report. No external assets, no JS required (uses native
<details>). Every finding links to the exact evidence that proves it, so the
report is auditable: the defining property of Sentari.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from ..models import PhaseResult, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    Severity.CRITICAL: "#b3123b", Severity.HIGH: "#d64541", Severity.MEDIUM: "#e08a1e",
    Severity.LOW: "#2f7fbf", Severity.INFO: "#5b6470",
}


def _esc(s: object) -> str:
    return html.escape(str(s if s is not None else ""))


def render_html(results: list[PhaseResult], target: str) -> str:
    findings = [f for r in results for f in r.findings]
    evidence = {e.id: e for r in results for e in r.evidence}
    counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tiles = "".join(
        f'<div class="tile" style="--c:{_SEV_COLOR[s]}">'
        f'<div class="n">{counts[s]}</div><div class="l">{s.value}</div></div>'
        for s in _SEV_ORDER
    )

    finding_rows = []
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        ev_links = " ".join(
            f'<a href="#ev-{_esc(eid)}" class="evref">{_esc(eid)}</a>' for eid in f.evidence_ids
        )
        ev_blocks = ""
        for eid in f.evidence_ids:
            ev = evidence.get(eid)
            if not ev:
                continue
            ev_blocks += (
                f'<details class="evd"><summary>evidence {_esc(eid)}: '
                f'{_esc(" ".join(ev.command))} (exit {ev.returncode})</summary>'
                f'<pre>{_esc(ev.stdout[:4000]) or "(no stdout)"}'
                f'{("</pre><pre class=err>" + _esc(ev.stderr[:1000])) if ev.stderr else ""}</pre>'
                f'</details>'
            )
        refs = ""
        if f.references:
            refs = '<div class="refs">refs: ' + ", ".join(
                f'<a href="{_esc(u)}" rel="noreferrer noopener" target="_blank">{_esc(u)}</a>'
                for u in f.references) + "</div>"
        rec = f'<div class="rec"><b>Fix:</b> {_esc(f.recommendation)}</div>' if f.recommendation else ""
        comp = (f.metadata or {}).get("compliance") or {}
        comp_tags = ""
        if comp:
            chips = []
            if comp.get("owasp"):
                chips.append(f'<span class="chip">OWASP {_esc(comp["owasp"])}</span>')
            for c in comp.get("cwe", []):
                chips.append(f'<span class="chip">{_esc(c)}</span>')
            if comp.get("nist"):
                chips.append(f'<span class="chip">NIST {_esc(comp["nist"])}</span>')
            comp_tags = '<div class="chips">' + "".join(chips) + "</div>"
        loc = f'<span class="loc">{_esc(f.location)}</span>' if f.location else ""
        finding_rows.append(
            f'<div class="finding">'
            f'<div class="fhead"><span class="badge" style="background:{_SEV_COLOR[f.severity]}">'
            f'{f.severity.value.upper()}</span><span class="ftitle">{_esc(f.title)}</span>{loc}</div>'
            f'<div class="fdesc">{_esc(f.description)}</div>{rec}{comp_tags}{refs}'
            f'<div class="evwrap">{ev_blocks}</div>'
            f'<div class="evrefline">evidence: {ev_links}</div>'
            f'</div>'
        )

    ev_appendix = "".join(
        f'<div class="evitem" id="ev-{_esc(eid)}"><code>{_esc(eid)}</code> '
        f'<b>{_esc(ev.tool)}</b>: {_esc(" ".join(ev.command))} '
        f'<span class="muted">exit {ev.returncode}, {ev.duration_sec}s, {_esc(ev.started_at)}</span>'
        f'<pre>{_esc(ev.stdout[:6000]) or "(no stdout)"}</pre></div>'
        for eid, ev in evidence.items()
    )
    phase_rows = "".join(
        f"<li><b>{_esc(r.phase)}</b>: {len(r.findings)} findings, {len(r.evidence)} evidence"
        + (f': <span class="muted">{_esc("; ".join(r.notes))}</span>' if r.notes else "")
        + (f': <span class="err">ERROR: {_esc(r.error)}</span>' if r.error else "")
        + "</li>"
        for r in results
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentari Report: {_esc(target)}</title>
<style>
:root{{--bg:#ffffff;--fg:#1a1d21;--card:#f6f7f9;--line:#e2e5ea;--muted:#6b7280}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f1216;--fg:#e6e8eb;--card:#171b21;--line:#262c34;--muted:#93a0af}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:24px 16px 80px}}
h1{{font-size:22px;margin:0 0 4px}}.sub{{color:var(--muted);margin-bottom:20px}}
.tiles{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 28px}}
.tile{{flex:1;min-width:90px;background:var(--card);border:1px solid var(--line);
border-left:4px solid var(--c);border-radius:10px;padding:12px 14px}}
.tile .n{{font-size:26px;font-weight:700;color:var(--c)}}.tile .l{{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.05em}}
h2{{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
border-bottom:1px solid var(--line);padding-bottom:6px;margin:32px 0 14px}}
.finding{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.fhead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.badge{{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}}
.ftitle{{font-weight:600}}.loc{{color:var(--muted);font-family:ui-monospace,monospace;font-size:12px}}
.fdesc{{margin:8px 0}}.rec{{margin:6px 0;font-size:14px}}.refs{{font-size:12px;color:var(--muted);margin-top:4px}}
.chips{{margin:8px 0 2px;display:flex;gap:6px;flex-wrap:wrap}}
.chip{{font-size:11px;background:var(--bg);border:1px solid var(--line);color:var(--muted);padding:2px 8px;border-radius:20px}}
.evrefline{{font-size:12px;color:var(--muted);margin-top:8px}}
.evref,.refs a{{color:#2f7fbf;text-decoration:none}}
.evd{{margin-top:8px;font-size:12px}}.evd summary{{cursor:pointer;color:var(--muted);font-family:ui-monospace,monospace}}
pre{{background:#0b0e12;color:#cdd6e0;padding:10px;border-radius:8px;overflow:auto;font-size:12px;max-height:340px;white-space:pre-wrap;word-break:break-word}}
pre.err{{color:#ff9c9c}}
.evitem{{border-bottom:1px solid var(--line);padding:10px 0}}.evitem code{{color:#2f7fbf}}
.muted{{color:var(--muted)}}.err{{color:#d64541}}ul{{padding-left:18px}}
.foot{{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}}
</style></head><body><div class="wrap">
<h1>Sentari Assessment Report</h1>
<div class="sub">Target: <b>{_esc(target)}</b> · Generated {generated} · {len(findings)} findings</div>
<div class="tiles">{tiles}</div>
<h2>Phases</h2><ul>{phase_rows}</ul>
<h2>Findings</h2>{''.join(finding_rows) or '<p>No findings.</p>'}
<h2>Evidence (ground truth)</h2>{ev_appendix or '<p>No evidence captured.</p>'}
<div class="foot">Every finding above is backed by a real command and its output.
Sentari does not generate findings without evidence.</div>
</div></body></html>"""
