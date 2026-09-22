# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Read-only web dashboard + REST API, built on the standard library only.

Serves runs saved by `sentari ... --save-run DIR` (each a JSON payload produced
by --json). It is READ-ONLY by design and binds to localhost by default: it
views completed assessments, it does not let a caller trigger scans. This gives
the "web dashboard" surface without the risk of a network-exposed scan trigger.

Routes:
  GET /                 dashboard (list of runs)
  GET /run/<id>         HTML view of one run
  GET /api/runs         JSON list of runs
  GET /api/runs/<id>    JSON of one run
"""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_COLOR = {"critical": "#b3123b", "high": "#d64541", "medium": "#e08a1e",
              "low": "#2f7fbf", "info": "#5b6470"}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _load_runs(runs_dir: Path) -> dict[str, dict]:
    runs = {}
    for p in sorted(runs_dir.glob("*.json")):
        try:
            runs[p.stem] = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return runs


def _findings(run: dict) -> list[dict]:
    results = run.get("results", run if isinstance(run, list) else [])
    return [f for r in results for f in r.get("findings", [])]


def _counts(findings: list[dict]) -> dict[str, int]:
    c = {k: 0 for k in _SEV_RANK}
    for f in findings:
        c[f.get("severity", "info")] = c.get(f.get("severity", "info"), 0) + 1
    return c


_PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{title}</title><style>
body{{font:15px system-ui,sans-serif;max-width:1040px;margin:0 auto;padding:24px 16px;background:#0f1216;color:#e6e8eb}}
a{{color:#5aa2e0;text-decoration:none}}h1{{font-size:22px;margin:0 0 4px}}h2{{font-size:16px;margin:28px 0 10px}}
table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;padding:8px;border-bottom:1px solid #262c34}}
.badge{{color:#fff;font-size:11px;padding:2px 8px;border-radius:20px}}
.chip{{font-size:11px;border:1px solid #262c34;color:#93a0af;padding:1px 7px;border-radius:20px;margin-right:4px}}
.muted{{color:#93a0af}}pre{{background:#0b0e12;padding:10px;border-radius:8px;overflow:auto;font-size:12px}}
.kpis{{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}}
.kpi{{background:#151a21;border:1px solid #232a33;border-radius:10px;padding:12px 16px;min-width:120px;flex:1}}
.kpi .n{{font-size:26px;font-weight:700}}.kpi .l{{font-size:12px;color:#93a0af;text-transform:uppercase;letter-spacing:.04em}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
.card{{background:#151a21;border:1px solid #232a33;border-radius:10px;padding:14px 16px}}
.matrix td{{text-align:center;border:1px solid #232a33;font-variant-numeric:tabular-nums}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr}}}}
</style>{body}"""


def _run_target(run: dict) -> str:
    for r in run.get("results", []):
        for fi in r.get("findings", []):
            if fi.get("target"):
                return fi["target"]
    return ""


def _kpi(n, label) -> str:
    return f'<div class=kpi><div class=n>{n}</div><div class=l>{_esc(label)}</div></div>'


def _sev_bars(counts: dict) -> str:
    """Horizontal severity distribution as inline SVG."""
    order = ["critical", "high", "medium", "low", "info"]
    total = sum(counts.get(s, 0) for s in order) or 1
    rows, y = [], 6
    for s in order:
        v = counts.get(s, 0)
        w = int(300 * v / total)
        rows.append(f'<rect x=70 y={y} width={w} height=16 fill="{_SEV_COLOR[s]}" rx=3/>'
                    f'<text x=0 y={y+13} fill="#93a0af" font-size=12>{s}</text>'
                    f'<text x={78+w} y={y+13} fill="#e6e8eb" font-size=12>{v}</text>')
        y += 24
    return f'<svg width=100% height={y} viewBox="0 0 400 {y}">{"".join(rows)}</svg>'


def _trend_svg(rows: list[dict]) -> str:
    """Total findings per run over time as an inline SVG area/line."""
    if not rows:
        return '<p class=muted>No runs yet.</p>'
    vals = [r["total"] for r in rows]
    mx = max(vals) or 1
    w, h, n = 460, 120, len(vals)
    step = w / max(n - 1, 1)
    pts = [(i * step, h - 10 - (h - 20) * v / mx) for i, v in enumerate(vals)]
    line = " ".join(f"{x:.0f},{y:.0f}" for x, y in pts)
    area = f"0,{h} " + line + f" {w},{h}"
    dots = "".join(f'<circle cx={x:.0f} cy={y:.0f} r=3 fill="#5aa2e0"/>' for x, y in pts)
    return (f'<svg width=100% height={h} viewBox="0 0 {w} {h}" preserveAspectRatio=none>'
            f'<polygon points="{area}" fill="#5aa2e022"/>'
            f'<polyline points="{line}" fill=none stroke="#5aa2e0" stroke-width=2/>{dots}'
            f'</svg><p class=muted>{n} run(s), peak {mx} findings</p>')


def _risk_matrix_html(findings: list[dict]) -> str:
    lv = ["critical", "high", "medium", "low"]
    im = ["low", "medium", "high"]
    cells = {(a, b): 0 for a in lv for b in im}
    seen = False
    for f in findings:
        risk = (f.get("metadata") or {}).get("risk")
        if risk and (risk.get("likelihood"), risk.get("impact")) in cells:
            cells[(risk["likelihood"], risk["impact"])] += 1
            seen = True
    if not seen:
        return '<p class=muted>No risk-rated findings yet.</p>'
    head = "<tr><th></th>" + "".join(f"<th>{i}</th>" for i in im) + "</tr>"
    body = ""
    for a in lv:
        row = f"<th>{a}</th>"
        for b in im:
            v = cells[(a, b)]
            shade = "#b3123b" if (a in ("critical", "high") and b == "high") else \
                    ("#e08a1e" if v else "#151a21")
            row += f'<td style="background:{shade if v else "#151a21"}">{v or ""}</td>'
        body += f"<tr>{row}</tr>"
    return f'<table class=matrix>{head}{body}</table><p class=muted>likelihood (rows) x impact (cols)</p>'


def _compliance_coverage(findings: list[dict]) -> str:
    owasp: dict[str, int] = {}
    for f in findings:
        c = (f.get("metadata") or {}).get("compliance") or {}
        if c.get("owasp"):
            owasp[c["owasp"]] = owasp.get(c["owasp"], 0) + 1
    if not owasp:
        return '<p class=muted>No compliance tags yet.</p>'
    rows = "".join(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>"
                   for k, v in sorted(owasp.items(), key=lambda x: -x[1]))
    return f'<table><tr><th>OWASP category</th><th>Findings</th></tr>{rows}</table>'


def _dashboard(runs: dict[str, dict]) -> str:
    all_findings = [f for run in runs.values() for f in _findings(run)]
    agg = _counts(all_findings)
    kev = sum(1 for f in all_findings if (f.get("metadata") or {}).get("known_exploited"))
    targets = {_run_target(run) for run in runs.values()} - {""}

    from ..trends import trend_rows
    trows = trend_rows(runs)

    kpis = "".join([
        _kpi(len(runs), "runs"), _kpi(len(all_findings), "findings"),
        _kpi(agg.get("critical", 0), "critical"), _kpi(agg.get("high", 0), "high"),
        _kpi(kev, "known exploited"), _kpi(len(targets), "targets"),
    ])

    rows = []
    for rid, run in sorted(runs.items(), reverse=True):
        f = _findings(run)
        c = _counts(f)
        badges = " ".join(
            f'<span class="badge" style="background:{_SEV_COLOR[s]}">{c[s]} {s}</span>'
            for s in ["critical", "high", "medium", "low", "info"] if c.get(s))
        rows.append(f'<tr><td><a href="/run/{_esc(rid)}">{_esc(rid)}</a></td>'
                    f'<td>{_esc(_run_target(run))}</td><td>{len(f)}</td><td>{badges}</td></tr>')
    table = ("<table><tr><th>Run</th><th>Target</th><th>Findings</th><th>Severity</th></tr>"
             + ("".join(rows) or '<tr><td colspan=4 class=muted>No runs. Scan with --save-run DIR.</td></tr>')
             + "</table>")

    body = (f'<h1>Sentari Executive Dashboard</h1>'
            f'<p class=muted>Read-only view of saved assessments.</p>'
            f'<div class=kpis>{kpis}</div>'
            f'<div class=grid>'
            f'<div class=card><b>Severity distribution</b>{_sev_bars(agg)}</div>'
            f'<div class=card><b>Findings over time</b>{_trend_svg(trows)}</div>'
            f'<div class=card><b>Risk prioritization matrix</b>{_risk_matrix_html(all_findings)}</div>'
            f'<div class=card><b>Compliance coverage</b>{_compliance_coverage(all_findings)}</div>'
            f'</div>'
            f'<h2>Runs</h2>{table}')
    return _PAGE.format(title="Sentari Dashboard", body=body)


def _run_view(rid: str, run: dict) -> str:
    findings = sorted(_findings(run), key=lambda x: -_SEV_RANK.get(x.get("severity", "info"), 0))
    ai = run.get("ai_analysis") or {}
    cards = []
    for f in findings:
        meta = f.get("metadata") or {}
        comp = meta.get("compliance") or {}
        chips = ""
        if comp.get("owasp"):
            chips += f'<span class=chip>OWASP {_esc(comp["owasp"])}</span>'
        for cw in comp.get("cwe", []):
            chips += f'<span class=chip>{_esc(cw)}</span>'
        cvss = (meta.get("cvss") or {}).get("score")
        if cvss is not None:
            chips += f'<span class=chip>CVSS {_esc(cvss)}</span>'
        if meta.get("known_exploited"):
            chips += '<span class=chip style="border-color:#b3123b;color:#e8687f">KNOWN EXPLOITED</span>'
        bi = meta.get("business_impact")
        if bi:
            chips += f'<span class=chip>impact {_esc(bi.get("impact"))}</span>'
        sev = f.get("severity", "info")
        cards.append(
            f'<tr><td><span class="badge" style="background:{_SEV_COLOR.get(sev,"#5b6470")}">{_esc(sev.upper())}</span></td>'
            f'<td><b>{_esc(f.get("title"))}</b><br><span class=muted>{_esc(f.get("location") or "")}</span><br>'
            f'{_esc(f.get("description"))}<br>{chips}</td></tr>')
    ai_html = ""
    if ai and ai.get("summary"):
        ai_html = f"<h2>AI triage <span class=muted>({_esc(ai.get('provider'))})</span></h2><pre>{_esc(ai.get('summary'))}</pre>"
    body = (f'<p><a href="/">&larr; all runs</a></p><h1>Run {_esc(rid)}</h1>{ai_html}'
            f'<h2>Findings ({len(findings)})</h2><table>{"".join(cards)}</table>')
    return _PAGE.format(title=f"Run {rid}", body=body)


def make_handler(load):
    """`load` is a zero-arg callable returning {run_id: payload}."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            runs = load()
            path = self.path.split("?")[0]
            if path == "/":
                self._send(200, _dashboard(runs))
            elif path == "/metrics":
                from ..metrics import render_metrics
                self._send(200, render_metrics(runs), "text/plain; version=0.0.4")
            elif path == "/api/runs":
                self._send(200, json.dumps({"runs": list(runs)}), "application/json")
            elif path.startswith("/api/runs/"):
                rid = path[len("/api/runs/"):]
                if rid in runs:
                    self._send(200, json.dumps(runs[rid]), "application/json")
                else:
                    self._send(404, json.dumps({"error": "not found"}), "application/json")
            elif path.startswith("/run/"):
                rid = path[len("/run/"):]
                if rid in runs:
                    self._send(200, _run_view(rid, runs[rid]))
                else:
                    self._send(404, "run not found")
            else:
                self._send(404, "not found")
    return Handler


def serve(runs_dir: Optional[str] = None, port: int = 8600, host: str = "127.0.0.1",
          db: Optional[str] = None) -> None:
    if db:
        from ..db import RunStore
        def load():
            store = RunStore(db)
            try:
                return store.all_runs()
            finally:
                store.close()
        source = f"db={db}"
    else:
        d = Path(runs_dir or "runs")
        d.mkdir(parents=True, exist_ok=True)
        def load():
            return _load_runs(d)
        source = f"runs-dir={d}"
    httpd = ThreadingHTTPServer((host, port), make_handler(load))
    print(f"Sentari dashboard (read-only) on http://{host}:{port}  {source}")
    print("Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
