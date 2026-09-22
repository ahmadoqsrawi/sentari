"""Graph of agents: specialized workers that share one blackboard.

Instead of one linear pass, the work is split into specialized nodes that run in
order and share a single context (the blackboard), so later nodes see what
earlier ones discovered. Across several targets the whole graph runs in parallel
and a coordinator correlates the shared findings.

Every node still runs the real phases and every finding is still evidence-backed.
When an AI provider is supplied, the coordinator adds a grounded synthesis
(prioritization and attack chains) over the real findings; without one, the
coordination is a deterministic cross-asset correlation. No node fabricates.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from .authorization import AuditLog, Scope, authorize
from .models import PhaseResult
from .phases import PHASES, PhaseContext
from .runner import ToolRunner

# Specialized nodes, each a group of phases sharing the blackboard in order.
NODES: list[tuple[str, list[str]]] = [
    ("recon", ["osint", "recon", "scanning"]),
    ("assess", ["sast", "cloud-audit", "vuln", "api", "proxy", "browser"]),
    ("verify", ["verification"]),
]


@dataclass
class GraphResult:
    target: str
    results: list[PhaseResult] = field(default_factory=list)
    node_summary: dict[str, int] = field(default_factory=dict)  # node -> findings count
    error: Optional[str] = None


def run_graph(target: str, scope: Scope, authorized: bool, audit: AuditLog, *,
              safe_mode: bool = True, timeout: int = 120, options: Optional[dict] = None
              ) -> GraphResult:
    """Run the node graph against one target on a shared blackboard."""
    authorize(target, scope, authorized, audit)
    gr = GraphResult(target=target)
    ctx = PhaseContext(target=target, runner=ToolRunner(timeout),
                       safe_mode=safe_mode, options=options or {})
    by_name = {cls.name: cls for cls in PHASES}
    for node, phase_names in NODES:
        count = 0
        for pname in phase_names:
            cls = by_name.get(pname)
            if cls is None:
                continue
            ctx.runner = ToolRunner(timeout)
            res = cls().run(ctx)
            ctx.shared.setdefault("prior_findings", []).extend(res.findings)
            gr.results.append(res)
            count += len(res.findings)
            audit.record("graph.phase", target=target, node=node, phase=pname,
                         findings=len(res.findings))
        gr.node_summary[node] = count
    return gr


def run_graph_targets(targets: list[str], scope: Scope, authorized: bool, audit: AuditLog, *,
                      safe_mode: bool = True, timeout: int = 120,
                      options: Optional[dict] = None, workers: int = 4, provider=None
                      ) -> tuple[list[GraphResult], list[dict], object]:
    """Run the graph across several targets in parallel; correlate the findings.

    Returns (per-target graph results, cross-asset correlation rows, coordination).
    When `provider` is given, the coordinator adds a grounded AI synthesis
    (prioritization and attack chains) over all findings; otherwise it is None."""
    graphs: list[GraphResult] = []
    with ThreadPoolExecutor(max_workers=min(workers, max(len(targets), 1))) as pool:
        futs = {pool.submit(_safe_graph, t, scope, authorized, audit,
                            safe_mode, timeout, options): t for t in targets}
        for fut in as_completed(futs):
            graphs.append(fut.result())
    graphs.sort(key=lambda g: g.target)

    from . import correlation
    runs = {g.target: {"results": [r.to_dict() for r in g.results]} for g in graphs}
    correlated = correlation.correlate(runs)

    coordination = None
    if provider is not None:
        from .ai.analyst import GroundedAnalyst
        all_results = [r for g in graphs for r in g.results]
        coordination = GroundedAnalyst(provider).analyze(all_results)
    return graphs, correlated, coordination


def _safe_graph(target, scope, authorized, audit, safe_mode, timeout, options) -> GraphResult:
    try:
        return run_graph(target, scope, authorized, audit,
                         safe_mode=safe_mode, timeout=timeout, options=options)
    except Exception as e:
        return GraphResult(target=target, error=f"{type(e).__name__}: {e}")
