"""Grounded AI triage.

Feeds the LLM ONLY the real findings and evidence excerpts Sentari collected,
and asks it to prioritize, correlate into attack chains, and write remediation.

The anti-fabrication guarantee extends to the AI: the model is instructed to
reference findings solely by the ids we supplied, and every id it returns is
validated against the real set: invented references are discarded. The LLM
reasons over ground truth; it does not get to invent vulnerabilities.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ..models import PhaseResult
from .providers import LLMProvider

_SYSTEM = (
    "You are a penetration-test triage analyst. You will receive a JSON list of "
    "FINDINGS that were confirmed by real security tools, each with an 'id'. "
    "Your job: prioritize by real-world exploitability, group related findings into "
    "attack chains, and give concise remediation. STRICT RULES: (1) Reference "
    "findings ONLY by the given ids. (2) Never invent findings, CVEs, or facts not "
    "present in the input. (3) If evidence is thin, say so. Respond with ONLY valid "
    "JSON of shape: {\"summary\": str, \"prioritized\": [id,...], "
    "\"chains\": [{\"name\": str, \"finding_ids\": [id,...], \"rationale\": str}], "
    "\"remediation\": {id: str}}."
)


@dataclass
class Analysis:
    summary: str = ""
    prioritized: list[str] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    remediation: dict[str, str] = field(default_factory=dict)
    provider: str = ""
    model: str = ""
    error: Optional[str] = None
    dropped_references: int = 0  # invented ids the model tried to use


def _findings_payload(results: list[PhaseResult]) -> tuple[list[dict], set[str]]:
    evidence = {e.id: e for r in results for e in r.evidence}
    items, ids = [], set()
    for r in results:
        for f in r.findings:
            ids.add(f.id)
            excerpt = ""
            if f.evidence_ids and f.evidence_ids[0] in evidence:
                excerpt = evidence[f.evidence_ids[0]].stdout[:300]
            items.append({
                "id": f.id, "phase": f.phase, "severity": f.severity.value,
                "title": f.title, "location": f.location or "",
                "description": f.description, "evidence_excerpt": excerpt,
            })
    return items, ids


class GroundedAnalyst:
    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def analyze(self, results: list[PhaseResult]) -> Analysis:
        ok, reason = self.provider.available()
        out = Analysis(provider=self.provider.name, model=self.provider.model)
        if not ok:
            out.error = f"AI provider unavailable: {reason}"
            return out

        items, valid_ids = _findings_payload(results)
        if not items:
            out.error = "No findings to analyze."
            return out

        user = "FINDINGS:\n" + json.dumps(items, ensure_ascii=False)
        try:
            raw = self.provider.complete(_SYSTEM, user)
        except Exception as e:
            out.error = f"AI call failed: {type(e).__name__}: {e}"
            return out

        data = _extract_json(raw)
        if data is None:
            out.error = "AI did not return parseable JSON."
            out.summary = raw[:500]
            return out

        # --- enforce grounding: keep only references to real finding ids ---
        out.summary = str(data.get("summary", ""))[:4000]
        dropped = 0

        prio = [i for i in data.get("prioritized", []) if i in valid_ids]
        dropped += len(data.get("prioritized", [])) - len(prio)
        out.prioritized = prio

        for ch in data.get("chains", []) or []:
            fids = [i for i in ch.get("finding_ids", []) if i in valid_ids]
            dropped += len(ch.get("finding_ids", []) or []) - len(fids)
            if fids:
                out.chains.append({"name": str(ch.get("name", "chain")),
                                   "finding_ids": fids,
                                   "rationale": str(ch.get("rationale", ""))})

        for fid, text in (data.get("remediation", {}) or {}).items():
            if fid in valid_ids:
                out.remediation[fid] = str(text)
            else:
                dropped += 1

        out.dropped_references = dropped
        return out


def _extract_json(text: str) -> Optional[dict]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        a, b = text.find("{"), text.rfind("}")
        if a >= 0 and b > a:
            try:
                return json.loads(text[a:b + 1])
            except json.JSONDecodeError:
                return None
    return None
