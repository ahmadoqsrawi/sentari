# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""AI-assisted OSINT, kept grounded.

The model is used for two things only, and neither one gets to assert a fact:

  * `seed_subdomains` asks the model for likely subdomain *labels* for a domain
    (dev, staging, vpn, and so on). These are guesses. The OSINT phase then
    DNS-resolves each candidate and records only the ones that actually resolve,
    so the evidence is a real DNS answer, not the model's opinion.
  * `summarize` writes a short analyst summary over the *real* assets already
    discovered. It describes given data; it does not add hosts.

If no provider is configured, the phase simply skips these and runs the passive
tools as before.
"""
from __future__ import annotations

import json
import re
from typing import Optional

_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def seed_subdomains(provider, domain: str, limit: int = 40) -> list[str]:
    """Ask the model for candidate subdomain labels. Returns labels, not hosts."""
    system = ("You are an OSINT assistant. Given a domain, list likely subdomain "
              "labels an organization might use (single labels only, no dots). "
              "Return a JSON array of strings, nothing else.")
    user = f"Domain: {domain}. Give up to {limit} likely subdomain labels."
    try:
        raw = provider.complete(system, user, max_tokens=400)
    except Exception:
        return []
    labels = _extract_list(raw)
    out = []
    for lbl in labels:
        lbl = str(lbl).strip().lower().split(".")[0]
        if _LABEL_RE.match(lbl) and lbl not in out:
            out.append(lbl)
        if len(out) >= limit:
            break
    return out


def summarize(provider, domain: str, assets: list[str], shodan_ports: Optional[list] = None) -> str:
    """Summarize the real, already-discovered OSINT surface. Adds no hosts."""
    if not assets and not shodan_ports:
        return ""
    system = ("You are a penetration-test analyst. Summarize the given OSINT "
              "surface in 2-4 sentences for the engagement notes. Use ONLY the "
              "data provided. Do not invent hosts, services, or vulnerabilities.")
    payload = {"domain": domain, "discovered_assets": assets[:200],
               "shodan_ports": shodan_ports or []}
    try:
        return provider.complete(system, json.dumps(payload), max_tokens=400).strip()
    except Exception:
        return ""


def _extract_list(raw: str) -> list:
    raw = raw.strip()
    start, end = raw.find("["), raw.rfind("]")
    if start != -1 and end > start:
        try:
            val = json.loads(raw[start:end + 1])
            if isinstance(val, list):
                return val
        except ValueError:
            pass
    # fallback: comma/newline separated
    return [p for p in re.split(r"[,\n]", raw) if p.strip()]
