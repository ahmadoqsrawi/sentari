"""Forward findings and run summaries to a SIEM.

Sends the real results of a scan to Splunk (HEC), Elasticsearch, a syslog
collector, or a generic webhook. Only findings that Sentari actually produced
are shipped; nothing here creates or changes a finding.

All transports use the standard library. Each finding becomes one event, plus a
final summary event with the per-severity counts.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from typing import Optional

SIEM_TYPES = ("webhook", "splunk", "elasticsearch", "syslog")


def _events(payload: dict, target: str) -> list[dict]:
    ts = datetime.now(timezone.utc).isoformat()
    findings = [f for r in payload.get("results", []) for f in r.get("findings", [])]
    events = []
    for f in findings:
        events.append({
            "ts": ts, "source": "sentari", "type": "finding", "target": target,
            "severity": f.get("severity"), "title": f.get("title"),
            "phase": f.get("phase"), "location": f.get("location"),
            "compliance": (f.get("metadata") or {}).get("compliance"),
        })
    counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1
    events.append({
        "ts": ts, "source": "sentari", "type": "summary", "target": target,
        "findings_total": len(findings), "counts": counts,
    })
    return events


def _post_json(url: str, body: bytes, headers: dict[str, str], timeout: int = 15) -> int:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.status


def ship(siem_type: str, url: str, payload: dict, target: str,
         token: Optional[str] = None) -> tuple[int, list[str]]:
    """Send the run's events to the SIEM. Returns (events_sent, errors)."""
    events = _events(payload, target)
    errors: list[str] = []
    sent = 0

    if siem_type == "webhook":
        try:
            _post_json(url, json.dumps({"events": events}).encode(),
                       {"Content-Type": "application/json"})
            sent = len(events)
        except Exception as e:
            errors.append(f"webhook: {e}")

    elif siem_type == "splunk":
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Splunk {token}"
        for ev in events:
            try:
                _post_json(url, json.dumps({"event": ev, "sourcetype": "sentari"}).encode(),
                           headers)
                sent += 1
            except Exception as e:
                errors.append(f"splunk: {e}")
                break

    elif siem_type == "elasticsearch":
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"ApiKey {token}"
        base = url.rstrip("/")
        for ev in events:
            try:
                _post_json(f"{base}/_doc", json.dumps(ev).encode(), headers)
                sent += 1
            except Exception as e:
                errors.append(f"elasticsearch: {e}")
                break

    elif siem_type == "syslog":
        host, _, port = url.partition(":")
        port_n = int(port) if port.isdigit() else 514
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for ev in events:
                # RFC 5424-ish line; keep it simple and parseable
                line = f"<134>1 {ev['ts']} sentari - - - {json.dumps(ev)}"
                sock.sendto(line.encode(), (host, port_n))
                sent += 1
            sock.close()
        except Exception as e:
            errors.append(f"syslog: {e}")
    else:
        errors.append(f"unknown SIEM type: {siem_type}")

    return sent, errors
