# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Tool schemas for native function-calling.

These are the OpenAI tool-spec format. The Anthropic provider converts them to
its own input_schema shape. They mirror the dispatcher's tools exactly, so the
same safety rules apply: record_finding requires an evidence_id, and there is no
tool for running an arbitrary command or changing the host.
"""
from __future__ import annotations


def _tool(name: str, description: str, properties: dict, required: list[str]):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required},
    }}


OPENAI_TOOLS = [
    _tool("dns_lookup", "Resolve the target host to IP addresses.", {}, []),
    _tool("port_scan", "TCP connect scan of common ports on the target.", {}, []),
    _tool("http_get", "GET a path on the target; returns status, server, missing "
          "security headers, and an evidence_id.",
          {"path": {"type": "string", "description": "path like /admin"},
           "port": {"type": "integer", "description": "optional port"}}, ["path"]),
    _tool("run_nuclei", "Run nuclei templates against discovered web ports.",
          {"severity": {"type": "string", "description": "optional csv, e.g. high,critical"}}, []),
    _tool("run_sqlmap", "Test a path for SQL injection (only when safe mode is off).",
          {"path": {"type": "string"}}, ["path"]),
    _tool("record_finding", "Record a finding. Requires an evidence_id returned by an "
          "earlier tool.",
          {"evidence_id": {"type": "string"},
           "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
           "title": {"type": "string"}, "description": {"type": "string"},
           "location": {"type": "string"}, "recommendation": {"type": "string"}},
          ["evidence_id", "severity", "title"]),
    _tool("finish", "End the assessment.", {"summary": {"type": "string"}}, []),
]
