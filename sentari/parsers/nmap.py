# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Parse nmap XML output (-oX -) into structured service records.

Pure parsing of real tool output: no inference. If nmap didn't report it, it
isn't here.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceRecord:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None

    def label(self) -> str:
        parts = [self.service or "unknown"]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


def parse_nmap_xml(xml_text: str) -> list[ServiceRecord]:
    records: list[ServiceRecord] = []
    if not xml_text.strip():
        return records
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return records
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_el = port.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            svc = port.find("service")
            records.append(
                ServiceRecord(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    state=state,
                    service=svc.get("name") if svc is not None else None,
                    product=svc.get("product") if svc is not None else None,
                    version=svc.get("version") if svc is not None else None,
                    extrainfo=svc.get("extrainfo") if svc is not None else None,
                )
            )
    return records
