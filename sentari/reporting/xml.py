"""XML report export (standard library).

Serializes the run's findings and evidence to XML for tools that ingest it.
Same content as the JSON output, in XML form.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.dom import minidom

from ..models import PhaseResult


def render_xml(results: list[PhaseResult], target: str) -> str:
    root = ET.Element("sentari-report", attrib={"target": target})
    for r in results:
        pe = ET.SubElement(root, "phase", attrib={"name": r.phase})
        for f in r.findings:
            fe = ET.SubElement(pe, "finding", attrib={
                "severity": f.severity.value, "id": f.id})
            ET.SubElement(fe, "title").text = f.title
            ET.SubElement(fe, "description").text = f.description
            if f.location:
                ET.SubElement(fe, "location").text = f.location
            comp = (f.metadata or {}).get("compliance") or {}
            if comp.get("owasp"):
                ET.SubElement(fe, "owasp").text = comp["owasp"]
            for cwe in comp.get("cwe", []):
                ET.SubElement(fe, "cwe").text = cwe
            cvss = (f.metadata or {}).get("cvss") or {}
            if cvss.get("score") is not None:
                ET.SubElement(fe, "cvss", attrib={"vector": cvss.get("vector", "")}).text = \
                    str(cvss["score"])
            for eid in f.evidence_ids:
                ET.SubElement(fe, "evidence-ref").text = eid
    xml = ET.tostring(root, encoding="unicode")
    return minidom.parseString(xml).toprettyxml(indent="  ")
