"""Pure parsers for the wrapped web tools (spec §5.5, §5.7).

whatweb (tech), wafw00f (WAF), and nuclei (templated vulns) emit JSON; these
extract the fields the modules record. No subprocess/network here.
"""

from __future__ import annotations

import json
from typing import Any

# nuclei severity string -> our finding catalog key
NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def parse_whatweb(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        data = [data]
    techs: list[dict[str, Any]] = []
    for entry in data or []:
        for name, info in (entry.get("plugins") or {}).items():
            version = None
            if isinstance(info, dict):
                v = info.get("version")
                if isinstance(v, list) and v:
                    version = str(v[0])
                elif isinstance(v, str):
                    version = v
            techs.append({"name": name, "version": version})
    return techs


def parse_wafw00f(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        data = [data]
    out: list[dict[str, Any]] = []
    for e in data or []:
        out.append({
            "url": e.get("url"),
            "detected": bool(e.get("detected")),
            "firewall": e.get("firewall"),
            "manufacturer": e.get("manufacturer"),
        })
    return out


def parse_nuclei(text: str) -> list[dict[str, Any]]:
    """nuclei -jsonl output: one JSON object per line."""
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        severity = str(info.get("severity") or "info").lower()
        out.append({
            "template": obj.get("template-id") or obj.get("templateID"),
            "name": info.get("name"),
            "severity": severity if severity in NUCLEI_SEVERITIES else "info",
            "matched": obj.get("matched-at") or obj.get("host"),
        })
    return out


def nuclei_finding_type(severity: str) -> str:
    sev = severity.lower()
    return f"nuclei.{sev}" if sev in NUCLEI_SEVERITIES else "nuclei.info"
