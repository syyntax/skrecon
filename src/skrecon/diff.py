"""Run deltas (spec §7): compare two engagements over the same scope for retests.

Highlights what changed — new/removed hosts, services, subdomains, and findings —
so a retest can focus on the delta.
"""

from __future__ import annotations

from typing import Any

from .store import EngagementStore


def _finding_key(f: dict) -> tuple:
    return (f["finding_type"], tuple(sorted(f["affected"])))


def diff_engagements(old: EngagementStore, new: EngagementStore) -> dict[str, Any]:
    old_hosts = {h["ip"] for h in old.list_hosts()}
    new_hosts = {h["ip"] for h in new.list_hosts()}

    def svc_set(store):
        return {(s["host_ip"], s["port"], s["proto"]) for s in store.list_services()}

    old_svc, new_svc = svc_set(old), svc_set(new)
    old_dom = {d["fqdn"] for d in old.list_domains()}
    new_dom = {d["fqdn"] for d in new.list_domains()}
    old_find = {_finding_key(f): f for f in old.list_findings()}
    new_find = {_finding_key(f): f for f in new.list_findings()}

    return {
        "new_hosts": sorted(new_hosts - old_hosts),
        "removed_hosts": sorted(old_hosts - new_hosts),
        "new_services": sorted(f"{h}:{p}/{pr}" for (h, p, pr) in (new_svc - old_svc)),
        "removed_services": sorted(f"{h}:{p}/{pr}" for (h, p, pr) in (old_svc - new_svc)),
        "new_subdomains": sorted(new_dom - old_dom),
        "new_findings": [new_find[k]["title"] for k in (new_find.keys() - old_find.keys())],
        "resolved_findings": [old_find[k]["title"] for k in (old_find.keys() - new_find.keys())],
    }


def render_diff_text(delta: dict[str, Any]) -> str:
    lines: list[str] = []
    sections = [
        ("New hosts", "new_hosts"),
        ("Removed hosts", "removed_hosts"),
        ("New services", "new_services"),
        ("Removed services", "removed_services"),
        ("New subdomains", "new_subdomains"),
        ("New findings", "new_findings"),
        ("Resolved findings", "resolved_findings"),
    ]
    for label, key in sections:
        items = delta[key]
        lines.append(f"{label}: {len(items)}")
        for item in items[:50]:
            lines.append(f"  + {item}")
    return "\n".join(lines)
