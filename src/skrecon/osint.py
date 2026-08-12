"""Pure parsers for Phase 2 OSINT providers (spec §4.5, §4.7, §4.9).

Kept free of network and API keys so the extraction/summarization logic is
unit-testable. The modules do the HTTP/API calls and feed raw responses here.
"""

from __future__ import annotations

from typing import Any


# --------------------------------------------------------------------------- #
# Certificate Transparency (crt.sh)
# --------------------------------------------------------------------------- #
def parse_crtsh(rows: list[dict[str, Any]], apex: str) -> tuple[set[str], list[dict[str, Any]]]:
    """From crt.sh JSON rows return (subdomain names in-apex, certificate summaries).

    `name_value` may hold several newline-separated names and wildcards; we
    normalize and keep only names within the apex domain.
    """
    apex = apex.lower().strip(".")
    names: set[str] = set()
    certs: list[dict[str, Any]] = []
    seen_cert: set[tuple] = set()
    for row in rows:
        for raw in str(row.get("name_value", "")).split("\n"):
            n = raw.strip().lower().lstrip("*.").rstrip(".")
            if n and (n == apex or n.endswith("." + apex)):
                names.add(n)
        key = (row.get("common_name"), row.get("issuer_name"), row.get("not_after"))
        if key not in seen_cert:
            seen_cert.add(key)
            certs.append({
                "common_name": row.get("common_name"),
                "issuer": row.get("issuer_name"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
            })
    return names, certs


def parse_certspotter(rows: list[dict[str, Any]], apex: str) -> tuple[set[str], list[dict[str, Any]]]:
    """Certspotter issuances -> (in-apex names, cert summaries). Fallback for crt.sh."""
    apex = apex.lower().strip(".")
    names: set[str] = set()
    certs: list[dict[str, Any]] = []
    for row in rows:
        dns_names = [str(n).strip().lower().lstrip("*.").rstrip(".") for n in row.get("dns_names", [])]
        in_apex = [n for n in dns_names if n and (n == apex or n.endswith("." + apex))]
        names.update(in_apex)
        issuer = row.get("issuer")
        issuer_name = issuer.get("name") if isinstance(issuer, dict) else issuer
        certs.append({
            "common_name": dns_names[0] if dns_names else None,
            "issuer": issuer_name,
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
        })
    return names, certs


# --------------------------------------------------------------------------- #
# Shodan host data
# --------------------------------------------------------------------------- #
def parse_shodan_host(data: dict[str, Any]) -> dict[str, Any]:
    services = []
    for d in data.get("data", []) or []:
        services.append({
            "port": d.get("port"),
            "proto": d.get("transport", "tcp"),
            "product": d.get("product"),
            "version": d.get("version"),
        })
    return {
        "ip": data.get("ip_str"),
        "ports": data.get("ports", []) or [],
        "services": services,
        "cves": sorted(data.get("vulns", []) or []),
        "hostnames": data.get("hostnames", []) or [],
        "org": data.get("org"),
        "os": data.get("os"),
    }


# --------------------------------------------------------------------------- #
# DeHashed breach data (PII — only the summary leaves this function for reports)
# --------------------------------------------------------------------------- #
def summarize_dehashed(payload: dict[str, Any]) -> dict[str, Any]:
    """Summarize a DeHashed response into per-source counts + a plaintext flag.

    The raw entries stay with the caller for the encrypted vault; this summary
    (counts, sources, whether any plaintext password appeared) is what reports use.
    """
    entries = payload.get("entries") or []
    by_source: dict[str, dict[str, Any]] = {}
    plaintext_any = False
    for e in entries:
        src = e.get("database_name") or e.get("obtained_from") or "unknown"
        bucket = by_source.setdefault(src, {"count": 0, "plaintext": False})
        bucket["count"] += 1
        if e.get("password"):
            bucket["plaintext"] = True
            plaintext_any = True
    return {
        "total": payload.get("total", len(entries)),
        "entry_count": len(entries),
        "by_source": by_source,
        "plaintext_any": plaintext_any,
    }
