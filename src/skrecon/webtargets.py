"""Derive web-service targets from discovered services (spec §5.4–5.7 inputs).

Phase-4 web modules run against web services found by nmap. We classify a service
as web by port or product banner and build a URL + scheme for it.
"""

from __future__ import annotations

import re
from typing import Any


def safe_name(url: str) -> str:
    """Filesystem-safe basename derived from a URL (for raw output files)."""
    return re.sub(r"[^a-z0-9]+", "_", url.lower()).strip("_") or "target"

HTTP_PORTS = {80, 8080, 8000, 8888, 8081, 3000, 5000}
HTTPS_PORTS = {443, 8443, 9443}
WEB_PORTS = HTTP_PORTS | HTTPS_PORTS


def _is_web(port: int, product: str) -> bool:
    return port in WEB_PORTS or "http" in product or "nginx" in product or "apache" in product


def web_targets(ctx) -> list[dict[str, Any]]:
    """Unique web services as {host, port, scheme, url}."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for s in ctx.store.list_services():
        host, port = s["host_ip"], s["port"]
        if port is None:
            continue
        product = (s.get("product") or "").lower()
        if not _is_web(port, product):
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        https = port in HTTPS_PORTS or "https" in product or "ssl" in product or "tls" in product
        scheme = "https" if https else "http"
        host_part = f"[{host}]" if ":" in host else host   # bracket IPv6 in URLs
        out.append({"host": host, "port": port, "scheme": scheme,
                    "url": f"{scheme}://{host_part}:{port}"})
    return out


def tls_targets(ctx) -> list[dict[str, Any]]:
    """Web services that speak TLS (for the tls module)."""
    return [t for t in web_targets(ctx) if t["scheme"] == "https"]
