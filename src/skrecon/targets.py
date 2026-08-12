"""Helpers for deriving what passive modules operate on from the resolved scope.

`registrable_domain` uses a naive last-two-labels heuristic. This is correct for
plain TLDs (example.com) but wrong for multi-part suffixes (example.co.uk). A
Public Suffix List is the proper fix and is planned; until then multi-part-suffix
domains should be listed explicitly via `client_root_domains`.
"""

from __future__ import annotations

from typing import Iterable

from .scope import ResolvedScope


def registrable_domain(host: str) -> str:
    labels = host.strip().strip(".").lower().split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host.strip().strip(".").lower()


def scope_domains(scope: ResolvedScope, extra_roots: Iterable[str] = ()) -> list[str]:
    """Unique registrable domains to evaluate for mail/WHOIS/typosquat modules."""
    domains: set[str] = set()
    for host in scope.hostnames:
        domains.add(registrable_domain(host))
    for root in extra_roots:
        if root:
            domains.add(registrable_domain(root))
    return sorted(domains)
