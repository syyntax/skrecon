"""Certificate Transparency subdomain discovery (spec §4.5).

Queries crt.sh for every certificate issued under each in-scope registrable domain
and extracts subdomains + certificate summaries. This is one of the richest passive
subdomain sources and needs no API key. Discovered names are recorded as (non-scope)
domains for the `subdomains` module to resolve and scope-check.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from ..model import Certificate, CertSource, DomainName, Observation, Phase
from ..osint import parse_certspotter, parse_crtsh
from ..targets import scope_domains
from .base import REGISTRY, Action, Readiness

CERT_STORE_CAP = 200   # bound certificate rows per domain (name extraction uses all rows)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class CtModule:
    name = "ct"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on: list[str] = []
    default_enabled = True

    def _domains(self, ctx) -> list[str]:
        return scope_domains(ctx.scope, ctx.settings.client_root_domains)

    def preflight(self, ctx) -> Readiness:
        if not self._domains(ctx):
            return Readiness.skip("no registrable domains in scope")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        domains = self._domains(ctx)
        return [Action(description=f"query crt.sh CT logs for {len(domains)} domain(s)",
                       phase=Phase.PASSIVE, targets=domains,
                       command="GET https://crt.sh/?q=%25.<domain>&output=json")]

    def _query_ct(self, ctx, apex: str) -> tuple[set[str], list[dict], list[str]]:
        """crt.sh primary, certspotter fallback. crt.sh is frequently down, so we
        fall back rather than lose the richest passive subdomain source."""
        names: set[str] = set()
        certs: list[dict] = []
        sources: list[str] = []

        _s, data = ctx.http_passive.get_json(
            f"https://crt.sh/?q=%25.{apex}&output=json", module=self.name, cache_key=f"crtsh:{apex}")
        if isinstance(data, list) and data:
            n, c = parse_crtsh(data, apex)
            names |= n
            certs += c
            sources.append("crt.sh")

        if not names:   # crt.sh down or empty -> certspotter fallback
            _s2, data2 = ctx.http_passive.get_json(
                f"https://api.certspotter.com/v1/issuances?domain={apex}"
                "&include_subdomains=true&expand=dns_names&expand=issuer",
                module=self.name, cache_key=f"certspotter:{apex}")
            if isinstance(data2, list) and data2:
                n, c = parse_certspotter(data2, apex)
                names |= n
                certs += c
                sources.append("certspotter")

        return names, certs, sources

    def run(self, ctx) -> Iterable:
        for apex in self._domains(ctx):
            names, certs, sources = self._query_ct(ctx, apex)
            if not sources:
                yield Observation(subject=apex, kind="ct", data={"found": False})
                continue

            for name in sorted(names):
                yield DomainName(fqdn=name, registrable_domain=apex,
                                 is_scope=name in ctx.scope.hostnames)
            for c in certs[:CERT_STORE_CAP]:
                yield Certificate(subject=c["common_name"] or apex, issuer=c["issuer"],
                                  sans=[], not_before=_parse_dt(c["not_before"]),
                                  not_after=_parse_dt(c["not_after"]), source=CertSource.CT)
            yield Observation(subject=apex, kind="ct", data={
                "found": True, "sources": sources, "subdomains": len(names), "certs": len(certs)})


REGISTRY.register(CtModule())
