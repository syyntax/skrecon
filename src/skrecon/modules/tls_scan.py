"""TLS/SSL analysis (spec §5.3).

ACTIVE: probes each TLS web service through the guarded prober for accepted
protocol versions and its certificate, flags weak protocols / expiry / self-signed,
and harvests certificate SANs as another subdomain source.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from ..findings import make_finding
from ..model import Certificate, CertSource, DomainName, Observation, Phase
from ..targets import registrable_domain
from ..tlscheck import evaluate_tls
from ..webtargets import tls_targets
from .base import REGISTRY, Action, Readiness


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class TlsModule:
    name = "tls"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on = ["nmap"]
    default_enabled = True

    def preflight(self, ctx) -> Readiness:
        if not tls_targets(ctx):
            return Readiness.skip("no TLS web services discovered")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        targets = tls_targets(ctx)
        return [Action(description=f"probe TLS (protocols + certificate) for {len(targets)} service(s)",
                       phase=Phase.ACTIVE, targets=[t["url"] for t in targets],
                       command="TLS handshake probe <host:port>")]

    def run(self, ctx) -> Iterable:
        for t in tls_targets(ctx):
            res = ctx.http.probe_tls(t["host"], t["port"], module=self.name)
            if res.planned:
                continue
            for ft, ev in evaluate_tls(res.protocols, res.cert):
                yield make_finding(ft, affected=[t["url"]], evidence=[ev],
                                   source_module=self.name, phase=Phase.ACTIVE,
                                   title_ctx={"url": t["url"]})
            if res.cert:
                for san in res.cert.get("sans", []):
                    name = str(san).lower().lstrip("*.")
                    yield DomainName(fqdn=name, registrable_domain=registrable_domain(name),
                                     is_scope=name in ctx.scope.hostnames)
                yield Certificate(subject=res.cert.get("subject"), issuer=res.cert.get("issuer"),
                                  sans=res.cert.get("sans", []), not_after=_parse_dt(res.cert.get("not_after")),
                                  self_signed=bool(res.cert.get("self_signed")), source=CertSource.TLS)
            yield Observation(subject=t["url"], kind="tls", data={"protocols": res.protocols})


REGISTRY.register(TlsModule())
