"""HTTP security-header analysis (spec §5.4).

ACTIVE: fetches each discovered web service through the guarded HTTP client (scope-
checked, gated, no redirect-following) and evaluates security headers + cookie flags.
"""

from __future__ import annotations

from typing import Iterable

from ..findings import make_finding
from ..headers import evaluate_headers
from ..model import Observation, Phase
from ..webtargets import web_targets
from .base import REGISTRY, Action, Readiness


class HeadersModule:
    name = "headers"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on = ["nmap"]
    default_enabled = True

    def preflight(self, ctx) -> Readiness:
        if not web_targets(ctx):
            return Readiness.skip("no web services discovered (run nmap first)")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        targets = web_targets(ctx)
        return [Action(description=f"fetch + evaluate security headers for {len(targets)} web service(s)",
                       phase=Phase.ACTIVE, targets=[t["url"] for t in targets],
                       command="GET <url> (no redirects) -> header analysis")]

    def run(self, ctx) -> Iterable:
        for t in web_targets(ctx):
            res = ctx.http.get(t["url"], module=self.name)
            if res.planned:
                continue
            if res.status is None:
                yield Observation(subject=t["url"], kind="headers", data={"error": res.error})
                continue
            for ft, ev in evaluate_headers(res.headers, res.set_cookies):
                yield make_finding(ft, affected=[t["url"]], evidence=[ev],
                                   source_module=self.name, phase=Phase.ACTIVE,
                                   title_ctx={"url": t["url"]})
            yield Observation(subject=t["url"], kind="headers",
                              data={"status": res.status, "server": res.headers.get("Server")})


REGISTRY.register(HeadersModule())
