"""Technology-stack fingerprinting via WhatWeb (spec §5.5).

ACTIVE: identifies web servers, frameworks, CMSes, and libraries (with versions
where exposed). Recorded as observations for cross-referencing with known vulns.
"""

from __future__ import annotations

import json
import shutil
from typing import Iterable

from ..model import Observation, Phase
from ..webparse import parse_whatweb
from ..webtargets import safe_name, web_targets
from .base import REGISTRY, Action, Readiness


class TechModule:
    name = "tech"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools = ["whatweb"]
    requires_keys: list[str] = []
    depends_on = ["nmap"]
    default_enabled = True

    def preflight(self, ctx) -> Readiness:
        if not shutil.which("whatweb"):
            return Readiness.skip("whatweb not installed (provided by the Docker image)")
        if not web_targets(ctx):
            return Readiness.skip("no web services discovered")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        targets = web_targets(ctx)
        return [Action(description=f"WhatWeb fingerprint {len(targets)} web service(s) (stealth)",
                       phase=Phase.ACTIVE, targets=[t["url"] for t in targets],
                       command="whatweb -a 1 --log-json <out> <url>")]

    def run(self, ctx) -> Iterable:
        out_dir = ctx.raw_dir / "whatweb"
        out_dir.mkdir(parents=True, exist_ok=True)
        for t in web_targets(ctx):
            out_file = out_dir / f"{safe_name(t['url'])}.json"
            res = ctx.executor.run("whatweb", ["-a", "1", "--log-json", str(out_file)],
                                   [t["url"]], module=self.name, phase=Phase.ACTIVE)
            if res.planned or not out_file.exists():
                continue
            try:
                data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            for tech in parse_whatweb(data):
                yield Observation(subject=t["url"], kind="tech", data=tech)


REGISTRY.register(TechModule())
