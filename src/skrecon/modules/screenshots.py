"""Web front-page screenshots via gowitness (spec §5.6).

ACTIVE: captures each web app's landing page for triage and the client appendix.
Best-effort wrapper (gowitness CLI varies across versions); records any images it
produces under raw/screenshots/. Skips cleanly when the tool is absent.
"""

from __future__ import annotations

import shutil
from typing import Iterable

from ..model import Observation, Phase
from ..webtargets import web_targets
from .base import REGISTRY, Action, Readiness


class ScreenshotsModule:
    name = "screenshots"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools = ["gowitness"]
    requires_keys: list[str] = []
    depends_on = ["nmap"]
    default_enabled = True

    def preflight(self, ctx) -> Readiness:
        if not shutil.which("gowitness"):
            return Readiness.skip("gowitness not installed (provided by the Docker image)")
        if not web_targets(ctx):
            return Readiness.skip("no web services discovered")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        targets = web_targets(ctx)
        return [Action(description=f"gowitness screenshot {len(targets)} web service(s)",
                       phase=Phase.ACTIVE, targets=[t["url"] for t in targets],
                       command="gowitness single --screenshot-path <out> <url>")]

    def run(self, ctx) -> Iterable:
        out_dir = ctx.raw_dir / "screenshots"
        out_dir.mkdir(parents=True, exist_ok=True)
        for t in web_targets(ctx):
            before = set(out_dir.glob("*.png"))
            res = ctx.executor.run("gowitness", ["single", "--screenshot-path", str(out_dir)],
                                   [t["url"]], module=self.name, phase=Phase.ACTIVE)
            if res.planned:
                continue
            for shot in sorted(set(out_dir.glob("*.png")) - before):
                yield Observation(subject=t["url"], kind="screenshot",
                                  data={"path": str(shot), "url": t["url"]})


REGISTRY.register(ScreenshotsModule())
