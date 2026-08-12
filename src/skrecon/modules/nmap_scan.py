"""Active service/OS detection via nmap (spec §5.2).

Runs nmap only against the ports masscan found open, per host, for service/version
detection (-sV) and OS fingerprinting (-O). Output is written in all formats via
-oA (raw preserved) and the XML is ingested into normalized Service records
(source=nmap, i.e. tester-confirmed). ACTIVE: every target is guard-validated.
"""

from __future__ import annotations

import shutil
from typing import Iterable

from ..model import Observation, Phase, Service, ServiceSource
from ..scanparse import parse_nmap_xml
from .base import REGISTRY, Action, Readiness


class NmapModule:
    name = "nmap"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools = ["nmap"]
    requires_keys: list[str] = []
    depends_on = ["masscan"]
    default_enabled = True

    def _open_by_host(self, ctx) -> dict[str, list[int]]:
        by_host: dict[str, list[int]] = {}
        for s in ctx.store.list_services(source="masscan"):
            by_host.setdefault(s["host_ip"], [])
            if s["port"] not in by_host[s["host_ip"]]:
                by_host[s["host_ip"]].append(s["port"])
        return by_host

    def preflight(self, ctx) -> Readiness:
        if not shutil.which("nmap"):
            return Readiness.skip("nmap not installed (provided by the Docker image)")
        if not self._open_by_host(ctx):
            return Readiness.skip("no masscan-discovered open ports to enumerate")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        by_host = self._open_by_host(ctx)
        timing = ctx.settings.rates.nmap_timing
        return [Action(
            description=f"nmap -sV -O ({timing}) against {len(by_host)} host(s) on masscan-open ports",
            phase=Phase.ACTIVE, targets=sorted(by_host),
            command="nmap -sV -O -Pn -<timing> -oA <raw>/nmap/<ip> -p <ports> <ip>")]

    def run(self, ctx) -> Iterable:
        by_host = self._open_by_host(ctx)
        timing = ctx.settings.rates.nmap_timing
        out_dir = ctx.raw_dir / "nmap"
        out_dir.mkdir(parents=True, exist_ok=True)

        for ip, ports in by_host.items():
            ports_csv = ",".join(str(p) for p in sorted(ports))
            prefix = out_dir / ip.replace(":", "_")
            res = ctx.executor.run(
                "nmap",
                ["-sV", "-O", "-Pn", f"-{timing}", "-oA", str(prefix), "-p", ports_csv],
                [ip], module=self.name, phase=Phase.ACTIVE,
            )
            # nmap -oA writes "<prefix>.xml" literally; with_suffix would wrongly
            # treat the ".5" in an IP like 203.0.113.5 as the suffix to replace.
            xml_path = prefix.with_name(prefix.name + ".xml")
            if res.planned or not xml_path.exists():
                continue

            for host in parse_nmap_xml(xml_path.read_text(encoding="utf-8", errors="replace")):
                if host.get("os"):
                    yield Observation(subject=host["ip"], kind="os", data={"os": host["os"]})
                for svc in host["services"]:
                    if svc["port"] is None:
                        continue
                    yield Service(host_ip=host["ip"], port=svc["port"], proto=svc["proto"],
                                  state=svc["state"] or "open", product=svc["product"],
                                  version=svc["version"], source=ServiceSource.NMAP)

        yield Observation(subject="nmap", kind="summary", data={"hosts": len(by_host)})


REGISTRY.register(NmapModule())
