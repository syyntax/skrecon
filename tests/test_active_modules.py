"""Active-module glue: executor result -> raw file -> parser -> Service records.

Uses a fake executor (no real masscan/nmap) that writes canned tool output, so the
module orchestration is tested end-to-end without the binaries. This is what caught
the nmap output-path bug (with_suffix vs. an IP ending in a numeric octet)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from skrecon.audit import AuditLog
from skrecon.config import Settings
from skrecon.guard import ExecResult
from skrecon.model import Phase, Service, ServiceSource
from skrecon.modules.masscan_scan import MasscanModule
from skrecon.modules.nmap_scan import NmapModule
from skrecon.scope import parse_scope_text
from skrecon.store import EngagementStore

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="95"/></os>
  </host>
</nmaprun>
"""


def make_ctx(tmp_path, scope_text, executor):
    return SimpleNamespace(
        scope=parse_scope_text(scope_text).scope,
        store=EngagementStore(tmp_path / "s.db"),
        settings=Settings(),
        raw_dir=tmp_path / "raw",
        executor=executor,
        audit=AuditLog(path=None),
    )


class MasscanFakeExec:
    """Writes a canned masscan -oL file to the path following -oL."""
    def run(self, tool, args, targets, *, module, phase, **kw):
        out = Path(args[args.index("-oL") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("open tcp 80 203.0.113.5 0\nopen tcp 443 203.0.113.5 0\n")
        return ExecResult(tool=tool, argv=[tool], planned=False, returncode=0,
                          allowed_targets=list(targets))


class NmapFakeExec:
    """Writes canned nmap XML to '<prefix>.xml' (the path following -oA)."""
    def run(self, tool, args, targets, *, module, phase, **kw):
        prefix = args[args.index("-oA") + 1]
        Path(prefix).parent.mkdir(parents=True, exist_ok=True)
        Path(prefix + ".xml").write_text(NMAP_XML)
        return ExecResult(tool=tool, argv=[tool], planned=False, returncode=0,
                          allowed_targets=list(targets))


def test_masscan_module_yields_open_services(tmp_path):
    ctx = make_ctx(tmp_path, "203.0.113.0/28\n", MasscanFakeExec())
    services = [r for r in MasscanModule().run(ctx) if isinstance(r, Service)]
    assert {s.port for s in services} == {80, 443}
    assert all(s.source is ServiceSource.MASSCAN and s.host_ip == "203.0.113.5" for s in services)


def test_nmap_module_reads_xml_for_ip_with_numeric_octet(tmp_path):
    ctx = make_ctx(tmp_path, "203.0.113.0/28\n", NmapFakeExec())
    # Seed a masscan-discovered open port so nmap has a host+port to enumerate.
    ctx.store.persist(Service(host_ip="203.0.113.5", port=80, proto="tcp",
                              state="open", source=ServiceSource.MASSCAN))
    records = list(NmapModule().run(ctx))
    services = [r for r in records if isinstance(r, Service) and r.source is ServiceSource.NMAP]
    assert any(s.product == "nginx" and s.version == "1.18.0" for s in services)
