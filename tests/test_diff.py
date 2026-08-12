"""Run-delta comparison (spec §7)."""

from __future__ import annotations

from skrecon.diff import diff_engagements
from skrecon.findings import make_finding
from skrecon.model import HostIP, Service, ServiceSource
from skrecon.store import EngagementStore


def test_diff_surfaces_new_hosts_services_findings(tmp_path):
    old = EngagementStore(tmp_path / "old.db")
    new = EngagementStore(tmp_path / "new.db")

    for store in (old, new):
        store.persist(HostIP(ip="203.0.113.5", version=4, in_scope=True))
        store.persist(Service(host_ip="203.0.113.5", port=443, proto="tcp", source=ServiceSource.NMAP))

    # The retest finds a new host, a new service, and a new finding.
    new.persist(HostIP(ip="203.0.113.6", version=4, in_scope=True))
    new.persist(Service(host_ip="203.0.113.6", port=22, proto="tcp", source=ServiceSource.NMAP))
    new.persist(make_finding("tls.cert.expired", affected=["https://203.0.113.6:443"],
                             evidence=["expired"], source_module="tls",
                             title_ctx={"url": "https://203.0.113.6:443"}))

    delta = diff_engagements(old, new)
    assert "203.0.113.6" in delta["new_hosts"]
    assert "203.0.113.6:22/tcp" in delta["new_services"]
    assert any("certificate expired" in t.lower() for t in delta["new_findings"])
    assert delta["removed_hosts"] == []
