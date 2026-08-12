"""Store + workspace round-trip (exercises the Phase-0 end-to-end persistence path)."""

from __future__ import annotations

from datetime import datetime, timezone

from skrecon.engagement import EngagementMeta
from skrecon.findings import make_finding
from skrecon.model import (
    Asset, AssetKind, Certificate, CertSource, Checkpoint, DnsRecord,
    Exposure, ExposureFormat, HostIP,
)
from skrecon.store import EngagementStore
from skrecon.workspace import Workspace, make_engagement_id


def test_make_engagement_id_shape():
    eid = make_engagement_id("Example Corp!!")
    assert eid.startswith("example-corp-")
    assert len(eid.split("-")) >= 3


def test_workspace_meta_roundtrip(tmp_path):
    ws = Workspace(tmp_path / "eng").create()
    meta = EngagementMeta.from_dict(
        {"id": "e1", "client": "C", "auth_ref": "T-9", "tester": "alice",
         "blackout": [{"daily_start": "22:00", "daily_end": "06:00"}]}
    )
    ws.write_meta(meta)
    m2 = ws.read_meta()
    assert m2.client == "C"
    assert len(m2.blackout_windows) == 1


def test_store_assets_checkpoints_export(tmp_path):
    ws = Workspace(tmp_path / "eng").create()
    meta = EngagementMeta.from_dict(
        {"id": "e1", "client": "C", "auth_ref": "T-9", "tester": "alice"}
    )
    with EngagementStore(ws.db_path) as store:
        store.upsert_engagement(meta)
        added = store.add_assets([Asset("example.com", AssetKind.HOSTNAME, "example.com")])
        assert added == 1
        # UNIQUE(kind, normalized) means a re-add is a no-op.
        assert store.add_assets([Asset("example.com", AssetKind.HOSTNAME, "example.com")]) == 0

        store.set_checkpoint(Checkpoint("dns", "h1", status="done"))
        assert store.is_done("dns", "h1")
        assert not store.is_done("dns", "other")

        assert store.get_engagement()["client"] == "C"
        out = store.export_json(ws.exports_dir / "e.json")
        assert out.exists()


def test_persist_dedups_and_upserts(tmp_path):
    with EngagementStore(tmp_path / "s.db") as store:
        f = make_finding("mail.dmarc.missing", affected=["example.com"], evidence=["x"],
                         source_module="mail", title_ctx={"domain": "example.com"})
        store.persist(f)
        store.persist(f)                                   # identical finding -> deduped
        assert store.counts()["finding"] == 1

        store.persist(HostIP(ip="203.0.113.5", version=4, in_scope=True))
        store.persist(HostIP(ip="203.0.113.5", version=4, ptr="host.example.com", in_scope=True))
        hosts = store.list_hosts()
        assert len(hosts) == 1 and hosts[0]["ptr"] == "host.example.com"   # upsert merged

        store.persist(DnsRecord(domain="example.com", rtype="A", value="203.0.113.5"))
        store.persist(DnsRecord(domain="example.com", rtype="A", value="203.0.113.5"))
        assert store.counts()["dns_record"] == 1


def test_persist_certificates_and_exposures(tmp_path):
    not_after = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with EngagementStore(tmp_path / "s.db") as store:
        store.persist(Certificate(subject="www.example.com", issuer="LE",
                                  sans=["www.example.com"], not_after=not_after, source=CertSource.CT))
        store.persist(Certificate(subject="www.example.com", issuer="LE",
                                  sans=["www.example.com"], not_after=not_after, source=CertSource.CT))
        assert store.counts()["certificate"] == 1        # deduped

        # Exposure carries counts only; re-run upserts the count, never duplicates.
        store.persist(Exposure(client_id="example.com", breach_source="BreachA",
                               record_count=5, fmt=ExposureFormat.PLAINTEXT, vault_ref="vault:breach"))
        store.persist(Exposure(client_id="example.com", breach_source="BreachA",
                               record_count=9, fmt=ExposureFormat.PLAINTEXT, vault_ref="vault:breach"))
        exposures = store.list_exposures()
        assert len(exposures) == 1 and exposures[0]["record_count"] == 9
