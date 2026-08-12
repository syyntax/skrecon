"""Store + workspace round-trip (exercises the Phase-0 end-to-end persistence path)."""

from __future__ import annotations

from skrecon.engagement import EngagementMeta
from skrecon.model import Asset, AssetKind, Checkpoint
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
