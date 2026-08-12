"""Encrypted PII vault (spec §2.6, §9.6): encryption-at-rest, access control, purge."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from skrecon.vault import EncryptedVault  # noqa: E402


def test_locked_without_passphrase(tmp_path):
    v = EncryptedVault(tmp_path / "vault", None)
    assert not v.available()
    assert "SKRECON_VAULT_PASSPHRASE" in v.unavailable_reason()


def test_roundtrip_and_encrypted_at_rest(tmp_path):
    v = EncryptedVault(tmp_path / "vault", "correct horse battery")
    assert v.available()
    v.add("breach", {"email": "victim@example.com", "password": "hunter2"})
    v.add_many("breach", [{"email": "a@b.c"}])
    assert v.count("breach") == 2

    # The on-disk blob must not contain the plaintext PII.
    blob = (tmp_path / "vault" / "breach.enc").read_bytes()
    assert b"victim@example.com" not in blob
    assert b"hunter2" not in blob

    # A fresh handle with the same passphrase decrypts it.
    assert EncryptedVault(tmp_path / "vault", "correct horse battery").count("breach") == 2


def test_wrong_passphrase_cannot_read(tmp_path):
    EncryptedVault(tmp_path / "vault", "right-key").add("breach", {"x": 1})
    # Wrong passphrase: decrypt fails -> count degrades to 0, never crashes.
    assert EncryptedVault(tmp_path / "vault", "wrong-key").count("breach") == 0


def test_retention_and_purge(tmp_path):
    v = EncryptedVault(tmp_path / "vault", "pw")
    v.add("breach", {"x": 1})
    assert v.has_data()
    assert not v.is_expired(90)

    # Age the vault past the retention window.
    meta_path = tmp_path / "vault" / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["created_at"] = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    meta_path.write_text(json.dumps(meta))
    assert v.is_expired(90)

    removed = v.purge()
    assert removed and not v.has_data()
