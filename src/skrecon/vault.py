"""Encrypted-at-rest PII vault (spec §2.6, §9.6).

Breach/credential and persona data are sensitive PII. They are stored here —
encrypted, access-controlled by an operator passphrase, and excluded from report
bodies (reports carry only aggregate counts). At engagement close, or once the
retention window elapses, the vault is purged.

Design:
- Key = scrypt(passphrase, per-vault random salt) -> Fernet (AES128-CBC + HMAC).
- The passphrase comes from SKRECON_VAULT_PASSPHRASE and is NEVER written to disk;
  only the salt and a created-at timestamp live in meta.json.
- If no passphrase is set (or `cryptography` is missing), the vault is unavailable
  and PII-handling modules skip rather than write plaintext. That is the safe default.
- Records are stored per category as a single encrypted blob (decrypt, append,
  re-encrypt) — fine for the modest volumes recon produces.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)


class EncryptedVault:
    def __init__(self, directory: str | Path, passphrase: Optional[str]) -> None:
        self.dir = Path(directory)
        self.passphrase = passphrase or None
        self._fernet = None

    # -- availability ----------------------------------------------------- #
    def available(self) -> bool:
        if not self.passphrase:
            return False
        try:
            import cryptography.fernet  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False

    def unavailable_reason(self) -> Optional[str]:
        if not self.passphrase:
            return "vault locked: set SKRECON_VAULT_PASSPHRASE to store PII encrypted"
        try:
            import cryptography.fernet  # noqa: F401
        except Exception:  # noqa: BLE001
            return "cryptography not installed (pip install '.[vault]')"
        return None

    # -- key / meta ------------------------------------------------------- #
    def _meta_path(self) -> Path:
        return self.dir / "meta.json"

    def _load_meta(self) -> dict[str, Any]:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._meta_path()
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        meta = {"salt": base64.b64encode(os.urandom(16)).decode(),
                "created_at": datetime.now(timezone.utc).isoformat()}
        path.write_text(json.dumps(meta), encoding="utf-8")
        return meta

    def _fernet_cipher(self):
        from cryptography.fernet import Fernet
        if self._fernet is None:
            salt = base64.b64decode(self._load_meta()["salt"])
            dk = hashlib.scrypt(self.passphrase.encode("utf-8"), salt=salt, **_SCRYPT)
            self._fernet = Fernet(base64.urlsafe_b64encode(dk))
        return self._fernet

    # -- storage ---------------------------------------------------------- #
    def _blob_path(self, category: str) -> Path:
        return self.dir / f"{category}.enc"

    def _read(self, category: str) -> list[dict[str, Any]]:
        path = self._blob_path(category)
        if not path.exists():
            return []
        return json.loads(self._fernet_cipher().decrypt(path.read_bytes()).decode("utf-8"))

    def _write(self, category: str, records: list[dict[str, Any]]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        token = self._fernet_cipher().encrypt(json.dumps(records).encode("utf-8"))
        self._blob_path(category).write_bytes(token)

    def add(self, category: str, record: dict[str, Any]) -> str:
        """Append one PII record to a category. Returns a vault reference string."""
        records = self._read(category)
        records.append(record)
        self._write(category, records)
        return f"vault:{category}#{len(records)}"

    def add_many(self, category: str, records: list[dict[str, Any]]) -> int:
        existing = self._read(category)
        existing.extend(records)
        self._write(category, existing)
        return len(records)

    def count(self, category: str) -> int:
        try:
            return len(self._read(category))
        except Exception:  # noqa: BLE001 — a decrypt failure must not crash a run
            return 0

    def has_data(self) -> bool:
        return self.dir.exists() and any(self.dir.glob("*.enc"))

    # -- retention -------------------------------------------------------- #
    def created_at(self) -> Optional[datetime]:
        if not self._meta_path().exists():
            return None
        raw = json.loads(self._meta_path().read_text(encoding="utf-8")).get("created_at")
        return datetime.fromisoformat(raw) if raw else None

    def is_expired(self, retention_days: int, now: Optional[datetime] = None) -> bool:
        created = self.created_at()
        if created is None:
            return False
        now = now or datetime.now(timezone.utc)
        return (now - created).days >= retention_days

    def purge(self) -> list[str]:
        """Securely remove all encrypted PII and the key salt. Irreversible."""
        removed: list[str] = []
        if self.dir.exists():
            for f in list(self.dir.glob("*.enc")) + [self._meta_path()]:
                if f.exists():
                    f.unlink()
                    removed.append(f.name)
        self._fernet = None
        return removed
