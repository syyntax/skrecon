"""Engagement directory layout and (de)serialization (spec §2.5 reproducibility).

Each engagement is a self-contained directory so runs are reproducible, resumable,
and isolated from every other engagement:

    engagements/<id>/
        engagement.json   metadata + blackout windows
        scope.txt         the exact scope this engagement enforces
        skrecon.db        normalized model + checkpoints + audit mirror
        audit.jsonl       append-only evidentiary log
        raw/              preserved native tool output (Phase 1+)
        exports/          JSON export + rendered report (Phase 5)
        vault/            encrypted PII store (Phase 2)
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .engagement import EngagementMeta

ENGAGEMENT_JSON = "engagement.json"
SCOPE_TXT = "scope.txt"
DB_FILE = "skrecon.db"
AUDIT_FILE = "audit.jsonl"


def make_engagement_id(client: str, when: datetime | None = None) -> str:
    when = when or datetime.now(timezone.utc)
    slug = re.sub(r"[^a-z0-9]+", "-", client.lower()).strip("-") or "engagement"
    return f"{slug}-{when:%Y%m%d}-{secrets.token_hex(2)}"


@dataclass
class Workspace:
    root: Path

    @property
    def engagement_json(self) -> Path:
        return self.root / ENGAGEMENT_JSON

    @property
    def scope_txt(self) -> Path:
        return self.root / SCOPE_TXT

    @property
    def db_path(self) -> Path:
        return self.root / DB_FILE

    @property
    def audit_path(self) -> Path:
        return self.root / AUDIT_FILE

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def exports_dir(self) -> Path:
        return self.root / "exports"

    @property
    def vault_dir(self) -> Path:
        return self.root / "vault"

    def exists(self) -> bool:
        return self.engagement_json.exists()

    def create(self) -> "Workspace":
        for d in (self.root, self.raw_dir, self.exports_dir, self.vault_dir):
            d.mkdir(parents=True, exist_ok=True)
        return self

    def write_meta(self, meta: EngagementMeta) -> None:
        self.engagement_json.write_text(
            json.dumps(meta.to_dict(), indent=2), encoding="utf-8"
        )

    def read_meta(self) -> EngagementMeta:
        data = json.loads(self.engagement_json.read_text(encoding="utf-8"))
        return EngagementMeta.from_dict(data)

    def write_scope(self, text: str) -> None:
        self.scope_txt.write_text(text, encoding="utf-8")

    def read_scope_text(self) -> str:
        return self.scope_txt.read_text(encoding="utf-8")


def open_workspace(output_dir: Path, engagement_id: str) -> Workspace:
    return Workspace(root=Path(output_dir) / engagement_id)
