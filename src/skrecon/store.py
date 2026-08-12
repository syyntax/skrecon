"""SQLite system-of-record for an engagement (spec §5, §6, §7).

One database file per engagement (`engagements/<id>/skrecon.db`) holds the
normalized model, checkpoints (resumability), and a queryable mirror of the audit
log. Raw tool output is preserved separately on disk; a JSON export mirrors the DB
for downstream tooling. PII (breach/persona plaintext) is NOT stored here — only
aggregate exposure metadata; raw records live in the encrypted vault (Phase 2).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .engagement import EngagementMeta
from .model import Asset, Checkpoint, to_jsonable, utcnow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement (
    id             TEXT PRIMARY KEY,
    client         TEXT NOT NULL,
    auth_ref       TEXT NOT NULL,
    tester         TEXT NOT NULL,
    start_ts       TEXT,
    end_ts         TEXT,
    retention_days INTEGER NOT NULL DEFAULT 90,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_entry   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    normalized  TEXT NOT NULL,
    in_scope    INTEGER NOT NULL DEFAULT 1,
    line_no     INTEGER,
    UNIQUE(kind, normalized)
);

CREATE TABLE IF NOT EXISTS domain (
    fqdn                TEXT PRIMARY KEY,
    registrable_domain  TEXT,
    is_scope            INTEGER NOT NULL DEFAULT 0,
    resolves            INTEGER
);

CREATE TABLE IF NOT EXISTS host_ip (
    ip        TEXT PRIMARY KEY,
    version   INTEGER NOT NULL,
    asn       INTEGER,
    netblock  TEXT,
    ptr       TEXT,
    in_scope  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS service (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip  TEXT NOT NULL,
    port     INTEGER NOT NULL,
    proto    TEXT NOT NULL DEFAULT 'tcp',
    state    TEXT NOT NULL DEFAULT 'open',
    product  TEXT,
    version  TEXT,
    source   TEXT NOT NULL,
    UNIQUE(host_ip, port, proto)
);

CREATE TABLE IF NOT EXISTS finding (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_type   TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    source_module  TEXT NOT NULL,
    phase          TEXT NOT NULL,
    affected       TEXT,             -- json array
    evidence       TEXT,             -- json array
    remediation    TEXT
);

-- Aggregate exposure metadata only. NO plaintext credentials here.
CREATE TABLE IF NOT EXISTS exposure (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT NOT NULL,
    breach_source TEXT NOT NULL,
    record_count  INTEGER NOT NULL DEFAULT 0,
    fmt           TEXT NOT NULL DEFAULT 'unknown',
    vault_ref     TEXT
);

CREATE TABLE IF NOT EXISTS checkpoint (
    module      TEXT NOT NULL,
    input_hash  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    started_at  TEXT,
    finished_at TEXT,
    PRIMARY KEY (module, input_hash)
);

CREATE TABLE IF NOT EXISTS audit_event (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    module   TEXT NOT NULL,
    action   TEXT NOT NULL,
    outcome  TEXT NOT NULL,
    phase    TEXT,
    target   TEXT,
    command  TEXT,
    detail   TEXT
);
"""


class EngagementStore:
    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "EngagementStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- engagement ------------------------------------------------------- #
    def upsert_engagement(self, meta: EngagementMeta) -> None:
        rec = meta.to_record()
        self.conn.execute(
            """INSERT INTO engagement (id, client, auth_ref, tester, start_ts, end_ts,
                                       retention_days, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   client=excluded.client, auth_ref=excluded.auth_ref,
                   tester=excluded.tester, start_ts=excluded.start_ts,
                   end_ts=excluded.end_ts, retention_days=excluded.retention_days""",
            (
                rec.id, rec.client, rec.auth_ref, rec.tester,
                rec.start.isoformat() if rec.start else None,
                rec.end.isoformat() if rec.end else None,
                rec.retention_days, rec.created_at.isoformat(),
            ),
        )
        self.conn.commit()

    def get_engagement(self) -> Optional[dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM engagement LIMIT 1").fetchone()
        return dict(row) if row else None

    # -- assets ----------------------------------------------------------- #
    def add_assets(self, assets: list[Asset]) -> int:
        n = 0
        for a in assets:
            cur = self.conn.execute(
                """INSERT OR IGNORE INTO asset (raw_entry, kind, normalized, in_scope, line_no)
                   VALUES (?, ?, ?, ?, ?)""",
                (a.raw_entry, a.kind.value, a.normalized, int(a.in_scope), a.line_no),
            )
            n += cur.rowcount
        self.conn.commit()
        return n

    def list_assets(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM asset ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # -- checkpoints ------------------------------------------------------ #
    def set_checkpoint(self, cp: Checkpoint) -> None:
        self.conn.execute(
            """INSERT INTO checkpoint (module, input_hash, status, started_at, finished_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(module, input_hash) DO UPDATE SET
                   status=excluded.status, started_at=excluded.started_at,
                   finished_at=excluded.finished_at""",
            (
                cp.module, cp.input_hash, cp.status,
                cp.started_at.isoformat() if cp.started_at else None,
                cp.finished_at.isoformat() if cp.finished_at else None,
            ),
        )
        self.conn.commit()

    def get_checkpoint(self, module: str, input_hash: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM checkpoint WHERE module=? AND input_hash=?",
            (module, input_hash),
        ).fetchone()
        return dict(row) if row else None

    def is_done(self, module: str, input_hash: str) -> bool:
        cp = self.get_checkpoint(module, input_hash)
        return bool(cp and cp["status"] == "done")

    # -- audit mirror ----------------------------------------------------- #
    def add_audit_event(self, event: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO audit_event (ts, module, action, outcome, phase, target, command, detail)
               VALUES (:ts, :module, :action, :outcome, :phase, :target, :command, :detail)""",
            {
                "ts": event.get("ts", utcnow().isoformat()),
                "module": event.get("module"),
                "action": event.get("action"),
                "outcome": event.get("outcome"),
                "phase": event.get("phase"),
                "target": event.get("target"),
                "command": event.get("command"),
                "detail": event.get("detail"),
            },
        )
        self.conn.commit()

    def count_audit_events(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM audit_event").fetchone()[0])

    # -- export ----------------------------------------------------------- #
    def export_json(self, path: str | Path) -> Path:
        out = Path(path)
        data = {
            "engagement": self.get_engagement(),
            "assets": self.list_assets(),
            "checkpoints": [dict(r) for r in
                            self.conn.execute("SELECT * FROM checkpoint").fetchall()],
            "counts": {
                "assets": len(self.list_assets()),
                "audit_events": self.count_audit_events(),
            },
            "exported_at": utcnow().isoformat(),
        }
        out.write_text(json.dumps(to_jsonable(data), indent=2), encoding="utf-8")
        return out
