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
from .model import (
    Asset,
    Certificate,
    Checkpoint,
    DnsRecord,
    DomainName,
    Exposure,
    Finding,
    HostIP,
    Observation,
    ResolutionEdge,
    Service,
    to_jsonable,
    utcnow,
)

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
    remediation    TEXT,
    dedup          TEXT UNIQUE       -- finding_type + sorted(affected); idempotent re-runs
);

-- Aggregate exposure metadata only. NO plaintext credentials here.
CREATE TABLE IF NOT EXISTS exposure (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT NOT NULL,
    breach_source TEXT NOT NULL,
    record_count  INTEGER NOT NULL DEFAULT 0,
    fmt           TEXT NOT NULL DEFAULT 'unknown',
    vault_ref     TEXT,
    UNIQUE(client_id, breach_source)
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

CREATE TABLE IF NOT EXISTS dns_record (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain  TEXT NOT NULL,
    rtype   TEXT NOT NULL,
    value   TEXT NOT NULL,
    UNIQUE(domain, rtype, value)
);

CREATE TABLE IF NOT EXISTS resolution_edge (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    src  TEXT NOT NULL,
    via  TEXT,
    dst  TEXT NOT NULL,
    UNIQUE(src, via, dst)
);

CREATE TABLE IF NOT EXISTS observation (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    subject  TEXT NOT NULL,
    kind     TEXT NOT NULL,
    data     TEXT
);

CREATE TABLE IF NOT EXISTS certificate (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    subject      TEXT,
    issuer       TEXT,
    sans         TEXT,             -- json array (another subdomain source)
    not_before   TEXT,
    not_after    TEXT,
    self_signed  INTEGER NOT NULL DEFAULT 0,
    source       TEXT NOT NULL,
    UNIQUE(subject, issuer, not_after, source)
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

    # -- normalized records (Phase 1+) ------------------------------------ #
    def persist(self, record: object) -> None:
        """Dispatch a yielded model record to the right table."""
        if isinstance(record, Finding):
            self.add_finding(record)
        elif isinstance(record, DomainName):
            self.upsert_domain(record)
        elif isinstance(record, HostIP):
            self.upsert_host(record)
        elif isinstance(record, DnsRecord):
            self.add_dns_record(record)
        elif isinstance(record, ResolutionEdge):
            self.add_resolution_edge(record)
        elif isinstance(record, Observation):
            self.add_observation(record)
        elif isinstance(record, Service):
            self.add_service(record)
        elif isinstance(record, Certificate):
            self.add_certificate(record)
        elif isinstance(record, Exposure):
            self.add_exposure(record)
        else:
            raise TypeError(f"cannot persist record of type {type(record).__name__}")

    def add_finding(self, f: Finding) -> int:
        dedup = f.finding_type + "|" + ",".join(sorted(f.affected))
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO finding
               (finding_type, title, severity, source_module, phase, affected, evidence, remediation, dedup)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (f.finding_type, f.title, f.severity.value, f.source_module, f.phase.value,
             json.dumps(f.affected), json.dumps(f.evidence), f.remediation, dedup),
        )
        self.conn.commit()
        return cur.rowcount

    def upsert_domain(self, d: DomainName) -> None:
        self.conn.execute(
            """INSERT INTO domain (fqdn, registrable_domain, is_scope, resolves)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(fqdn) DO UPDATE SET
                   registrable_domain=COALESCE(excluded.registrable_domain, domain.registrable_domain),
                   is_scope=excluded.is_scope,
                   resolves=COALESCE(excluded.resolves, domain.resolves)""",
            (d.fqdn, d.registrable_domain, int(d.is_scope),
             None if d.resolves is None else int(d.resolves)),
        )
        self.conn.commit()

    def upsert_host(self, h: HostIP) -> None:
        self.conn.execute(
            """INSERT INTO host_ip (ip, version, asn, netblock, ptr, in_scope)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                   asn=COALESCE(excluded.asn, host_ip.asn),
                   netblock=COALESCE(excluded.netblock, host_ip.netblock),
                   ptr=COALESCE(excluded.ptr, host_ip.ptr),
                   in_scope=excluded.in_scope""",
            (h.ip, h.version, h.asn, h.netblock, h.ptr, int(h.in_scope)),
        )
        self.conn.commit()

    def add_dns_record(self, r: DnsRecord) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO dns_record (domain, rtype, value) VALUES (?, ?, ?)",
            (r.domain, r.rtype, r.value),
        )
        self.conn.commit()

    def add_resolution_edge(self, e: ResolutionEdge) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO resolution_edge (src, via, dst) VALUES (?, ?, ?)",
            (e.src, e.via, e.dst),
        )
        self.conn.commit()

    def add_observation(self, o: Observation) -> None:
        self.conn.execute(
            "INSERT INTO observation (subject, kind, data) VALUES (?, ?, ?)",
            (o.subject, o.kind, json.dumps(to_jsonable(o.data))),
        )
        self.conn.commit()

    def add_service(self, s: Service) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO service (host_ip, port, proto, state, product, version, source)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (s.host_ip, s.port, s.proto, s.state, s.product, s.version, s.source.value),
        )
        self.conn.commit()

    def add_certificate(self, c: Certificate) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO certificate
               (subject, issuer, sans, not_before, not_after, self_signed, source)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (c.subject, c.issuer, json.dumps(c.sans),
             c.not_before.isoformat() if c.not_before else None,
             c.not_after.isoformat() if c.not_after else None,
             int(c.self_signed), c.source.value),
        )
        self.conn.commit()

    def add_exposure(self, e: Exposure) -> None:
        # One row per (client, source); a re-run replaces the count.
        self.conn.execute(
            """INSERT INTO exposure (client_id, breach_source, record_count, fmt, vault_ref)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(client_id, breach_source) DO UPDATE SET
                   record_count=excluded.record_count, fmt=excluded.fmt,
                   vault_ref=excluded.vault_ref""",
            (e.client_id, e.breach_source, e.record_count, e.fmt.value, e.vault_ref),
        )
        self.conn.commit()

    # -- queries ---------------------------------------------------------- #
    def list_findings(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM finding ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, finding_type"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["affected"] = json.loads(d["affected"] or "[]")
            d["evidence"] = json.loads(d["evidence"] or "[]")
            out.append(d)
        return out

    def list_hosts(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM host_ip ORDER BY ip").fetchall()]

    def list_domains(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM domain ORDER BY fqdn").fetchall()]

    def list_certificates(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM certificate ORDER BY not_after DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["sans"] = json.loads(d["sans"] or "[]")
            out.append(d)
        return out

    def list_exposures(self) -> list[dict[str, Any]]:
        return [dict(r) for r in
                self.conn.execute("SELECT * FROM exposure ORDER BY record_count DESC").fetchall()]

    def counts(self) -> dict[str, int]:
        tables = ("asset", "domain", "host_ip", "service", "finding", "certificate",
                  "exposure", "dns_record", "observation", "audit_event")
        return {
            t: int(self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
            for t in tables
        }

    # -- export ----------------------------------------------------------- #
    def export_json(self, path: str | Path) -> Path:
        out = Path(path)
        data = {
            "engagement": self.get_engagement(),
            "assets": self.list_assets(),
            "domains": self.list_domains(),
            "hosts": self.list_hosts(),
            "certificates": self.list_certificates(),
            "exposures": self.list_exposures(),   # counts only — no plaintext PII
            "findings": self.list_findings(),
            "checkpoints": [dict(r) for r in
                            self.conn.execute("SELECT * FROM checkpoint").fetchall()],
            "counts": self.counts(),
            "exported_at": utcnow().isoformat(),
        }
        out.write_text(json.dumps(to_jsonable(data), indent=2), encoding="utf-8")
        return out
