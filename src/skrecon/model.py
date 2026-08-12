"""Normalized data model (spec §5).

Heterogeneous tool output is mapped onto these entities so it correlates into one
graph. These are plain dataclasses + enums (stdlib only); the SQLite store
(`skrecon.store`) persists them and the reporters render them.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Phase(str, enum.Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AssetKind(str, enum.Enum):
    DOMAIN = "domain"        # a listed registrable/parent domain
    HOSTNAME = "hostname"    # a specific host
    IP = "ip"                # single address
    CIDR = "cidr"            # network range
    URL = "url"              # scheme://host[/path]


class ServiceSource(str, enum.Enum):
    MASSCAN = "masscan"      # tester-confirmed (active)
    NMAP = "nmap"            # tester-confirmed (active)
    SHODAN = "shodan"        # third-party-observed (passive)
    CENSYS = "censys"        # third-party-observed (passive)


class CertSource(str, enum.Enum):
    CT = "ct"                # certificate transparency log (passive)
    TLS = "tls"              # observed on the wire (active)


class ExposureFormat(str, enum.Enum):
    PLAINTEXT = "plaintext"
    HASHED = "hashed"
    UNKNOWN = "unknown"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Core entities (spec §5.1)
# --------------------------------------------------------------------------- #
@dataclass
class Engagement:
    id: str
    client: str
    auth_ref: str                         # authorization / ticket reference
    tester: str
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    retention_days: int = 90
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class Asset:
    """One normalized entry derived from a scope.txt line."""
    raw_entry: str
    kind: AssetKind
    normalized: str                       # hostname or network string
    in_scope: bool = True
    line_no: Optional[int] = None


@dataclass
class DomainName:
    fqdn: str
    registrable_domain: Optional[str] = None
    is_scope: bool = False
    resolves: Optional[bool] = None


@dataclass
class HostIP:
    ip: str
    version: int                          # 4 or 6
    asn: Optional[int] = None
    netblock: Optional[str] = None
    ptr: Optional[str] = None
    in_scope: bool = False


@dataclass
class DnsRecord:
    domain: str
    rtype: str                            # A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, PTR
    value: str


@dataclass
class ResolutionEdge:
    """Part of the domain -> CNAME -> IP chain, kept for correlation."""
    src: str
    via: Optional[str]                    # intermediate CNAME, if any
    dst: str                              # terminal IP or name


@dataclass
class Service:
    host_ip: str
    port: int
    proto: str = "tcp"                    # tcp | udp
    state: str = "open"
    product: Optional[str] = None
    version: Optional[str] = None
    source: ServiceSource = ServiceSource.NMAP


@dataclass
class Certificate:
    subject: str
    issuer: Optional[str] = None
    sans: list[str] = field(default_factory=list)   # another subdomain source
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    self_signed: bool = False
    source: CertSource = CertSource.CT


@dataclass
class Finding:
    """The core report unit (spec §7). `finding_type` is a stable catalog key."""
    finding_type: str                     # e.g. "mail.dmarc.missing"
    title: str
    severity: Severity
    source_module: str
    affected: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    remediation: Optional[str] = None
    phase: Phase = Phase.PASSIVE


@dataclass
class Exposure:
    """Breach/credential record — PII. Stored in the encrypted vault only; reports
    carry aggregate counts, never plaintext (spec §4.9, §9.6)."""
    client_id: str
    breach_source: str
    record_count: int = 0
    fmt: ExposureFormat = ExposureFormat.UNKNOWN
    vault_ref: Optional[str] = None       # pointer into the encrypted store


@dataclass
class Persona:
    """Harvested employee/email — PII, minimized and handled like Exposure."""
    name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    source: Optional[str] = None
    vault_ref: Optional[str] = None


@dataclass
class Screenshot:
    service: str                          # host:port reference
    full_path: str
    thumb_path: Optional[str] = None


@dataclass
class Observation:
    """A normalized fact that is not itself a finding (banner, header, SPF text)."""
    subject: str
    kind: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEvent:
    ts: datetime
    module: str
    action: str
    outcome: str
    phase: Optional[Phase] = None
    target: Optional[str] = None
    command: Optional[str] = None         # redacted before storage
    detail: Optional[str] = None


@dataclass
class Checkpoint:
    module: str
    input_hash: str
    status: str = "pending"               # pending | running | done | failed
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


# --------------------------------------------------------------------------- #
# Serialization helper
# --------------------------------------------------------------------------- #
def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses/enums/datetimes into JSON-safe values."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    return obj
