"""Pure RDAP domain parsing + derived findings (spec §4.3).

`parse_rdap_domain` normalizes an RDAP JSON body; `evaluate_domain` derives expiry
and registrar-lock findings. Both are pure so the date logic is unit-testable
without network. The `whois-rdap` module fetches the JSON and calls these.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class RdapDomain:
    registration: Optional[datetime] = None
    expiration: Optional[datetime] = None
    last_changed: Optional[datetime] = None
    statuses: list[str] = field(default_factory=list)
    registrar: Optional[str] = None
    delegation_signed: Optional[bool] = None


def _parse_dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_rdap_domain(data: dict[str, Any]) -> RdapDomain:
    out = RdapDomain()
    for event in data.get("events", []) or []:
        action = str(event.get("eventAction", "")).lower()
        when = _parse_dt(event.get("eventDate"))
        if action == "registration":
            out.registration = when
        elif action == "expiration":
            out.expiration = when
        elif action in ("last changed", "last update of rdap database"):
            out.last_changed = out.last_changed or when
    out.statuses = [str(s).lower() for s in (data.get("status") or [])]
    secure = data.get("secureDNS") or {}
    if "delegationSigned" in secure:
        out.delegation_signed = bool(secure["delegationSigned"])
    for entity in data.get("entities", []) or []:
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        if "registrar" in roles:
            out.registrar = _vcard_name(entity) or out.registrar
    return out


def _vcard_name(entity: dict[str, Any]) -> Optional[str]:
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "fn":
                return str(item[3])
    except (KeyError, IndexError, TypeError):
        pass
    return None


def evaluate_domain(
    parsed: RdapDomain,
    domain: str,
    *,
    now: Optional[datetime] = None,
    warn_days: int = 60,
) -> list[tuple[str, str, dict[str, object]]]:
    """Return (finding_type, evidence, title_ctx) tuples."""
    now = now or datetime.now(timezone.utc)
    out: list[tuple[str, str, dict[str, object]]] = []

    if parsed.expiration is not None:
        date_str = parsed.expiration.date().isoformat()
        ctx = {"domain": domain, "date": date_str}
        if parsed.expiration < now:
            out.append(("domain.expired", f"expired {date_str}", ctx))
        elif (parsed.expiration - now).days <= warn_days:
            days = (parsed.expiration - now).days
            out.append(("domain.expiring_soon", f"expires in {days} day(s) ({date_str})", ctx))

    if parsed.statuses and not any("transfer prohibited" in s for s in parsed.statuses):
        out.append(("domain.no_registrar_lock",
                    f"status: {', '.join(parsed.statuses)}", {"domain": domain}))

    return out
