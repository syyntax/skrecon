"""Pure TLS-posture evaluation (spec §5.3).

Given the protocol versions a host accepted and its certificate, return
(finding_type, evidence) tuples. No network — the `tls` module probes via
GuardedHttp.probe_tls and calls this.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

_LEGACY = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def evaluate_tls(
    protocols: list[str],
    cert: Optional[dict],
    *,
    now: Optional[datetime] = None,
    expiry_warn_days: int = 30,
) -> list[tuple[str, str]]:
    now = now or datetime.now(timezone.utc)
    out: list[tuple[str, str]] = []

    legacy = [p for p in protocols if p in _LEGACY]
    if legacy:
        out.append(("tls.protocol.legacy", "accepts " + ", ".join(legacy)))

    if cert:
        not_after = _parse_dt(cert.get("not_after"))
        if not_after is not None:
            if not_after < now:
                out.append(("tls.cert.expired", f"expired {not_after.date().isoformat()}"))
            elif (not_after - now).days <= expiry_warn_days:
                out.append(("tls.cert.expiring",
                            f"expires {not_after.date().isoformat()} ({(not_after - now).days}d)"))
        if cert.get("self_signed"):
            out.append(("tls.cert.self_signed", f"issuer == subject: {cert.get('issuer')}"))

    return out
