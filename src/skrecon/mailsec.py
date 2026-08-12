"""Pure evaluators for mail-security posture (spec §4.2).

These take raw DNS TXT strings and return (finding_type, evidence) tuples. Keeping
them pure (no DNS/network) makes the phishing-relevant logic — SPF strength, DMARC
policy — exhaustively unit-testable. The `mail` module does the DNS lookups and
calls these.
"""

from __future__ import annotations

from typing import Optional

# Mechanisms that consume one of SPF's 10-lookup budget (RFC 7208 §4.6.4).
_SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def _find_record(txts: list[str], prefix: str) -> Optional[str]:
    for t in txts:
        if t.strip().lower().startswith(prefix):
            return t.strip()
    return None


def parse_tags(record: str) -> dict[str, str]:
    """Parse a 'k=v; k=v' style record (DMARC/BIMI/etc.) into a dict."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def count_spf_lookups(spf_record: str) -> int:
    n = 0
    for tok in spf_record.lower().split():
        mech = tok.lstrip("+-~?")
        name = mech.split(":")[0].split("=")[0]
        if name in _SPF_LOOKUP_MECHANISMS:
            n += 1
    return n


def evaluate_spf(txts: list[str]) -> list[tuple[str, str]]:
    spf = _find_record(txts, "v=spf1")
    if spf is None:
        return [("mail.spf.missing", "no v=spf1 TXT record")]
    low = spf.lower()
    out: list[tuple[str, str]] = []
    if "+all" in low:
        out.append(("mail.spf.passall", spf))
    elif "-all" in low:
        pass  # hard fail — the strong, recommended posture
    elif "~all" in low or "?all" in low:
        out.append(("mail.spf.softfail", spf))
    lookups = count_spf_lookups(spf)
    if lookups > 10:
        out.append(("mail.spf.lookups_high", f"{spf}  (~{lookups} DNS-lookup mechanisms)"))
    return out


def evaluate_dmarc(txts: list[str]) -> list[tuple[str, str]]:
    rec = _find_record(txts, "v=dmarc1")
    if rec is None:
        return [("mail.dmarc.missing", "no v=DMARC1 TXT record")]
    tags = parse_tags(rec)
    out: list[tuple[str, str]] = []
    policy = tags.get("p", "").lower()
    if policy == "none":
        out.append(("mail.dmarc.policy_none", rec))
    if "rua" not in tags:
        out.append(("mail.dmarc.no_rua", rec))
    return out
