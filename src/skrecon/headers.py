"""Pure HTTP security-header evaluation (spec §5.4).

Takes a response's headers (and Set-Cookie list) and returns (finding_type,
evidence) tuples. No network — the `headers` module fetches via GuardedHttp and
calls this.
"""

from __future__ import annotations

from typing import Iterable

# header (lowercased) -> finding_type emitted when absent
_REQUIRED = {
    "strict-transport-security": "http.header.hsts.missing",
    "content-security-policy": "http.header.csp.missing",
    "x-frame-options": "http.header.xfo.missing",
    "x-content-type-options": "http.header.xcto.missing",
    "referrer-policy": "http.header.referrer.missing",
    "permissions-policy": "http.header.permissions.missing",
}


def evaluate_headers(
    headers: dict[str, str],
    cookies: Iterable[str] = (),
) -> list[tuple[str, str]]:
    lower = {k.lower(): v for k, v in headers.items()}
    out: list[tuple[str, str]] = []

    for header, finding_type in _REQUIRED.items():
        if header not in lower:
            out.append((finding_type, f"missing {header}"))

    # X-Content-Type-Options present but not 'nosniff' is still a gap.
    xcto = lower.get("x-content-type-options", "")
    if xcto and xcto.strip().lower() != "nosniff":
        out.append(("http.header.xcto.missing", f"x-content-type-options: {xcto!r} (want nosniff)"))

    for raw in cookies:
        missing = _cookie_missing_flags(raw)
        if missing:
            name = raw.split("=", 1)[0].strip()
            out.append(("http.cookie.insecure", f"cookie {name!r} missing: {', '.join(missing)}"))

    return out


def _cookie_missing_flags(set_cookie: str) -> list[str]:
    low = set_cookie.lower()
    missing = []
    if "secure" not in low:
        missing.append("Secure")
    if "httponly" not in low:
        missing.append("HttpOnly")
    if "samesite" not in low:
        missing.append("SameSite")
    return missing
