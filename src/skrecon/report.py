"""Report generation (spec §7): one data model -> Markdown (canonical) + HTML.

Reads only the engagement store, which by construction holds no plaintext PII
(breach/persona raw data stays in the encrypted vault; only aggregate counts reach
here). Structure follows PTES reconnaissance phases. Rendering is stdlib-only string
building — the report layout is fixed, so no template engine is pulled in.
"""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from typing import Any

from .model import utcnow
from .store import EngagementStore

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

CATEGORY_LABELS = {
    "dns": "DNS & DNSSEC",
    "domain": "Domain Registration (WHOIS/RDAP)",
    "mail": "Mail Security Posture",
    "exposure": "Breach & Credential Exposure",
    "shodan": "Internet Exposure (Shodan)",
    "typosquat": "Typosquatting / Brand Abuse",
    "tls": "TLS/SSL",
    "http": "HTTP Security Headers",
    "waf": "Web Application Firewall",
    "nuclei": "Templated Vulnerabilities (nuclei)",
}

SEV_COLORS = {
    "critical": "#7c1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#2563eb", "info": "#4b5563",
}


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
def build_report_model(store: EngagementStore) -> dict[str, Any]:
    findings = store.list_findings()          # already severity-sorted
    domains = store.list_domains()
    by_cat: dict[str, list] = defaultdict(list)
    for f in findings:
        by_cat[f["finding_type"].split(".")[0]].append(f)
    sev_counts = Counter(f["severity"] for f in findings)

    return {
        "engagement": store.get_engagement() or {},
        "generated_at": utcnow().isoformat(timespec="seconds"),
        "counts": store.counts(),
        "severity_counts": {s: sev_counts.get(s, 0) for s in SEVERITY_ORDER},
        "findings": findings,
        "findings_by_category": dict(by_cat),
        "top_findings": [f for f in findings if f["severity"] in ("critical", "high")][:10],
        "in_scope_domains": [d for d in domains if d["is_scope"]],
        "discovered_subdomains": [d for d in domains if not d["is_scope"]],
        "hosts": store.list_hosts(),
        "services": store.list_services(),
        "certificates": store.list_certificates(),
        "exposures": store.list_exposures(),
        "screenshots": store.list_observations("screenshot"),
    }


def _sev_sorted(findings: list) -> list:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f["severity"])
                 if f["severity"] in SEVERITY_ORDER else 99)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def render_markdown(model: dict[str, Any]) -> str:
    eng = model["engagement"]
    out: list[str] = []
    w = out.append

    w(f"# Reconnaissance Report — {eng.get('client', 'Unknown Client')}\n")
    w("| Field | Value |")
    w("|-------|-------|")
    for label, key in [("Engagement", "id"), ("Authorization", "auth_ref"),
                       ("Tester", "tester"), ("Start", "start_ts"), ("End", "end_ts")]:
        if eng.get(key):
            w(f"| {label} | {eng[key]} |")
    w(f"| Generated | {model['generated_at']} |")
    w("")

    # Executive summary
    sev = model["severity_counts"]
    c = model["counts"]
    w("## Executive Summary\n")
    w(f"This engagement identified **{sum(sev.values())} finding(s)** across "
      f"{c.get('domain', 0)} domain(s), {c.get('host_ip', 0)} host(s), and "
      f"{c.get('service', 0)} service(s).\n")
    w("| Severity | " + " | ".join(s.capitalize() for s in SEVERITY_ORDER) + " |")
    w("|----------|" + "------|" * len(SEVERITY_ORDER))
    w("| Count | " + " | ".join(str(sev[s]) for s in SEVERITY_ORDER) + " |")
    w("")
    if model["top_findings"]:
        w("**Most significant findings:**\n")
        for f in model["top_findings"]:
            w(f"- `{f['severity'].upper()}` {f['title']}")
        w("")

    # Asset inventory
    w("## Asset Inventory\n")
    w(f"- **In-scope domains:** {len(model['in_scope_domains'])}")
    w(f"- **Discovered subdomains:** {len(model['discovered_subdomains'])}")
    w(f"- **Hosts / IPs:** {len(model['hosts'])}")
    w(f"- **Services:** {len(model['services'])}")
    w(f"- **Certificates:** {len(model['certificates'])}\n")

    if model["services"]:
        w("### Services\n")
        w("| Host | Port | Proto | Product | Version | Source |")
        w("|------|------|-------|---------|---------|--------|")
        for s in model["services"]:
            w(f"| {s['host_ip']} | {s['port']} | {s['proto']} | {s.get('product') or ''} "
              f"| {s.get('version') or ''} | {s['source']} |")
        w("")

    if model["hosts"]:
        w("### Hosts\n")
        w("| IP | PTR | ASN | In scope |")
        w("|----|-----|-----|----------|")
        for h in model["hosts"]:
            w(f"| {h['ip']} | {h.get('ptr') or ''} | {h.get('asn') or ''} | "
              f"{'yes' if h.get('in_scope') else 'no'} |")
        w("")

    # Findings by category
    w("## Findings\n")
    if not model["findings"]:
        w("_No findings recorded._\n")
    for cat, items in sorted(model["findings_by_category"].items()):
        w(f"### {CATEGORY_LABELS.get(cat, cat.title())}\n")
        for f in _sev_sorted(items):
            w(f"#### `{f['severity'].upper()}` {f['title']}")
            if f["affected"]:
                w(f"- **Affected:** {', '.join(f['affected'])}")
            if f["evidence"]:
                w(f"- **Evidence:** {'; '.join(f['evidence'])}")
            if f.get("remediation"):
                w(f"- **Remediation:** {f['remediation']}")
            w(f"- **Source:** {f['source_module']}\n")

    # Breach exposure (counts only)
    w("## Breach & Credential Exposure\n")
    if model["exposures"]:
        w("> Raw breach records are stored in the encrypted vault and excluded from this report; "
          "only aggregate counts are shown.\n")
        w("| Client | Source | Records | Format |")
        w("|--------|--------|---------|--------|")
        for e in model["exposures"]:
            w(f"| {e['client_id']} | {e['breach_source']} | {e['record_count']} | {e['fmt']} |")
    else:
        w("_No breach exposure recorded (or DeHashed not run)._")
    w("")

    # Screenshots
    if model["screenshots"]:
        w("## Screenshots\n")
        for o in model["screenshots"]:
            data = o["data"]
            w(f"- [{data.get('url', o['subject'])}]({data.get('path', '')})")
        w("")

    w("---")
    w(f"_Generated by skrecon (birdseye) at {model['generated_at']}. "
      "Structure follows PTES reconnaissance phases._")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _badge(sev: str) -> str:
    return (f'<span style="background:{SEV_COLORS.get(sev, "#4b5563")};color:#fff;'
            f'padding:1px 7px;border-radius:4px;font-size:12px;font-weight:600">'
            f'{_e(sev.upper())}</span>')


def render_html(model: dict[str, Any]) -> str:
    eng = model["engagement"]
    sev = model["severity_counts"]
    c = model["counts"]
    parts: list[str] = []
    w = parts.append

    w("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    w("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    w(f"<title>Recon Report — {_e(eng.get('client', 'Client'))}</title>")
    w("""<style>
    body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:960px;
    margin:0 auto;padding:24px;color:#1f2937;line-height:1.5}
    h1{border-bottom:3px solid #111;padding-bottom:6px} h2{margin-top:32px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
    table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}
    th,td{border:1px solid #e5e7eb;padding:6px 9px;text-align:left} th{background:#f9fafb}
    .finding{border:1px solid #e5e7eb;border-left-width:4px;border-radius:6px;padding:10px 14px;margin:10px 0;background:#fff}
    .meta{color:#6b7280;font-size:13px} code{background:#f3f4f6;padding:1px 5px;border-radius:4px}
    .note{background:#fffbeb;border:1px solid #fcd34d;padding:8px 12px;border-radius:6px;font-size:13px}
    </style></head><body>""")

    w(f"<h1>Reconnaissance Report — {_e(eng.get('client', 'Unknown Client'))}</h1>")
    w("<table>")
    for label, key in [("Engagement", "id"), ("Authorization", "auth_ref"),
                       ("Tester", "tester"), ("Start", "start_ts"), ("End", "end_ts")]:
        if eng.get(key):
            w(f"<tr><th>{_e(label)}</th><td>{_e(eng[key])}</td></tr>")
    w(f"<tr><th>Generated</th><td>{_e(model['generated_at'])}</td></tr></table>")

    w("<h2>Executive Summary</h2>")
    w(f"<p>This engagement identified <strong>{sum(sev.values())} finding(s)</strong> across "
      f"{c.get('domain', 0)} domain(s), {c.get('host_ip', 0)} host(s), and "
      f"{c.get('service', 0)} service(s).</p>")
    w("<table><tr>" + "".join(f"<th>{s.capitalize()}</th>" for s in SEVERITY_ORDER) + "</tr><tr>"
      + "".join(f"<td>{_badge(s)} {sev[s]}</td>" for s in SEVERITY_ORDER) + "</tr></table>")

    w("<h2>Asset Inventory</h2><ul>")
    w(f"<li><strong>In-scope domains:</strong> {len(model['in_scope_domains'])}</li>")
    w(f"<li><strong>Discovered subdomains:</strong> {len(model['discovered_subdomains'])}</li>")
    w(f"<li><strong>Hosts / IPs:</strong> {len(model['hosts'])}</li>")
    w(f"<li><strong>Services:</strong> {len(model['services'])} &nbsp; "
      f"<strong>Certificates:</strong> {len(model['certificates'])}</li></ul>")
    if model["services"]:
        w("<table><tr><th>Host</th><th>Port</th><th>Proto</th><th>Product</th><th>Version</th><th>Source</th></tr>")
        for s in model["services"]:
            w(f"<tr><td>{_e(s['host_ip'])}</td><td>{_e(s['port'])}</td><td>{_e(s['proto'])}</td>"
              f"<td>{_e(s.get('product'))}</td><td>{_e(s.get('version'))}</td><td>{_e(s['source'])}</td></tr>")
        w("</table>")

    w("<h2>Findings</h2>")
    if not model["findings"]:
        w("<p><em>No findings recorded.</em></p>")
    for cat, items in sorted(model["findings_by_category"].items()):
        w(f"<h3>{_e(CATEGORY_LABELS.get(cat, cat.title()))}</h3>")
        for f in _sev_sorted(items):
            w(f"<div class='finding' style='border-left-color:{SEV_COLORS.get(f['severity'], '#4b5563')}'>")
            w(f"<div>{_badge(f['severity'])} <strong>{_e(f['title'])}</strong></div>")
            if f["affected"]:
                w(f"<div class='meta'>Affected: {_e(', '.join(f['affected']))}</div>")
            if f["evidence"]:
                w(f"<div class='meta'>Evidence: {_e('; '.join(f['evidence']))}</div>")
            if f.get("remediation"):
                w(f"<div>Remediation: {_e(f['remediation'])}</div>")
            w(f"<div class='meta'>Source: {_e(f['source_module'])}</div></div>")

    w("<h2>Breach &amp; Credential Exposure</h2>")
    if model["exposures"]:
        w("<div class='note'>Raw breach records are stored in the encrypted vault and excluded from "
          "this report; only aggregate counts are shown.</div>")
        w("<table><tr><th>Client</th><th>Source</th><th>Records</th><th>Format</th></tr>")
        for e in model["exposures"]:
            w(f"<tr><td>{_e(e['client_id'])}</td><td>{_e(e['breach_source'])}</td>"
              f"<td>{_e(e['record_count'])}</td><td>{_e(e['fmt'])}</td></tr>")
        w("</table>")
    else:
        w("<p><em>No breach exposure recorded (or DeHashed not run).</em></p>")

    if model["screenshots"]:
        w("<h2>Screenshots</h2><ul>")
        for o in model["screenshots"]:
            data = o["data"]
            w(f"<li><a href='{_e(data.get('path', ''))}'>{_e(data.get('url', o['subject']))}</a></li>")
        w("</ul>")

    w(f"<hr><p class='meta'>Generated by skrecon (birdseye) at {_e(model['generated_at'])}. "
      "Structure follows PTES reconnaissance phases.</p></body></html>")
    return "".join(parts)


def write_reports(store: EngagementStore, out_dir, *, fmt: str = "both") -> list:
    """Render report(s) into out_dir. fmt in {md, html, both}. Returns written paths."""
    from pathlib import Path
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model = build_report_model(store)
    written = []
    if fmt in ("md", "both"):
        p = out_dir / "report.md"
        p.write_text(render_markdown(model), encoding="utf-8")
        written.append(p)
    if fmt in ("html", "both"):
        p = out_dir / "report.html"
        p.write_text(render_html(model), encoding="utf-8")
        written.append(p)
    return written
