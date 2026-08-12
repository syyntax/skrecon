# birdseye (`skrecon`)

Authorized reconnaissance orchestrator for **Stormkeep** penetration-testing engagements.

`skrecon` ingests a client `scope.txt`, runs a suite of mature open-source and API-based recon tools
in two architecturally-separated phases (**passive** → **active**), normalizes their output into a
single correlated data model, and produces a client-ready report plus machine-readable exports.

> ⚠️ **Authorized use only.** This tool is run exclusively against systems you are contractually
> authorized to test. The active phase is gated behind an explicit authorization confirmation and a
> non-bypassable scope guard — see [`DESIGN.md`](DESIGN.md) §6 and the build spec §9.

See [`DESIGN.md`](DESIGN.md) for the full architecture, data model, and phased plan.

---

## Status

Built in phases (spec §12). Current state:

| Phase | Contents | Status |
|-------|----------|--------|
| **0** | config/secrets, scope parser+normalizer, engagement metadata, **scope guard**, authorization gate, blackout windows, audit log, data model, dry-run, preflight | **✅ implemented** |
| **1** | passive DNS / reverse-DNS / WHOIS-RDAP (+expiry) / mail-posture (SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI) / typosquat, plus the passive pipeline, resolver, HTTP client, cache & findings catalog | **✅ implemented** |
| **2** | passive CT subdomains (crt.sh + certspotter fallback) / subdomain aggregation & resolution / Shodan / theHarvester / DeHashed, plus the **encrypted PII vault** (Fernet) and `engagement close`/`status` with retention auto-purge | **✅ implemented** |
| **3** | active masscan → nmap (`-sV -O -oA`) → normalized services, behind the authorization gate; scope guard extended to validate in-scope CIDR ranges | **✅ implemented** |
| **4** | active TLS/SSL (protocols + cert + SAN harvest) / HTTP security headers / tech fingerprint (WhatWeb) / screenshots (gowitness) / WAF (wafw00f) / nuclei (opt-in, off by default); guarded, redirect-safe HTTP + TLS prober | **✅ implemented** |
| 5 | consolidated JSON + MD/HTML report + run deltas | planned |

## Install (development)

The safety-critical core is stdlib-only, so the test suite runs with just `pytest`:

```bash
python -m pip install -e ".[dev]"
```

To use the CLI (needs `typer`):

```bash
python -m pip install -e .
```

The Phase 1 passive modules need their tool bindings (dnspython for DNS/mail,
dnstwist for typosquatting). Modules whose bindings are absent are reported as
`skipped` by `preflight` and skipped at run time rather than failing:

```bash
python -m pip install -e ".[passive]"
```

The DeHashed/harvester modules store breach & persona PII in an encrypted vault,
which needs `cryptography` and a passphrase (`SKRECON_VAULT_PASSPHRASE`). Without
them those modules skip rather than write PII unencrypted:

```bash
python -m pip install -e ".[vault]"
```

## Quickstart

```bash
# 1. Parse & normalize a scope file — inspect exactly what the guard will enforce.
skrecon scope check ./scope.txt

# 2. Report which modules/tools/keys are ready.
skrecon preflight

# 3. Create an engagement (writes engagements/<id>/ with metadata + audit DB).
skrecon init --client "Example Corp" --auth-ref TICKET-123 \
    --tester alice --scope ./scope.txt

# 4. Plan the whole run without touching anything.
skrecon run --engagement <id> --dry-run
```

## Safety model (Phase 0)

- **Scope guard** lives in the core: modules reach the network only through a guarded executor /
  HTTP client that refuses any out-of-scope target, logs the refusal, and continues. No module can
  bypass it.
- **Authorization gate**: the active phase refuses to run without recorded engagement metadata plus
  an explicit `--i-am-authorized` confirmation.
- **Blackout windows**: active scanning is refused during configured windows.
- **`--dry-run`**: prints every target and action with zero execution.
- **PII hygiene**: breach/persona data is stored encrypted-at-rest, excluded from report bodies, and
  auto-purged at engagement close per `retention_days`.

## Tests

```bash
python -m pytest -q
```
