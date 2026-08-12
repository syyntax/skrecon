# birdseye / `skrecon` — Design Document

**Status:** Draft for review · **Author:** engagement tooling team · **Date:** 2026-08-12
**Scope of this doc:** Answers the open questions in the build spec §13, lays out the architecture,
data model, safety design, and a phased build plan. **No implementation code is written until the
decisions in [§11](#11-decisions-that-need-your-sign-off) are confirmed.**

This document is deliverable #1 from spec §14. It refers back to the build spec (`stormkeep-recon-build-prompt.md`)
by section number rather than restating it.

---

## 1. One-paragraph summary

`skrecon` (product name **birdseye**) is a CLI orchestrator that runs the recon phase of an
**authorized** Stormkeep pentest. It ingests `scope.txt` and engagement metadata, runs a suite of
mature open-source tools and OSINT APIs in two architecturally-separated phases (passive → active),
normalizes their heterogeneous output into a single correlated data model, and produces a
client-ready report plus machine-readable exports. Its most important property is *not* breadth of
tooling — it's the **scope guard** and **authorization gate** that make the active phase provably
unable to touch anything outside the resolved scope. Those are built and tested first.

---

## 2. Decisions at a glance (answers to spec §13)

| # | Open question | Recommendation | Confidence |
|---|---------------|----------------|-----------|
| 1 | Language / runtime / packaging | **Python 3.11+**, Typer CLI. Install via **pipx**; ship a **Docker image** that bundles the external binaries. | High — recommend and proceed |
| 2 | Storage: JSON / SQLite / graph | **SQLite** as system-of-record (SQLAlchemy) + **JSON export**; raw tool output preserved on disk; **separate encrypted store** for PII. | High — recommend and proceed |
| 3 | Second-source providers beyond Shodan/DeHashed | **LOCKED:** Shodan + DeHashed only for v1 (keys confirmed). crt.sh + certspotter (CT, keyless) + subfinder still included. Censys/HIBP adapters deferred (no keys) — provider interface stays pluggable so they drop in later. | ✅ Resolved |
| 4 | UDP scanning & AXFR | Both **opt-in, off by default**. AXFR is active-adjacent → gated behind the auth gate + `--enable-axfr`. UDP behind `--udp`, top-N ports only. | High — recommend and proceed |
| 5 | Default rates / nuclei set | masscan **1000 pps** default (hard-warn above 20k); nmap **-T3** + `--max-rate` cap; **nuclei off by default**, and when enabled: safe/non-intrusive tags only (exclude `dos`,`intrusive`,`fuzzing`), rate-limited. | High — recommend and proceed |
| 6 | Retention policy for breach/PII | **LOCKED:** retain encrypted-at-rest, then **auto-purge** at `retention_days` (default **90**, per-engagement configurable); reports carry counts only. | ✅ Resolved (90-day default) |
| 7 | Report format + methodology mapping | **LOCKED:** both Markdown (canonical) + HTML (client-facing) from one model via Jinja2, structure mapped to **PTES** recon phases. | ✅ Resolved |
| 8 | Multi-tester / multi-engagement | **LOCKED:** v1 = single engagement per run, file-isolated; many engagements coexist on disk; live multi-tester collaboration deferred. | ✅ Resolved |

The four "Confirm / Needs" rows are collected as questions in [§11](#11-decisions-that-need-your-sign-off).

---

## 3. Language & runtime — why Python

**Recommendation: Python 3.11+.**

| Factor | Python | Go |
|--------|--------|----|
| Domain libraries | dnspython, python-whois/`rdap`, `shodan`, `censys`, **sslyze** (native lib, not just CLI), **dnstwist**, **theHarvester** are Python — import them, don't shell out | Strong ProjectDiscovery stack (subfinder, httpx, nuclei, gowitness) but all consumed as **binaries** anyway |
| Data model / reporting | pydantic + SQLAlchemy + Jinja2 is a best-in-class combo for the normalized model, JSON export, and templated reports | Workable but more boilerplate |
| Concurrency for this workload | Orchestration is **I/O-bound** (subprocess + HTTP); `asyncio` + a bounded worker pool is more than enough | Goroutines are nicer, but not needed here |
| Single-binary distribution | Weaker | Strong — *but* moot: we must ship masscan/nmap/etc. regardless, so we ship **Docker** either way | 

The decisive point: we orchestrate C binaries (masscan, nmap) and Go binaries (subfinder, nuclei,
gowitness) **no matter the language**, so Go's single-binary win largely evaporates — the real
deliverable is a reproducible **container**. Meanwhile several tools we wrap are *themselves Python*
(sslyze, dnstwist, theHarvester), so Python lets us call them in-process with structured results and
real error handling instead of parsing stdout. Python also gets us to a correlated data model and a
polished report fastest.

**Packaging:** `pipx install skrecon` for operators who already have the toolchain; a **Docker
image** (`stormkeep/skrecon`) that bundles every external binary for reproducibility across machines
(spec §6). CLI built with **Typer** (subcommands, `--help`, good ergonomics) + **rich** for progress
and readable output.

---

## 4. High-level architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │                     CLI (Typer)                  │
                    │  init · preflight · passive · active · report ·  │
                    │  engagement close · diff · dry-run flag          │
                    └───────────────┬─────────────────────────────────┘
                                    │
          ┌─────────────────────────┴───────────────────────────┐
          │                    Core / Engine                     │
          │                                                       │
          │  Config resolver (defaults→file→env→flags)            │
          │  Scope parser & normalizer  ─────►  Resolved Scope    │
          │  ┌──────────────── SCOPE GUARD ─────────────────┐     │
          │  │ Authorization gate · in-scope validator ·    │     │
          │  │ blackout-window clock · guarded Executor &   │     │
          │  │ guarded HTTP client (the ONLY way modules    │     │
          │  │ reach a target)                              │     │
          │  └──────────────────────────────────────────────┘     │
          │  Pipeline/DAG scheduler · rate limiter · cache ·       │
          │  checkpoint/resume · audit log · data store (repo)     │
          └───────────────┬───────────────────────────────────────┘
                          │  Context (injected into every module)
        ┌─────────────────┴───────────────────────────────┐
        │                 Module registry                   │
        │  PASSIVE modules            ACTIVE modules         │
        │  dns, mail, whois/rdap,     masscan, nmap, tls,    │
        │  ct, subdomains, shodan,    headers, tech, shots,  │
        │  harvester, dehashed, …     waf, nuclei(opt), …    │
        └───────────────────────────────────────────────────┘
                          │
              ┌───────────┴────────────┐
              │  Store + Reporters      │
              │  SQLite · JSON export · │
              │  MD/HTML report ·       │
              │  encrypted PII vault    │
              └─────────────────────────┘
```

### 4.1 Module interface (the plugin contract)

Every capability is an independent module implementing one interface so new modules drop in without
touching the core (spec §6):

```python
class Module(Protocol):
    name: str                      # "ct", "nmap", "dehashed"
    phase: Phase                   # PASSIVE | ACTIVE
    touches_targets: bool          # True ⇒ subject to scope guard + auth gate
    requires_tools: list[str]      # external binaries, e.g. ["masscan"]
    requires_keys:  list[str]      # env var names, e.g. ["SHODAN_API_KEY"]
    depends_on:     list[str]      # module names that must complete first
    default_enabled: bool

    def preflight(self, ctx: Context) -> Readiness: ...      # tools/keys present?
    def plan(self, ctx: Context)      -> list[Action]: ...   # for --dry-run
    def run(self, ctx: Context)       -> Iterable[Record]: ...# yields Assets/Findings/Observations
```

`Record` is any normalized entity (Asset, Host, Service, Certificate, Finding, Exposure, Screenshot,
Observation). Modules **never** open sockets directly — they receive a `Context` whose only routes to
a target are the **guarded** executor and HTTP client (see §6). This is what makes the scope guard
un-bypassable "in the core, not in individual modules" (spec §9.1).

### 4.2 Pipeline / DAG

Modules declare `depends_on`; the scheduler topologically sorts them and runs independent modules
concurrently within a phase, bounded by the global rate limiter and per-module concurrency. Data
flows through the store, not direct calls, so a module simply queries the records it needs.

```
passive:  dns ─┬─► reverse-dns ─┐
               ├─► shodan        ├─► (resolving in-scope hosts) ─────────────┐
   ct ─┬───────┴─► subdomains ───┘                                            │
subfinder┘                                                                    ▼
whois/rdap (indep)   mail (indep)   dehashed/harvester (CLIENT scope, indep)  │
                                                                              │  auth gate
active:  masscan ─► nmap(-oA) ─► services ─┬─► tls                            │  crossed here
                                           ├─► headers                        │
                                           ├─► tech-fingerprint  ◄────────────┘
                                           ├─► screenshots
                                           ├─► waf
                                           └─► nuclei (opt-in)
```

### 4.3 Resumability

Each `(module, input-hash)` pair is a checkpoint row: `pending → running → done/failed`. On restart
the scheduler skips `done` work and resumes the rest (spec §6). Expensive lookups (CT, WHOIS, Shodan)
are cached with TTLs so re-runs don't re-bill APIs.

### 4.4 Graceful degradation

Preflight classifies every module as **ready / skipped(missing tool) / skipped(missing key) /
disabled**. A module failing at runtime is caught, logged to the audit trail, marked `failed`, and
the run continues (spec §2.7, §10). One dead API never crashes the engagement.

---

## 5. Data model

**Storage decision:** **SQLite** as the system of record via SQLAlchemy, with a **JSON export** that
mirrors the model for downstream tooling and re-import (spec §7). Rationale vs. the alternatives:

- **Flat JSON only** — no good for the correlation/join needs (host ↔ service ↔ finding ↔ cert) or
  for resumable checkpoints and run-diffs.
- **Graph store** — overkill. The correlation graph is small (thousands of nodes) and every query we
  need is a handful of SQL joins. Not worth an external server or the ops burden.
- **SQLite** — one portable file per engagement (matches "reproducible, resumable engagement" and
  makes retention/cleanup a file operation), zero server, trivially diffable across runs, and the
  natural home for checkpoints and the audit log.

Raw native tool outputs (including nmap `-oA`) are preserved on disk under the engagement directory
regardless — the DB holds the *normalized* view, not the only copy.

### 5.1 Entities

| Entity | Key fields | Notes |
|--------|-----------|-------|
| **Engagement** | id, client, auth_ref/ticket, tester, start, end, blackout_windows[] | Report header + audit anchor (spec §3.3) |
| **Asset** | raw_entry, kind(domain\|url\|host\|ip\|cidr), normalized, in_scope | One row per `scope.txt` line + normalization result |
| **DomainName** | fqdn, registrable_domain, is_scope, resolves | |
| **HostIP** | ip, version(4\|6), asn, netblock, ptr, in_scope | CIDR expansion produces these |
| **DnsRecord** | domain, type, value | Full record set (§4.1) |
| **ResolutionEdge** | from(domain), via(cname), to(ip) | The domain→CNAME→IP chain (§4.1) |
| **Service** | host_ip, port, proto, state, product, version, source(masscan\|nmap\|shodan) | `source` distinguishes tester-confirmed vs. third-party-observed (spec §4.7) |
| **Certificate** | subject, issuer, sans[], not_before, not_after, self_signed, source(ct\|tls) | SANs feed subdomain discovery (§4.5, §5.3) |
| **Finding** | title, category, severity, source_module, evidence[], affected[], remediation | The core report unit (spec §7) |
| **Exposure** | client_id, breach_source, record_count, plaintext\|hashed, vault_ref | **PII — encrypted store only**, never plaintext in report (§4.9, §9.6) |
| **Persona** | name, email, role, source | **PII** — minimize + same handling (§4.8) |
| **Screenshot** | service, full_path, thumb_path | Report appendix (§5.6) |
| **Observation** | subject, kind, data(json) | Normalized facts that aren't findings (banners, headers, SPF text) |
| **AuditEvent** | ts, actor, module, action, target, command/endpoint(redacted), outcome | Evidentiary record (spec §7) |
| **Checkpoint** | module, input_hash, status, started, finished | Resume/skip |

### 5.2 Severity & findings

Recon findings are posture/exposure observations, not exploited vulns, so we use a simple
**Info / Low / Medium / High / Critical** scale with a fixed catalog of finding types (e.g.
`mail.dmarc.missing`, `tls.protocol.legacy`, `domain.expiring`, `http.header.hsts.missing`,
`exposure.credentials`) each carrying a default severity + remediation template. This keeps findings
consistent across runs and makes run-diffs meaningful.

---

## 6. Safety architecture — built and tested first (spec §9)

This is the core of the tool. All four guardrails live in the engine, above the modules.

**6.1 Scope guard (un-bypassable).** The parser normalizes `scope.txt` (strip scheme/path → host,
expand CIDR with a cap + override, classify domain vs IP, dedupe, report malformed lines) into a
**Resolved Scope** set of hostnames + IP networks. Any host derived later (subdomains from CT, hosts
from Shodan, CIDR expansions) is validated against this set. Modules cannot reach the network except
through `ctx.executor` (subprocess) and `ctx.http` (requests); **both refuse any target not in the
Resolved Scope, log the refusal, and skip it** — the module continues with the allowed targets. An
active subprocess is assembled by the core from a validated target list, so a module can't smuggle an
out-of-scope arg past the guard.

**6.2 Authorization gate.** Active phase refuses to start unless: (a) required engagement metadata is
present (auth_ref, tester, dates), and (b) an explicit `--i-am-authorized` confirmation (flag or
interactive prompt) is given. The confirmation and metadata are written to the audit log before the
first packet.

**6.3 Blackout windows & throttling.** A clock check refuses to launch/continue active modules during
configured blackout windows (spec §3.3, §9.4). Conservative default rates for masscan/nmap/brute-forcing
(see §2 row 5) with explicit overrides required to go louder.

**6.4 Dry-run.** `--dry-run` runs the full pipeline through `plan()` only: prints every target and
every action (exact commands / API calls) with no execution, so the operator verifies scope and
intensity first (spec §9.5). This is also the primary test surface for the scope guard.

**6.5 Sensitive-data hygiene.** Breach/persona data goes to a separate **encrypted-at-rest** store
(e.g. an age/GPG-wrapped SQLite or encrypted blob), is excluded from default report output, and is
subject to the `engagement close` retention step. Secrets are redacted in the audit log (spec §9.6).

**Passive/active separation** is enforced by making them distinct subcommands with distinct code
paths: passive modules have `touches_targets = False` and are wired to the *unguarded* third-party
HTTP client only; they can run before the active authorization window exists (spec §9.3). AXFR is the
one passive-looking check that actually touches client-authoritative nameservers, so it's classified
**active-adjacent** and gated like an active module (spec §4.1, §13).

---

## 7. Configuration & secrets (spec §8)

Layered precedence: **built-in defaults → `skrecon.toml` → environment → CLI flags**. Secrets
(`SHODAN_API_KEY`, `DEHASHED_API_KEY`, optional `CENSYS_*`, `HIBP_API_KEY`) come only from env or a
git-ignored secrets file; a shipped **`.env.example`** documents them. `skrecon preflight` prints a
readiness table: which modules are enabled, and which are skipped for missing tools or keys. Per-module
enable/disable flags and phase selection (`passive`, `active`, `all`) are all config-driven.

---

## 8. Module catalog (maps spec §4–§5 to the plugin model)

**Passive** (`touches_targets = False`, may run over `CLIENT` scope):

| Module | Wraps | Keys | Notes |
|--------|-------|------|-------|
| `dns` | dnspython | — | A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA, resolution chain |
| `reverse-dns` | dnspython | — | PTR for scoped + resolved IPs |
| `mail` | dnspython + parsers | — | SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI scoring |
| `whois-rdap` | `whois`, RDAP libs | — | expiry/lock/privacy findings; IP→ASN→netblocks |
| `typosquat` | dnstwist | — | registered look-alikes, live MX/web |
| `ct` | crt.sh / certspotter | — | first-class subdomain source |
| `subdomains` | subfinder (+CT, +Shodan) | (subfinder sources optional) | aggregate, dedupe, mark resolving |
| `shodan` | Shodan API | `SHODAN_API_KEY` | third-party-observed ports/CVEs — labeled as such |
| `harvester` | theHarvester | (source keys optional) | emails/personas → **PII handling** |
| `dehashed` | DeHashed API | `DEHASHED_API_KEY` | breach exposure → **encrypted vault**, counts only in report |
| *extras (later)* | cloud-bucket, github-leak, wayback, ip-reputation | varies | spec §4.10 |

**Active** (`touches_targets = True`, scope guard + auth gate + blackout enforced):

| Module | Wraps | Notes |
|--------|-------|-------|
| `masscan` | masscan | wide port sweep, rate-limited default 1000 pps → feeds nmap |
| `nmap` | nmap `-sV -O -oA` | only masscan-open ports; XML ingested; intrusive NSE opt-in |
| `tls` | sslyze | protocols/ciphers/cert issues; SANs → more subdomains |
| `headers` | HTTP client | HSTS/CSP/XFO/XCTO/Referrer/Permissions + cookie flags |
| `tech` | WhatWeb/Wappalyzer | server/framework/CMS/CDN/WAF/JS versions |
| `screenshots` | gowitness | thumbnails in report appendix |
| `waf` | wafw00f | so later findings are read correctly |
| `nuclei` | nuclei | **off by default**; safe/non-intrusive templates only when enabled |
| *extras (later)* | content-discovery, vhost, smb/snmp/ldap enum, http-methods | noisier ones opt-in + throttled (spec §5.7) |

---

## 9. Output & reporting (spec §7)

- **Raw** native outputs preserved under `engagements/<id>/raw/<module>/`.
- **JSON** export of the full model (+ the SQLite file itself) for re-import and downstream tooling.
- **Report** in Markdown (canonical) and HTML (client-facing) from one Jinja2 template set:
  exec summary → asset inventory → findings by category/severity with evidence & remediation →
  DNS/mail posture → breach-exposure **summary (counts, no plaintext)** → screenshots appendix →
  metadata header. Structure mapped to **PTES** recon phases.
- **Audit log** — structured, timestamped, secret-redacted, one row per command/API call.
- **Deltas** — `skrecon diff <runA> <runB>` highlights new hosts/ports/services for retests.

---

## 10. Phased build plan (mirrors spec §12; each phase runs & tests standalone)

| Phase | Ships | Test gate |
|-------|-------|-----------|
| **0 — Core & safety** | config/secrets, scope parser+normalizer, engagement metadata, **scope guard**, auth gate, blackout clock, data model, audit log, `--dry-run`, `preflight` | Unit tests on parser + **adversarial scope-guard tests** (out-of-scope host/IP/CIDR/subdomain all refused); dry-run prints correct plan. **Hardened before anything else.** |
| **1 — Passive DNS/WHOIS/mail** | `dns`, `reverse-dns`, `whois-rdap` (+expiry), `mail`, `typosquat` | Run against a controlled domain; findings + resolution chain in DB/report |
| **2 — Passive OSINT/exposure** | `ct`, `subdomains`, `shodan`, `harvester`, `dehashed` (+encrypted vault) | Keyed modules gated by preflight; PII lands in vault, not report body |
| **3 — Active discovery** | `masscan` → `nmap -oA` → normalized services, behind auth gate | Against a local benign target; scope guard blocks an injected out-of-scope IP |
| **4 — Active web analysis** | `tls`, `headers`, `tech`, `screenshots`, `waf`, opt-in `nuclei` | Per-host findings + screenshot thumbnails |
| **5 — Reporting** | consolidated JSON, MD/HTML report, screenshots appendix, `diff` | Sample report against benign authorized target (spec §14.5) |

---

## 11. Decisions — resolved (2026-08-12)

All eight §13 questions are settled; the four that needed your input were confirmed:

1. **API keys** → **Shodan + DeHashed** only for v1. Censys/HIBP adapters deferred; the provider
   interface stays pluggable so they drop in later without core changes.
2. **PII retention** → **retain encrypted-at-rest, then auto-purge** at `retention_days`
   (**default 90**, per-engagement configurable). `engagement close` honors the window; reports keep
   counts only. *(Flag: confirm 90 days or give me the firm's number.)*
3. **Reporting** → **both** Markdown (canonical) + HTML (client-facing) from one data model,
   **PTES**-mapped.
4. **Concurrency** → **single engagement per run**, file-isolated; many engagements coexist on disk;
   live multi-tester collaboration deferred.

Accepted defaults (no objection raised): Python 3.11+/Typer, SQLite + JSON, opt-in UDP/AXFR,
conservative default rates, Docker packaging. **Build starts at Phase 0 (core + safety).**
