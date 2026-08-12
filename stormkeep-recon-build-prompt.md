# Build Specification & Planning Prompt: Stormkeep Recon Orchestrator

> **How to use this document.** This is a planning-and-build prompt for a terminal-based network
> reconnaissance orchestrator used during **authorized** penetration-testing engagements. Hand it
> to a coding model (or work through it yourself). **Do not start writing code immediately.** First
> produce a design: propose a language, an architecture, a data model, and a phased build plan, and
> surface the open questions listed at the end for a decision. Only then implement, in modular
> phases, with each phase runnable and testable on its own.

---

## 1. Purpose & context

Build a command-line tool (working name: **`skrecon`**) that automates the reconnaissance phase of
authorized penetration tests conducted by the firm **Stormkeep**. A client provides a list of
in-scope external, publicly accessible URLs and/or IP addresses in a file named `scope.txt`. The
tool ingests that file and orchestrates a suite of well-known open-source and API-based recon tools,
normalizes their output into a single data model, and produces a professional report the tester can
deliver to the client.

The tool distinguishes two phases with fundamentally different rules of engagement:

- **Passive reconnaissance** — no packets sent to client-owned targets; only third-party sources,
  public records, and OSINT APIs are queried. May cover the broader client organization (see the
  `CLIENT` variable) even when specific assets are not in `scope.txt`.
- **Active reconnaissance** — direct interaction with targets. **Must run *only* against hosts that
  resolve from or are explicitly listed in `scope.txt`.** This boundary is a hard, non-negotiable
  safety constraint (see §9).

---

## 2. Guiding principles & constraints

These shape every design decision and should be stated back in the design doc:

1. **Authorization first.** The tool is only ever run against systems the operator is contractually
   authorized to test. The active phase must be explicitly gated behind an authorization
   confirmation and must refuse to run without it.
2. **Scope is the source of truth.** No active module may ever touch a host outside the resolved
   scope. Out-of-scope targets are a hard failure, not a warning (see §9).
3. **Least surprise / safe defaults.** Default settings should be conservative: modest scan rates,
   sane timeouts, no destructive or intrusive checks unless explicitly enabled.
4. **Passive vs. active separation is architectural**, not just a flag — the two phases are distinct
   subcommands/stages so passive OSINT can be run before authorization for the active window is
   confirmed.
5. **Reproducibility.** A given `scope.txt` + config should yield a re-runnable, resumable
   engagement with a complete audit trail of what was run, when, and against what.
6. **Sensitive-data hygiene.** Breach data and credentials (see DeHashed) are sensitive PII. They
   must be handled deliberately: access-controlled storage, no needless plaintext exposure in
   reports, and a documented retention posture.
7. **Graceful degradation.** A missing tool, an expired API key, or a rate-limited service should
   disable that one module and continue — never crash the whole run.

---

## 3. Inputs & configuration

### 3.1 `scope.txt`
- One target per line: bare domains (`example.com`), URLs (`https://app.example.com/login`),
  hostnames, single IPv4/IPv6 addresses, and CIDR ranges (`203.0.113.0/28`).
- The parser must normalize these: strip schemes/paths to derive hostnames, expand CIDR ranges into
  host lists (with a sane cap and an override), de-duplicate, and classify each entry as
  domain-based or IP-based.
- Support comments (`#`) and blank lines. Validate and report malformed entries rather than
  silently dropping them.

### 3.2 The `CLIENT` variable
- A configurable value (env var and/or CLI flag and/or config file) holding the **client
  organization / brand name** used for passive recon that is broader than the scoped assets (e.g.,
  breach searches, email/subdomain harvesting, typosquatting) even when the primary domain is not in
  `scope.txt`.
- Optionally accept a list of client-associated **root domains** and **brand keywords** to widen
  passive collection precisely.

### 3.3 Engagement metadata
Capture and store with the results (used in the report header and audit log): client name,
engagement/authorization reference or ticket ID, tester name/handle, engagement start & end dates,
and any agreed **blackout windows** (times when active scanning is prohibited).

### 3.4 Secrets & API keys
- Keys for Shodan, DeHashed, and any other API sources (e.g., certificate/subdomain data providers)
  must come from environment variables or a secrets file that is **git-ignored** — never hardcoded.
- Provide a preflight that reports which API-backed modules are enabled based on available keys, and
  which will be skipped.

### 3.5 Global runtime config
Rate limits / concurrency per module, timeouts, retry policy, output directory, verbosity, and a
`--dry-run` mode that plans and prints every action without executing it.

---

## 4. Passive reconnaissance modules

All of the following send **no traffic to client targets** (they query third parties, public
records, and OSINT APIs). These may operate over `CLIENT` scope, not just `scope.txt`.

### 4.1 DNS & nameserver enumeration
- Forward resolution for all domains: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`, `SRV`, `CAA`,
  `PTR` where relevant.
- **Reverse DNS (PTR)** for every in-scope IP, and for IPs resolved from scoped domains.
- **DNSSEC** presence/validation status.
- **Zone-transfer check (AXFR)** against listed nameservers (this touches the nameservers, which are
  typically client-authoritative — treat as active-adjacent and gate accordingly / make it opt-in).
- Record the full resolution chain (domain → CNAME → IP) so it can be reported and correlated.

### 4.2 Mail-security posture
For each domain, parse and evaluate: **SPF** (presence, `-all` vs `~all`, lookup count),
**DMARC** (presence, policy `p=`, `rua`/`ruf`), **DKIM** (known/guessed selectors), and the newer
**MTA-STS**, **TLS-RPT**, and **BIMI** records. Flag missing or weak policies (e.g., no DMARC, `p=none`,
overly permissive SPF) as findings — these were called out explicitly and matter for phishing risk.

### 4.3 WHOIS / RDAP
- **Domain WHOIS/RDAP:** registrar, registrant (where available), creation/updated/**expiration**
  dates, nameservers, status codes (e.g., clientTransferProhibited), DNSSEC flags.
- **Derived findings:** domain **expired**, **expiring soon** (configurable threshold, e.g. ≤ 60
  days), missing registrar lock, privacy/proxy status.
- **IP/ASN WHOIS (RDAP):** owning org, ASN, allocated netblock/CIDR, abuse contacts. Use ASN data to
  enumerate the organization's broader netblocks for passive footprinting.

### 4.4 Typosquatting / brand-abuse (dnstwist-style)
Generate permutations of the client's domain(s) and check for **registered** look-alikes, resolving
IPs, live MX (phishing infrastructure), and any that host active web content. Report potential
typosquats and homoglyph domains.

### 4.5 Certificate Transparency (CT) — *high-value subdomain source*
Query CT logs (e.g., crt.sh-style sources) for all certificates issued for client domains to
enumerate **subdomains**, historical hostnames, issuers, and validity windows. This is one of the
richest passive subdomain discovery methods and should be a first-class module.

### 4.6 Passive subdomain enumeration
Aggregate subdomains from multiple passive sources (CT logs, Shodan, and other subdomain/DNS
datasets you choose), de-duplicate, and mark which resolve. Feed resolving in-scope hosts forward to
the active phase (respecting scope).

### 4.7 Shodan / internet-exposure intelligence
For scoped IPs and discovered hosts, pull Shodan host data: open ports/services **as last observed
by Shodan (passive — Shodan scanned, not you)**, product/version banners, detected vulnerabilities
(CVE list), exposed services, and geolocation/hosting. Optionally support a second source (e.g.,
Censys) behind the same interface. Clearly label this data as third-party-observed, not
tester-confirmed.

### 4.8 Email & persona harvesting (OSINT)
Harvest public email addresses and employee names associated with the client (theHarvester-style,
plus search-engine and public-source collection). Derive the likely **email-address format** (e.g.,
`first.last@`) for the report. **Note:** persona/employee data is sensitive and privacy-implicating —
collect only what's relevant to the engagement and handle per §2.6.

### 4.9 Breach & credential exposure (DeHashed)
Query DeHashed for the client's domain(s) and `CLIENT` identifiers to surface **compromised
credentials and leaked records**. In the report, summarize exposure (counts, breach sources, whether
plaintext or hashed) and **avoid dumping plaintext secrets** into deliverables by default; store raw
findings encrypted/access-controlled and reference them. This runs on `CLIENT` scope even when the
domain isn't in `scope.txt`.

### 4.10 Suggested additional passive modules
- **Cloud-asset enumeration:** guess/confirm public S3 buckets, Azure blob containers, and GCS
  buckets tied to client naming; flag public/misconfigured ones.
- **Code & secret leakage:** search public GitHub/GitLab and paste sites for the client's domains,
  internal hostnames, and API-key patterns.
- **Archived content (Wayback):** historical URLs, old endpoints, and parameters from web archives.
- **Search-engine reconnaissance ("dorking"):** exposed files, login portals, index-of listings.
- **Document metadata:** extract author names, software versions, and internal paths from publicly
  posted files (PDF/Office).
- **IP reputation / blocklist status** for scoped IPs.

---

## 5. Active reconnaissance modules

**All modules in this section run *only* against hosts validated as in-scope (see §9).** Order
matters: discovery → enumeration → service-specific analysis.

### 5.1 Port discovery — Masscan
- Fast, wide port sweep across scoped IPs/CIDRs to identify open TCP (and optionally UDP) ports.
- **Rate must be operator-controllable** and conservative by default; masscan can saturate links and
  disrupt targets if run too aggressively.
- Output feeds the Nmap stage (only the ports masscan found open).

### 5.2 Service/OS detection — Nmap
- Run Nmap against the open ports discovered by masscan for **service/version detection (`-sV`)**,
  **OS fingerprinting (`-O`)**, and default script scanning as appropriate.
- Output in **all formats via `-oA`** (normal, XML, grepable) so results are both human-readable and
  machine-parseable; ingest the XML into the data model.
- Provide knobs for timing templates and script categories; keep intrusive NSE scripts opt-in.

### 5.3 TLS/SSL analysis
For services speaking TLS (443 and any other TLS ports found), analyze with an sslyze/testssl-style
engine: supported **protocol versions** (flag SSLv3/TLS 1.0/1.1), **cipher suites** (flag weak/export/
NULL), certificate details (issuer, SANs — *another subdomain source*, validity, expiry, self-signed,
chain issues), and known TLS issues (e.g., Heartbleed, ROBOT, weak DH). Report per-host findings with
severity.

### 5.4 HTTP security headers
For each web service, capture response headers and evaluate the presence/quality of: **HSTS**,
**Content-Security-Policy**, **X-Frame-Options**, **X-Content-Type-Options**, **Referrer-Policy**,
**Permissions-Policy**, and cookie flags (`Secure`, `HttpOnly`, `SameSite`). Report missing/weak
headers as findings.

### 5.5 Technology-stack fingerprinting
Identify web servers, frameworks, CMSes, languages, CDNs/WAFs, and JS libraries (Wappalyzer/WhatWeb-
style). Capture versions where exposed so they can be cross-referenced with known-vulnerability data.

### 5.6 Screenshots of web front pages
Capture full-page screenshots of each web app's landing page (gowitness/aquatone/EyeWitness-style)
and embed thumbnails in the report, linked to full-resolution images. Useful for quickly triaging a
large scope and for the client-facing appendix.

### 5.7 Suggested additional active modules
- **WAF detection** (wafw00f-style) so later findings are interpreted correctly.
- **Templated vulnerability scanning** (Nuclei-style) for known CVEs, exposures, and
  misconfigurations — keep it to safe/non-intrusive templates by default.
- **Web content/endpoint discovery:** `robots.txt`, `sitemap.xml`, `security.txt`, favicon hashing
  (correlate to Shodan), and *optionally* directory brute-forcing — clearly flagged as **noisier/more
  intrusive** and opt-in with throttling.
- **Virtual-host discovery** (host-header fuzzing against discovered IPs).
- **Service-specific enumeration** for non-web ports found open: SMB/NetBIOS, SNMP, LDAP, RDP,
  databases, mail (SMTP/IMAP/POP) banners and safe enumeration checks.
- **HTTP method enumeration** (e.g., dangerous methods like `PUT`/`TRACE`).

---

## 6. Architecture & technical requirements

Propose and justify choices for:

- **Language & runtime.** Pick one primary language (e.g., Python or Go are natural fits for
  orchestrating CLI tools and HTTP APIs) and explain the trade-off.
- **Module/plugin architecture.** Each recon capability is an independent module exposing a common
  interface (name, phase [passive|active], dependencies, `run(context) -> findings`, required
  API keys/tools). New modules should be addable without touching the core.
- **Normalized data model.** Define core entities — **Engagement**, **Target/Asset**, **Host/IP**,
  **DomainName**, **Service** (port/protocol/product/version), **Certificate**, **Finding**
  (with severity, source, evidence), **Credential/Exposure**, **Screenshot** — so heterogeneous tool
  output correlates into one graph. Decide storage: structured files (JSON/SQLite) are usually enough;
  justify anything heavier.
- **Concurrency & rate control.** Per-module concurrency and global rate limiting; respect external
  API quotas (Shodan, DeHashed) and keep active-scan rates polite by default.
- **Orchestration & dependencies.** A pipeline/DAG so modules that depend on others (e.g., Nmap
  needs masscan output; active web modules need discovered web services) run in the right order and
  can run in parallel where independent.
- **Resumability & checkpointing.** Recon is long-running; persist progress so an interrupted run
  resumes without redoing completed work. Cache expensive lookups.
- **Preflight checks.** Verify required external binaries (masscan, nmap, TLS scanner, screenshot
  engine, etc.) and API keys before starting; report a clear readiness summary.
- **Containerization.** Provide a Docker image (or documented environment) so the tool + its many
  external dependencies are reproducible across machines.

---

## 7. Output, logging & reporting

- **Preserve raw outputs.** Keep every tool's native output (including Nmap's `-oA` set) under a
  per-engagement directory so nothing is lost to parsing.
- **Machine-readable results.** Emit a consolidated **JSON** (and/or SQLite) representation of the
  full data model for downstream tooling and re-import.
- **Human report.** Generate a clean **Markdown and/or HTML** report with: an executive summary; an
  **asset inventory** (domains, IPs, subdomains, services); a **findings** section grouped by
  category and severity with evidence; a **DNS/mail-posture** section; a **breach-exposure** summary;
  a **screenshots** appendix; and the engagement metadata header. Consider mapping the structure to a
  recognized methodology (e.g., PTES recon phases) for client familiarity.
- **Findings model.** Each finding carries: title, affected asset(s), severity, the source
  module/tool, supporting evidence, and a short remediation recommendation.
- **Audit log.** A structured, timestamped log of every command/API call issued, against which
  target, and its outcome — this is the engagement's evidentiary record. Redact secrets in logs.
- **Deltas (nice-to-have).** Support comparing two runs of the same scope to highlight what changed
  (new hosts/ports/services) for retests.

---

## 8. Configuration & secrets management

- Layered config: sensible built-in defaults → config file → environment variables → CLI flags
  (highest precedence).
- All secrets via env/secret file only; provide a `.env.example` and ensure real secrets are
  git-ignored. The tool should print which modules are enabled/disabled based on present keys.
- Per-module enable/disable flags, and phase selection (`passive-only`, `active-only`, `all`).

## 9. Safety, guardrails & scope enforcement (critical)

This section defines the tool's most important behavior and should be designed and tested first:

1. **Scope guard.** Before any active module contacts a host, its resolved target (IP or hostname,
   including CIDR-expanded and subdomain-derived hosts) is validated against the parsed, normalized
   scope. **Any out-of-scope target is refused and logged** — the module skips it rather than
   proceeding. This check lives in the core, not in individual modules, so no module can bypass it.
2. **Authorization gate.** The active phase refuses to run unless an explicit authorization
   confirmation is provided (e.g., a required flag/prompt plus recorded engagement metadata).
3. **Passive/active separation.** Passive modules never send traffic to client targets; keep them in
   a separate stage so they can run before the active window opens.
4. **Blackout windows & throttling.** Honor configured blackout windows (refuse active scanning
   during them) and enforce conservative default rates for masscan/nmap/brute-forcing to avoid
   disrupting production systems.
5. **Dry-run.** `--dry-run` prints the full plan (every target and action) without executing, so the
   operator can verify scope and intensity before launching.
6. **Sensitive-data handling.** Breach/credential and persona data stored access-controlled and,
   where feasible, encrypted at rest; plaintext secrets excluded from default report output; a
   documented retention/cleanup step at engagement close.

---

## 10. Non-functional requirements

Robust error handling and retries with backoff; clear, leveled logging (quiet/normal/verbose);
graceful handling of unavailable tools/APIs (disable module, continue); testability (unit tests for
parsers and the scope guard, integration tests against benign local targets); good CLI ergonomics
(subcommands, `--help`, progress indication for long stages); and maintainable, documented,
extensible code.

---

## 11. Suggested tooling to wrap (implementer's discretion)

The tool should orchestrate mature, well-known utilities rather than reimplement them. Candidates by
function: **DNS** (dnspython/dig, dnstwist), **WHOIS/RDAP** (whois, RDAP libraries), **CT/subdomains**
(crt.sh-style sources, amass/subfinder), **exposure** (Shodan/Censys APIs), **email/OSINT**
(theHarvester), **breach** (DeHashed API), **port scan** (masscan, nmap), **TLS** (sslyze/testssl.sh),
**headers/tech** (custom HTTP client + WhatWeb/Wappalyzer), **screenshots** (gowitness/aquatone/
EyeWitness), **templated vulns** (nuclei), **WAF** (wafw00f). Confirm each tool's license permits use
in a commercial engagement.

---

## 12. Suggested phased build plan

1. **Phase 0 — Core & safety:** config/secrets loading, `scope.txt` parser + normalizer (CIDR
   expansion, classification), engagement metadata, the **scope guard**, audit logging, data model,
   `--dry-run`. Ship this first and test it hard.
2. **Phase 1 — Passive DNS/WHOIS/mail:** resolution, reverse DNS, WHOIS/RDAP + expiry findings,
   SPF/DMARC/DKIM/MTA-STS evaluation, dnstwist.
3. **Phase 2 — Passive OSINT/exposure:** CT-log subdomains, Shodan, email harvesting, DeHashed,
   plus chosen extras (cloud assets, code leakage, Wayback).
4. **Phase 3 — Active discovery:** masscan → nmap (`-oA`) → normalized services, behind the
   authorization gate.
5. **Phase 4 — Active web analysis:** TLS scan, security headers, tech fingerprint, screenshots,
   WAF, and (opt-in) nuclei/content discovery.
6. **Phase 5 — Reporting:** consolidated JSON, Markdown/HTML report, screenshots appendix, run
   deltas.

Each phase must run end-to-end and be independently testable before moving on.

---

## 13. Open questions to resolve in the design doc

- Primary **language/runtime** and packaging (pipx, single Go binary, Docker-only)?
- **Storage**: flat JSON, SQLite, or a graph store — given the correlation needs?
- Which **second-source** providers (if any) beyond Shodan/DeHashed, and are keys available?
- How should **UDP scanning** and **zone-transfer/AXFR** be treated given their intrusiveness — opt-in
  only?
- Default **rate limits** for masscan/nmap and default nuclei template set?
- **Retention policy** for breach/PII data at engagement close?
- Report **format priority** (Markdown vs. HTML vs. both) and whether to map to a named methodology
  (PTES/OWASP)?
- Multi-tester / multi-engagement concurrency, or single-engagement-at-a-time?

---

## 14. Deliverables expected from the build

1. A short **design document** answering §13 and laying out architecture + data model.
2. The **`skrecon` CLI** implementing the phased plan, with the scope guard and authorization gate in
   place from Phase 0.
3. **Docker image / environment** and a documented setup (including `.env.example`).
4. **Tests** for parsers and the scope guard at minimum.
5. A **sample report** generated against a benign, authorized test target to demonstrate output.
