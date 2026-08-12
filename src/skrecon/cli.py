"""skrecon command-line interface (spec §10 CLI ergonomics).

Subcommands (Phase 0):
    version    show version
    scope      parse & inspect a scope.txt exactly as the guard will enforce it
    preflight  report config, API-key, and external-tool readiness
    init       create an engagement (metadata + scope + audit DB)
    run        orchestrate an engagement (supports --dry-run and the auth gate)

Recon modules land in Phases 1–4; `run` already wires the full safety path so the
scope guard and authorization gate are exercised from day one.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from .audit import AuditLog
from .cache import Cache
from .config import IMPLEMENTED_PROVIDERS, KNOWN_API_KEYS, Settings
from .diff import diff_engagements, render_diff_text
from .engagement import EngagementMeta
from .errors import BlackoutError, NotAuthorizedError, SkreconError
from .report import write_reports
from .guard import ActiveGate, GuardedExecutor, GuardedHttp, ScopeGuard
from .model import Asset, AssetKind, Phase
from .modules.base import REGISTRY, Context
from .net import PassiveHttp, PassiveResolver
from .pipeline import run_phase
from .scope import ScopeParseResult, parse_scope_file, parse_scope_text
from .store import EngagementStore
from .vault import EncryptedVault
from .workspace import make_engagement_id, open_workspace

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="birdseye / skrecon - authorized recon orchestrator for Stormkeep engagements.",
)
console = Console()

# External tools wrapped in later phases; preflight reports their availability now.
KNOWN_TOOLS: dict[str, str] = {
    "dnstwist": "typosquatting (Phase 1)",
    "subfinder": "passive subdomains (Phase 2)",
    "theHarvester": "email/persona OSINT (Phase 2)",
    "masscan": "port discovery (Phase 3)",
    "nmap": "service/OS detection (Phase 3)",
    "sslyze": "TLS analysis (Phase 4)",
    "whatweb": "tech fingerprint (Phase 4)",
    "gowitness": "screenshots (Phase 4)",
    "wafw00f": "WAF detection (Phase 4)",
    "nuclei": "templated vulns (Phase 4, opt-in)",
}


class PhaseChoice(str, Enum):
    passive = "passive"
    active = "active"
    all = "all"


class ReportFormat(str, Enum):
    md = "md"
    html = "html"
    both = "both"


def _default_config() -> Optional[Path]:
    p = Path("skrecon.toml")
    return p if p.exists() else None


def _load_settings(config: Optional[Path], overrides: Optional[dict] = None) -> Settings:
    cfg = config or _default_config()
    try:
        return Settings.load(cfg, overrides=overrides or {})
    except SkreconError as exc:
        console.print(f"[red]config error:[/red] {exc}")
        raise typer.Exit(code=2)


def _assets_from_scope(result: ScopeParseResult) -> list[Asset]:
    assets: list[Asset] = []
    for e in result.entries:
        normalized = e.hostname or e.network or e.raw
        assets.append(
            Asset(
                raw_entry=e.raw,
                kind=AssetKind(e.kind),
                normalized=normalized,
                in_scope=True,
                line_no=e.line_no,
            )
        )
    return assets


def _print_scope_result(result: ScopeParseResult, *, expand: bool, limit: int) -> None:
    table = Table(title="Parsed scope entries", show_lines=False)
    table.add_column("line", justify="right", style="dim")
    table.add_column("kind")
    table.add_column("normalized")
    table.add_column("raw", style="dim")
    for e in result.entries:
        table.add_row(str(e.line_no), e.kind, e.hostname or e.network or "", e.raw)
    console.print(table)

    s = result.scope
    console.print(
        f"[bold]Resolved scope:[/bold] {len(s.hostnames)} hostname(s), "
        f"{len(s.networks)} network(s)."
    )
    if s.networks:
        console.print("  networks: " + ", ".join(str(n) for n in s.networks))

    if result.errors:
        console.print(f"\n[yellow]{len(result.errors)} malformed line(s) reported (not dropped silently):[/yellow]")
        for line_no, raw, reason in result.errors:
            console.print(f"  [red]line {line_no}[/red]: {raw!r} - {reason}")

    if expand:
        hosts, truncated = s.expanded_hosts(limit=limit)
        note = " (truncated)" if truncated else ""
        console.print(f"\n[bold]CIDR expansion preview[/bold] ({len(hosts)} host(s){note}):")
        console.print("  " + ", ".join(hosts[:limit]) if hosts else "  (none)")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command()
def version() -> None:
    """Show the skrecon version."""
    console.print(f"skrecon (birdseye) {__version__}")


scope_app = typer.Typer(help="Inspect a scope.txt.")
app.add_typer(scope_app, name="scope")


@scope_app.command("check")
def scope_check(
    path: Path = typer.Argument(..., help="Path to scope.txt"),
    expand: bool = typer.Option(False, "--expand", help="Preview CIDR expansion into host IPs."),
    max_hosts: int = typer.Option(256, "--max-hosts", help="Expansion preview cap."),
) -> None:
    """Parse & normalize a scope file exactly as the guard will enforce it."""
    try:
        result = parse_scope_file(path, max_expanded_hosts=max_hosts)
    except SkreconError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2)
    _print_scope_result(result, expand=expand, limit=max_hosts)
    if result.scope.is_empty():
        console.print("[red]No valid in-scope entries.[/red]")
        raise typer.Exit(code=1)


@app.command()
def preflight(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to skrecon.toml"),
) -> None:
    """Report configuration, API-key, and external-tool readiness."""
    settings = _load_settings(config)

    cfg_table = Table(title="Configuration", show_header=False)
    cfg_table.add_row("output_dir", str(settings.output_dir))
    cfg_table.add_row("client", settings.client or "[dim]unset[/dim]")
    cfg_table.add_row("include_subdomains", str(settings.include_subdomains))
    cfg_table.add_row("max_expanded_hosts", str(settings.max_expanded_hosts))
    cfg_table.add_row("enable_axfr / enable_udp", f"{settings.enable_axfr} / {settings.enable_udp}")
    cfg_table.add_row("retention_days", str(settings.retention_days))
    cfg_table.add_row("masscan_pps", str(settings.rates.masscan_pps))
    console.print(cfg_table)

    warn = settings.masscan_rate_warning()
    if warn:
        console.print(f"[yellow]warning:[/yellow] {warn}")

    keys = settings.present_api_keys()
    key_table = Table(title="API providers")
    key_table.add_column("provider")
    key_table.add_column("env var(s)")
    key_table.add_column("status")
    for provider, vars_ in KNOWN_API_KEYS.items():
        if provider not in IMPLEMENTED_PROVIDERS:
            status = "[dim]deferred (v1)[/dim]"
        elif keys.get(provider):
            status = "[green]ready[/green]"
        else:
            status = "[yellow]skipped (missing key)[/yellow]"
        key_table.add_row(provider, ", ".join(vars_), status)
    console.print(key_table)

    tool_table = Table(title="External tools")
    tool_table.add_column("tool")
    tool_table.add_column("used for")
    tool_table.add_column("status")
    for tool, purpose in KNOWN_TOOLS.items():
        found = shutil.which(tool)
        status = f"[green]found[/green] ({found})" if found else "[yellow]missing[/yellow]"
        tool_table.add_row(tool, purpose, status)
    console.print(tool_table)

    mod_table = Table(title="Registered recon modules")
    mod_table.add_column("module")
    mod_table.add_column("phase")
    mod_table.add_column("needs")
    mod_table.add_column("enabled")
    for m in REGISTRY.all():
        needs = ", ".join(list(m.requires_tools) + list(m.requires_keys)) or "-"
        enabled = settings.module_enabled(m.name, default=getattr(m, "default_enabled", True))
        mod_table.add_row(m.name, m.phase.value, needs, "yes" if enabled else "no")
    console.print(mod_table)
    console.print(f"[dim]{len(REGISTRY)} module(s) registered.[/dim]")


@app.command()
def init(
    client: str = typer.Option(..., "--client", help="Client organization / brand name."),
    auth_ref: str = typer.Option(..., "--auth-ref", help="Authorization / ticket reference."),
    tester: str = typer.Option(..., "--tester", help="Tester name/handle."),
    scope: Path = typer.Option(..., "--scope", help="Path to scope.txt."),
    engagement_id: Optional[str] = typer.Option(None, "--id", help="Engagement id (generated if omitted)."),
    start: Optional[str] = typer.Option(None, "--start", help="Engagement start (ISO 8601)."),
    end: Optional[str] = typer.Option(None, "--end", help="Engagement end (ISO 8601)."),
    retention_days: Optional[int] = typer.Option(None, "--retention-days", help="PII retention window."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", help="Override output directory."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to skrecon.toml"),
) -> None:
    """Create an engagement: metadata + scope + audit DB."""
    overrides: dict = {}
    if output_dir:
        overrides["output_dir"] = output_dir
    if retention_days is not None:
        overrides["retention_days"] = retention_days
    settings = _load_settings(config, overrides)

    try:
        result = parse_scope_file(scope, max_expanded_hosts=settings.max_expanded_hosts)
    except SkreconError as exc:
        console.print(f"[red]scope error:[/red] {exc}")
        raise typer.Exit(code=2)

    if result.errors:
        console.print(f"[yellow]{len(result.errors)} malformed scope line(s):[/yellow]")
        for line_no, raw, reason in result.errors:
            console.print(f"  line {line_no}: {raw!r} - {reason}")
    if result.scope.is_empty():
        console.print("[red]refusing to create engagement: no valid in-scope entries.[/red]")
        raise typer.Exit(code=1)

    eid = engagement_id or make_engagement_id(client)
    meta = EngagementMeta.from_dict(
        {
            "id": eid,
            "client": client,
            "auth_ref": auth_ref,
            "tester": tester,
            "start": start,
            "end": end,
            "retention_days": settings.retention_days,
            "blackout": settings.blackout,
        }
    )

    ws = open_workspace(settings.output_dir, eid)
    if ws.exists():
        console.print(f"[red]engagement already exists:[/red] {ws.root}")
        raise typer.Exit(code=1)
    ws.create()
    ws.write_meta(meta)
    ws.write_scope(scope.read_text(encoding="utf-8"))

    with EngagementStore(ws.db_path) as store:
        store.upsert_engagement(meta)
        added = store.add_assets(_assets_from_scope(result))

    audit = AuditLog(ws.audit_path, secrets=settings.secret_values())
    audit.record(module="core", action="engagement-init", outcome="created",
                 detail=f"id={eid} assets={added}")

    console.print(f"[green]created engagement[/green] [bold]{eid}[/bold] at {ws.root}")
    console.print(f"  client={client}  auth_ref={auth_ref}  tester={tester}")
    console.print(f"  scope: {len(result.scope.hostnames)} host(s), {len(result.scope.networks)} network(s); {added} asset(s) stored")
    if meta.blackout_windows:
        console.print(f"  blackout windows: {', '.join(w.label() for w in meta.blackout_windows)}")
    console.print(f"\nNext: [bold]skrecon run --engagement {eid} --dry-run[/bold]")


@app.command()
def run(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement id."),
    phase: PhaseChoice = typer.Option(PhaseChoice.passive, "--phase", help="Which phase(s) to run."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan every action without executing."),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore checkpoints and re-run completed modules."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized",
        help="Explicit authorization confirmation required for the ACTIVE phase.",
    ),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", help="Override output directory."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to skrecon.toml"),
) -> None:
    """Orchestrate an engagement's passive/active modules through the safety path."""
    overrides: dict = {"output_dir": output_dir} if output_dir else {}
    settings = _load_settings(config, overrides)

    ws = open_workspace(settings.output_dir, engagement_id)
    if not ws.exists():
        console.print(f"[red]no such engagement:[/red] {ws.root}  (run `skrecon init` first)")
        raise typer.Exit(code=1)

    meta = ws.read_meta()
    result = parse_scope_text(ws.read_scope_text(), max_expanded_hosts=settings.max_expanded_hosts)
    scope = result.scope

    store = EngagementStore(ws.db_path)
    audit = AuditLog(ws.audit_path, secrets=settings.secret_values())
    # Mirror audit lines into the DB for queryability (best-effort).
    audit.echo = lambda line: _safe_mirror(store, line)

    guard = ScopeGuard(scope=scope, audit=audit, include_subdomains=settings.include_subdomains)
    gate = ActiveGate(authorized=i_am_authorized, audit=audit, engagement=meta)
    executor = GuardedExecutor(guard=guard, gate=gate, audit=audit, dry_run=dry_run)
    http = GuardedHttp(guard=guard, audit=audit, gate=gate, dry_run=dry_run)
    cache = Cache(ws.cache_dir, ttl_seconds=settings.cache_ttl_hours * 3600)
    resolver = PassiveResolver(audit=audit, cache=cache, timeout=settings.dns_timeout,
                               nameservers=settings.dns_nameservers)
    http_passive = PassiveHttp(audit=audit, cache=cache, timeout=settings.http_timeout)
    vault = EncryptedVault(ws.vault_dir, os.environ.get("SKRECON_VAULT_PASSPHRASE"))

    # Auto-purge PII once the retention window has elapsed (spec §9.6).
    if vault.is_expired(meta.retention_days):
        removed = vault.purge()
        if removed:
            audit.record(module="core", action="retention-purge", outcome="purged",
                         detail=f"retention {meta.retention_days}d elapsed; removed {len(removed)} file(s)")
            console.print(f"  [yellow]retention window elapsed — purged encrypted vault "
                          f"({len(removed)} file(s)).[/yellow]")

    ctx = Context(
        settings=settings, engagement=meta, scope=scope, guard=guard, gate=gate,
        executor=executor, http=http, store=store, audit=audit,
        resolver=resolver, http_passive=http_passive, cache=cache, vault=vault,
        raw_dir=ws.raw_dir,
    )

    phases = {
        PhaseChoice.passive: [Phase.PASSIVE],
        PhaseChoice.active: [Phase.ACTIVE],
        PhaseChoice.all: [Phase.PASSIVE, Phase.ACTIVE],
    }[phase]

    # --- engagement header ---
    console.print(f"[bold]Engagement[/bold] {meta.id}  client={meta.client}  tester={meta.tester}")
    console.print(f"  scope: {len(scope.hostnames)} host(s), {len(scope.networks)} network(s)")
    console.print(f"  phase(s): {', '.join(p.value for p in phases)}   dry-run: {dry_run}")

    blackout = meta.is_blackout()
    if blackout:
        console.print(f"  [yellow]currently inside blackout window:[/yellow] {blackout.label()}")

    exit_code = 0
    try:
        for ph in phases:
            modules = [m for m in REGISTRY.by_phase(ph)
                       if settings.module_enabled(m.name, default=getattr(m, "default_enabled", True))]
            console.print(f"\n[bold]{ph.value} phase[/bold]: {len(modules)} module(s)")

            if ph is Phase.ACTIVE and not dry_run:
                # Enforce the authorization + blackout gate before any active work.
                gate.ensure_active_allowed()
                console.print("  [green]authorization gate satisfied.[/green]")

            if not modules:
                console.print("  [dim](no modules registered/enabled for this phase)[/dim]")
                continue

            run_phase(ctx, modules, dry_run=dry_run, resume=not fresh, on_event=_pipeline_event)
    except NotAuthorizedError as exc:
        console.print(f"\n[red]refused:[/red] {exc}")
        console.print("  provide [bold]--i-am-authorized[/bold] and recorded engagement metadata to run the active phase.")
        exit_code = 3
    except BlackoutError as exc:
        console.print(f"\n[red]refused:[/red] {exc}")
        exit_code = 3
    except SkreconError as exc:
        console.print(f"\n[red]error:[/red] {exc}")
        exit_code = 2
    finally:
        if not dry_run:
            _print_findings_summary(store)
            write_reports(store, ws.exports_dir, fmt="both")
        store.export_json(ws.exports_dir / "engagement.json")
        store.close()

    console.print(f"\naudit log: {ws.audit_path}")
    console.print(f"export:    {ws.exports_dir / 'engagement.json'}")
    if not dry_run:
        console.print(f"report:    {ws.exports_dir / 'report.html'}  (+ report.md)")
    if exit_code:
        raise typer.Exit(code=exit_code)


def _pipeline_event(event: dict) -> None:
    kind = event["kind"]
    name = event["module"]
    if kind == "skip":
        console.print(f"  [yellow]skip[/yellow] {name}: {escape(str(event.get('reason')))}")
    elif kind == "plan":
        actions = event.get("actions", [])
        tag = ""
        if not event.get("ready", True):
            tag = f"  [yellow](would skip: {escape(str(event.get('reason')))})[/yellow]"
        console.print(f"  [cyan]plan[/cyan] {name}: {len(actions)} action(s){tag}")
        for a in actions:
            console.print(f"      - {escape(a.description)}")
            if a.command:
                console.print(f"        [dim]{escape(a.command)}[/dim]")
    elif kind == "run":
        console.print(f"  [green]run[/green]  {name} ...")
    elif kind == "done":
        console.print(f"  [green]done[/green] {name}: {event['records']} record(s), "
                      f"{event['findings']} finding(s)")
    elif kind == "error":
        console.print(f"  [red]error[/red] {name}: {escape(str(event.get('reason')))}")


_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _print_findings_summary(store: EngagementStore) -> None:
    findings = store.list_findings()
    if not findings:
        return
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    summary = "  ".join(
        f"[{_SEV_STYLE.get(s, '')}]{s}: {counts[s]}[/]" for s in order if s in counts
    )
    console.print(f"\n[bold]Findings[/bold] ({len(findings)}):  {summary}")
    for f in findings[:12]:
        sev = f["severity"]
        console.print(f"  [{_SEV_STYLE.get(sev, '')}]{sev:>8}[/] {f['finding_type']:24} "
                      f"{', '.join(f['affected'])}")
    if len(findings) > 12:
        console.print(f"  [dim]... and {len(findings) - 12} more (see export)[/dim]")


def _safe_mirror(store: EngagementStore, line: str) -> None:
    try:
        store.add_audit_event(json.loads(line))
    except Exception:  # noqa: BLE001 — mirroring must never break a run
        pass


engagement_app = typer.Typer(help="Engagement lifecycle (status / close).")
app.add_typer(engagement_app, name="engagement")


def _open_engagement(engagement_id: str, output_dir: Optional[Path], config: Optional[Path]):
    overrides = {"output_dir": output_dir} if output_dir else {}
    settings = _load_settings(config, overrides)
    ws = open_workspace(settings.output_dir, engagement_id)
    if not ws.exists():
        console.print(f"[red]no such engagement:[/red] {ws.root}")
        raise typer.Exit(code=1)
    return settings, ws, ws.read_meta()


def _vault_line(vault: EncryptedVault, meta) -> str:
    created = vault.created_at()
    if not vault.has_data():
        return "encrypted vault: [dim]empty[/dim]"
    due = (created + timedelta(days=meta.retention_days)).date().isoformat() if created else "n/a"
    if vault.available():
        counts = f"breach={vault.count('breach')} persona={vault.count('persona')}"
    else:
        counts = "[yellow]locked[/yellow] (set SKRECON_VAULT_PASSPHRASE to view)"
    return f"encrypted vault: {counts}; retained until {due} (retention {meta.retention_days}d)"


@engagement_app.command("status")
def engagement_status(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement id."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Show engagement metadata, counts, and vault/retention status."""
    _settings, ws, meta = _open_engagement(engagement_id, output_dir, config)
    vault = EncryptedVault(ws.vault_dir, os.environ.get("SKRECON_VAULT_PASSPHRASE"))
    console.print(f"[bold]{meta.id}[/bold]  client={meta.client}  auth_ref={meta.auth_ref}  tester={meta.tester}")
    with EngagementStore(ws.db_path) as store:
        console.print(f"  counts: {store.counts()}")
    console.print(f"  {_vault_line(vault, meta)}")


@engagement_app.command("close")
def engagement_close(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement id."),
    purge_now: bool = typer.Option(False, "--purge-now", help="Purge the encrypted vault immediately."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Close the engagement; purge PII now or when its retention window elapses."""
    settings, ws, meta = _open_engagement(engagement_id, output_dir, config)
    vault = EncryptedVault(ws.vault_dir, os.environ.get("SKRECON_VAULT_PASSPHRASE"))
    audit = AuditLog(ws.audit_path, secrets=settings.secret_values())

    expired = vault.is_expired(meta.retention_days)
    if purge_now or expired:
        removed = vault.purge()
        reason = "operator requested" if purge_now else "retention window elapsed"
        audit.record(module="core", action="engagement-close", outcome="purged",
                     detail=f"{reason}; removed {len(removed)} vault file(s)")
        console.print(f"[green]engagement closed[/green]; encrypted vault purged "
                      f"({len(removed)} file(s); {reason}).")
    else:
        created = vault.created_at()
        due = (created + timedelta(days=meta.retention_days)).date().isoformat() if created else "n/a"
        audit.record(module="core", action="engagement-close", outcome="closed",
                     detail=f"vault retained until {due}")
        console.print(f"[green]engagement closed[/green]. {_vault_line(vault, meta)}")
        console.print("  vault auto-purges on the next run after that date, or use "
                      "[bold]--purge-now[/bold] to purge immediately.")


@app.command()
def report(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement id."),
    fmt: ReportFormat = typer.Option(ReportFormat.both, "--format", help="md | html | both."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Render the Markdown/HTML report from an engagement's stored results."""
    _settings, ws, _meta = _open_engagement(engagement_id, output_dir, config)
    with EngagementStore(ws.db_path) as store:
        written = write_reports(store, ws.exports_dir, fmt=fmt.value)
    for p in written:
        console.print(f"[green]wrote[/green] {p}")


@app.command()
def diff(
    old: str = typer.Option(..., "--old", help="Baseline engagement id."),
    new: str = typer.Option(..., "--new", help="Retest engagement id."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Compare two engagements over the same scope (retest deltas)."""
    settings = _load_settings(config, {"output_dir": output_dir} if output_dir else {})
    ws_old = open_workspace(settings.output_dir, old)
    ws_new = open_workspace(settings.output_dir, new)
    for ws_, name in ((ws_old, old), (ws_new, new)):
        if not ws_.exists():
            console.print(f"[red]no such engagement:[/red] {name}")
            raise typer.Exit(code=1)
    with EngagementStore(ws_old.db_path) as o, EngagementStore(ws_new.db_path) as n:
        delta = diff_engagements(o, n)
    console.print(f"[bold]diff {old} -> {new}[/bold]")
    console.print(render_diff_text(delta))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
