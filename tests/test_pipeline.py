"""Scheduler behavior (spec §6 orchestration, §2.7 graceful degradation)."""

from __future__ import annotations

from types import SimpleNamespace

from skrecon.audit import AuditLog
from skrecon.findings import make_finding
from skrecon.model import Phase
from skrecon.modules.base import Action, Readiness
from skrecon.pipeline import run_phase, toposort
from skrecon.scope import parse_scope_text
from skrecon.store import EngagementStore


class FakeModule:
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list = []
    requires_keys: list = []
    default_enabled = True

    def __init__(self, name, deps=(), findings=0, fail=False, ready=True):
        self.name = name
        self.depends_on = list(deps)
        self._findings = findings
        self._fail = fail
        self._ready = ready
        self.ran = 0

    def preflight(self, ctx):
        return Readiness.ok() if self._ready else Readiness.skip("not ready")

    def plan(self, ctx):
        return [Action(f"plan {self.name}", Phase.PASSIVE)]

    def run(self, ctx):
        self.ran += 1
        if self._fail:
            raise RuntimeError("boom")
        for i in range(self._findings):
            yield make_finding("dns.dnssec.missing", affected=[f"{self.name}-{i}.example.com"],
                               evidence=["e"], source_module=self.name,
                               title_ctx={"domain": f"{self.name}-{i}.example.com"})


def make_ctx(tmp_path):
    store = EngagementStore(tmp_path / "s.db")
    audit = AuditLog(path=None)
    scope = parse_scope_text("example.com\n").scope
    return SimpleNamespace(store=store, audit=audit, scope=scope)


def test_toposort_respects_dependencies():
    dns = FakeModule("dns")
    rev = FakeModule("reverse-dns", deps=["dns"])
    order = [m.name for m in toposort([rev, dns])]
    assert order.index("dns") < order.index("reverse-dns")


def test_run_persists_findings(tmp_path):
    ctx = make_ctx(tmp_path)
    results = run_phase(ctx, [FakeModule("dns", findings=3)], on_event=None)
    assert results[0].status == "done"
    assert results[0].findings == 3
    assert ctx.store.counts()["finding"] == 3


def test_failure_is_isolated(tmp_path):
    ctx = make_ctx(tmp_path)
    good = FakeModule("dns", findings=1)
    bad = FakeModule("reverse-dns", deps=["dns"], fail=True)
    good2 = FakeModule("mail", findings=1)
    results = {r.module: r for r in run_phase(ctx, [good, bad, good2])}
    assert results["reverse-dns"].status == "failed"
    assert results["dns"].status == "done"
    assert results["mail"].status == "done"       # run continued past the failure
    assert good2.ran == 1


def test_resume_skips_completed(tmp_path):
    ctx = make_ctx(tmp_path)
    mod = FakeModule("dns", findings=1)
    run_phase(ctx, [mod])
    run_phase(ctx, [mod], resume=True)
    assert mod.ran == 1                            # not re-run on the second pass


def test_dry_run_plans_without_running(tmp_path):
    ctx = make_ctx(tmp_path)
    mod = FakeModule("dns", findings=5)
    results = run_phase(ctx, [mod], dry_run=True)
    assert results[0].status == "planned"
    assert mod.ran == 0
    assert ctx.store.counts()["finding"] == 0


def test_skipped_module_not_run(tmp_path):
    ctx = make_ctx(tmp_path)
    mod = FakeModule("dns", ready=False)
    results = run_phase(ctx, [mod])
    assert results[0].status == "skipped"
    assert mod.ran == 0


def test_dry_run_plans_even_when_not_ready(tmp_path):
    # A tool that only exists in Docker (masscan) still shows its plan in dry-run.
    ctx = make_ctx(tmp_path)
    mod = FakeModule("masscan", ready=False)
    results = run_phase(ctx, [mod], dry_run=True)
    assert results[0].status == "planned"
    assert mod.ran == 0
