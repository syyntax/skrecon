"""Module scheduler / DAG runner (spec §6 orchestration, §2.7 graceful degradation).

Orders modules by their `depends_on`, runs independent ones in a stable order,
persists every yielded record, checkpoints each module for resumability, and
isolates failures so one dead module never aborts the run.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from .model import Checkpoint, Finding, utcnow


@dataclass
class ModuleResult:
    module: str
    status: str                      # done | skipped | failed | planned
    records: int = 0
    findings: int = 0
    reason: Optional[str] = None
    actions: list = field(default_factory=list)


def toposort(modules: list) -> list:
    """Kahn's algorithm over depends_on (edges to modules outside the set are
    ignored). Ties broken by name for determinism; cycles fall back to name order."""
    by_name = {m.name: m for m in modules}
    indeg = {m.name: 0 for m in modules}
    edges: dict[str, list[str]] = {m.name: [] for m in modules}
    for m in modules:
        for dep in getattr(m, "depends_on", []) or []:
            if dep in by_name:
                edges[dep].append(m.name)
                indeg[m.name] += 1
    queue = sorted(n for n, d in indeg.items() if d == 0)
    order: list = []
    while queue:
        n = queue.pop(0)
        order.append(by_name[n])
        newly = []
        for nb in edges[n]:
            indeg[nb] -= 1
            if indeg[nb] == 0:
                newly.append(nb)
        queue = sorted(queue + newly)
    if len(order) != len(modules):  # dependency cycle — degrade deterministically
        seen = {m.name for m in order}
        order.extend(sorted((m for m in modules if m.name not in seen), key=lambda m: m.name))
    return order


def input_hash(ctx) -> str:
    """Checkpoint key: stable for the same scope so resume skips completed work."""
    payload = json.dumps(ctx.scope.summary(), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def run_phase(
    ctx,
    modules: list,
    *,
    dry_run: bool = False,
    resume: bool = True,
    on_event: Optional[Callable[[dict[str, Any]], None]] = None,
) -> list[ModuleResult]:
    emit = on_event or (lambda e: None)
    results: list[ModuleResult] = []
    ih = input_hash(ctx)

    for m in toposort(modules):
        ready = m.preflight(ctx)
        if not ready.ready:
            ctx.audit.record(module=m.name, action="preflight", outcome="skipped",
                             detail=ready.skipped_reason)
            emit({"kind": "skip", "module": m.name, "reason": ready.skipped_reason})
            results.append(ModuleResult(m.name, "skipped", reason=ready.skipped_reason))
            continue

        if dry_run:
            actions = list(m.plan(ctx))
            emit({"kind": "plan", "module": m.name, "actions": actions})
            results.append(ModuleResult(m.name, "planned", records=len(actions), actions=actions))
            continue

        if resume and ctx.store.is_done(m.name, ih):
            emit({"kind": "skip", "module": m.name, "reason": "already completed (resume)"})
            results.append(ModuleResult(m.name, "skipped", reason="resume"))
            continue

        ctx.store.set_checkpoint(Checkpoint(m.name, ih, status="running", started_at=utcnow()))
        emit({"kind": "run", "module": m.name})
        n = nf = 0
        try:
            for rec in m.run(ctx):
                ctx.store.persist(rec)
                n += 1
                if isinstance(rec, Finding):
                    nf += 1
        except Exception as exc:  # noqa: BLE001 — a module failure must not abort the run
            ctx.store.set_checkpoint(
                Checkpoint(m.name, ih, status="failed", started_at=utcnow(), finished_at=utcnow()))
            ctx.audit.record(module=m.name, action="run", outcome="error", detail=str(exc))
            emit({"kind": "error", "module": m.name, "reason": str(exc)})
            results.append(ModuleResult(m.name, "failed", reason=str(exc)))
            continue

        ctx.store.set_checkpoint(
            Checkpoint(m.name, ih, status="done", started_at=utcnow(), finished_at=utcnow()))
        emit({"kind": "done", "module": m.name, "records": n, "findings": nf})
        results.append(ModuleResult(m.name, "done", records=n, findings=nf))

    return results
