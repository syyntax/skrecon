"""The module plugin contract (spec §6).

Every recon capability implements `Module`. New modules register themselves and
declare their phase, tool/key dependencies, and ordering — the core schedules them
and injects a `Context` that carries the *only* sanctioned routes to a target
(the guard, gate, and guarded executor). A module physically cannot reach the
network except through those.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Protocol, runtime_checkable

from ..audit import AuditLog
from ..config import Settings
from ..engagement import EngagementMeta
from ..guard import ActiveGate, GuardedExecutor, GuardedHttp, ScopeGuard
from ..model import Phase
from ..scope import ResolvedScope
from ..store import EngagementStore


@dataclass
class Readiness:
    ready: bool
    skipped_reason: Optional[str] = None

    @classmethod
    def ok(cls) -> "Readiness":
        return cls(True, None)

    @classmethod
    def skip(cls, reason: str) -> "Readiness":
        return cls(False, reason)


@dataclass
class Action:
    """A single planned unit of work, surfaced by --dry-run."""
    description: str
    phase: Phase
    targets: list[str] = field(default_factory=list)
    command: Optional[str] = None      # exact command / endpoint (redacted for secrets)


@dataclass
class Context:
    """Everything a module is given. The guard/gate/executor are the only ways
    to reach a target; `http_passive` is for third-party OSINT APIs only."""
    settings: Settings
    engagement: EngagementMeta
    scope: ResolvedScope
    guard: ScopeGuard
    gate: ActiveGate
    executor: GuardedExecutor
    http: GuardedHttp
    store: EngagementStore
    audit: AuditLog
    cache: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Module(Protocol):
    name: str
    phase: Phase
    touches_targets: bool
    requires_tools: list[str]
    requires_keys: list[str]
    depends_on: list[str]
    default_enabled: bool

    def preflight(self, ctx: Context) -> Readiness: ...
    def plan(self, ctx: Context) -> list[Action]: ...
    def run(self, ctx: Context) -> Iterable[Any]: ...


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, Module] = {}

    def register(self, module: Module) -> Module:
        if module.name in self._modules:
            raise ValueError(f"duplicate module name: {module.name}")
        self._modules[module.name] = module
        return module

    def get(self, name: str) -> Optional[Module]:
        return self._modules.get(name)

    def all(self) -> list[Module]:
        return list(self._modules.values())

    def by_phase(self, phase: Phase) -> list[Module]:
        return [m for m in self._modules.values() if m.phase is phase]

    def __len__(self) -> int:
        return len(self._modules)


# Process-wide registry. Phase 1+ modules append to this at import time.
REGISTRY = ModuleRegistry()
