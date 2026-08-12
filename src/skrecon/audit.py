"""Structured, timestamped, secret-redacted audit log (spec §7, §9.6).

Every command / API call / guard decision is recorded as one JSON line — the
engagement's evidentiary record. Secrets are redacted before anything is written.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from .model import Phase, utcnow

# Generic patterns that look like secrets even if we don't know the literal value.
# Each pattern has exactly two groups: group(1) is the prefix to keep, group(2) is
# the secret value to replace.
_SECRET_PATTERNS = [
    re.compile(r"(?i)((?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"),
    re.compile(r"(?i)((?:-p|--password)\s+)(\S+)"),
]

_REDACTED = "***REDACTED***"


@dataclass
class AuditLog:
    """Append-only JSONL audit log."""
    path: Optional[Path] = None
    secrets: tuple[str, ...] = ()
    echo: Optional[Any] = None          # optional callable(str) for live output
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def redact(self, text: Optional[str]) -> Optional[str]:
        if not text:
            return text
        out = text
        # Redact known literal secret values first (longest first to avoid partials).
        for secret in sorted((s for s in self.secrets if s), key=len, reverse=True):
            out = out.replace(secret, _REDACTED)
        # Then redact anything that structurally looks like a secret.
        for pat in _SECRET_PATTERNS:
            out = pat.sub(lambda m: m.group(1) + _REDACTED, out)
        return out

    def record(
        self,
        *,
        module: str,
        action: str,
        outcome: str,
        phase: Optional[Phase] = None,
        target: Optional[str] = None,
        command: Optional[str] = None,
        detail: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "ts": utcnow().isoformat(),
            "module": module,
            "action": action,
            "outcome": outcome,
            "phase": phase.value if isinstance(phase, Phase) else phase,
            "target": target,
            "command": self.redact(command),
            "detail": self.redact(detail),
        }
        if extra:
            event.update({k: self.redact(v) if isinstance(v, str) else v for k, v in extra.items()})
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            if self.echo is not None:
                self.echo(line)
        return event

    # Convenience wrappers for the most common outcomes.
    def refused(self, *, module: str, target: str, reason: str, phase: Optional[Phase] = None) -> None:
        self.record(module=module, action="target-refused", outcome="refused",
                    phase=phase, target=target, detail=reason)

    def allowed(self, *, module: str, target: str, phase: Optional[Phase] = None) -> None:
        self.record(module=module, action="target-allowed", outcome="allowed",
                    phase=phase, target=target)


def build_secrets(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(v for v in values if v)
