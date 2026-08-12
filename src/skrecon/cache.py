"""Tiny on-disk cache for expensive passive lookups (spec §6 "cache expensive lookups").

Keyed by a namespaced string, stored as JSON under the engagement's cache/ dir with
a timestamp, expired by TTL. Re-runs of DNS/RDAP/CT lookups don't re-hit the network
(or re-bill APIs). A disabled cache (no directory) is a transparent no-op.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional


class Cache:
    def __init__(self, directory: Optional[Path], ttl_seconds: float) -> None:
        self.dir = Path(directory) if directory else None
        self.ttl = ttl_seconds
        if self.dir is not None:
            self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Optional[Path]:
        if self.dir is None:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return self.dir / f"{digest}.json"

    def get(self, key: str) -> Optional[Any]:
        path = self._path(key)
        if path is None or not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if self.ttl >= 0 and (time.time() - payload.get("ts", 0)) > self.ttl:
            return None
        return payload.get("value")

    def set(self, key: str, value: Any) -> None:
        path = self._path(key)
        if path is None:
            return
        try:
            path.write_text(json.dumps({"ts": time.time(), "value": value}), encoding="utf-8")
        except (OSError, TypeError):
            pass  # caching is best-effort; never fail a lookup because the cache failed
