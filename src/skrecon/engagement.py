"""Engagement metadata and blackout-window evaluation (spec §3.3, §9.4).

Metadata is recorded with results (report header + audit anchor). Blackout windows
gate the ACTIVE phase: `is_blackout(now)` returning True means active scanning is
refused. Supports absolute ISO ranges and recurring daily windows with weekdays and
a timezone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import ConfigError
from .model import Engagement, utcnow

_WEEKDAYS = {
    "mon": 0, "monday": 0,
    "tue": 1, "tuesday": 1,
    "wed": 2, "wednesday": 2,
    "thu": 3, "thursday": 3,
    "fri": 4, "friday": 4,
    "sat": 5, "saturday": 5,
    "sun": 6, "sunday": 6,
}


def _parse_dt(value: Any, field_name: str) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    if isinstance(value, str):
        raw = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ConfigError(f"{field_name}: invalid datetime {value!r}") from exc
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise ConfigError(f"{field_name}: unsupported datetime value {value!r}")


def _parse_time(value: str, field_name: str) -> time:
    try:
        parts = value.strip().split(":")
        return time(int(parts[0]), int(parts[1]))
    except (ValueError, AttributeError, IndexError) as exc:
        raise ConfigError(f"{field_name}: invalid time {value!r} (want HH:MM)") from exc


_WEEKDAY_ABBR = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}


def _get_tz(name: str):
    """Resolve a timezone. UTC needs no tz database (works everywhere); other
    zones require the IANA db (stdlib zoneinfo, plus the `tzdata` package on
    platforms like Windows that lack a system copy)."""
    if name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(
            f"blackout: timezone {name!r} unavailable "
            "(install the 'tzdata' package for non-UTC zones on this platform)"
        ) from exc


def _parse_weekdays(values: Any) -> frozenset[int]:
    if not values:
        return frozenset()
    out: set[int] = set()
    for v in values:
        key = str(v).strip().lower()
        if key not in _WEEKDAYS:
            raise ConfigError(f"blackout: unknown weekday {v!r}")
        out.add(_WEEKDAYS[key])
    return frozenset(out)


@dataclass
class BlackoutWindow:
    """Either an absolute [start, end] range or a recurring daily window."""
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    daily_start: Optional[time] = None
    daily_end: Optional[time] = None
    weekdays: frozenset[int] = field(default_factory=frozenset)
    tz: str = "UTC"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BlackoutWindow":
        tz = str(d.get("tz", "UTC"))
        _get_tz(tz)  # validate now (raises ConfigError if unavailable)
        w = cls(
            start=_parse_dt(d.get("start"), "blackout.start"),
            end=_parse_dt(d.get("end"), "blackout.end"),
            daily_start=_parse_time(d["daily_start"], "blackout.daily_start")
            if d.get("daily_start") else None,
            daily_end=_parse_time(d["daily_end"], "blackout.daily_end")
            if d.get("daily_end") else None,
            weekdays=_parse_weekdays(d.get("weekdays")),
            tz=tz,
        )
        w.validate()
        return w

    def validate(self) -> None:
        has_absolute = self.start is not None or self.end is not None
        has_daily = self.daily_start is not None or self.daily_end is not None
        if not has_absolute and not has_daily:
            raise ConfigError("blackout: window has neither absolute range nor daily times")
        if has_absolute and (self.start is None or self.end is None):
            raise ConfigError("blackout: absolute window needs both start and end")
        if has_daily and (self.daily_start is None or self.daily_end is None):
            raise ConfigError("blackout: daily window needs both daily_start and daily_end")
        if has_absolute and self.start > self.end:  # type: ignore[operator]
            raise ConfigError("blackout: start is after end")

    def contains(self, now: datetime) -> bool:
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if self.start is not None and self.end is not None:
            if self.start <= now <= self.end:
                return True
        if self.daily_start is not None and self.daily_end is not None:
            local = now.astimezone(_get_tz(self.tz))
            if self.weekdays and local.weekday() not in self.weekdays:
                return False
            t = local.time()
            if self.daily_start <= self.daily_end:
                return self.daily_start <= t <= self.daily_end
            # window wraps past midnight
            return t >= self.daily_start or t <= self.daily_end
        return False

    def label(self) -> str:
        if self.start is not None and self.end is not None:
            return f"{self.start.isoformat()}..{self.end.isoformat()}"
        days = ",".join(_WEEKDAY_ABBR[w] for w in sorted(self.weekdays)) if self.weekdays else "daily"
        return f"{days} {self.daily_start}-{self.daily_end} {self.tz}"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"tz": self.tz}
        if self.start is not None and self.end is not None:
            d["start"] = self.start.isoformat()
            d["end"] = self.end.isoformat()
        if self.daily_start is not None and self.daily_end is not None:
            d["daily_start"] = self.daily_start.strftime("%H:%M")
            d["daily_end"] = self.daily_end.strftime("%H:%M")
            if self.weekdays:
                d["weekdays"] = [_WEEKDAY_ABBR[w] for w in sorted(self.weekdays)]
        return d


@dataclass
class EngagementMeta:
    """Runtime engagement object (metadata + blackout windows)."""
    id: str
    client: str
    auth_ref: str
    tester: str
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    retention_days: int = 90
    blackout_windows: list[BlackoutWindow] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EngagementMeta":
        missing = [k for k in ("id", "client", "auth_ref", "tester") if not d.get(k)]
        if missing:
            raise ConfigError(f"engagement metadata missing required field(s): {', '.join(missing)}")
        windows = [BlackoutWindow.from_dict(w) for w in d.get("blackout", [])]
        return cls(
            id=str(d["id"]),
            client=str(d["client"]),
            auth_ref=str(d["auth_ref"]),
            tester=str(d["tester"]),
            start=_parse_dt(d.get("start"), "engagement.start"),
            end=_parse_dt(d.get("end"), "engagement.end"),
            retention_days=int(d.get("retention_days", 90)),
            blackout_windows=windows,
        )

    def is_blackout(self, now: Optional[datetime] = None) -> Optional[BlackoutWindow]:
        """Return the first matching blackout window, or None."""
        now = now or utcnow()
        for w in self.blackout_windows:
            if w.contains(now):
                return w
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "client": self.client,
            "auth_ref": self.auth_ref,
            "tester": self.tester,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "retention_days": self.retention_days,
            "blackout": [w.to_dict() for w in self.blackout_windows],
        }

    def to_record(self) -> Engagement:
        return Engagement(
            id=self.id,
            client=self.client,
            auth_ref=self.auth_ref,
            tester=self.tester,
            start=self.start,
            end=self.end,
            retention_days=self.retention_days,
        )
