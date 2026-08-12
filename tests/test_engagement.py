"""Engagement metadata + blackout-window evaluation (spec §3.3, §9.4)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from skrecon.engagement import EngagementMeta
from skrecon.errors import ConfigError

_INV = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}
BASE = {"id": "e1", "client": "Example", "auth_ref": "T-1", "tester": "alice"}


def meta(**over):
    d = dict(BASE)
    d.update(over)
    return EngagementMeta.from_dict(d)


def test_missing_required_fields_raise():
    with pytest.raises(ConfigError):
        EngagementMeta.from_dict({"client": "X"})  # no id/auth_ref/tester


def test_absolute_blackout_window():
    m = meta(blackout=[{"start": "2026-08-20T00:00:00Z", "end": "2026-08-21T00:00:00Z"}])
    assert m.is_blackout(datetime(2026, 8, 20, 12, tzinfo=timezone.utc)) is not None
    assert m.is_blackout(datetime(2026, 8, 22, 12, tzinfo=timezone.utc)) is None


def test_daily_blackout_with_weekdays():
    dt = datetime(2026, 8, 19, 12, tzinfo=timezone.utc)
    wd = dt.weekday()
    inside = meta(blackout=[{"daily_start": "09:00", "daily_end": "17:00",
                             "weekdays": [_INV[wd]]}])
    outside_day = meta(blackout=[{"daily_start": "09:00", "daily_end": "17:00",
                                  "weekdays": [_INV[(wd + 1) % 7]]}])
    assert inside.is_blackout(dt) is not None
    assert outside_day.is_blackout(dt) is None
    assert inside.is_blackout(dt.replace(hour=20)) is None    # outside the hours


def test_daily_blackout_wraps_past_midnight():
    m = meta(blackout=[{"daily_start": "22:00", "daily_end": "06:00"}])
    base = datetime(2026, 8, 19, tzinfo=timezone.utc)
    assert m.is_blackout(base.replace(hour=23)) is not None
    assert m.is_blackout(base.replace(hour=3)) is not None
    assert m.is_blackout(base.replace(hour=12)) is None


def test_unknown_timezone_rejected():
    with pytest.raises(ConfigError):
        meta(blackout=[{"daily_start": "09:00", "daily_end": "17:00", "tz": "Mars/Phobos"}])


def test_round_trip_serialization():
    m = meta(
        start="2026-08-01T00:00:00Z",
        blackout=[
            {"start": "2026-08-20T00:00:00+00:00", "end": "2026-08-21T00:00:00+00:00"},
            {"daily_start": "22:00", "daily_end": "06:00", "weekdays": ["mon", "fri"]},
        ],
    )
    m2 = EngagementMeta.from_dict(m.to_dict())
    assert m2.id == m.id
    assert m2.client == m.client
    assert len(m2.blackout_windows) == 2
