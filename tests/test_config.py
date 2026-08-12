"""Layered configuration precedence (spec §8)."""

from __future__ import annotations

from pathlib import Path

from skrecon.config import RateConfig, Settings


def write_toml(tmp_path: Path) -> Path:
    p = tmp_path / "skrecon.toml"
    p.write_text(
        "output_dir = 'out'\n"
        "retention_days = 45\n"
        "include_subdomains = true\n"
        "[rates]\n"
        "masscan_pps = 5000\n",
        encoding="utf-8",
    )
    return p


def test_defaults():
    s = Settings.load(None, env={})
    assert s.rates.masscan_pps == 1000
    assert s.retention_days == 90
    assert s.include_subdomains is False
    assert s.output_dir == Path("engagements")


def test_file_overrides_defaults(tmp_path):
    s = Settings.load(write_toml(tmp_path), env={})
    assert s.output_dir == Path("out")
    assert s.retention_days == 45
    assert s.include_subdomains is True
    assert s.rates.masscan_pps == 5000


def test_env_overrides_file(tmp_path):
    s = Settings.load(write_toml(tmp_path), env={"SKRECON_RETENTION_DAYS": "30"})
    assert s.retention_days == 30           # env beats file
    assert s.rates.masscan_pps == 5000      # untouched by env


def test_cli_overrides_env(tmp_path):
    s = Settings.load(
        write_toml(tmp_path),
        env={"SKRECON_RETENTION_DAYS": "30"},
        overrides={"retention_days": 7},
    )
    assert s.retention_days == 7            # CLI beats env beats file


def test_present_api_keys():
    s = Settings()
    keys = s.present_api_keys(env={"SHODAN_API_KEY": "x"})
    assert keys["shodan"] is True
    assert keys["dehashed"] is False        # needs BOTH key + email
    keys2 = s.present_api_keys(env={"DEHASHED_API_KEY": "k", "DEHASHED_EMAIL": "a@b.c"})
    assert keys2["dehashed"] is True


def test_secret_values_collected():
    s = Settings()
    vals = s.secret_values(env={"SHODAN_API_KEY": "abc123", "DEHASHED_EMAIL": "x@y.z"})
    assert "abc123" in vals


def test_masscan_rate_warning():
    s = Settings(rates=RateConfig(masscan_pps=30000))
    assert s.masscan_rate_warning() is not None
    assert Settings(rates=RateConfig(masscan_pps=1000)).masscan_rate_warning() is None
