"""Layered configuration (spec §8).

Precedence (low → high):  built-in defaults → skrecon.toml → environment → CLI overrides.

Secrets are NEVER read from the config file. API keys come only from the
environment (loaded from a git-ignored .env by the operator's shell/tooling).
`present_api_keys()` reports which key-backed providers are available so preflight
can show what will run vs. be skipped.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from .errors import ConfigError

# Provider -> required env var(s). A provider is "available" only if ALL its vars
# are present. Censys/HIBP are declared but their adapters are deferred (v1).
KNOWN_API_KEYS: dict[str, list[str]] = {
    "shodan": ["SHODAN_API_KEY"],
    "dehashed": ["DEHASHED_API_KEY", "DEHASHED_EMAIL"],
    "censys": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    "hibp": ["HIBP_API_KEY"],
}

# Providers with real adapters in the current build. Others report as "deferred".
IMPLEMENTED_PROVIDERS = {"shodan", "dehashed"}

MASSCAN_PPS_WARN_THRESHOLD = 20000


def load_env_file(path: str | Path = ".env", *, override: bool = False) -> list[str]:
    """Load KEY=VALUE lines from a .env file into os.environ.

    A convenience so operators don't have to `source` the file. Real environment
    variables take precedence unless override=True (least surprise). Handles
    comments, blank lines, `export ` prefixes, surrounding quotes, and a BOM.
    Returns the variable NAMES loaded (never values).
    """
    p = Path(path)
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8-sig")   # utf-8-sig tolerates a BOM
    except OSError:
        return []
    loaded: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = val
            loaded.append(key)
    return loaded


@dataclass
class RateConfig:
    masscan_pps: int = 1000
    nmap_timing: str = "T3"
    nmap_max_rate: int = 200
    http_concurrency: int = 8
    api_concurrency: int = 2

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "RateConfig":
        base = cls()
        return cls(
            masscan_pps=int(d.get("masscan_pps", base.masscan_pps)),
            nmap_timing=str(d.get("nmap_timing", base.nmap_timing)),
            nmap_max_rate=int(d.get("nmap_max_rate", base.nmap_max_rate)),
            http_concurrency=int(d.get("http_concurrency", base.http_concurrency)),
            api_concurrency=int(d.get("api_concurrency", base.api_concurrency)),
        )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _csv_list(value: str) -> list[str]:
    return [x.strip() for x in str(value).split(",") if x.strip()]


@dataclass
class Settings:
    output_dir: Path = Path("engagements")
    client: Optional[str] = None
    client_root_domains: list[str] = field(default_factory=list)
    client_keywords: list[str] = field(default_factory=list)
    include_subdomains: bool = False
    max_expanded_hosts: int = 65536
    enable_axfr: bool = False
    enable_udp: bool = False
    retention_days: int = 90
    # passive-recon thresholds / tuning (Phase 1+)
    expiry_warn_days: int = 60           # WHOIS/RDAP "expiring soon" threshold
    dns_timeout: float = 5.0
    dns_nameservers: list[str] = field(default_factory=list)  # empty = system resolvers
    http_timeout: float = 15.0
    cache_ttl_hours: int = 168           # 7 days; caches expensive OSINT lookups
    # active phase (Phase 3+)
    masscan_ports: str = (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,"
        "1723,3306,3389,5432,5900,6379,8080,8443,8000,8888,9200,27017"
    )
    rates: RateConfig = field(default_factory=RateConfig)
    modules: dict[str, bool] = field(default_factory=dict)   # explicit enable/disable
    blackout: list[dict[str, Any]] = field(default_factory=list)
    verbosity: int = 1

    # --- construction --------------------------------------------------- #
    @classmethod
    def load(
        cls,
        config_file: Optional[str | Path] = None,
        *,
        env: Optional[Mapping[str, str]] = None,
        overrides: Optional[Mapping[str, Any]] = None,
    ) -> "Settings":
        env = os.environ if env is None else env
        settings = cls()

        if config_file:
            settings._merge_file(Path(config_file))
        settings._merge_env(env)
        if overrides:
            settings._merge_overrides(overrides)
        settings._validate()
        return settings

    def _merge_file(self, path: Path) -> None:
        if not path.exists():
            raise ConfigError(f"config file not found: {path}")
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            raise ConfigError(f"cannot parse config {path}: {exc}") from exc

        if "output_dir" in data:
            self.output_dir = Path(str(data["output_dir"]))
        for key in ("client", "masscan_ports"):
            if key in data:
                setattr(self, key, str(data[key]))
        for key in ("client_root_domains", "client_keywords"):
            if key in data:
                setattr(self, key, [str(x) for x in data[key]])
        for key in ("include_subdomains", "enable_axfr", "enable_udp"):
            if key in data:
                setattr(self, key, _as_bool(data[key]))
        for key in ("max_expanded_hosts", "retention_days", "expiry_warn_days", "cache_ttl_hours"):
            if key in data:
                setattr(self, key, int(data[key]))
        for key in ("dns_timeout", "http_timeout"):
            if key in data:
                setattr(self, key, float(data[key]))
        if "dns_nameservers" in data:
            self.dns_nameservers = [str(x) for x in data["dns_nameservers"]]
        if "rates" in data:
            self.rates = RateConfig.from_dict(data["rates"])
        if "modules" in data:
            self.modules = {str(k): _as_bool(v) for k, v in data["modules"].items()}
        if "blackout" in data:
            self.blackout = list(data["blackout"])

    def _merge_env(self, env: Mapping[str, str]) -> None:
        mapping = {
            "SKRECON_OUTPUT_DIR": ("output_dir", Path),
            "SKRECON_CLIENT": ("client", str),
            "SKRECON_CLIENT_ROOT_DOMAINS": ("client_root_domains", _csv_list),
            "SKRECON_CLIENT_KEYWORDS": ("client_keywords", _csv_list),
            "SKRECON_INCLUDE_SUBDOMAINS": ("include_subdomains", _as_bool),
            "SKRECON_MAX_EXPANDED_HOSTS": ("max_expanded_hosts", int),
            "SKRECON_ENABLE_AXFR": ("enable_axfr", _as_bool),
            "SKRECON_ENABLE_UDP": ("enable_udp", _as_bool),
            "SKRECON_RETENTION_DAYS": ("retention_days", int),
            "SKRECON_VERBOSITY": ("verbosity", int),
        }
        for var, (attr, cast) in mapping.items():
            if env.get(var):
                setattr(self, attr, cast(env[var]))

    def _merge_overrides(self, overrides: Mapping[str, Any]) -> None:
        for key, value in overrides.items():
            if value is None:
                continue
            if not hasattr(self, key):
                raise ConfigError(f"unknown override: {key}")
            if key == "output_dir":
                value = Path(value)
            setattr(self, key, value)

    def _validate(self) -> None:
        if self.max_expanded_hosts <= 0:
            raise ConfigError("max_expanded_hosts must be positive")
        if self.retention_days < 0:
            raise ConfigError("retention_days must be >= 0")
        if self.rates.masscan_pps <= 0:
            raise ConfigError("rates.masscan_pps must be positive")

    # --- helpers -------------------------------------------------------- #
    def module_enabled(self, name: str, *, default: bool = True) -> bool:
        return self.modules.get(name, default)

    def present_api_keys(self, env: Optional[Mapping[str, str]] = None) -> dict[str, bool]:
        env = os.environ if env is None else env
        return {
            provider: all(bool(env.get(v)) for v in vars_)
            for provider, vars_ in KNOWN_API_KEYS.items()
        }

    def secret_values(self, env: Optional[Mapping[str, str]] = None) -> list[str]:
        """Concrete secret strings to redact from logs/audit."""
        env = os.environ if env is None else env
        values: list[str] = []
        for vars_ in KNOWN_API_KEYS.values():
            for v in vars_:
                val = env.get(v)
                if val:
                    values.append(val)
        return values

    def masscan_rate_warning(self) -> Optional[str]:
        if self.rates.masscan_pps > MASSCAN_PPS_WARN_THRESHOLD:
            return (
                f"masscan rate {self.rates.masscan_pps} pps exceeds the safe default "
                f"threshold of {MASSCAN_PPS_WARN_THRESHOLD}; this can disrupt targets."
            )
        return None
