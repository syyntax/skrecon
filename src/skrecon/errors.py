"""Exception hierarchy for skrecon.

The scope/authorization/blackout errors are the load-bearing safety exceptions:
raising them is how the guard refuses an unsafe action.
"""

from __future__ import annotations


class SkreconError(Exception):
    """Base class for all skrecon errors."""


class ConfigError(SkreconError):
    """Invalid or unreadable configuration."""


class ScopeError(SkreconError):
    """A scope file could not be parsed, or a scope operation was invalid."""


class OutOfScopeError(SkreconError):
    """A target failed the scope guard. This is a hard failure, never a warning.

    Raised by the guarded executor / HTTP client when asked to reach a host or IP
    that is not in the resolved scope.
    """

    def __init__(self, target: str, reason: str = "not in resolved scope") -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"out-of-scope target refused: {target!r} ({reason})")


class NotAuthorizedError(SkreconError):
    """An active operation was attempted without a satisfied authorization gate."""


class BlackoutError(SkreconError):
    """An active operation was attempted during a configured blackout window."""

    def __init__(self, window: str) -> None:
        self.window = window
        super().__init__(f"active scanning refused: inside blackout window {window}")
