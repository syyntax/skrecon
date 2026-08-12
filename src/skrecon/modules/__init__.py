"""Recon module plugins.

Importing this package loads the plugin contract (`base`) first, then each module
file, whose import registers a module instance into `base.REGISTRY`. Order matters:
`base` must load before the modules that import from it.
"""

from .base import (  # noqa: F401
    Action,
    Context,
    Module,
    ModuleRegistry,
    Readiness,
    REGISTRY,
)

# Importing each module registers it into REGISTRY. Heavy libraries (dnspython,
# dnstwist) are imported lazily inside the modules, so these imports are cheap and
# never fail when an optional dependency is absent.
from . import dns_enum        # noqa: F401,E402  registers "dns"
from . import reverse_dns     # noqa: F401,E402  registers "reverse-dns"
from . import whois_rdap      # noqa: F401,E402  registers "whois-rdap"
from . import mail            # noqa: F401,E402  registers "mail"
from . import typosquat       # noqa: F401,E402  registers "typosquat"
