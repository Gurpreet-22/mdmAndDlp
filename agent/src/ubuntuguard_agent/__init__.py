"""UbuntuGuard endpoint agent.

Phase 1: foundation only. Configuration, structured logging, the service
lifecycle and the policy-signature verification core. There is no network code
in this package yet - enrollment is Phase 2 and the first HTTP request is
Phase 3.
"""

from __future__ import annotations

#: Reported to the server as `agent_version` and in inventory. Single source.
__version__ = "0.1.0"

#: Sent as `release_build` at enrollment and in inventory. False means the
#: dev-only environment overrides in config.py are active, which the dashboard
#: flags because such a device's effective settings may not match policy.
#: Set to False at runtime by config loading, never written here.
__all__ = ["__version__"]
