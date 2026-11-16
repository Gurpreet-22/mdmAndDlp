"""USB device control: typed policy in, enforced USBGuard rules out.

Runs as root on a managed endpoint. It takes a USB policy -- typed device
matchers and a mode -- and derives the operating-system rules itself, then
confirms with the OS that they actually took effect.

The policy arrives as data, never as instructions, and that division is the
security property. Whoever sets policy decides *what* should be allowed; this
package decides *how* that is expressed to USBGuard. Because the policy
vocabulary is closed and carries no rule text, command, path or package name,
a compromised management server can change what is allowed but cannot execute
anything on an endpoint.

The policy format is UbuntuGuard's `usb_control` v1, so this is also the root
component its design calls `enforcerd` -- see README for how the two connect.

Modules, in dependency order:

  classes    USB interface class names to numeric codes
  intent     parse and validate the payload; reject anything unexpected
  derive     turn validated intent into USBGuard rules
  system     capability probing, state readback, rule installation
  snapshots  root-only snapshot store for rollback
  ops        the four typed operations, with no transport
  service    Unix socket, SO_PEERCRED check, daemon entry point
  client     reference client, and the wire format made executable

`ops` is deliberately transport-free, so the privileged logic can be tested
without root and the wire framing can change without touching it.

Only the policy-translation names are re-exported here. `ops`, `service` and
`client` are imported as modules rather than flattened, because their names
(`Enforcer`, `EnforcerServer`, `EnforcerClient`) read much better qualified.
"""

from __future__ import annotations

from .classes import (
    ALWAYS_ALLOW_CLASS_CODES,
    PROTECTED_CLASS_CODES,
    REQUIRED_ALWAYS_ALLOW,
)
from .derive import (
    TRAILING_ALLOW_NOTE,
    compute_fingerprint,
    derive_rules,
    extract_fingerprint,
    render_policy,
    verify_fingerprint,
)
from .intent import (
    MODE_ALLOWLIST,
    MODE_BLOCK_ALL,
    MODE_MONITOR,
    MODES,
    SCHEMA_ID,
    AllowlistEntry,
    DeviceMatch,
    IntentError,
    UsbControlIntent,
    parse,
)

#: 0.3.0 is the first version built against UbuntuGuard's `usb_control`
#: protocol. 0.1 and 0.2 were a standalone register-driven tool with its own
#: control plane, which this replaces entirely; the version is bumped rather
#: than reset so a deployed endpoint reporting 0.2.x is recognisable as
#: running the superseded design.
__version__ = "0.3.0"

__all__ = [
    "ALWAYS_ALLOW_CLASS_CODES",
    "AllowlistEntry",
    "DeviceMatch",
    "IntentError",
    "MODES",
    "MODE_ALLOWLIST",
    "MODE_BLOCK_ALL",
    "MODE_MONITOR",
    "PROTECTED_CLASS_CODES",
    "REQUIRED_ALWAYS_ALLOW",
    "SCHEMA_ID",
    "TRAILING_ALLOW_NOTE",
    "UsbControlIntent",
    "__version__",
    "compute_fingerprint",
    "derive_rules",
    "extract_fingerprint",
    "parse",
    "render_policy",
    "verify_fingerprint",
]
