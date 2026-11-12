"""The only package permitted to touch the operating system.

Features D1 and D2: a platform-neutral core behind a fixed adapter interface,
with Ubuntu as the only implementation. Everything that reads `/proc`, `/sys`,
`/etc` or calls `uname` lives here and nowhere else, so adding support for a
future Ubuntu release - or a second operating system - means adding an
implementation of `OsAdapter` rather than restructuring the agent.

A note on the directory name: the architecture approved for this calls this
boundary the "platform adapter", and the obvious name for the package would be
`platform`. It is `osadapter` instead because `platform` is a standard-library
module, and a package that shadows a stdlib name is a maintenance trap - the
imports resolve correctly today only because Python 3 uses absolute imports by
default, and anyone who adds a relative import or reorders `sys.path` finds out
the hard way. The boundary itself is unchanged.
"""

from __future__ import annotations

from ubuntuguard_agent.osadapter.base import HostFacts, OsAdapter, OsRelease
from ubuntuguard_agent.osadapter.ubuntu import (
    SUPPORTED_OS_IDS,
    VALIDATED_OS_VERSION_IDS,
    UbuntuAdapter,
    detect_adapter,
)

__all__ = [
    "SUPPORTED_OS_IDS",
    "VALIDATED_OS_VERSION_IDS",
    "HostFacts",
    "OsAdapter",
    "OsRelease",
    "UbuntuAdapter",
    "detect_adapter",
]
