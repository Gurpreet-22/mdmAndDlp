"""Platform-neutral core. No OS calls, no filesystem, no network.

Feature D1: everything in this package is pure logic over values passed in, so
it is testable without a laptop, a server or a database. Anything that needs to
touch the operating system lives behind the adapter in `osadapter/`, and
anything that needs the network will live in `transport/` from Phase 2.

The rule is worth keeping literally. The moment a module here imports `os.path`
or opens a socket, the test suite needs an environment, and the tests that cover
the signing format - the ones that catch a byte-level disagreement with the
server - stop being runnable in isolation.
"""

from __future__ import annotations
