"""`python -m ubuntuguard_agent`.

The systemd unit invokes the module rather than the console script, so the
service does not depend on a `bin/` entry point surviving a reinstall of the
virtualenv.
"""

from __future__ import annotations

import sys

from ubuntuguard_agent.cli import main

if __name__ == "__main__":
    sys.exit(main())
