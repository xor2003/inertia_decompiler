#!/usr/bin/env python3
"""Layer: validation compatibility.

Responsibility: retain the historical BC5 command and exact driver module identity.
"""

from __future__ import annotations

import sys

from tools.comparator import bc5_cli

if __name__ == "__main__":
    raise SystemExit(bc5_cli.main())

sys.modules[__name__] = bc5_cli
