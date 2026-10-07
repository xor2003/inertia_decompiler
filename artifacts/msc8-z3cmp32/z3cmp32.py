#!/usr/bin/env python3
"""Layer: validation compatibility.

Responsibility: retain the historical MSC8 command and exact driver module identity.
"""

from __future__ import annotations

import sys

from tools.comparator import msc8_cli

if __name__ == "__main__":
    raise SystemExit(msc8_cli.main())

sys.modules[__name__] = msc8_cli
