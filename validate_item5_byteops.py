"""Compatibility import and command for development tooling.

Layer: Tooling/compatibility.
Responsibility: preserve the historical script while tools.dev owns implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.dev import validate_item5_byteops as _implementation  # noqa: E402

if __name__ == "__main__":
    sys.exit(0 if _implementation.test_byteops_decompilation() else 1)
else:
    sys.modules[__name__] = _implementation
