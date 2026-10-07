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

from tools.dev import decompile32 as _implementation  # noqa: E402

sys.modules[__name__] = _implementation
