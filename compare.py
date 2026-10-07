"""Compatibility import and command for comparator tooling.

Layer: Tooling/compatibility.
Responsibility: preserve the historical script while tools.comparator owns implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.comparator import compare as _implementation  # noqa: E402

if __name__ == "__main__":
    _implementation.test_instructions()
else:
    sys.modules[__name__] = _implementation
