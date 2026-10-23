"""Layer: validation compatibility.

Responsibility: preserve the historical MSC8 adapter as its exact compatibility owner.
"""

from __future__ import annotations

import sys
from pathlib import Path

# A copied adapter must select its own layout before following package symlinks.
_SOURCE_ROOT: str = str(Path(__file__).absolute().parents[2])
if not sys.path or sys.path[0] != _SOURCE_ROOT:
    sys.path.insert(0, _SOURCE_ROOT)

from tools.comparator import msc8_compat  # noqa: E402

sys.modules[__name__] = msc8_compat
