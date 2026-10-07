"""Layer: validation compatibility.

Responsibility: retain the historical verdict import as the exact canonical owner.
"""

from __future__ import annotations

import sys

from tools.comparator import verdict

sys.modules[__name__] = verdict
