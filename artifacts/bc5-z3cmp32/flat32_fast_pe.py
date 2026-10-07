"""Layer: validation compatibility.

Responsibility: preserve the verified PE cache import as its exact qualified owner.
"""

from __future__ import annotations

import sys

from tools.comparator import verified_pe

sys.modules[__name__] = verified_pe
