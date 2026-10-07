"""Layer: validation compatibility.

Responsibility: preserve the MSC8 region import as its exact qualified owner.
"""

from __future__ import annotations

import sys

from tools.comparator import msc8_region

sys.modules[__name__] = msc8_region
