"""Layer: validation compatibility.

Responsibility: preserve the MSC8 catalog import as its exact qualified owner.
"""

from __future__ import annotations

import sys

from tools.comparator import msc8_catalog

sys.modules[__name__] = msc8_catalog
