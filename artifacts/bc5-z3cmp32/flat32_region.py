"""Layer: validation compatibility.

Responsibility: preserve the BC5 region import as its exact qualified owner.
"""

from __future__ import annotations

import sys

from tools.comparator import bc5_region

sys.modules[__name__] = bc5_region
