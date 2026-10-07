"""Layer: validation compatibility.

Responsibility: preserve the historical BC5 adapter as its exact compatibility owner.
"""

from __future__ import annotations

import sys

from tools.comparator import bc5_compat

sys.modules[__name__] = bc5_compat
