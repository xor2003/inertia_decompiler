"""Layer: validation compatibility.

Responsibility: preserve the historical MSC8 adapter as its exact compatibility owner.
"""

from __future__ import annotations

import sys

from tools.comparator import msc8_compat

sys.modules[__name__] = msc8_compat
