"""Compatibility owner for the historical tools.dosunit.straightline_ssa path.

Layer: dosunit semantic comparison.
Responsibility: keep legacy pickles and imports resolving to the canonical
comparison engine module so serialized contracts retain their identity.
"""

from __future__ import annotations

import sys

from tools.dosunit.compare import straightline_ssa as _canonical

sys.modules[__name__] = _canonical
