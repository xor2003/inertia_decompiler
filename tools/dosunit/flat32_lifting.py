"""Compatibility owner for the historical tools.dosunit.flat32_lifting path.

Layer: dosunit validation lowering adapter.
Responsibility: keep legacy pickles and imports resolving to the canonical
flat32 architecture module so serialized contracts retain their identity.
"""

from __future__ import annotations

import sys

from tools.dosunit.architectures import flat32 as _canonical

sys.modules[__name__] = _canonical
