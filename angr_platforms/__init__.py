"""Repository package entry point.

Layer: Frontend/runtime package surface.
Responsibility: expose the inner platform tree with canonical import identity.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_INNER = _ROOT / "angr_platforms"

# Make `import angr_platforms.X86_16` resolve to the inner package tree.
__path__ = [str(_INNER)]

# Keep legacy nested alias alive.
sys.modules.setdefault("angr_platforms.angr_platforms", sys.modules[__name__])

from .import_identity import install_x86_16_legacy_import_alias  # noqa: E402

install_x86_16_legacy_import_alias()
