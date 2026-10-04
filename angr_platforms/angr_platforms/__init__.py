"""Installed package entry point.

Layer: Frontend/runtime package surface.
Responsibility: preserve canonical platform identity in the installed layout.
"""
from __future__ import annotations

import sys

from .import_identity import install_x86_16_legacy_import_alias

# Legacy tests and callers still import nested paths like
# ``angr_platforms.angr_platforms.X86_16...``. Keep that package alias alive
# while the real package root remains ``angr_platforms``.
sys.modules.setdefault("angr_platforms.angr_platforms", sys.modules[__name__])

install_x86_16_legacy_import_alias()
