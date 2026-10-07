"""Layer: frontend package boundaries.

Responsibility: expose real-mode x86 architecture and control coordinates without eager pipeline startup.
"""

from __future__ import annotations

from .lifter_import import install_lifter_import

install_lifter_import()
