"""Binary-derived real16 joint-system construction for recursive proofs.

Layer: dosunit real16 joint-system construction (staging).

Responsibility: re-export the authoritative production construction owner
(``tools.dosunit.recursive_proofs.real16_joint_construction``) so the
fixtures do not maintain a second semantic implementation. Only the public
builder is forwarded; the previous module's private helpers
(``_admitted_component``, ``_pair_step``, ``_effect``, ``_image_hash``) are
gone, so tests that patched them must use the production module surface.
"""
from __future__ import annotations

from tools.dosunit.recursive_proofs.real16_joint_construction import (
    build_real16_joint_system,
)

__all__ = [
    "build_real16_joint_system",
]
