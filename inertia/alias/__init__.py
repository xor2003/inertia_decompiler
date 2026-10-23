"""Alias-layer package exports.

Layer: Alias.
Responsibility: owns storage identity and stack-slot identity.
Owns storage identity and stack-slot identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

lazy import inertia.alias.alias_model as alias_model
lazy import inertia.alias.domains as domains
lazy import inertia.alias.state as state
lazy import inertia.alias.transfer as transfer

__all__ = (
    "alias_model",
    "domains",
    "state",
    "transfer",
)
