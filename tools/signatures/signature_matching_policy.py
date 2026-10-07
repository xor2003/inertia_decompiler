"""Read signature-matching runtime policy from the environment.

Layer: Tooling/optional evidence.
Responsibility: expose signature-matching policy without making signatures required semantic evidence.
"""

from __future__ import annotations

import os

_TRUE_VALUES = {"1", "true", "yes", "on"}


def signature_matching_disabled() -> bool:
    """Return True when signature-based helper matching is disabled for this run."""
    value = os.environ.get("INERTIA_DISABLE_SIGNATURES", "")
    return value.strip().lower() in _TRUE_VALUES
