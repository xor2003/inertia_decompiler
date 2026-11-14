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


def signature_match_scan_read_only() -> bool:
    """Return True when catalog scans are confined to the batch setup phase.

    Per-function workers carry this flag so a cold match cache degrades to an
    honest no-evidence result instead of every worker materializing the spec
    set and scanning the catalog concurrently.
    """
    value = os.environ.get("INERTIA_SIGNATURE_MATCH_READ_ONLY_8616", "")
    return value.strip().lower() in _TRUE_VALUES
