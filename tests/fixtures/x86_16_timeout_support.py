"""Shared watchdog scaling for real-decompiler tests."""

from __future__ import annotations

import os


def scaled_decompile_timeout(timeout: int) -> int:
    """Scale a watchdog under xdist without changing serial test semantics."""
    raw_scale = os.environ.get("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", "").strip()
    if not raw_scale and os.environ.get("PYTEST_XDIST_WORKER"):
        raw_scale = "1.5"
    try:
        scale = float(raw_scale) if raw_scale else 1.0
    except ValueError:
        scale = 1.0
    if scale <= 1.0:
        return timeout
    return max(timeout, round(timeout * scale))
