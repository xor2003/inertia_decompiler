"""Bound focused CLI processes without changing their inner analysis deadline.

Layer: Tooling/gates.
Responsibility: share the established process-setup allowance across batch and
serial focused decompilation runners.
"""

from __future__ import annotations

DECOMPILE_FUNCTION_PROCESS_SETUP_SECONDS: int = 120


def focused_decompile_process_timeout(analysis_timeout: int) -> int:
    """Include the existing setup allowance outside the CLI analysis budget."""
    return max(int(analysis_timeout), 30) + DECOMPILE_FUNCTION_PROCESS_SETUP_SECONDS
