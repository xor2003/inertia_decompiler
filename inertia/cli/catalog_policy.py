# cython: language_level=3, infer_types=True
"""Configure bounded candidate catalog recovery.

Layer: CLI/fallback/reporting.
Responsibility: validate the independent function-discovery time budget.
"""

from __future__ import annotations
import typing
import cython

import argparse

DEFAULT_CATALOG_TIMEOUT: cython.longlong = 60


@cython.ccall
def positive_catalog_timeout(value: object) -> cython.longlong:
    """Reject invalid budgets instead of silently falling back to a small cap."""
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("catalog timeout must be a positive integer") from error
    if seconds <= 0:
        raise argparse.ArgumentTypeError("catalog timeout must be a positive integer")
    return seconds
