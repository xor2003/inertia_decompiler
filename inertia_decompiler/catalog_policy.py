"""Configure bounded candidate catalog recovery.

Layer: CLI/fallback/reporting.
Responsibility: validate the independent function-discovery time budget.
"""

import argparse

DEFAULT_CATALOG_TIMEOUT: int = 60


def positive_catalog_timeout(value: str) -> int:
    """Reject invalid budgets instead of silently falling back to a small cap."""
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("catalog timeout must be a positive integer") from error
    if seconds <= 0:
        raise argparse.ArgumentTypeError("catalog timeout must be a positive integer")
    return seconds
