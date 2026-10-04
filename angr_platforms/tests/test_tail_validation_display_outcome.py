"""Contract tests for the owned tail-validation display-status normalizer."""

from __future__ import annotations

import pytest

from inertia_decompiler.work_items import (
    TailValidationDisplayOutcome,
    normalize_tail_validation_status,
)


@pytest.mark.parametrize("outcome", list(TailValidationDisplayOutcome))
def test_normalize_tail_validation_status_maps_valid_values(
    outcome: TailValidationDisplayOutcome,
) -> None:
    """Every declared outcome value round-trips through the normalizer."""
    assert normalize_tail_validation_status(outcome.value) is outcome


@pytest.mark.parametrize("raw", ["", None, "missing", "PASSED", " passed "])
def test_normalize_tail_validation_status_fails_closed(
    raw: str | None,
) -> None:
    """Missing, malformed, and case-mismatched statuses stay uncollected."""
    assert (
        normalize_tail_validation_status(raw)
        is TailValidationDisplayOutcome.UNCOLLECTED
    )
