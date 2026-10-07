"""Tests for typed runtime result boundaries."""

from __future__ import annotations

import pytest
from inertia.pipeline.errors import PipelineHardError
from inertia.pipeline.result_contracts import (
    require_optional_result_type_8616,
    require_result_type_8616,
)


def test_result_contract_returns_exact_runtime_type() -> None:
    """A matching owner result survives without coercion."""
    value = [1, 2]

    assert require_result_type_8616(value, list, owner="test.owner") is value


def test_result_contract_rejects_truthy_wrong_type() -> None:
    """A truthy integer cannot silently satisfy a bool pipeline contract."""
    with pytest.raises(PipelineHardError, match=r"test\.owner returned int, expected bool"):
        require_result_type_8616(1, bool, owner="test.owner")


def test_optional_result_contract_accepts_none_and_rejects_wrong_type() -> None:
    """Only None bypasses the optional result's concrete type check."""
    assert require_optional_result_type_8616(None, int, owner="test.owner") is None
    with pytest.raises(PipelineHardError, match=r"test\.owner returned str, expected int"):
        require_optional_result_type_8616("1", int, owner="test.owner")
