"""Ownership routing admits planned core layers without arbitrary test roots."""

from __future__ import annotations

import pytest

from tools.dev.test_ownership_manifest import _pytest_target_path_reason


@pytest.mark.parametrize("layer", ["frontend", "ir", "semantics", "alias", "lowering", "structuring", "validation"])
def test_core_layer_test_paths_are_admitted(layer: str) -> None:
    """Keep layer migration inside explicitly supported test homes."""
    assert _pytest_target_path_reason(f"tests/{layer}/test_control.py") is None


@pytest.mark.parametrize("path", ["tests/random/test_control.py", "tests/frontend/control.py", "inertia/test_control.py"])
def test_unowned_test_roots_remain_refused(path: str) -> None:
    """Do not weaken path admission into an unconstrained repository glob."""
    assert _pytest_target_path_reason(path) is not None
