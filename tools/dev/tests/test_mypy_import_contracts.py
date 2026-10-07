"""Focused MyPy checks must retain the return types of owned providers."""

import tomllib
from pathlib import Path

import pytest


@pytest.mark.parametrize("module", [
    "inertia.cli.cache_io",
    "inertia.semantics.callsite_summary",
])
def test_owned_return_type_providers_are_not_skipped(module: str) -> None:
    root = Path(__file__).resolve().parents[3]
    with (root / "pyproject.toml").open("rb") as source:
        config = tomllib.load(source)["tool"]["mypy"]

    assert config["strict"] is True
    assert any(
        module in override["module"] and override.get("follow_imports") == "normal"
        for override in config["overrides"]
    ), f"{module} must remain typed even outside Make's full source selection"
