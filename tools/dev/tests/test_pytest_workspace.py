"""Temporary-root isolation and explicit runner-policy controls."""

from pathlib import Path

import pytest

from tools.dev.pytest_workspace import ROOT, workspace_basetemp

pytestmark = pytest.mark.tooling


def test_default_roots_are_ignored_and_distinct(tmp_path: Path) -> None:
    first = workspace_basetemp(tmp_path, None)
    second = workspace_basetemp(tmp_path, None)
    assert first.parent == tmp_path / ".cache" / "pytest"
    assert first != second
    assert first.parent.is_dir()


def test_explicit_runner_root_is_preserved(tmp_path: Path) -> None:
    explicit = tmp_path / "partition" / "worker-0"
    assert workspace_basetemp(tmp_path, explicit) == explicit
    assert not (tmp_path / ".cache").exists()


def test_actual_default_tmp_path_is_in_ignored_cache(tmp_path: Path) -> None:
    assert tmp_path.is_relative_to(ROOT / ".cache" / "pytest")
