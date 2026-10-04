"""Checks for lossless diagnostic text around display-only path aliases."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from scripts.compact_paths import PathCompactor, compact_stream, main


@pytest.mark.parametrize("prefix", ["", "./", "/repo/"])
def test_longest_alias_preserves_failure_details(prefix: str) -> None:
    original = f'{prefix}angr_platforms/angr_platforms/X86_16/lowering/owner.py:17: E123 "failure"\n'
    assert PathCompactor(Path("/repo")).line(original) == 'X16/lowering/owner.py:17: E123 "failure"\n'


@pytest.mark.parametrize("foreign", ["/other/", "../", "my-", "folder/", "word"])
def test_foreign_path_suffix_is_not_rewritten(foreign: str) -> None:
    text = f"{foreign}angr_platforms/tests/test_owner.py:7"
    assert PathCompactor(Path("/repo")).line(text) == text


def test_stream_preserves_counts_unicode_and_multiple_locations() -> None:
    text = "FAILED /repo/angr_platforms/tests/test_a.py::test_x — scripts/check.py:42\n9 failed, 393 passed\n"
    source, output = io.StringIO(text), io.StringIO()
    compact_stream(source, output, Path("/repo"))
    assert source.getvalue() == text
    assert output.getvalue() == "FAILED TEST/test_a.py::test_x — SCRIPTS/check.py:42\n9 failed, 393 passed\n"


def test_exact_root_and_unterminated_line() -> None:
    compactor = PathCompactor(Path("/repo"))
    assert compactor.line("/repo/PROGRESS.md /repo-other/PROGRESS.md") == "./PROGRESS.md /repo-other/PROGRESS.md"


def test_cli_legend_explains_aliases(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("tools/dosunit/owner.py:3\n"))
    assert main(["--repo", "/repo", "--legend"]) == 0
    output = capsys.readouterr().out
    assert "X16/ = angr_platforms/angr_platforms/X86_16/\n" in output
    assert output.endswith("DU/owner.py:3\n")
