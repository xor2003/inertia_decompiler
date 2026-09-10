"""Keep shared Make linter scopes as paths, never pytest node selectors."""

import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SEGMENT_OWNER = "angr_platforms/angr_platforms/X86_16/ir/native_segment_live_out.py"


@pytest.mark.parametrize("target", ["ruff", "mypy"])
def test_make_linter_receives_paths_and_segment_owner(target: str) -> None:
    command = subprocess.run(
        ["make", "--no-print-directory", "-n", target, "Q=", f"PYTHON={sys.executable}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=30,
    )
    assert command.returncode == 0, command.stderr
    arguments = shlex.split(command.stdout)
    assert SEGMENT_OWNER in arguments
    assert not [argument for argument in arguments if "::" in argument]
