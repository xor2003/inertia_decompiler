"""Keep shared Make linter scopes as paths, never pytest node selectors."""

import json
import shlex
import subprocess
import sys
import tomllib
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


def test_native_stack_anchor_contract_is_typed_in_reduced_mypy_scopes() -> None:
    """Do not erase the coordinate type when its consumer is checked alone."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as source:
        config = tomllib.load(source)
    owner = "angr_platforms.angr_platforms.X86_16.ir.native_stack_anchor"
    matching = [rule for rule in config["tool"]["mypy"]["overrides"] if owner in rule.get("module", [])]
    assert matching
    assert all(rule.get("follow_imports") == "normal" for rule in matching)


def _ruff_codes(source: str) -> set[str]:
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--no-fix", "--output-format=json",
         "--config", str(REPO_ROOT / "pyproject.toml"),
         "--stdin-filename", "inertia_decompiler/policy_probe.py", "-"],
        input=source, cwd=REPO_ROOT, capture_output=True, text=True,
        check=False, timeout=30,
    )
    assert result.returncode in (0, 1), result.stderr
    return {finding["code"] for finding in json.loads(result.stdout)}


@pytest.mark.parametrize(
    ("source", "required"),
    [
        ("value = undefined_name\n", {"F821", "D100"}),
        ("def calculate(value):\n    return value\n", {"ANN001", "ANN201", "D103"}),
        ("def calculate(values: list[int] = []) -> int:\n    return len(values)\n", {"B006"}),
        ('def calculate() -> int:\n    """ """\n    return 0\n', {"D419"}),
        ("def calculate(value: int) -> int:\n" + "".join(
            f"    if value == {number}:\n        return {number}\n" for number in range(12)
        ) + "    return -1\n", {"C901"}),
        ("def calculate(value: int) -> bool:\n"
         "    if value == 2 or value == 3 or value == 4 or value == 5 or value == 6 or value == 7:\n"
         "        return True\n    return False\n", {"PLR0916"}),
    ],
)
def test_ruff_preserves_safety_and_maintainability_checks(source: str, required: set[str]) -> None:
    assert required <= _ruff_codes(source)


def test_ruff_allows_readable_literals_and_explicit_control_flow() -> None:
    source = '''"""Layer: Tooling. Responsibility: demonstrate readable control flow"""


def classify(width: int, values: list[int]) -> list[int]:
    """Collect values matching a register width without requiring section boilerplate"""
    if width == 16:
        target = 32
    else:
        target = 8
    output = []
    for value in values:
        output.append(value + target)
    return output
'''
    assert not _ruff_codes(source)
