"""Deliberately corrupt pointer effects to test the existing tiny-case oracle.

Host runs test rejection strength only, not DOS ABI or 16-bit equivalence.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.msc6_pointer_memory_harness import POINTER_MEMORY_HARNESS_MAIN

SOURCE = Path(__file__).resolve().parents[2] / "examples/msc6_constructs/pointer_memory.c"


def test_original_and_rebuilt_pointer_cases_use_identical_observations():
    source = SOURCE.read_text()
    assert source[source.index("int main(void)"):].strip() == POINTER_MEMORY_HARNESS_MAIN.strip()


@pytest.mark.parametrize("mutation,exit_code", [
    ("none", 255), ("lost_write", 1), ("alias_destroyed", 4), ("zero_length_write", 6),
    ("reversed_overlap", 8),
])
def test_pointer_oracle_rejects_wrong_effects(tmp_path, mutation, exit_code):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.fail("gcc is required to exercise pointer-oracle negative controls")
    source = SOURCE.read_text()
    if mutation == "lost_write":
        source = source.replace("dst[i] = value;", "dst[i] = 0;")
    elif mutation == "alias_destroyed":
        source = source.replace("tmp = *left;", "if (left == right) { *left = 0; return; }\n    tmp = *left;")
    elif mutation == "zero_length_write":
        source = source.replace("for (i = 0; i < count; ++i) {", "for (i = 0; i < (count ? count : 1); ++i) {", 1)
    elif mutation == "reversed_overlap":
        source = source.replace("dst[i] = src[i] + 1U;", "dst[count - 1 - i] = src[count - 1 - i] + 1U;")
    path = tmp_path / "oracle.c"
    path.write_text(source)
    binary = tmp_path / "oracle"
    built = subprocess.run([compiler, "-std=c89", "-pedantic-errors", str(path), "-o", str(binary)],
                           capture_output=True, text=True, timeout=15, check=False)
    assert built.returncode == 0, built.stderr
    result = subprocess.run([str(binary)], capture_output=True, timeout=5, check=False)
    assert result.returncode == exit_code
