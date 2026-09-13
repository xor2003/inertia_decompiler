"""Check nested-loop control flow and GP preservation over every signed limit."""

import subprocess
from pathlib import Path

import pytest

_REFERENCE = r"""
static unsigned short reference(short limit) {
    int total = 0;
    for (int i = 0; i < limit; ++i) {
        int j = 0;
        do {
            if (j == i) { ++j; continue; }
            total += i + j;
            if (total > 40) break;
            ++j;
        } while (j < limit);
        if (total > 40) break;
    }
    return (unsigned short)total;
}
"""

_HARNESS = r"""
#include <stdio.h>
unsigned long inertia_esi, inertia_edi;
int main(void) {
    for (int limit = -32768; limit <= 32767; ++limit) {
        inertia_esi = 0xabcde123UL;
        inertia_edi = 0x9876f456UL;
        unsigned short actual = nested_loops((short)limit);
        unsigned short expected = reference((short)limit);
        if (actual != expected) {
            fprintf(stderr, "limit=%d actual=%u expected=%u\n", limit, actual, expected);
            return 1;
        }
        if (inertia_esi != 0xabcde123UL || inertia_edi != 0x9876f456UL) return 2;
    }
    return 0;
}
"""


def assert_nested_loop_behavior(generated_c: str, directory: Path) -> None:
    """Compile and compare all signed limits without relying on loop spelling."""
    source = directory / "nested_loop.c"
    executable = directory / "nested_loop"
    source.write_text(generated_c + _REFERENCE + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=3)
    assert executed.returncode == 0, "nested loop behavior mismatch: " + executed.stderr


def test_nested_loop_oracle_accepts_reference(tmp_path):
    assert_nested_loop_behavior(_REFERENCE.replace("reference", "nested_loops"), tmp_path)


@pytest.mark.parametrize(("old", "new"), [
    ("j == i", "j != i"),
    ("total > 40", "total > 41"),
    ("return (unsigned short)total;", "inertia_esi = 0; return (unsigned short)total;"),
])
def test_nested_loop_oracle_rejects_corruption(tmp_path, old, new):
    generated = "extern unsigned long inertia_esi;\n" + _REFERENCE.replace("reference", "nested_loops")
    with pytest.raises(AssertionError, match="nested loop behavior mismatch"):
        assert_nested_loop_behavior(generated.replace(old, new), tmp_path)
