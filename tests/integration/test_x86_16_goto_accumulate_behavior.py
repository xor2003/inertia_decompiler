"""Check conditional accumulation independently of recovered loop spelling."""

import subprocess
from pathlib import Path

import pytest

_REFERENCE = r"""
unsigned short goto_accumulate(short x) {
    unsigned short total = 0;
    while (x > 0) {
        total = (unsigned short)(total + x);
        --x;
        if ((x & 1) == 0) total = (unsigned short)(total + 2);
    }
    return total;
}
"""

_HARNESS = r"""
#include <stdio.h>
unsigned long inertia_esi, inertia_edi;
unsigned short inertia_flags;
static int check(int input) {
    unsigned long n = input > 0 ? (unsigned long)input : 0;
    unsigned short expected = (unsigned short)(n * (n + 1) / 2 + 2 * ((n + 1) / 2));
    inertia_esi = 0xabcde123UL;
    inertia_edi = 0x9876f456UL;
    unsigned short actual = goto_accumulate((short)input);
    if (actual != expected) {
        fprintf(stderr, "input=%d actual=%u expected=%u\n", input, actual, expected);
        return 1;
    }
    if (inertia_esi != 0xabcde123UL || inertia_edi != 0x9876f456UL) {
        fprintf(stderr, "input=%d callee-saved register changed\n", input);
        return 2;
    }
    return 0;
}
int main(void) {
    /* Dense small inputs cover both edges; spaced pairs cover word overflow. */
    for (int input = -256; input <= 512; ++input) {
        if (check(input)) return 1;
    }
    for (int input = 513; input < 32767; input += 127) {
        if (check(input) || check(input + 1)) return 1;
    }
    return check(-32768) || check(32767);
}
"""


def assert_goto_accumulate_behavior(generated_c: str, directory: Path) -> None:
    """Check signed termination, conditional updates, wrapping and preserved GP state."""
    source = directory / "goto_accumulate.c"
    executable = directory / "goto_accumulate"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=3)
    assert executed.returncode == 0, "conditional accumulation mismatch: " + executed.stderr


def test_goto_accumulate_oracle_accepts_reference(tmp_path):
    assert_goto_accumulate_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("old", "new"), [
    ("(x & 1) == 0", "1"),
    ("(x & 1) == 0", "0"),
    ("(x & 1) == 0", "(x & 1) != 0"),
    ("return total;", "inertia_edi = 0; return total;"),
])
def test_goto_accumulate_oracle_rejects_corruption(tmp_path, old, new):
    generated = "extern unsigned long inertia_edi;\n" + _REFERENCE
    with pytest.raises(AssertionError, match="conditional accumulation mismatch"):
        assert_goto_accumulate_behavior(generated.replace(old, new), tmp_path)
