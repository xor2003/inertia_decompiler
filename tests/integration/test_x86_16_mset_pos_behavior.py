"""Check signed cursor remainders without relying on temporary names."""

import subprocess
from pathlib import Path

import pytest

_HARNESS = r"""
unsigned short mono_x, mono_y;
int main(void) {
    for (unsigned bits = 0; bits <= 65535; ++bits) {
        unsigned short x = (unsigned short)bits;
        unsigned short y = (unsigned short)(65535 - bits);
        int signed_x = x < 32768 ? x : (int)x - 65536;
        int signed_y = y < 32768 ? y : (int)y - 65536;
        mono_x = mono_y = 0x5555;
        if (_mset_pos(x, y) != 0) return 1;
        if (mono_x != (unsigned short)(signed_x % 80)) return 2;
        if (mono_y != (unsigned short)(signed_y % 25)) return 3;
    }
    return 0;
}
"""

_REFERENCE = r"""
extern unsigned short mono_x, mono_y;
unsigned short _mset_pos(unsigned short x, unsigned short y) {
    int signed_x = x < 32768 ? x : (int)x - 65536;
    int signed_y = y < 32768 ? y : (int)y - 65536;
    mono_x = (unsigned short)(signed_x % 80);
    mono_y = (unsigned short)(signed_y % 25);
    return 0;
}
"""


def assert_mset_pos_behavior(generated_c: str, directory: Path) -> None:
    """Exhaust both 16-bit inputs and reject undefined host-C arithmetic."""
    source = directory / "mset_pos.c"
    executable = directory / "mset_pos"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=3)
    assert executed.returncode == 0, "mset_pos behavior mismatch: " + executed.stderr


def test_mset_pos_oracle_accepts_signed_remainders(tmp_path: Path) -> None:
    assert_mset_pos_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("original", "replacement"), [
    ("signed_x % 80", "(signed_x < 0 ? x : signed_x) % 80"),
    ("signed_y % 25", "(signed_y < 0 ? y : signed_y) % 25"),
    ("signed_x % 80", "signed_x % 25"),
    ("return 0", "return 1"),
    ("signed_x % 80", "((signed_x >> 15) << 16 | x) % 80"),
])
def test_mset_pos_oracle_rejects_corruption(tmp_path: Path, original: str, replacement: str) -> None:
    with pytest.raises(AssertionError, match="mset_pos behavior mismatch"):
        assert_mset_pos_behavior(_REFERENCE.replace(original, replacement), tmp_path)
