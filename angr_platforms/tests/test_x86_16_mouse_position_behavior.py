"""Executable wrapper checks at the modeled mouse-interrupt ABI boundary."""

import subprocess
from pathlib import Path

import pytest

_REFERENCE = """
extern unsigned short MouseX, MouseY;
extern unsigned char MOUSE;
unsigned short interrupt_int33(unsigned short ax, unsigned short cx, unsigned short dx);
unsigned short _MousePOS(unsigned short x, unsigned short y) {
    if (!MOUSE) return 0;
    MouseX = x << 1;
    MouseY = y;
    return interrupt_int33(4, x << 1, y);
}
"""
_HARNESS = """
unsigned short MouseX, MouseY;
unsigned char MOUSE;
static unsigned calls, bad;
static unsigned short expected_x, expected_y, returned_ax;
unsigned short interrupt_int33(unsigned short ax, unsigned short cx, unsigned short dx) {
    ++calls;
    bad += ax != 4 || cx != expected_x || dx != expected_y;
    bad += MouseX != expected_x || MouseY != expected_y;
    return returned_ax;
}
int main(void) {
    static const unsigned char states[] = {0, 1, 255};
    static const unsigned short results[] = {0, 4, 65535};
    for (unsigned s = 0; s < 3; ++s)
    for (unsigned r = 0; r < 3; ++r)
    for (unsigned value = 0; value <= 65535; ++value) {
        unsigned short x = (unsigned short)value, y = (unsigned short)(65535 - value);
        MOUSE = states[s];
        returned_ax = results[r];
        expected_x = (unsigned short)(x << 1);
        expected_y = y;
        MouseX = 0x1234; MouseY = 0x5678;
        calls = bad = 0;
        unsigned short result = _MousePOS(x, y);
        if (result != (MOUSE ? returned_ax : 0) || bad) return 1;
        if (calls != (MOUSE ? 1u : 0u)) return 2;
        if (MouseX != (MOUSE ? expected_x : 0x1234)) return 3;
        if (MouseY != (MOUSE ? expected_y : 0x5678)) return 4;
        if (MOUSE != states[s]) return 5;
    }
    return 0;
}
"""


def assert_mouse_position_behavior(generated_c: str, directory: Path) -> None:
    """Check unchanged C against the generic interrupt AX-result contract.

    The stub models the owned helper ABI, not a particular installed DOS mouse
    driver. No assumption that an unmodeled interrupt preserves AX is made.
    """
    source, executable = directory / "mouse.c", directory / "mouse"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=3)
    assert executed.returncode == 0, "MousePOS behavior mismatch: " + executed.stderr


def test_mouse_oracle_accepts_modeled_wrapper(tmp_path: Path) -> None:
    assert_mouse_position_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("original", "replacement"), [
    ("if (!MOUSE)", "if (MOUSE)"),
    ("MouseX = x << 1", "MouseX = x"),
    ("MouseY = y", "MouseY = x"),
    ("interrupt_int33(4, x << 1, y)", "interrupt_int33(4, x, y)"),
    ("return interrupt_int33(4, x << 1, y)", "(void)interrupt_int33(4, x << 1, y); return 4"),
])
def test_mouse_oracle_rejects_corruption(tmp_path: Path, original: str, replacement: str) -> None:
    with pytest.raises(AssertionError, match="MousePOS behavior mismatch"):
        assert_mouse_position_behavior(_REFERENCE.replace(original, replacement), tmp_path)
