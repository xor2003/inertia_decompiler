"""Execute byte-fill output against signed bounds and surrounding storage."""

import subprocess
from pathlib import Path

import pytest

_HARNESS = r"""
unsigned long inertia_esi, inertia_edi;
int main(void) {
    static unsigned char bytes[32769];
    const short counts[] = {-32768, -1, 0, 1, 8, 127, 256, 32767};
    const unsigned short values[] = {0, 3, 127, 128, 255, 511, 65535};
    for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c) {
        for (unsigned v = 0; v < sizeof(values) / sizeof(values[0]); ++v) {
            for (unsigned i = 0; i < sizeof(bytes); ++i) bytes[i] = 0xa5;
            inertia_esi = 0xabcd1234UL;
            inertia_edi = 0x13572468UL;
            fill_bytes((char *)bytes + 1, values[v], counts[c]);
            if (inertia_esi != 0xabcd1234UL || inertia_edi != 0x13572468UL) return 1;
            for (unsigned i = 0; i < sizeof(bytes); ++i) {
                int touched = counts[c] > 0 && i > 0 && i <= (unsigned)counts[c];
                unsigned char expected = touched ? (unsigned char)values[v] : 0xa5;
                if (bytes[i] != expected) return 2;
            }
        }
    }
    return 0;
}
"""

_REFERENCE = r"""
extern unsigned long inertia_esi, inertia_edi;
void fill_bytes(char *dst, unsigned short value, short count) {
    for (int i = 0; i < count; ++i) dst[i] = (char)value;
    return;
}
"""


def assert_pointer_fill_behavior(generated_c: str, directory: Path) -> None:
    """Compile and check byte writes, untouched storage and callee-preserved GPs."""
    source = directory / "pointer_fill.c"
    executable = directory / "pointer_fill"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=3)
    assert executed.returncode == 0, "pointer fill behavior mismatch: " + executed.stderr


def test_pointer_fill_oracle_accepts_reference(tmp_path):
    assert_pointer_fill_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("original", "replacement"), [
    ("dst[i]", "dst[0]"),
    ("i < count", "i <= count"),
    ("(char)value", "(char)(value + 1)"),
    ("return;", "inertia_esi = 0; return;"),
])
def test_pointer_fill_oracle_rejects_corruption(tmp_path, original, replacement):
    with pytest.raises(AssertionError, match="pointer fill behavior mismatch"):
        assert_pointer_fill_behavior(_REFERENCE.replace(original, replacement), tmp_path)
