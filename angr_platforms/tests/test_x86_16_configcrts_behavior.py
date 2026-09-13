"""Executable acceptance for the ConfigCrts word-copy loop."""

import subprocess
from pathlib import Path

import pytest

_HARNESS = r"""
uint8_t inertia_memory[1u << 20];
uint16_t inertia_ds;
unsigned short CrtConfig[8];
int main(void) {
    for (unsigned seed = 1; seed <= 3; ++seed) {
        inertia_ds = (uint16_t)(0x1200 + seed);
        unsigned base = (unsigned)inertia_ds << 4;
        for (unsigned i = 0; i < sizeof(inertia_memory); ++i)
            inertia_memory[i] = (uint8_t)(i + seed);
        for (unsigned i = 0; i < 8; ++i)
            CrtConfig[i] = (uint16_t)(0x8103 + seed * 0x123 + i * 0x207);
        if (_ConfigCrts() != CrtConfig[7]) return 1;
        if (inertia_ds != 0x1200 + seed) return 2;
        for (unsigned i = 0; i < sizeof(inertia_memory); ++i) {
            uint8_t expected = (uint8_t)(i + seed);
            if (i >= base && i < base + 16) {
                unsigned offset = i - base;
                expected = (uint8_t)(CrtConfig[offset / 2] >> (8 * (offset % 2)));
            }
            if (inertia_memory[i] != expected) return 3;
        }
        for (unsigned i = 0; i < 8; ++i)
            if (CrtConfig[i] != (uint16_t)(0x8103 + seed * 0x123 + i * 0x207)) return 4;
    }
    return 0;
}
"""

_REFERENCE = r"""
#include <stdint.h>
extern uint8_t inertia_memory[];
extern uint16_t inertia_ds;
extern unsigned short CrtConfig[];
unsigned short _ConfigCrts(void) {
    for (unsigned i = 0; i < 8; ++i) {
        unsigned address = ((unsigned)inertia_ds << 4) + i * 2;
        inertia_memory[address] = (uint8_t)CrtConfig[i];
        inertia_memory[address + 1] = (uint8_t)(CrtConfig[i] >> 8);
    }
    return CrtConfig[7];
}
"""


def assert_configcrts_behavior(generated_c: str, directory: Path) -> None:
    """Check unchanged C's return, copy, source preservation and global writes.

    This bounded oracle does not compare machine stack or scratch registers.
    The generated function must separately pass tail validation.
    """
    source = directory / "configcrts.c"
    executable = directory / "configcrts"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=2)
    assert executed.returncode == 0, "ConfigCrts behavior mismatch"


def test_configcrts_oracle_accepts_word_copy(tmp_path: Path) -> None:
    assert_configcrts_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("original", "replacement"), [
    ("i < 8", "i < 7"),
    ("i * 2", "i"),
    ("CrtConfig[i] >> 8", "CrtConfig[i] >> 7"),
    ("return CrtConfig[7]", "return CrtConfig[6]"),
    ("return CrtConfig[7]", "inertia_memory[0] = 0; return CrtConfig[7]"),
    ("return CrtConfig[7]", "++inertia_ds; return CrtConfig[7]"),
    ("return CrtConfig[7]", "CrtConfig[0] = 0; return CrtConfig[7]"),
])
def test_configcrts_oracle_rejects_corruption(tmp_path: Path, original: str, replacement: str) -> None:
    with pytest.raises(AssertionError, match="ConfigCrts behavior mismatch"):
        assert_configcrts_behavior(_REFERENCE.replace(original, replacement), tmp_path)
