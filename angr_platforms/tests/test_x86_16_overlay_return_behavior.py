"""Check far return values independently of saved-register representation.

Layer: Tests.
Responsibility: execute generated Overlay C against its binary memory/ABI contract.
"""

import subprocess
from pathlib import Path

import pytest
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616

_HARNESS = r'''
#include <stdio.h>
uint8_t inertia_memory[1048576];
unsigned long inertia_esi, inertia_eax;
unsigned short inertia_es;
static void store_word(unsigned segment, unsigned offset, unsigned value)
{
    unsigned address = (segment << 4) + (offset & 65535);
    inertia_memory[address] = value;
    inertia_memory[address + 1] = value >> 8;
}
int main(void)
{
    const unsigned segments[] = {16, 4660};
    const unsigned indices[] = {0, 3, 127};
    const unsigned words[] = {0, 17185, 65535};
    for (unsigned s = 0; s < 2; ++s)
        for (unsigned i = 0; i < 3; ++i)
            for (unsigned h = 0; h < 3; ++h)
                for (unsigned l = 0; l < 3; ++l) {
                    unsigned segment = segments[s], index = indices[i];
                    store_word(segment, 24, words[h]);
                    store_word(segment, 36 + 2 * index, words[l]);
                    inertia_esi = 0x12345678UL;
                    inertia_eax = 0x9abc0000UL;
                    uint32_t actual = (uint32_t)_overlay_functionAddress(segment, index);
                    uint32_t expected = ((uint32_t)words[h] << 16) | words[l];
                    if (actual != expected || inertia_esi != 0x12345678UL) {
                        fprintf(stderr, "far-return mismatch: expected=%08x actual=%08x si=%08lx\n",
                                expected, actual, inertia_esi);
                        return 1;
                    }
                }
    return 0;
}
'''


def assert_overlay_return_behavior(text: str, directory: Path) -> None:
    """Compile unchanged output and check 54 far-return and saved-SI cases."""
    source = directory / "overlay.c"
    executable = directory / "overlay"
    source.write_text(text + _HARNESS, encoding="utf-8")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-variable",
         "-Wno-unused-but-set-variable", "-O2", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_RETURN = "return ((uint32_t)SEG_U16(seg, 24) << 16) | SEG_U16(seg, 36 + (index << 1));"


def _control(body: str) -> str:
    return (render_c_runtime_header_8616("portable-flat")
            + "\nextern unsigned long inertia_esi;\n"
            + "long _overlay_functionAddress(unsigned short seg, unsigned short index) {"
            + body + "}\n")


def test_overlay_return_oracle_accepts_correct_value(tmp_path: Path) -> None:
    assert_overlay_return_behavior(_control(_RETURN), tmp_path)


@pytest.mark.parametrize("body", [
    _RETURN.replace("SEG_U16(seg, 24)", "(inertia_esi & 65535)"),
    "inertia_esi ^= 1;" + _RETURN,
    _RETURN.replace("index << 1", "index"),
], ids=["restored-si-as-return", "saved-si-clobber", "wrong-slot-stride"])
def test_overlay_return_oracle_rejects_corruption(tmp_path: Path, body: str) -> None:
    with pytest.raises(AssertionError, match="far-return mismatch"):
        assert_overlay_return_behavior(_control(body), tmp_path)
