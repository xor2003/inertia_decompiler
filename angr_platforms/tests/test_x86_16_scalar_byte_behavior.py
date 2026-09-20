"""Validate scalar byte arithmetic without banning legitimate ABI storage.

Layer: Tests.
Responsibility: execute unchanged add_sc C over every byte pair and check the
binary's saved SI/DI contract, including their unaffected upper register words.
"""

import subprocess
from pathlib import Path

import pytest

_PRELUDE = """
#include <stdint.h>
#include <stdio.h>
unsigned long inertia_esi, inertia_edi;
"""
_HARNESS = r"""
int main(void)
{
    const unsigned long seeds[] = {0, 0x12345678UL, 0xffffffffUL, 0x80008000UL};
    for (unsigned s = 0; s < sizeof(seeds) / sizeof(seeds[0]); ++s)
    for (unsigned d = 0; d < sizeof(seeds) / sizeof(seeds[0]); ++d)
    for (unsigned a = 0; a < 256; ++a)
    for (unsigned b = 0; b < 256; ++b) {
        inertia_esi = seeds[s];
        inertia_edi = seeds[d];
        uint8_t expected = (uint8_t)(a + b);
        uint8_t actual = (uint8_t)add_sc((signed char)a, (unsigned char)b);
        if (actual != expected || inertia_esi != seeds[s] || inertia_edi != seeds[d]) {
            fprintf(stderr, "byte-add mismatch: a=%u b=%u expected=%u actual=%u "
                    "esi=%08lx/%08lx edi=%08lx/%08lx\n", a, b, expected, actual,
                    inertia_esi, seeds[s], inertia_edi, seeds[d]);
            return 1;
        }
    }
    return 0;
}
"""


def assert_scalar_byte_add_behavior(generated_body: str, directory: Path) -> None:
    """Check all 65,536 byte pairs under 16 independent saved-register states."""
    executable = directory / "byte-add-behavior"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=all", "-x", "c", "-",
         "-o", str(executable)],
        input=_PRELUDE + generated_body + _HARNESS,
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, f"byte-add compilation failed: {compiled.stderr}"
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=10)
    assert executed.returncode == 0, f"byte-add execution failed: {executed.stderr}"


_SAVE_RESTORE = """
    unsigned char local_4 = inertia_esi;
    unsigned char local_3 = inertia_esi >> 8;
    unsigned char local_2 = inertia_edi;
    unsigned char local_1 = inertia_edi >> 8;
    inertia_esi = (inertia_esi & 0xffff0000UL) | local_4 | (local_3 << 8);
    inertia_edi = (inertia_edi & 0xffff0000UL) | local_2 | (local_1 << 8);
"""


def _function(body: str) -> str:
    return "signed char add_sc(signed char a, unsigned char b) {" + body + "}\n"


@pytest.mark.parametrize("setup", ["", _SAVE_RESTORE], ids=["direct", "saved-byte-locals"])
def test_byte_add_oracle_accepts_valid_abi_storage(tmp_path: Path, setup: str) -> None:
    assert_scalar_byte_add_behavior(_function(setup + "return a + b;"), tmp_path)


@pytest.mark.parametrize("body", [
    "return a - b;",
    "return (a + b) * 0;",
    "return (a + b) & 127;",
    "inertia_esi ^= 1; return a + b;",
    "inertia_esi &= 65535; return a + b;",
    "inertia_edi ^= 1; return a + b;",
    "inertia_edi &= 65535; return a + b;",
], ids=["subtract", "constant", "lost-sign-bit", "si-low", "si-high", "di-low", "di-high"])
def test_byte_add_oracle_rejects_corruption(tmp_path: Path, body: str) -> None:
    with pytest.raises(AssertionError, match="byte-add execution failed"):
        assert_scalar_byte_add_behavior(_function(body), tmp_path)
