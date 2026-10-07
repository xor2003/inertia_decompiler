"""Check binary word-sum semantics independently of loop presentation."""

import subprocess
from pathlib import Path

import pytest

_HARNESS = r"""
unsigned long inertia_esi, inertia_edi;
int main(void) {
    unsigned short words[513];
    const short counts[] = {-32768, -1, 0, 1, 4, 31, 256, 511};
    const unsigned seeds[] = {0, 65535, 32768, 4660};
    for (unsigned s = 0; s < sizeof(seeds) / sizeof(seeds[0]); ++s) {
        for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c) {
            for (unsigned i = 0; i < 513; ++i) words[i] = (unsigned short)(i * 40503U + seeds[s]);
            unsigned expected = 0;
            for (int i = 0; i < counts[c]; ++i) expected += words[i + 1];
            inertia_esi = 0xabcd1234UL;
            inertia_edi = 0x13572468UL;
            unsigned short result = sum_words(counts[c] > 0 ? words + 1 : 0, counts[c]);
            if (result != (unsigned short)expected) return 1;
            if (inertia_esi != 0xabcd1234UL || inertia_edi != 0x13572468UL) return 2;
            for (unsigned i = 0; i < 513; ++i)
                if (words[i] != (unsigned short)(i * 40503U + seeds[s])) return 3;
        }
    }
    return 0;
}
"""

_REFERENCE = r"""
extern unsigned long inertia_esi, inertia_edi;
unsigned short sum_words(unsigned short *src, short count) {
    unsigned short total = 0;
    for (int i = 0; i < count; ++i) total += src[i];
    return total;
}
"""


def assert_pointer_sum_behavior(generated_c: str, directory: Path) -> None:
    """Compile and execute word sums, checking memory and architectural effects."""
    source = directory / "pointer_sum.c"
    executable = directory / "pointer_sum"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=3)
    assert executed.returncode == 0, "pointer sum behavior mismatch: " + executed.stderr


def test_pointer_sum_oracle_accepts_reference(tmp_path):
    assert_pointer_sum_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("original", "replacement"), [
    ("src[i]", "src[0]"),
    ("i < count", "i <= count"),
    ("total +=", "total ="),
    ("return total;", "inertia_edi = 0; return total;"),
    ("return total;", "if (count > 0) { src[0] = 0; } return total;"),
])
def test_pointer_sum_oracle_rejects_corruption(tmp_path, original, replacement):
    with pytest.raises(AssertionError, match="pointer sum behavior mismatch"):
        assert_pointer_sum_behavior(_REFERENCE.replace(original, replacement), tmp_path)
