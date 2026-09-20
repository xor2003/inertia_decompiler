"""Compile QuickSort unchanged and observe partition progress and swap effects.

Layer: Tests.
Responsibility: reject lost pivot comparisons, nonterminating partition scans,
wrong pointer arguments, and failed sorting on bounded signed-byte inputs.
"""

import subprocess
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)

_HARNESS = r'''
#include <stdlib.h>
#include <stdio.h>
unsigned short COMPARES;
g_08F0_entry ITEMS[3];
static unsigned swaps, draws;
static unsigned short last_left, last_right;
static unsigned case_index;

#define require(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "case=%u line=%d invariant=%s\n", case_index, __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

CALL_RESULT SWAP(g_08F0_entry *left, g_08F0_entry *right)
{
    require(swaps == draws && swaps < 16);
    require(left >= ITEMS && left < ITEMS + 3);
    require(right >= ITEMS && right < ITEMS + 3);
    last_left = left - ITEMS;
    last_right = right - ITEMS;
    g_08F0_entry temporary = *left;
    *left = *right;
    *right = temporary;
    ++swaps;
    CALL_RETURN;
}

CALL_RESULT DRAW(unsigned short left, unsigned short right)
{
    require(swaps == draws + 1 && left == last_left && right == last_right);
    ++draws;
    CALL_RETURN;
}

int main(void)
{
    static const signed char cases[][3] = {
        {3, 1, 2}, {1, 2, 3}, {3, 2, 1}, {2, 3, 1}, {2, 1, 3}, {1, 3, 2},
        {-2, 0, 3}, {3, -2, 0}, {0, 3, -2}, {1, 1, 1}
    };
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        case_index = c;
        for (unsigned i = 0; i < 3; ++i) {
            ITEMS[i].field_0 = cases[c][i];
            ITEMS[i].field_1 = i;
        }
        swaps = draws = COMPARES = 0;
        inertia_esi = 0x12345678UL;
        inertia_edi = 0x87654321UL;
        SORT(1, 0);
        SORT(1, 1);
        require(swaps == 0 && draws == 0 && COMPARES == 0);
        require(inertia_esi == 0x12345678UL && inertia_edi == 0x87654321UL);
        for (unsigned i = 0; i < 3; ++i) {
            require((signed char)ITEMS[i].field_0 == cases[c][i]);
            require((unsigned char)ITEMS[i].field_1 == i);
        }
        SORT(0, 2);
        require(swaps == draws && COMPARES > 0);
        require(inertia_esi == 0x12345678UL && inertia_edi == 0x87654321UL);
        unsigned identities = 0;
        for (unsigned i = 0; i < 3; ++i) {
            unsigned identity = (unsigned char)ITEMS[i].field_1;
            require(identity < 3);
            require((signed char)ITEMS[i].field_0 == cases[c][identity]);
            identities |= 1u << identity;
            if (i) require((signed char)ITEMS[i - 1].field_0 <= (signed char)ITEMS[i].field_0);
        }
        require(identities == 7);
    }
    return 0;
}
'''


def assert_quicksort_behavior(text: str, directory: Path, *, named: bool) -> None:
    """Check ten bounded partitions, keeping unchanged generated C and strict gcc."""
    names = (
        ("QuickSort", "abarWork", "iCompares", "Swaps", "SwapBars", "int", "return 0")
        if named else
        ("sub_10ce0", "g_0B4C", "g_0BAA", "sub_107b8", "sub_10768", "void", "return")
    )
    keys = ("SORT", "ITEMS", "COMPARES", "SWAP", "DRAW", "CALL_RESULT", "CALL_RETURN")
    bindings = "\n".join(f"#define {key} {value}" for key, value in zip(keys, names, strict=True))
    (directory / "generated.c").write_text(text, encoding="utf-8")
    harness = directory / "harness.c"
    runtime = coherent_gp_runtime_header_8616() + coherent_gp_runtime_definitions_8616()
    harness.write_text(runtime + '#include "generated.c"\n' + bindings + _HARNESS, encoding="ascii")
    executable = directory / "quicksort"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=5)
    assert executed.returncode == 0, (
        "generated QuickSort violated the partition/call contract: "
        f"exit={executed.returncode}; {executed.stdout}{executed.stderr}"
    )
