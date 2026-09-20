"""Compile HeapSort output against its source-level ordered call contract.

Layer: Tests.
Responsibility: check loop bounds, call order, scalar arguments and pointers
without treating C casts or loop-header formatting as semantic failures.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)

_HARNESS = r'''
#include <stdlib.h>

unsigned short ROWS;
g_08F0_entry ITEMS[32768];
static int count, next_up, next_down, phase;

static void require(int condition)
{
    if (!condition) exit(1);
}

CALL_RESULT UP(unsigned short index)
{
    require(phase == 0 && next_up < count && index == next_up);
    ++next_up;
    CALL_RETURN;
}

CALL_RESULT SWAP(g_08F0_entry *left, g_08F0_entry *right)
{
    require(next_up == count && next_down > 0 && phase == 0);
    require(left == &ITEMS[0] && right == &ITEMS[next_down]);
    phase = 1;
    CALL_RETURN;
}

CALL_RESULT DRAW(unsigned short left, unsigned short right)
{
    require(phase == 1 && left == 0 && right == next_down);
    phase = 2;
    CALL_RETURN;
}

CALL_RESULT DOWN(unsigned short index)
{
    require(phase == 2 && index == next_down - 1);
    --next_down;
    phase = 0;
    CALL_RETURN;
}

static void check_count(int rows)
{
    /* Exercise both saved low words and preserved upper register lanes. */
    const unsigned long saved_esi = 0xa53c0000UL | (unsigned long)rows;
    const unsigned long saved_edi = 0x5ac3ffffUL ^ (unsigned long)rows;
    inertia_esi = saved_esi;
    inertia_edi = saved_edi;
    count = rows;
    ROWS = rows;
    next_up = 1;
    next_down = rows - 1;
    phase = 0;
    for (int i = 0; i < 32768; ++i) {
        ITEMS[i].field_0 = i % 127;
        ITEMS[i].field_1 = (i + 17) % 127;
    }
    SORT();
    require(inertia_esi == saved_esi && inertia_edi == saved_edi);
    require(ROWS == rows && next_up == (rows > 1 ? rows : 1));
    require(next_down == (rows > 0 ? 0 : -1) && phase == 0);
    /* Callee stubs observe calls only; this wrapper must not write the array. */
    for (int i = 0; i < 32768; ++i)
        require(ITEMS[i].field_0 == i % 127 && ITEMS[i].field_1 == (i + 17) % 127);
}

int main(void)
{
    for (int rows = 0; rows <= 512; ++rows) check_count(rows);
    check_count(1024);
    check_count(32767);
    return 0;
}
'''


def assert_heapsort_behavior(text: str, directory: Path, *, named: bool = False) -> None:
    """Compile unchanged C and check source-valid row counts and call effects."""
    names = (
        ("HeapSort", "cRow", "abarWork", "PercolateUp", "Swaps", "SwapBars", "PercolateDown", "int", "return 0")
        if named else
        ("sub_10970", "g_0BA2", "g_0B4C", "sub_109e8", "sub_107b8", "sub_10768", "sub_10a88", "void", "return")
    )
    macros = ("SORT", "ROWS", "ITEMS", "UP", "SWAP", "DRAW", "DOWN", "CALL_RESULT", "CALL_RETURN")
    bindings = "\n".join(f"#define {key} {value}" for key, value in zip(macros, names, strict=True))
    generated = directory / "generated.c"
    harness = directory / "harness.c"
    executable = directory / "heapsort"
    generated.write_text(text, encoding="utf-8")
    runtime = coherent_gp_runtime_header_8616() + coherent_gp_runtime_definitions_8616()
    harness.write_text(runtime + '#include "generated.c"\n' + bindings + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=10)
    assert executed.returncode == 0, "generated HeapSort violated the ordered call/pointer oracle"
