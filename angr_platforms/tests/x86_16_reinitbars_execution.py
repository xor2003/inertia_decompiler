"""Layer: Tests.

Responsibility: execute generated ReInitBars loops without requiring for syntax.
"""

import subprocess
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_symbols_8616


def assert_reinitbars_loop_behavior(body: str, tmp_path: Path) -> None:
    """Check calls, copies, iteration order and callee-saved register state."""
    source = tmp_path / "reinitbars_loop.c"
    executable = tmp_path / "reinitbars_loop"
    # Host unsigned long may be 64-bit; architectural GP lanes are always 32-bit.
    runtime_state = "".join(f"uint32_t {symbol};\n" for symbol in runtime_gp_state_symbols_8616())
    # Deliberate corruptions must not invoke the host's crash reporter via abort.
    source.write_text(
        "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n" + runtime_state + """
static void fail_check(const char *condition) {
    fputs(condition, stderr);
    exit(EXIT_FAILURE);
}
#define assert(condition) ((condition) ? (void)0 : fail_check(#condition))
typedef struct { unsigned short value; } bar;
static bar abarWork[4], abarPerm[4];
static unsigned short cRow;
static unsigned long clStart;
static unsigned int draws, clocks;
static long clock(void) { ++clocks; return 123; }
static int DrawBar(unsigned short row) {
    assert(row == draws);
    assert(row < cRow);
    assert(abarWork[row].value == abarPerm[row].value);
    ++draws;
    return 0;
}
""" + body + """
int main(void) {
    const unsigned short rows[] = {0, 1, 3};
    for (unsigned int trial = 0; trial < 3; ++trial) {
        const uint32_t saved_esi = UINT32_C(0x13579bdf) ^ trial;
        const uint32_t saved_edi = UINT32_C(0x2468ace0) ^ trial;
        inertia_esi = saved_esi;
        inertia_edi = saved_edi;
        cRow = rows[trial];
        draws = clocks = 0;
        clStart = 0;
        for (unsigned int i = 0; i < 4; ++i) {
            abarPerm[i].value = 10 + i;
            abarWork[i].value = 99;
        }
        ReInitBars();
        assert(inertia_esi == saved_esi && inertia_edi == saved_edi);
        assert(clStart == 123 && clocks == 1 && draws == cRow);
        for (unsigned int i = 0; i < 4; ++i)
            assert(abarWork[i].value == (i < cRow ? abarPerm[i].value : 99));
    }
    return 0;
}
""", encoding="utf-8",
    )
    compiled = subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert compiled.returncode == 0, f"generated ReInitBars failed compilation: {compiled.stderr}"
    result = subprocess.run(
        [str(executable)], capture_output=True, text=True, timeout=5, check=False,
    )
    assert result.returncode == 0, f"generated ReInitBars failed execution: {result.stderr}"
