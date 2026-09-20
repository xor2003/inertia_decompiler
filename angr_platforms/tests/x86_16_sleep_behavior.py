"""Execute generated Sleep against a deterministic clock.

Layer: Tests.
Responsibility: verify signed deadlines and clock effects without depending on
C formatting. Cases avoid signed 32-bit overflow; host-long wrap is not modeled.
"""

import subprocess
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)

SLEEP_REGISTER_STATE_PRELUDE: str = (
    "#define SLEEP_STATE_INITIALIZE() do { inertia_esi = 0x12345678UL; inertia_edi = 0x87654321UL; } while (0)\n"
    "#define SLEEP_STATE_PRESERVED() (inertia_esi == 0x12345678UL && inertia_edi == 0x87654321UL)\n"
)

_HARNESS = r'''
#include <stdlib.h>
#ifndef SLEEP_STATE_PRESERVED
#define SLEEP_STATE_PRESERVED() 1
#endif
#ifndef SLEEP_STATE_INITIALIZE
#define SLEEP_STATE_INITIALIZE() ((void)0)
#endif
static long tick, calls, limit;
clock_t clock(void)
{
    if (++calls > limit) exit(1);
    return tick++;
}
int main(void)
{
    SLEEP_STATE_INITIALIZE();
    const long starts[] = {-1000, 0, 65530, 131072, 10000000};
    const long waits[] = {-3, 0, 1, 2, 7, 255, 256, 65535, 65536, 131072};
    for (unsigned i = 0; i < sizeof(starts) / sizeof(starts[0]); ++i)
        for (unsigned j = 0; j < sizeof(waits) / sizeof(waits[0]); ++j) {
            tick = starts[i];
            calls = 0;
            limit = waits[j] > 0 ? waits[j] + 2 : 2;
            Sleep(waits[j]);
            if (!SLEEP_STATE_PRESERVED()) return 2;
            if (calls != limit || tick != starts[i] + limit) return 1;
        }
    return 0;
}
'''


def assert_sleep_behavior(text: str, directory: Path, *, harness_prelude: str = "") -> None:
    """Compile unchanged generated C and verify nonoverflowing clock deadlines."""
    generated = directory / "generated.c"
    harness = directory / "harness.c"
    executable = directory / "sleep-test"
    generated.write_text(text, encoding="utf-8")
    runtime = coherent_gp_runtime_header_8616() + coherent_gp_runtime_definitions_8616()
    harness.write_text(runtime + '#include "generated.c"\n' + harness_prelude + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=10)
    assert executed.returncode == 0, "generated Sleep violated the clock deadline oracle"
