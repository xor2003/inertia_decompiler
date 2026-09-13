"""Execute generated Sleep against a deterministic clock.

Layer: Tests.
Responsibility: verify signed deadlines and clock effects without depending on
C formatting. Cases avoid signed 32-bit overflow; host-long wrap is not modeled.
"""

import subprocess
from pathlib import Path

_HARNESS = r'''
#include <stdlib.h>
static long tick, calls, limit;
clock_t clock(void)
{
    if (++calls > limit) exit(1);
    return tick++;
}
int main(void)
{
    const long starts[] = {-1000, 0, 65530, 131072, 10000000};
    const long waits[] = {-3, 0, 1, 2, 7, 255, 256, 65535, 65536, 131072};
    for (unsigned i = 0; i < sizeof(starts) / sizeof(starts[0]); ++i)
        for (unsigned j = 0; j < sizeof(waits) / sizeof(waits[0]); ++j) {
            tick = starts[i];
            calls = 0;
            limit = waits[j] > 0 ? waits[j] + 2 : 2;
            Sleep(waits[j]);
            if (calls != limit || tick != starts[i] + limit) return 1;
        }
    return 0;
}
'''


def assert_sleep_behavior(text: str, directory: Path) -> None:
    """Compile unchanged generated C and verify nonoverflowing clock deadlines."""
    generated = directory / "generated.c"
    harness = directory / "harness.c"
    executable = directory / "sleep-test"
    generated.write_text(text, encoding="utf-8")
    harness.write_text('#include "generated.c"\n' + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=10)
    assert executed.returncode == 0, "generated Sleep violated the clock deadline oracle"
