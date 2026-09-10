"""Execute generated DOS free wrappers against an exhaustive call-result oracle.

Layer: Tests.
Responsibility: verify generated calls, error messages, arguments and returns.
"""

import subprocess
from pathlib import Path

_HARNESS = r'''
#include GENERATED_C
#include <stdarg.h>
#include <string.h>

REGS rin, rout;
SREGS sreg;
unsigned long inertia_eax;
static unsigned expected_segment, expected_result, expected_flag;
static unsigned calls, errors, bad;

int intdosx(union REGS *a0, union REGS *a1, struct SREGS *a2)
{
    ++calls;
    if (a0 != &rin || a1 != &rout || a2 != &sreg ||
        a0->h.ah != 0x49 || a2->es != expected_segment) bad = 1;
    a1->x.cflag = expected_flag;
    return (int)(int16_t)expected_result;
}

int ERROR(const char *fmt, ...)
{
    va_list args;
    ++errors;
    if (fmt == NULL || strcmp(fmt, "dos_free: error freeing segment 0x%x: error 0x%x")) bad = 1;
    va_start(args, fmt);
    if ((unsigned)va_arg(args, int) != expected_segment ||
        (unsigned)va_arg(args, int) != expected_result) bad = 1;
    va_end(args);
    return 0;
}

int main(void)
{
    for (expected_flag = 0; expected_flag < 2; ++expected_flag)
        for (expected_result = 0; expected_result < 0x10000; ++expected_result) {
            expected_segment = (expected_result * 17u + 3u) & 0xffffu;
            inertia_eax = 0xa5a50000u | (expected_result ^ 0xffffu);
            calls = errors = bad = 0;
            unsigned value = _dos_free(expected_segment);
            if (bad || calls != 1 || errors != expected_flag ||
                value != (expected_flag ? expected_result : 0)) return 1;
        }
    return 0;
}
'''


def assert_dos_free_behavior(text: str, directory: Path) -> None:
    """Compile unchanged emitted C and check calls, arguments and all word returns."""
    generated = directory / "generated.c"
    harness = directory / "harness.c"
    executable = directory / "dos-free"
    generated.write_text(text, encoding="utf-8")
    harness.write_text(_HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Werror", "-O2", f'-DGENERATED_C="{generated}"',
         str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False, timeout=10,
    )
    assert executed.returncode == 0, "generated DOS free wrapper violated the call/result oracle"
