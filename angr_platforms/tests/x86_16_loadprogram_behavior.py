"""Compile and execute the DOS load-program wrapper's observable contract.

Layer: Tests.
Responsibility: verify call arguments, error propagation, and conditional output
writes without depending on temporary variable spelling in generated C.
"""

import subprocess
from pathlib import Path

_HARNESS = r'''
#include "generated.c"
unsigned short exeLoadParams[11];
static unsigned short error_code;
static unsigned calls, bad_args;
unsigned short loadprog(unsigned short file, unsigned short segment,
                        unsigned short mode, unsigned short lo, unsigned short hi)
{
    ++calls;
    bad_args += file != 0x1234 || segment != 0 || mode != 1 || lo != 0x5678 || hi != 0xabcd;
    return error_code;
}
int main(void)
{
    static const unsigned short errors[] = {0, 1, 2, 255, 256, 32767, 32768, 65535};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        unsigned short cs[2] = {0x1111, 0x2222}, ss[2] = {0x3333, 0x4444};
        error_code = errors[i];
        calls = bad_args = 0;
        for (unsigned j = 0; j < 11; ++j) exeLoadParams[j] = 0x7000 + j;
        unsigned short result = _dos_loadProgram(0x1234, 0xabcd5678UL, cs, ss);
        if (result != error_code || calls != 1 || bad_args) return 1;
        if (cs[0] != (error_code ? 0x1111 : 0x700a)) return 2;
        if (ss[0] != (error_code ? 0x3333 : 0x7008)) return 3;
        if (cs[1] != 0x2222 || ss[1] != 0x4444) return 4;
        for (unsigned j = 0; j < 11; ++j)
            if (exeLoadParams[j] != 0x7000 + j) return 5;
    }
    return 0;
}
'''


def assert_loadprogram_behavior(text: str, directory: Path) -> None:
    """Execute unchanged generated C against the bounded wrapper oracle."""
    (directory / "generated.c").write_text(text, encoding="ascii")
    source = directory / "loadprogram.c"
    source.write_text(_HARNESS, encoding="ascii")
    executable = directory / "loadprogram"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=2)
    assert executed.returncode == 0, "load-program behavior mismatch"
