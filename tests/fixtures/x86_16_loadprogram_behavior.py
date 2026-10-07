"""Compile and execute the DOS load-program wrapper's observable contract.

Layer: Tests.
Responsibility: verify call arguments, error propagation, and conditional output
writes for a caller-declared ABI mode, without depending on temporary variable
or parameter-name spelling in generated C.

The emitted ``_dos_loadProgram`` contract is evidence-based binary ABI: five
stack words ``(file, command_lo, command_hi, cs_ptr, ss_ptr)``.  The original
source grouped the middle two words as one ``const char FAR *cmdline`` /
``unsigned long`` argument ``(file, command, cs, ss)``.  Both forms describe
the same machine-level invocation; the caller must declare which emitted
shape is under test so a wrong shape fails at compile time instead of being
silently coerced.
"""

import subprocess
from enum import Enum
from pathlib import Path


class LoadProgramAbi(Enum):
    """Declared ABI of the emitted ``_dos_loadProgram`` under test.

    SOURCE: source-level signature ``(file, unsigned long command, *cs, *ss)``;
    the 32-bit command travels as one C argument and lands in two stack words.
    BINARY: binary ABI signature ``(file, command_lo, command_hi, *cs, *ss)``;
    the decompiler exposes each stack word as its own parameter.
    """

    SOURCE = "source"
    BINARY = "binary"


_INVOCATION = {
    LoadProgramAbi.SOURCE: "_dos_loadProgram(0x1234, 0xabcd5678UL, cs, ss)",
    LoadProgramAbi.BINARY: "_dos_loadProgram(0x1234, 0x5678, 0xabcd, cs, ss)",
}

# __LOADPROGRAM_INVOKE__ is replaced with the declared-ABI call expression.
_HARNESS_TEMPLATE = r'''
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
        unsigned short result = __LOADPROGRAM_INVOKE__;
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


def assert_loadprogram_behavior(text: str, directory: Path, *, abi: LoadProgramAbi) -> None:
    """Execute unchanged generated C against the bounded wrapper oracle.

    ``abi`` is a required explicit declaration of which emitted signature is
    under test. A pass is bounded execution evidence for the tested vectors,
    not an all-input proof. A mismatched declaration fails at compile time
    rather than being guessed.
    """
    (directory / "generated.c").write_text(text, encoding="ascii")
    source = directory / "loadprogram.c"
    harness = _HARNESS_TEMPLATE.replace("__LOADPROGRAM_INVOKE__", _INVOCATION[abi])
    source.write_text(harness, encoding="ascii")
    executable = directory / "loadprogram"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, f"abi={abi.value} compile failed:\n{compiled.stderr}"
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=2)
    assert executed.returncode == 0, f"load-program behavior mismatch (abi={abi.value})"
