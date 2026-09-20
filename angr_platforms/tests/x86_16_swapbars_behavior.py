"""Execute unchanged SwapBars C against its call and saved-register contract.

Layer: Tests.
Responsibility: check argument values, call order and explicit word restores
without depending on generated local names or byte-pair formatting.
"""

import subprocess
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    DEFAULT_GP_RUNTIME_ABI_8616,
    GPRegisterRuntimeABI8616,
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)

_HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
static unsigned event, first, second;
#define require(condition) do { if (!(condition)) { \
    fprintf(stderr, "event=%u invariant=%s\n", event, #condition); exit(1); \
} } while (0)

static void observe(unsigned kind, unsigned row)
{
    require(event < 3);
    require(kind == (event == 2));
    require(row == (event == 1 ? second : first));
    ++event;
    /* Adversarial callees distinguish the explicit low-word restores from
       accidentally restoring the entire entry register or omitting saves. */
    inertia_esi = 0xabcd0000UL | event;
    inertia_edi = 0xdcba0000UL | (event + 16);
}
void sub_106c8(unsigned short row) { observe(0, row); }
void sub_10498(unsigned short row) { observe(1, row); }
void sub_10768(unsigned short, unsigned short);
int main(void)
{
    static const unsigned rows[] = {0, 1, 127, 128, 255, 256, 32767, 32768, 65535};
    static const unsigned words[] = {0, 1, 0x80ff, 0xff80, 0xffff};
    for (unsigned i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i)
        for (unsigned j = 0; j < sizeof(rows) / sizeof(rows[0]); ++j)
            for (unsigned k = 0; k < sizeof(words) / sizeof(words[0]); ++k) {
                first = rows[i]; second = rows[j]; event = 0;
                unsigned si = words[k], di = words[k] ^ 0xa55a;
                inertia_esi = 0x12340000UL | si;
                inertia_edi = 0x56780000UL | di;
                sub_10768(first, second);
                require(event == 3);
                require(inertia_esi == (0xabcd0000UL | si));
                require(inertia_edi == (0xdcba0000UL | di));
            }
    return 0;
}
'''


def assert_swapbars_behavior(
    function_c: str, tmp_path: Path,
    *, gp_runtime_abi: GPRegisterRuntimeABI8616 = DEFAULT_GP_RUNTIME_ABI_8616,
) -> None:
    """Compile unchanged C and exercise call values and partial-register effects."""
    source = tmp_path / "swapbars_oracle.c"
    executable = tmp_path / "swapbars_oracle"
    runtime = (
        coherent_gp_runtime_header_8616() + coherent_gp_runtime_definitions_8616()
        if gp_runtime_abi is GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS
        else "unsigned long inertia_esi, inertia_edi;\n"
    )
    source.write_text(runtime + _HARNESS + "\n" + function_c, encoding="utf-8")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Werror", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=20,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False, timeout=10,
    )
    assert executed.returncode == 0, f"violated the SwapBars oracle: {executed.stderr}"
