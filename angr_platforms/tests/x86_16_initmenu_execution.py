"""Layer: Tests.

Responsibility: execute generated InitMenu pause guards against source behavior.
"""

import subprocess
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)


def assert_initmenu_pause_guard_behavior(body: str, tmp_path: Path) -> None:
    """Detect lost high-word guards using observable output calls."""
    source = tmp_path / "initmenu_pause.c"
    executable = tmp_path / "initmenu_pause"
    source.write_text(
        coherent_gp_runtime_header_8616() + coherent_gp_runtime_definitions_8616() + """#include <stdint.h>
#include <stdio.h>
#include <string.h>
unsigned short cszMenu = 0, fSound = 0;
char *aszMenu[] = {"unused"};
long clPause;
static int row, col, limit_outputs, zero_outputs;
int settextcolor(int color) { return color; }
int32_t setbkcolor(int32_t color) { return color; }
int DrawFrame(unsigned short a, unsigned short b, unsigned short c, unsigned short d)
{ (void)a; (void)b; (void)c; (void)d; return 0; }
int32_t aNldiv(int32_t value, int32_t divisor) { return value / divisor; }
void settextposition(int r, int c) { row = r; col = c; }
void outtext(char *text) {
    if (col == 48 && strcmp(text, "            ") == 0) {
        limit_outputs += row == -4;
        zero_outputs += row == -3;
    }
}
""" + body + """
int main(void) {
    const long pauses[] = {0, 900, 0x10384};
    for (unsigned i = 0; i < sizeof(pauses) / sizeof(pauses[0]); ++i) {
        clPause = pauses[i]; limit_outputs = zero_outputs = 0;
        inertia_esi = 0x1234a55a; inertia_edi = 0xabcd5aa5;
        InitMenu();
        if (inertia_esi != 0x1234a55a || inertia_edi != 0xabcd5aa5) return 2;
        printf("%ld:%d:%d\\n", clPause, limit_outputs, zero_outputs);
    }
    return 0;
}
""",
        encoding="utf-8",
    )
    built = subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert built.returncode == 0, built.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "0:0:1\n900:1:0\n66436:0:0\n", result.stdout
