"""Layer: Tooling/gates.

Responsibility: execute unchanged sidecar-free RunMenu C against source dispatch.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    DEFAULT_GP_RUNTIME_ABI_8616,
    GPRegisterRuntimeABI8616,
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)

from inertia_decompiler.generated_c_function_extraction import (
    generated_function_definition_span,
    load_generated_function_artifacts,
)


@dataclass(frozen=True)
class RunMenuExecutionEvidence:
    """Execution verdict bound to the exact generated function definition."""

    definition_digest: str
    failure: str | None

    def accepts(self, definition: str) -> bool:
        """Require successful execution of this exact function, not another body."""
        return self.failure is None and self.definition_digest == sha256(definition.encode()).hexdigest()


def collect_runmenu_execution_evidence(
    directory: Path, workdir: Path, *, definition: str | None = None,
) -> RunMenuExecutionEvidence:
    """Execute the final emitted body with supporting export declarations."""
    from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616

    digest = ""
    try:
        source = load_generated_function_artifacts(directory, (0x102E0,))[0x102E0]
        start, end = generated_function_definition_span(source, "sub_102e0")
        if definition is None:
            definition = source[start:end]
        if generated_function_definition_span(definition, "sub_102e0") != (0, len(definition)):
            raise ValueError("expected exactly one emitted RunMenu definition")
        # Test final rendering itself; digest matching must remain exact.
        source = source[:start] + definition + source[end:]
        digest = sha256(definition.encode()).hexdigest()
        assert_runmenu_behavior(render_c_runtime_header_8616("portable-flat") + source, workdir)
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        return RunMenuExecutionEvidence(digest, f"{type(error).__name__}: {error}")
    return RunMenuExecutionEvidence(digest, None)

_HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
uint8_t inertia_memory[0x20000];
uint16_t inertia_cs, inertia_ds, inertia_es, inertia_ss;
unsigned short g_0B46, inertia_flags, g_0BA2 = 17, g_0160 = 2, xffff;
long g_0132;
static unsigned key, reads, upper_calls, event_count, events[8], cursor_calls;
static void require(int ok) { if (!ok) exit(20); }
static void event(unsigned value) {
    require(event_count < 8); events[event_count++] = value;
}
void sub_10060(void) { event(1); }
void sub_10678(void) { event(2); }
void sub_10498(unsigned short a) { require(a == 0); event(3); }
void sub_10808(void) { event(10); }
void sub_108d0(void) { event(11); }
void sub_10970(void) { event(12); }
void sub_10b50(void) { event(13); }
void sub_10c18(void) { event(14); }
void sub_10ce0(unsigned short a, unsigned short b) {
    require(a == 0 && b == 17); event(15);
}
void sub_128e4(unsigned short row, unsigned short col) {
    require(row == 3 && col == 75);
    require(SEG_U16(inertia_ds, 2986) == 0);
    require(SEG_U16(inertia_ds, 2980) == 0);
}
void sub_12bc0(unsigned short state) {
    require(state == (cursor_calls % 2 == 0)); ++cursor_calls;
}
unsigned short sub_11292(void) {
    require(reads < 2); return reads++ == 0 ? key : 27;
}
unsigned short sub_11278(unsigned short value) {
    require(value == (upper_calls++ == 0 ? key : 27));
    return value >= 'a' && value <= 'z' ? value - ('a' - 'A') : value;
}
int main(void) {
    const long pauses[] = {0, 30, 900, 930, 0x10384};
    for (key = 0; key < 256; ++key)
    for (unsigned p = 0; p < sizeof(pauses) / sizeof(pauses[0]); ++p)
    for (unsigned sound = 0; sound < 2; ++sound) {
        unsigned expected[8] = {0}, count = 0, choice = 0xffff;
        unsigned normalized = key >= 'a' && key <= 'z' ? key - 32 : key;
        long pause = pauses[p];
        unsigned final_sound = sound;
        switch (normalized) {
        case 'I': choice = 0; break;
        case 'B': choice = 1; break;
        case 'H': choice = 2; break;
        case 'E': choice = 3; break;
        case 'S': choice = 4; break;
        case 'Q': choice = 5; break;
        case '<': if (pause <= 900) pause += 30; expected[count++] = 1; break;
        case '>': if (pause) pause -= 30; expected[count++] = 1; break;
        case 'T': final_sound = !sound; expected[count++] = 1; break;
        }
        if (choice != 0xffff) {
            expected[count++] = 2; expected[count++] = 10 + choice;
            expected[count++] = 3;
        }
        memset(inertia_memory, 0, sizeof(inertia_memory));
        SEG_U16(inertia_ds, 2988) = 0xffff;
        SEG_U16(inertia_ds, 2986) = SEG_U16(inertia_ds, 2980) = 99;
        SEG_U16(inertia_ds, 2886) = g_0B46 = sound;
        g_0132 = pauses[p]; reads = upper_calls = event_count = cursor_calls = 0;
        inertia_esi = 0x1234a55a; inertia_edi = 0xabcd5aa5;
        sub_102e0();
        require(reads == (key == 27 ? 1u : 2u));
        require(upper_calls == reads && cursor_calls == 2 * reads);
        require(event_count == count && memcmp(events, expected, count * sizeof(unsigned)) == 0);
        require(SEG_U16(inertia_ds, 2988) == choice);
        require(g_0132 == pause && g_0B46 == final_sound);
        require(inertia_esi == 0x1234a55a && inertia_edi == 0xabcd5aa5);
    }
    puts("runmenu:2560 cases passed");
    return 0;
}
"""


def assert_runmenu_behavior(
    generated_c: str, tmp_path: Path,
    *, gp_runtime_abi: GPRegisterRuntimeABI8616 = DEFAULT_GP_RUNTIME_ABI_8616,
) -> None:
    """Check key dispatch, call arguments, ESC, globals and preserved registers."""
    source = tmp_path / "runmenu.c"
    executable = tmp_path / "runmenu"
    if not isinstance(gp_runtime_abi, GPRegisterRuntimeABI8616):
        raise ValueError(f"expected GPRegisterRuntimeABI8616, got {gp_runtime_abi!r}")
    header, definitions = "", "unsigned long inertia_esi, inertia_edi;\n"
    if gp_runtime_abi is GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS:
        header = coherent_gp_runtime_header_8616()
        definitions = coherent_gp_runtime_definitions_8616()
    source.write_text(header + generated_c + definitions + _HARNESS, encoding="utf-8")
    built = subprocess.run(
        ["gcc", "-std=c99", "-Werror=implicit-function-declaration", str(source), "-o", str(executable)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert built.returncode == 0, built.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0, f"RunMenu execution failed: exit={result.returncode}; {result.stderr}"
    assert result.stdout == "runmenu:2560 cases passed\n"
