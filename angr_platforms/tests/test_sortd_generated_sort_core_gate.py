"""Tests for the generated SORTD sort-core parity gate."""

import subprocess
from pathlib import Path

import pytest
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_symbols_8616
from angr_platforms.X86_16.lowering.gp_word_runtime import (
    GPRegisterRuntimeABI8616 as ABI,
)

from inertia_decompiler.generated_c_function_extraction import (
    load_generated_function_artifacts,
)
from scripts.check_sortd_generated_sort_core import (
    SORT_FUNCTIONS,
    _map_binary_globals,
    extract_generated_functions,
)
from scripts.sortd_gp_runtime import prepare_sortd_gp_runtime

_BEEP_ADDR = 0x10E70
_SLEEP_ADDR = 0x10F38
_SWAPS_ADDR = 0x107B8
_INSERTION_SORT_ADDR = 0x10808


@pytest.mark.parametrize("mutation", [
    "", "output_values[1] = 0;", "output_values[2] = 0;",
    "output_values[1] = 38; output_values[2] = 215;",
    "last_divisor = 121;", "output_calls = 4;", "output_values[4] = 0x33;",
])
def test_timer_oracle_checks_values_and_rejects_corruption(tmp_path: Path, mutation: str) -> None:
    consumer = tmp_path / "timer.c"
    consumer.write_text(
        "extern unsigned short output_ports[8], output_values[8], last_divisor;\n"
        "extern int output_calls;\n"
        "int beep_timer_programming_matches(unsigned short);\n"
        "int main(void) {\n"
        "unsigned short ports[5] = {67, 66, 66, 97, 97};\n"
        "unsigned short values[5] = {182, 215, 38, 0x33, 0x30};\n"
        "for (int i = 0; i < 5; ++i) { output_ports[i] = ports[i]; output_values[i] = values[i]; }\n"
        "last_divisor = 120; output_calls = 5;\n"
        + mutation + "\nreturn beep_timer_programming_matches(120) ? 0 : 1;\n}\n",
        encoding="ascii",
    )
    runtime = Path(__file__).with_name("fixtures") / "sortd_generated_behavior_runtime.c"
    executable = tmp_path / "timer"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(runtime), str(consumer), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=15,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=5)
    assert executed.returncode == bool(mutation), executed.stderr


def test_behavior_slice_includes_timing_and_speaker_functions() -> None:
    assert _BEEP_ADDR in SORT_FUNCTIONS
    assert _SLEEP_ADDR in SORT_FUNCTIONS


def test_extracts_function_definition_without_following_diagnostics() -> None:
    transcript = """
/* == function 0x107b8 sub_107b8 == */
/* -- c -- */
extern unsigned short g_0BA4;
void sub_107b8(unsigned short *left, unsigned short *right)
{
    g_0BA4 += 1;
    left[0] = right[0];
}
[dbg] next worker
/* == function 0x10808 sub_10808 == */
/* -- c -- */
void sub_10808(void)
{
    return;
}
"""

    functions = extract_generated_functions(transcript)

    assert tuple(functions) == (0x107B8, 0x10808)
    assert functions[0x107B8].source.endswith("}\n")
    assert "[dbg]" not in functions[0x107B8].source


def test_extracts_numeric_worker_definition_under_source_label() -> None:
    transcript = """
/* == function 0x10010 main == */
/* -- c -- */
unsigned short sub_10010(void)
{
    return 0;
}
/* == function 0x107b8 Swaps == */
/* -- c -- */
void sub_107b8(unsigned short *left, unsigned short *right)
{
    left[0] = right[0];
}
"""

    functions = extract_generated_functions(transcript)

    assert tuple(functions) == (0x107B8,)
    assert functions[0x107B8].name == "sub_107b8"
    assert "void sub_107b8" in functions[0x107B8].source


def test_extracts_deferred_c_independently_of_marker_order() -> None:
    transcript = """
/* == function 0x10808 sub_10808 == */
/* == function 0x107b8 sub_107b8 == */
#include <DOS.H>
extern unsigned short g_0BA4;
void sub_10808(void) { g_0BA4 = 1; }
void sub_107b8(void) { g_0BA4 = 2; }
"""

    functions = extract_generated_functions(transcript)

    assert _SWAPS_ADDR in functions
    assert _INSERTION_SORT_ADDR in functions
    assert "sub_10808" not in functions[0x107B8].source
    assert "sub_107b8" not in functions[0x10808].source


def test_timestamped_diagnostic_markers_do_not_capture_worker_logs() -> None:
    transcript = """
[03:18:00] /* == function 0x107b8 sub_107b8 == */
/* -- c -- */
void sub_107b8(void) { g_0BA4 = 1; }
[dbg] clean parallel function worker: start 0x107b8
[03:18:01] /* info: function 0x107b8 sub_107b8 attempt=decompiled validation=passed */
extern unsigned short g_0BA4;
void sub_107b8(void) { g_0BA4 = 2; }
"""

    functions = extract_generated_functions(transcript)

    assert tuple(functions) == (0x107B8,)
    assert "[dbg]" not in functions[0x107B8].source
    assert "g_0BA4 = 1" not in functions[0x107B8].source
    assert "g_0BA4 = 2" in functions[0x107B8].source
    assert functions[0x107B8].source.endswith("}\n")


def test_loads_exact_address_named_function_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "000107b8-sub_107b8.c"
    artifact.write_text("void sub_107b8(void) { return; }\n")

    sources = load_generated_function_artifacts(tmp_path, (0x107B8,))

    assert sources == {0x107B8: "void sub_107b8(void) { return; }\n"}


def test_maps_scalar_and_array_globals_to_exact_ds_offsets() -> None:
    source = """
extern g_0B4C_entry g_0B4C[];
extern unsigned short g_0B50[3];
extern unsigned short g_0BA4;
extern long g_0132;
extern unsigned long g_0B48;
"""

    mapped = _map_binary_globals(source)

    assert "#define g_0B4C ((g_0B4C_entry *)(inertia_memory + 0x0B4Cu))" in mapped
    assert "#define g_0B50 ((unsigned short *)(inertia_memory + 0x0B50u))" in mapped
    assert "#define g_0BA4 (*(unsigned short *)(inertia_memory + 0x0BA4u))" in mapped
    assert "#define g_0132 (*(inertia_i32 *)(inertia_memory + 0x0132u))" in mapped
    assert "#define g_0B48 (*(inertia_u32 *)(inertia_memory + 0x0B48u))" in mapped


@pytest.mark.parametrize("abi", list(ABI))
def test_sortd_runtime_links_and_resets_complete_gp_abi(tmp_path: Path, abi: ABI) -> None:
    symbols = runtime_gp_state_symbols_8616()
    declarations = "\n".join(f"extern unsigned long {symbol};" for symbol in symbols)
    if abi is ABI.COHERENT_WORD_VIEWS:
        declarations = ""
    assignments = "\n".join(f"{symbol} = 0x12345678UL;" for symbol in symbols)
    checks = "\n".join(f"if ({symbol} != 0x12345678UL) return 1;" for symbol in symbols)
    reset_checks = "\n".join(f"if ({symbol} != 0UL) return 2;" for symbol in symbols)
    consumer = tmp_path / "consumer.c"
    consumer.write_text(
        declarations + "\nvoid reset_runtime_observation(void);\nint main(void) {\n"
        + assignments + "\n" + checks + "\nreset_runtime_observation();\n"
        + reset_checks + "\nreturn 0;\n}\n",
        encoding="ascii",
    )
    runtime = Path(__file__).with_name("fixtures") / "sortd_generated_behavior_runtime.c"
    runtime, flags = prepare_sortd_gp_runtime(tmp_path, runtime, abi)
    executable = tmp_path / "runtime-abi"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-flto", *flags, str(runtime),
         str(consumer), "-o", str(executable)],
        text=True, capture_output=True, timeout=15, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5, check=False)
    assert executed.returncode == 0, executed.stderr


def test_sortd_runtime_rejects_untyped_abi_before_writing_files(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="expected GPRegisterRuntimeABI8616"):
        prepare_sortd_gp_runtime(tmp_path, tmp_path / "absent.c", "coherent_word_views")
    assert not tuple(tmp_path.iterdir())
