from __future__ import annotations

import shutil
import signal
import subprocess

import pytest
from inertia.lowering.c_runtime_header import (
    LOWERED_RUNTIME_HELPER_DECLARATIONS_8616,
    LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616,
    interrupt_helper_declarations_8616,
    is_lowered_runtime_macro_8616,
    render_c_runtime_header_8616,
    render_near_pointer_arithmetic_macros_8616,
    render_pointer_storage_macros_8616,
    runtime_helper_declaration_8616,
)

from inertia.lowering.analysis_helpers import InterruptCall, interrupt_service_name


def test_x86_16_c_runtime_header_renders_portable_flat_helpers() -> None:
    header = render_c_runtime_header_8616("portable-flat")

    assert "#include <stddef.h>" in header
    assert "#include <stdint.h>" in header
    assert "extern uint8_t inertia_memory[];" in header
    assert "extern uint16_t inertia_ds;" in header
    assert "#define SEG_LINEAR(seg, off)" in header
    assert "#define MK_FP(seg, off)" in header
    assert "#define SEG_U8(seg, off)" in header
    assert "#define MEM_U16(ptr)" in header


def test_x86_16_c_runtime_header_renders_msc_dos_helpers() -> None:
    header = render_c_runtime_header_8616("msc-dos")

    assert "#include <DOS.H>" in header
    assert "typedef unsigned char  uint8_t;" in header
    assert "typedef long clock_t;" in header
    assert "#define MK_FP(seg, off)" in header
    assert "#define SEG_PTR(seg, off)" in header
    assert "#define SEG_U32(seg, off)" in header
    assert "inertia_memory" not in header
    assert "extern uint16_t inertia_ds;" in header


def test_x86_16_c_runtime_header_is_case_and_space_tolerant() -> None:
    assert render_c_runtime_header_8616("  PORTABLE-FLAT  ") == render_c_runtime_header_8616("portable-flat")
    assert render_c_runtime_header_8616("  MSC-DOS  ") == render_c_runtime_header_8616("msc-dos")


def test_x86_16_c_runtime_header_uses_signed_microsoft_clock_type() -> None:
    assert "typedef long clock_t;" in render_c_runtime_header_8616("portable-flat")
    assert "typedef unsigned long clock_t;" not in render_c_runtime_header_8616("portable-flat")
    assert "typedef long clock_t;" in render_c_runtime_header_8616("msc-dos")


def test_x86_16_c_runtime_header_declares_every_lowered_zero_arg_runtime_call() -> None:
    for target in ("portable-flat", "msc-dos"):
        header = render_c_runtime_header_8616(target)
        for declaration in LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616.values():
            assert declaration in header


def test_x86_16_c_runtime_header_declares_typed_runtime_abi() -> None:
    for target in ("portable-flat", "msc-dos"):
        header = render_c_runtime_header_8616(target)
        for declaration in LOWERED_RUNTIME_HELPER_DECLARATIONS_8616.values():
            assert declaration in header


def test_x86_16_c_runtime_header_declares_target_width_signed_division_helper() -> None:
    portable = render_c_runtime_header_8616("portable-flat")
    msc = render_c_runtime_header_8616("msc-dos")

    assert "int32_t aNldiv(int32_t dividend, int32_t divisor);" in portable
    assert "long aNldiv(long dividend, long divisor);" in msc
    assert "long aNldiv(" not in portable


def test_x86_16_c_runtime_header_exposes_exact_memset_abi() -> None:
    declaration = "void * memset(void *dst, int value, unsigned short count);"

    assert runtime_helper_declaration_8616("memset", "portable-flat") == declaration
    assert runtime_helper_declaration_8616("memset", "msc-dos") == declaration


def test_x86_16_c_runtime_header_declares_generic_interrupt_runtime_helper() -> None:
    declarations = interrupt_helper_declarations_8616(
        [InterruptCall(insn_addr=0x101D, vector=0x33)],
        "pseudo",
    )

    assert declarations == ["unsigned short interrupt_int33(void);"]


def test_x86_16_c_runtime_header_declares_mouse_position_interrupt_inputs() -> None:
    declarations = interrupt_helper_declarations_8616(
        [InterruptCall(insn_addr=0x1023, vector=0x33, ax=4)],
        "pseudo",
    )

    assert declarations == [
        "unsigned short interrupt_int33(unsigned short ax, unsigned short cx, unsigned short dx);"
    ]


def test_generic_interrupt_service_names_match_runtime_declarations() -> None:
    """Unmodeled vectors must use the actual runtime ABI, not diagnostic names."""
    for vector in (0x05, 0x18, 0x22, 0x2F, 0x33, 0x80, 0xFF):
        call = InterruptCall(insn_addr=0x1000, vector=vector)
        declarations = interrupt_helper_declarations_8616([call], "pseudo")
        name = interrupt_service_name(call, "pseudo")
        assert any(f" {name}(" in declaration for declaration in declarations), (vector, name, declarations)


def test_x86_16_c_runtime_header_keeps_raw_and_service_interrupt_declarations() -> None:
    declarations = interrupt_helper_declarations_8616(
        [
            InterruptCall(insn_addr=0x1010, vector=0x16),
            InterruptCall(insn_addr=0x1020, vector=0x21, ah=0x09),
        ],
        "modern",
    )

    assert "unsigned short bios_int16_keyboard(void);" in declarations
    assert "unsigned short dos_int21();" in declarations
    assert "unsigned _bios_keybrd(unsigned keycmd);" in declarations
    assert "void print_dos_string(const char *s);" in declarations


def test_x86_16_c_runtime_header_exposes_target_width_external_abis() -> None:
    assert runtime_helper_declaration_8616("setbkcolor", "portable-flat") == (
        "int32_t setbkcolor(int32_t color);"
    )
    assert runtime_helper_declaration_8616("setbkcolor", "msc-dos") == (
        "long setbkcolor(long color);"
    )
    for target in ("portable-flat", "msc-dos"):
        assert runtime_helper_declaration_8616("sprintf", target) == (
            "int sprintf(char *buf, const char *fmt, ...);"
        )


def test_x86_16_c_runtime_header_refuses_unknown_target() -> None:
    assert render_c_runtime_header_8616(None) == ""
    assert render_c_runtime_header_8616("") == ""
    assert render_c_runtime_header_8616("unknown") == ""


def test_x86_16_c_runtime_header_distinguishes_macros_from_callables() -> None:
    assert is_lowered_runtime_macro_8616("SEG_U32")
    assert not is_lowered_runtime_macro_8616("aNldiv")


@pytest.mark.parametrize("target", ["msc-dos", "portable-flat"])
def test_pointer_storage_macros_share_target_abi(target: str) -> None:
    macros = render_pointer_storage_macros_8616(target)
    assert macros in render_c_runtime_header_8616(target)
    intermediate = "(uintptr_t)" if target == "portable-flat" else ""
    for bits in (16, 32):
        assert f"((uint{bits}_t){intermediate}(ptr))" in macros


def test_pointer_storage_macros_refuse_unknown_target() -> None:
    with pytest.raises(ValueError, match="Unsupported pointer-storage target"):
        render_pointer_storage_macros_8616("unknown")


@pytest.mark.parametrize("optimization", ["-O0", "-O2"])
@pytest.mark.parametrize("corruption", [None, "flatten_segments", "word_step", "no_wrap"])
def test_near_byte_arithmetic_preserves_segments_word_wrap_and_null(tmp_path, optimization, corruption):
    """Execute offset arithmetic independently of host pointer bits and pointee size."""
    compiler = shutil.which("gcc")
    assert compiler is not None, "GCC is required for the pointer representation oracle"
    source = tmp_path / "near.c"
    header = render_c_runtime_header_8616("portable-flat")
    corrupted_additions = {
        "flatten_segments": "((void *)((uint8_t *)(ptr) + (uint16_t)(bytes)))",
        "word_step": "NEAR_PTR(dst_seg, (uint16_t)(NEAR_OFFSET(src_seg, ptr) + 2 * (uint16_t)(bytes)))",
        "no_wrap": "((void *)((uint8_t *)SEG_PTR(dst_seg, NEAR_OFFSET(src_seg, ptr)) + (uint16_t)(bytes)))",
    }
    if corruption is not None:
        header += "#undef NEAR_BYTE_ADD\n#define NEAR_BYTE_ADD(src_seg, dst_seg, ptr, bytes) " + corrupted_additions[corruption] + "\n"
    source.write_text(header + r"""
uint8_t inertia_memory[0x30000];
uint16_t inertia_cs, inertia_ds, inertia_es, inertia_ss;
int main(int argc, char **argv) {
    static const uint16_t cases[][4] = {
        {0x123, 0x432, 17, 6},
        {0x123, 0x432, 0xfffe, 2},
        {0x123, 0x432, 0xffff, 3},
        {0x123, 0x432, 0x1234, 0xfffe},
        {0x123, 0x432, 0, 0},
        {0x123, 0x432, 0, 7}
    };
    unsigned int i;
    uint8_t unrelated_native_object = 0;
    (void)argv;
    if (argc > 1) {
        (void)NEAR_BYTE_ADD(0x123, 0x432, &unrelated_native_object, 2);
        return 90;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint16_t source_segment = cases[i][0], target_segment = cases[i][1];
        uint16_t original = cases[i][2], delta = cases[i][3];
        uint16_t expected = (uint16_t)(original + delta);
        void *base = original ? SEG_PTR(source_segment, original) : 0;
        void *result = NEAR_BYTE_ADD(source_segment, target_segment, base, delta);
        void *expected_pointer = expected ? SEG_PTR(target_segment, expected) : 0;
        if (NEAR_OFFSET(source_segment, base) != original) return 1;
        if (result != expected_pointer) return 2;
        if (NEAR_OFFSET(target_segment, result) != expected) return 3;
    }
    return 0;
}
""")
    executable = tmp_path / "near"
    compiled = subprocess.run(
        [compiler, "-std=c99", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         optimization, str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False, timeout=10,
    )
    if corruption is not None:
        assert executed.returncode == 2, "the pointer-value oracle must reject the deliberately incorrect helper"
        return
    assert executed.returncode == 0, executed.stderr
    refused = subprocess.run(
        [str(executable), "unbound"], capture_output=True, text=True, check=False, timeout=10,
    )
    assert refused.returncode == -signal.SIGABRT, "an unbound native object must abort, not become a guessed DOS offset"


@pytest.mark.parametrize("target", ["msc-dos", "portable-flat"])
def test_near_arithmetic_macros_share_the_authoritative_target_header(target):
    """Headers and macro classification must expose one coherent runtime owner."""
    macros = render_near_pointer_arithmetic_macros_8616(target)
    assert macros in render_c_runtime_header_8616(target)
    for name in ("NEAR_OFFSET", "NEAR_PTR", "NEAR_BYTE_ADD"):
        assert is_lowered_runtime_macro_8616(name)


def test_near_arithmetic_macros_refuse_unknown_target():
    with pytest.raises(ValueError, match="Unsupported near-pointer arithmetic target"):
        render_near_pointer_arithmetic_macros_8616("unknown")
