"""Compile coherent word/full register views without disabling strict aliasing."""

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.c_runtime_header import render_c_runtime_header_8616
from inertia.lowering.gp_register_state import (
    lower_architectural_gp_register_state_8616,
    runtime_gp_state_symbols_8616,
)
from inertia.lowering.gp_word_runtime import (
    GP_WORD_RUNTIME_LANES_8616,
    GPRegisterRuntimeABI8616,
    gp_runtime_abi_8616,
    select_gp_runtime_abi_8616,
)

import tools.compiler_toolchain.build_msc6_examples as build
from tools.compiler_toolchain.msc6_runtime_support import msc6_runtime_state_declarations, msc6_runtime_support_source


def test_lowering_initializes_fresh_codegen_and_preserves_explicit_legacy_abi():
    for _ in range(2):
        codegen = SimpleNamespace(cfunc=None, project=None)
        assert not lower_architectural_gp_register_state_8616(codegen)
        assert gp_runtime_abi_8616(codegen) is GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS
        select_gp_runtime_abi_8616(codegen, GPRegisterRuntimeABI8616.SCALAR)
        lower_architectural_gp_register_state_8616(codegen)
        assert gp_runtime_abi_8616(codegen) is GPRegisterRuntimeABI8616.SCALAR


def test_default_msc6_provider_matches_production_lowering():
    assert msc6_runtime_state_declarations() == msc6_runtime_state_declarations(
        GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS,
    )
    assert msc6_runtime_support_source() == msc6_runtime_support_source(
        GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS,
    )


@pytest.mark.parametrize("invalid", [None, "coherent_word_views", 1])
def test_lowering_rejects_corrupt_existing_abi_before_processing_ast(invalid):
    codegen = SimpleNamespace(_inertia_gp_runtime_abi_8616=invalid)
    with pytest.raises(ValueError, match="expected GPRegisterRuntimeABI8616"):
        lower_architectural_gp_register_state_8616(codegen)


def test_final_result_cache_tracks_gp_runtime_and_projection_owners():
    from pathlib import Path

    from inertia.lowering import gp_word_assignment, gp_word_runtime
    from inertia.cli.cache import DECOMPILATION_CACHE_SOURCE_FILES

    for owner_module, leaf in (
        (gp_word_runtime, "gp_word_runtime.py"),
        (gp_word_assignment, "gp_word_assignment.py"),
    ):
        assert Path(owner_module.__file__).parent / leaf in DECOMPILATION_CACHE_SOURCE_FILES


def test_word_runtime_covers_existing_architectural_lanes():
    assert {lane.full_symbol for lane in GP_WORD_RUNTIME_LANES_8616} == set(runtime_gp_state_symbols_8616())
    assert len({lane.storage_symbol for lane in GP_WORD_RUNTIME_LANES_8616}) == 8
    assert len({lane.word_symbol for lane in GP_WORD_RUNTIME_LANES_8616}) == 8
    registers = Arch86_16().registers
    for lane in GP_WORD_RUNTIME_LANES_8616:
        full_offset, full_size = registers[lane.full_register]
        word_offset, word_size = registers[lane.word_register]
        assert (full_offset, full_size) == (word_offset, 4)
        assert word_size == 2


@pytest.mark.parametrize("optimization,corruption", [
    ("-O0", None), ("-O2", None), ("-O2", "split_storage"), ("-O2", "wrong_word"),
])
def test_compiled_shared_views_preserve_upper_words_and_wrap(tmp_path, optimization, corruption):
    compiler = shutil.which("gcc")
    assert compiler is not None, "GCC is required for the mandatory compiled GP runtime oracle"
    abi = GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS
    header = render_c_runtime_header_8616(None, gp_runtime_abi=abi)
    definitions = msc6_runtime_support_source(abi)
    if corruption == "wrong_word":
        header = header.replace(".word.low)", ".word.high)")
    elif corruption == "split_storage":
        for lane in GP_WORD_RUNTIME_LANES_8616:
            header = header.replace(
                f"#define {lane.word_symbol} ({lane.storage_symbol}.word.low)",
                f"extern unsigned short {lane.word_symbol};",
            )
            definitions += f"unsigned short {lane.word_symbol} = 0;\n"
    (tmp_path / "runtime.h").write_text(header)
    # Separate translation units prove the lvalues share external storage.
    (tmp_path / "runtime.c").write_text('#include "runtime.h"\n' + definitions)
    (tmp_path / "test.c").write_text('#include "runtime.h"\n#include "runtime.h"\n' + _client_body())
    executable = tmp_path / "test"
    compiled = subprocess.run(
        [compiler, "-std=c89", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         "-fstrict-aliasing", optimization, str(tmp_path / "test.c"), str(tmp_path / "runtime.c"),
         "-o", str(executable)], capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=10)
    assert executed.returncode == (0 if corruption is None else 1), executed.stderr


def _client_body():
    """Use identical behavior checks on the host and actual 16-bit compiler."""
    operations = []
    for lane in GP_WORD_RUNTIME_LANES_8616:
        full, word = lane.full_symbol, lane.word_symbol
        operations.append(f"""
    {full} = 0x12345678UL;
    CHECK({word} == 0x5678U);
    {word} = 0xabcdU;
    CHECK({full} == 0x1234abcdUL);
    {full} = 0xffffffffUL;
    {word} += 1U;
    CHECK({full} == 0xffff0000UL);
    {word} -= 2U;
    CHECK({full} == 0xfffffffeUL);
    {word} = ({word} & 0xff00U) | 0x56U;
    CHECK({full} == 0xffffff56UL);
    {word} = ({word} & 0x00ffU) | 0x1200U;
    CHECK({full} == 0xffff1256UL);
""")
    return (
        '#define CHECK(value) do { if (!(value)) return 1; } while (0)\n'
        + "int main(void) {\n" + "".join(operations) + "return 0;\n}\n"
    )


def test_runtime_header_recognizes_verified_borland_dos_order_and_refuses_unknown_target(
    tmp_path: Path,
) -> None:
    """Accept probed Borland DOS byte order without weakening unknown-target refusal."""
    compiler = shutil.which("gcc")
    assert compiler is not None
    abi = GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS
    (tmp_path / "runtime.h").write_text(
        render_c_runtime_header_8616(None, gp_runtime_abi=abi), encoding="utf-8",
    )
    source = tmp_path / "target.c"
    source.write_text(
        '#include "runtime.h"\n'
        "int main(void) { inertia_gp_lane lane; lane.full = 0x12345678UL; "
        "return lane.word.low == 0x5678U ? 0 : 1; }\n",
        encoding="utf-8",
    )
    host_order_macros = (
        "-U__BYTE_ORDER__", "-U__ORDER_BIG_ENDIAN__", "-U__ORDER_LITTLE_ENDIAN__",
    )
    borland_dos = subprocess.run(
        [compiler, "-std=c89", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         *host_order_macros, "-D__TURBOC__=1", "-D__MSDOS__=1", "-I", str(tmp_path),
         str(source), "-o", str(tmp_path / "borland-dos")],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert borland_dos.returncode == 0, borland_dos.stderr
    executed = subprocess.run(
        [str(tmp_path / "borland-dos")], capture_output=True, text=True, check=False, timeout=10,
    )
    assert executed.returncode == 0, executed.stderr

    unknown_target = subprocess.run(
        [compiler, "-std=c89", "-pedantic-errors", *host_order_macros,
         "-I", str(tmp_path), "-c", str(source), "-o", str(tmp_path / "unknown.o")],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert unknown_target.returncode != 0
    assert "Inertia GP runtime needs a known target byte order" in unknown_target.stderr

    for index, partial in enumerate(("-D__TURBOC__=1", "-D__MSDOS__=1")):
        half_target = subprocess.run(
            [compiler, "-std=c89", "-pedantic-errors", *host_order_macros, partial,
             "-I", str(tmp_path), "-c", str(source), "-o", str(tmp_path / f"half{index}.o")],
            capture_output=True, text=True, check=False, timeout=30,
        )
        assert half_target.returncode != 0
        assert "Inertia GP runtime needs a known target byte order" in half_target.stderr

    big_endian_source = tmp_path / "big-endian.c"
    big_endian_source.write_text(
        '#include <stddef.h>\n#include "runtime.h"\n'
        "typedef char inertia_big_endian_word_order["
        "(offsetof(inertia_gp_lane, word.high) == 0 && "
        "offsetof(inertia_gp_lane, word.low) == 2) ? 1 : -1];\n",
        encoding="utf-8",
    )
    big_endian = subprocess.run(
        [compiler, "-std=c89", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         *host_order_macros, "-D__BYTE_ORDER__=4321", "-D__ORDER_BIG_ENDIAN__=4321",
         "-I", str(tmp_path), "-c", str(big_endian_source), "-o", str(tmp_path / "big-endian.o")],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert big_endian.returncode == 0, big_endian.stderr


def test_runtime_header_rejects_misdetected_narrow_dword(tmp_path: Path) -> None:
    """The dword sizeof guard must fire even while the union stays four bytes.

    MS C 5.1's preprocessor truncates 32-bit literals, so a word-wide typedef
    can pass the union-size check while silently shrinking ``full``; the
    explicit ``sizeof(inertia_gp_dword)`` guard exists for that defect class.
    """
    compiler = shutil.which("gcc")
    assert compiler is not None
    abi = GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS
    header = render_c_runtime_header_8616(None, gp_runtime_abi=abi)
    assert "sizeof(inertia_gp_dword)" in header
    # On a 32-bit-int host the active typedef is unsigned int; corrupting that
    # branch to a 16-bit type keeps the union at four bytes via word.low/high.
    corrupted = header.replace(
        "typedef unsigned int inertia_gp_dword;",
        "typedef unsigned short inertia_gp_dword;",
    )
    assert corrupted != header
    (tmp_path / "runtime.h").write_text(corrupted, encoding="utf-8")
    source = tmp_path / "narrow.c"
    source.write_text(
        '#include "runtime.h"\nint main(void) { return 0; }\n', encoding="utf-8",
    )
    compiled = subprocess.run(
        [compiler, "-std=c89", "-pedantic-errors",
         "-I", str(tmp_path), "-c", str(source), "-o", str(tmp_path / "narrow.o")],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode != 0
    assert "inertia_gp_dword_must_be_four_bytes" in compiled.stderr


@pytest.mark.requires_kvm
@pytest.mark.skipif(
    not build.DEFAULT_KVIKDOS.is_file() or not build.DEFAULT_MSC6_ROOT.is_dir(),
    reason="external DOS runtime gate requires kvikdos and MS C 6",
)
def test_msc6_word_runtime_compiles_and_executes(tmp_path):
    """Require the real DOS target to agree with the host storage oracle."""
    assert build.DEFAULT_KVIKDOS.is_file(), "kvikdos is required for the GP runtime DOS gate"
    assert build.DEFAULT_MSC6_ROOT.is_dir(), "MS C 6 is required for the GP runtime DOS gate"
    source = tmp_path / "GPWORD.C"
    source.write_text(
        msc6_runtime_state_declarations(GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS) + _client_body(),
    )
    built, *diagnostics = build._compile_and_link(
        source, tmp_path, kvikdos=build.DEFAULT_KVIKDOS, msc6_root=build.DEFAULT_MSC6_ROOT,
        obj_name="GPWORD.OBJ", exe_name="GPWORD.EXE", map_name="GPWORD.MAP",
        runtime_support=True, gp_runtime_abi=GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS,
    )
    assert built, "\n".join(diagnostics)
    passed, exit_code, stdout, stderr = build._run_example(
        tmp_path / "GPWORD.EXE", tmp_path, kvikdos=build.DEFAULT_KVIKDOS,
    )
    assert passed and exit_code == 0, (exit_code, stdout, stderr)
