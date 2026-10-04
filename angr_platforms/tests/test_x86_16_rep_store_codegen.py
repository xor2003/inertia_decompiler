"""Execute a sidecar-free REP store kernel without wrapper argument recovery."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)
from test_compare_ghidra_function_coverage import _write_mz

_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = r'''
#include "generated.c"
#include <string.h>
uint8_t inertia_memory[0x100000];
uint16_t inertia_cs, inertia_ds, inertia_es = 0x1000, inertia_ss;
uint16_t inertia_flags = REP_BACKWARD ? 0 : 0xffff;
static unsigned char expected[0x100000];
int main(void)
{
    inertia_edi = 0xcafe0000UL;
    memset(inertia_memory, 0x5a, sizeof(inertia_memory));
    memset(expected, 0x5a, sizeof(expected));
    unsigned count = REP_COUNT;
    for (unsigned j = 0; j < count; ++j) {
        unsigned offset = (REP_START + (REP_BACKWARD ? -2 : 2) * j) & 0xffff;
        expected[0x10000 + offset] = REP_VALUE & 0xff;
        expected[0x10000 + ((offset + 1) & 0xffff)] = REP_VALUE >> 8;
    }
    if (REP_KERNEL() != ((REP_VALUE + 1) & 0xffff)) return 2;
    if ((inertia_edi >> 16) != 0xcafeUL) return 3;
    return memcmp(expected, inertia_memory, sizeof(expected)) != 0;
}
'''

_CORRECT_C = r'''
#include <stdint.h>
extern uint8_t inertia_memory[];
unsigned short sub_10010(void)
{
    for (unsigned count = 0; count < 3; ++count) {
        inertia_memory[0x10200 + 2 * count] = 0x34;
        inertia_memory[0x10201 + 2 * count] = 0x12;
    }
    return 0x1235;
}
'''


def _compiled_kernel_label(generated: Path, tmp_path: Path) -> str:
    """Bind the sole compiled public label without parsing or altering C text.

    The CLI selects exactly one binary address. Labels from optional metadata
    may differ; ELF symbol metadata establishes only its exported spelling.
    Multiple public procedures refuse rather than choosing by a familiar name.
    """
    object_path = tmp_path / "kernel.o"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-c",
         str(generated), "-o", str(object_path)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    symbols = subprocess.run(
        ["nm", "--defined-only", "--extern-only", "--format=posix", str(object_path)],
        capture_output=True, text=True, check=False, timeout=10,
    )
    (tmp_path / "kernel.symbols.txt").write_text(symbols.stdout, encoding="utf-8")
    assert symbols.returncode == 0, symbols.stderr
    # This is a third-party symbol-table boundary, not recovered semantics.
    records = [line.split() for line in symbols.stdout.splitlines()]
    procedures = [record[0] for record in records if len(record) >= 2 and record[1] == "T"]
    assert len(procedures) == 1, "expected exactly one public procedure in the selected kernel"
    label = procedures[0]
    assert label.isascii() and label.replace("$", "_").isidentifier(), "invalid compiled C label"
    return label


def _assert_generated_stores(
    text: str, tmp_path: Path, *, count: int = 3, start: int = 0x200,
    value: int = 0x1234, backward: bool = False,
) -> None:
    """Compile unchanged C and check termination, return and every memory byte."""
    generated = tmp_path / "generated.c"
    generated.write_text(text, encoding="ascii")
    label = _compiled_kernel_label(generated, tmp_path)
    harness = tmp_path / "harness.c"
    runtime = coherent_gp_runtime_header_8616() + coherent_gp_runtime_definitions_8616()
    harness.write_text(runtime + _HARNESS, encoding="ascii")
    executable = tmp_path / "repeat"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         f"-DREP_COUNT={count}", f"-DREP_START={start}", f"-DREP_VALUE={value}",
         f"-DREP_BACKWARD={int(backward)}", f"-DREP_KERNEL={label}",
         str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=2)
    assert executed.returncode == 0, "REP store violated the memory/return oracle"


def test_rep_store_execution_oracle_accepts_complete_effects(tmp_path: Path) -> None:
    _assert_generated_stores(_CORRECT_C, tmp_path)


@pytest.mark.parametrize("label", ["alternate_kernel_label", "$optional_kernel"])
def test_rep_store_execution_oracle_accepts_an_optional_symbol_label(tmp_path: Path, label: str) -> None:
    """Names are optional metadata, not the memory/return oracle's identity."""
    _assert_generated_stores(_CORRECT_C.replace("sub_10010", label), tmp_path)


def test_rep_store_execution_oracle_refuses_ambiguous_public_entry(tmp_path: Path) -> None:
    """Multiple exported procedures cannot establish the requested entry label."""
    ambiguous = _CORRECT_C + "\nunsigned short unrelated(void) { return 0; }\n"
    with pytest.raises(AssertionError, match="exactly one public procedure"):
        _assert_generated_stores(ambiguous, tmp_path)


@pytest.mark.parametrize("old,new", [
    ("count < 3", "count < 2"),
    ("count < 3", "count < 4"),
    ("= 0x34", "= 0x35"),
    ("return 0x1235", "return 0x1234"),
    ("return 0x1235", "inertia_memory[0] = 0; return 0x1235"),
])
def test_rep_store_execution_oracle_rejects_corrupt_effects(tmp_path: Path, old: str, new: str) -> None:
    with pytest.raises(AssertionError, match="violated the memory/return oracle"):
        _assert_generated_stores(_CORRECT_C.replace(old, new), tmp_path)


@pytest.mark.parametrize("prefix,backward,count,start,value", [
    (0xf3, False, 3, 0x200, 0x1234), (0xf2, False, 3, 0x200, 0x1234),
    (0xf3, False, 0, 0x200, 0x1234), (0xf3, True, 0, 0x200, 0x1234),
    (0xf3, False, 1, 0xffff, 0xffff), (0xf3, True, 1, 0xffff, 0xff),
    (0xf3, True, 3, 1, 0xabcd), (0xf2, True, 3, 0x200, 0x8000),
    (0xf3, False, 3, 0xfffe, 0xffff), (0xf3, True, 3, 0, 0xabcd),
])
@pytest.mark.requires_kvm
def test_rep_stosw_generated_c_keeps_loop_carried_store_state(
    tmp_path: Path, prefix: int, backward: bool, count: int, start: int, value: int,
) -> None:
    """Require exact wrapping stores, termination and the separate return effect."""
    binary = tmp_path / "repeat.exe"
    entry = bytes.fromhex("e80d00b8004ccd21") + b"\x90" * 8
    # Return arithmetic keeps this a mixed-effect body, not an intrinsic-only wrapper.
    # CLD; MOV DI,0200h; MOV AX,1234h; MOV CX,3; REP STOSW; INC AX; RET.
    body = bytes([0xfd if backward else 0xfc, 0xbf]) + start.to_bytes(2, "little")
    body += b"\xb8" + value.to_bytes(2, "little") + b"\xb9" + count.to_bytes(2, "little")
    body += bytes([prefix, 0xab, 0x40, 0xc3])
    _write_mz(binary, entry + body)
    decompiled = subprocess.run(
        [sys.executable, str(_ROOT / "decompile.py"), str(binary), "--addr", "0x10010",
         "--timeout", "30", "--ignore-local-sidecar-hints", "--no-alternate-source-c", "--c-target", "portable-flat"],
        cwd=_ROOT, env=dict(os.environ, PYTHON_JIT="1", PYTHONHASHSEED="0"),
        capture_output=True, text=True, check=False, timeout=120,
    )
    stdout_artifact = tmp_path / "decompile.stdout.txt"
    stdout_artifact.write_text(decompiled.stdout, encoding="utf-8")
    (tmp_path / "decompile.stderr.txt").write_text(decompiled.stderr, encoding="utf-8")
    assert decompiled.returncode == 0, f"{decompiled.stderr}\nCLI stdout: {stdout_artifact}"
    assert "validation=passed" in decompiled.stderr
    assert "whole-tail validation clean across 1 functions" in decompiled.stderr
    _assert_generated_stores(decompiled.stdout, tmp_path, count=count, start=start, value=value, backward=backward)
