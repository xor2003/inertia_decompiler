"""Execute a sidecar-free REP store kernel without wrapper argument recovery."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_compare_ghidra_function_coverage import _write_mz

_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = r'''
#include "generated.c"
#include <string.h>
uint8_t inertia_memory[0x100000];
uint16_t inertia_cs, inertia_ds, inertia_es = 0x1000, inertia_ss;
uint16_t inertia_flags = REP_BACKWARD ? 0 : 0xffff;
unsigned long inertia_edi = 0xcafe0000UL;
static unsigned char expected[0x100000];
int main(void)
{
    memset(inertia_memory, 0x5a, sizeof(inertia_memory));
    memset(expected, 0x5a, sizeof(expected));
    unsigned count = REP_COUNT;
    for (unsigned j = 0; j < count; ++j) {
        unsigned offset = (REP_START + (REP_BACKWARD ? -2 : 2) * j) & 0xffff;
        expected[0x10000 + offset] = REP_VALUE & 0xff;
        expected[0x10000 + ((offset + 1) & 0xffff)] = REP_VALUE >> 8;
    }
    if (sub_10010() != ((REP_VALUE + 1) & 0xffff)) return 2;
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


def _assert_generated_stores(
    text: str, tmp_path: Path, *, count: int = 3, start: int = 0x200,
    value: int = 0x1234, backward: bool = False,
) -> None:
    """Compile unchanged C and check termination, return and every memory byte."""
    (tmp_path / "generated.c").write_text(text, encoding="ascii")
    harness = tmp_path / "harness.c"
    harness.write_text(_HARNESS, encoding="ascii")
    executable = tmp_path / "repeat"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         f"-DREP_COUNT={count}", f"-DREP_START={start}", f"-DREP_VALUE={value}",
         f"-DREP_BACKWARD={int(backward)}", str(harness), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=2)
    assert executed.returncode == 0, "REP store violated the memory/return oracle"


def test_rep_store_execution_oracle_accepts_complete_effects(tmp_path: Path) -> None:
    _assert_generated_stores(_CORRECT_C, tmp_path)


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
])
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
    assert decompiled.returncode == 0, decompiled.stderr
    assert "validation=passed" in decompiled.stderr
    assert "whole-tail validation clean across 1 functions" in decompiled.stderr
    _assert_generated_stores(decompiled.stdout, tmp_path, count=count, start=start, value=value, backward=backward)
