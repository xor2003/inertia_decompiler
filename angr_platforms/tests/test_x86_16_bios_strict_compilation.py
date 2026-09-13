"""Require sidecar-free BIOS output to satisfy the strict C acceptance gate."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_compare_ghidra_function_coverage import _write_mz

REPO_ROOT = Path(__file__).resolve().parents[2]

_BIOS_HARNESS = r"""
uint8_t inertia_memory[1u << 20];
uint16_t inertia_cs, inertia_ds, inertia_es, inertia_ss;
int main(void) {
    for (unsigned seed = 1; seed <= 3; ++seed) {
        for (unsigned i = 0; i < sizeof(inertia_memory); ++i)
            inertia_memory[i] = (uint8_t)(1 + (i + seed) % 255);
        inertia_cs = 0x1000;
        inertia_ds = 0x2000;
        inertia_ss = 0x3000;
        inertia_es = (uint16_t)(0x4000 + seed);
        sub_10010();
        if (inertia_es != 0 || inertia_cs != 0x1000 ||
            inertia_ds != 0x2000 || inertia_ss != 0x3000)
            return 1;
        for (unsigned i = 0; i < sizeof(inertia_memory); ++i) {
            uint8_t expected = (i == 0x417 || i == 0x418)
                ? 0 : (uint8_t)(1 + (i + seed) % 255);
            if (inertia_memory[i] != expected)
                return 2;
        }
    }
    return 0;
}
"""

_REFERENCE_DECLARATIONS = """
#include <stdint.h>
extern uint8_t inertia_memory[];
extern uint16_t inertia_cs, inertia_ds, inertia_es, inertia_ss;
"""


def _execute_bios_c(tmp_path: Path, generated_c: str) -> subprocess.CompletedProcess[str]:
    """Strictly compile unchanged C and check its observable BDA/segment effects.

    Local C storage is not a raw machine-stack snapshot. This oracle covers
    the global memory/segment contract, not complete register or stack effects.
    """
    source = tmp_path / "bios_behavior.c"
    executable = tmp_path / "bios_behavior"
    source.write_text(generated_c + _BIOS_HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False, timeout=5,
    )


def test_bios_behavior_oracle_accepts_exact_write(tmp_path: Path) -> None:
    body = "void sub_10010(void) { inertia_es = 0; inertia_memory[0x417] = 0; inertia_memory[0x418] = 0; }"
    assert _execute_bios_c(tmp_path, _REFERENCE_DECLARATIONS + body).returncode == 0


@pytest.mark.parametrize("body", [
    "inertia_memory[0x417] = 0; inertia_memory[0x418] = 0;",  # Lost ES live-out.
    "inertia_es = 0;",  # Lost global store.
    "inertia_es = 0; inertia_memory[0x417] = 0;",  # Incorrect byte width.
    "inertia_es = 0; inertia_memory[0x418] = 0; inertia_memory[0x419] = 0;",  # Wrong address.
    "inertia_es = 0; inertia_memory[0x417] = 1; inertia_memory[0x418] = 0;",  # Wrong value.
    "inertia_es = 0; inertia_memory[0x417] = 0; inertia_memory[0x418] = 0; inertia_ds = 0;",
    "inertia_es = 0; inertia_memory[0x417] = 0; inertia_memory[0x418] = 0; inertia_memory[0x500] = 0;",
])
def test_bios_behavior_oracle_rejects_corruption(tmp_path: Path, body: str) -> None:
    generated_c = _REFERENCE_DECLARATIONS + "void sub_10010(void) {" + body + "}"
    assert _execute_bios_c(tmp_path, generated_c).returncode != 0


def test_binary_bios_store_compiles_without_unused_stack_carriers(tmp_path: Path) -> None:
    """Preserve the ES/BDA write without leaving compile-invalid local setup."""
    binary = tmp_path / "bios.exe"
    # Separate CALL/exit entry from the original BIOSFUNC _bios_clearkeyflags
    # machine body. Neither recovery nor validation receives its source/COD.
    entry = bytes.fromhex("e80d00b8004ccd21") + b"\x90" * 8
    body = bytes.fromhex("558bec83ec04c746fc1704c746fe00002bdb8ec3bb1704268c078be55dc3")
    _write_mz(binary, entry + body)
    environment = dict(os.environ, PYTHON_JIT="1", PYTHONHASHSEED="0")
    decompiled = subprocess.run(
        [sys.executable, str(REPO_ROOT / "decompile.py"), str(binary),
         "--addr", "0x10010", "--timeout", "60", "--ignore-local-sidecar-hints",
         "--no-alternate-source-c", "--c-target", "portable-flat"],
        cwd=REPO_ROOT, env=environment, capture_output=True, text=True, check=False, timeout=120,
    )
    assert decompiled.returncode == 0, decompiled.stderr
    assert "validation=passed" in decompiled.stderr
    assert "whole-tail validation clean across 1 functions" in decompiled.stderr
    executed = _execute_bios_c(tmp_path, decompiled.stdout)
    assert executed.returncode == 0, executed.stderr
