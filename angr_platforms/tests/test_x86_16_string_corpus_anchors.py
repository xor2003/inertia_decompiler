"""Exercise COD string bodies without mutating shared corpus outputs."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616
from angr_platforms.X86_16.lowering.gp_word_runtime import (
    DEFAULT_GP_RUNTIME_ABI_8616,
    coherent_gp_runtime_definitions_8616,
)
from x86_16_timeout_support import scaled_decompile_timeout

REPO_ROOT = Path(__file__).resolve().parents[2]
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
SCRIPT_PATH = REPO_ROOT / "scripts" / "decompile_cod_dir.py"

_RUNTIME_HEADER = render_c_runtime_header_8616("portable-flat", gp_runtime_abi=DEFAULT_GP_RUNTIME_ABI_8616)
_PRELUDE = _RUNTIME_HEADER + coherent_gp_runtime_definitions_8616() + """
#include <stdint.h>
#include <stdio.h>
#include <string.h>
uint8_t inertia_memory[0x100000];
unsigned short inertia_flags, inertia_es, flags, xffff;
"""
_HARNESS = """
static uint8_t expected[sizeof(inertia_memory)];
int main(void) {
    unsigned failures = 0;
    for (unsigned backward = 0; backward < 2; ++backward) {
        for (unsigned count = 0; count <= 3; ++count) {
            memset(inertia_memory, 0x5a, sizeof(inertia_memory));
            memset(expected, 0x5a, sizeof(expected));
            inertia_flags = backward ? 0x400 : 0;
            inertia_es = 0x4321;
            inertia_edi = 0xcafe0042UL;
            inertia_esi = 0xbeef8173UL;
            for (unsigned i = 0; i < count; ++i) {
                unsigned offset = backward ? 0x200 - 2*i : 0x200 + 2*i;
                expected[0x12340 + offset] = 0xff;
                expected[0x12340 + offset + 1] = 0x80;
            }
            unsigned result = __fimemset(0x12340200UL, count, 0x80ff);
            unsigned return_bad = result != 0;
            unsigned memory_bad = memcmp(expected, inertia_memory, sizeof(expected)) != 0;
            unsigned es_bad = inertia_es != 0x4321;
            unsigned edi_bad = inertia_edi != 0xcafe0042UL;
            unsigned esi_bad = inertia_esi != 0xbeef8173UL;
            if (return_bad || memory_bad || es_bad || edi_bad || esi_bad) {
                fprintf(stderr,
                    "backward=%u count=%u return_bad=%u memory_bad=%u es_bad=%u edi_bad=%u esi_bad=%u\\n",
                    backward, count, return_bad, memory_bad, es_bad, edi_bad, esi_bad);
                ++failures;
            }
        }
    }
    return failures != 0;
}
"""
_CORRECT_BODY = """
unsigned short __fimemset(unsigned long to, unsigned short n, unsigned short c) {
    for (unsigned i = 0; i < n; ++i) {
        unsigned off = (unsigned short)to + ((inertia_flags & 0x400) ? -2*i : 2*i);
        SEG_U16(to >> 16, off) = c;
    }
    return 0;
}
"""


def _assert_fimemset_behavior(body: str, tmp_path: Path) -> None:
    """Check unchanged generated C for defined values, stores and saved registers."""
    # Use the canonical runtime definitions for both body-only output and full
    # translation units. Identical C macro redefinitions are valid, unlike
    # competing harness definitions of the generated memory-access contract.
    executable = tmp_path / "fimemset"
    compiled = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-o", str(executable), "-"],
        input=_PRELUDE + body + _HARNESS, capture_output=True, text=True,
        check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run(
        [str(executable)], check=False, timeout=2, capture_output=True, text=True,
    )
    assert executed.returncode == 0, (
        f"fimemset behavior mismatch: {executed.returncode}\n{executed.stderr}"
    )


@pytest.mark.parametrize("includes_runtime_header", [False, True])
def test_fimemset_behavior_oracle_accepts_correct_stores(
    tmp_path: Path, includes_runtime_header: bool,
) -> None:
    body = (_RUNTIME_HEADER if includes_runtime_header else "") + _CORRECT_BODY
    _assert_fimemset_behavior(body, tmp_path)


@pytest.mark.parametrize("before,after,diagnostic", [
    ("i < n", "i + 1 < n", "memory_bad=1"),
    ("= c;", "= c ^ 0x100;", "memory_bad=1"),
    ("return 0;", "inertia_es = 0; return 0;", "es_bad=1"),
    ("return 0;", "inertia_edi = 0; return 0;", "edi_bad=1"),
    ("return 0;", "inertia_esi = 0; return 0;", "esi_bad=1"),
    ("return 0;", "return 1;", "return_bad=1"),
])
def test_fimemset_behavior_oracle_rejects_corruption(
    tmp_path: Path, before: str, after: str, diagnostic: str,
) -> None:
    with pytest.raises(AssertionError, match=diagnostic) as caught:
        _assert_fimemset_behavior(_CORRECT_BODY.replace(before, after), tmp_path)
    assert "backward=0 count=3" in str(caught.value)
    assert "backward=1 count=3" in str(caught.value)


def test_monoprin_fimemset_emits_string_intrinsic_fallback_anchor(tmp_path: Path) -> None:
    """Require successful corpus decompilation before inspecting its private output."""
    shutil.copyfile(MONOPRIN_COD, tmp_path / MONOPRIN_COD.name)
    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = "angr_platforms" if not existing_pythonpath else f"angr_platforms:{existing_pythonpath}"
    result = subprocess.run(
        [
            str(REPO_ROOT / ".venv" / "bin" / "python"),
            str(SCRIPT_PATH),
            str(tmp_path),
            "--cod-file",
            MONOPRIN_COD.name,
            "--proc-name",
            "__fimemset",
            "--timeout",
            str(scaled_decompile_timeout(20)),
            "--max-workers",
            "1",
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    rendered = (tmp_path / "MONOPRIN.dec").read_text(encoding="utf-8", errors="replace")
    assert "/* == 1/1 MONOPRIN.COD :: __fimemset [NEAR] == */" in rendered
    section_start = rendered.index("/* == 1/1 MONOPRIN.COD :: __fimemset [NEAR] == */")
    section_end = rendered.find("/* == end 1/1 MONOPRIN.COD :: __fimemset [NEAR] == */", section_start)
    section = rendered[section_start : section_end if section_end != -1 else None]
    assert "/* == c (string intrinsic fallback) == */" not in section
    assert "/* -- c (string intrinsic fallback) -- */" not in section
    _assert_fimemset_behavior(section, tmp_path)
