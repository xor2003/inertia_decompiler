"""Recompiled C must link against the emitted architectural GP state ABI."""

import subprocess

import pytest
from angr_platforms.X86_16.lowering.gp_word_runtime import GPRegisterRuntimeABI8616

from scripts import build_msc6_examples as build
from scripts.msc6_runtime_support import msc6_runtime_state_declarations, msc6_runtime_support_source

GP_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")


@pytest.mark.parametrize("abi", list(GPRegisterRuntimeABI8616))
def test_msc6_runtime_defines_shared_gp_state(monkeypatch, tmp_path, abi):
    """Link the real runtime and preserve distinct segment and GP state."""
    monkeypatch.setattr(
        build, "_run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    build._compile_and_link_unlocked(
        tmp_path / "consumer.c", tmp_path, kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path, obj_name="TEST.OBJ", exe_name="TEST.EXE",
        map_name="TEST.MAP", runtime_support=True, gp_runtime_abi=abi,
    )
    consumer = tmp_path / "consumer.c"
    declarations = msc6_runtime_state_declarations(abi)
    (tmp_path / "dos.h").write_text(
        "struct SREGS { unsigned short es, cs, ss, ds; };\n"
        "void segread(struct SREGS *state);\n"
    )
    segment_probe = """
#include <dos.h>
extern unsigned short inertia_cs, inertia_ds, inertia_es, inertia_ss;
void inertia_init_segments(void);
void segread(struct SREGS *state) {
    state->cs = 0x1234; state->ds = 0x2345;
    state->es = 0x3456; state->ss = 0x4567;
}
"""
    checks = "\n".join(
        f"inertia_{name} = 0xabcd1234UL;\n"
        f"inertia_{name} = (inertia_{name} & 0xffff0000UL) | 0x8173UL;\n"
        f"if (inertia_{name} != 0xabcd8173UL) return 1;"
        for name in GP_REGISTERS
    )
    consumer.write_text(
        declarations + segment_probe + "\nint main(void) {\n" + checks
        + "\ninertia_init_segments();\n"
        "return inertia_cs != 0x1234 || inertia_ds != 0x2345 ||\n"
        "       inertia_es != 0x3456 || inertia_ss != 0x4567;\n}\n"
    )
    executable = tmp_path / "runtime_state"
    compiled = subprocess.run(
        ["gcc", "-std=c89", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         "-I", str(tmp_path), "-x", "c", str(tmp_path / "INERTIA.C"),
         str(consumer), "-o", str(executable)],
        capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    assert subprocess.run([str(executable)], check=False).returncode == 0


def test_c89_preparation_preserves_gp_runtime_abi_width(tmp_path):
    """Missing extern recovery must not narrow an architectural lane to a word."""
    prepared = build._prepare_decompiled_source_for_c89(
        "unsigned long read_lane(void) { return inertia_esi; }\n"
    )
    source = prepared + """
int main(void) {
    inertia_esi = 0xabcd8173UL;
    return read_lane() != 0xabcd8173UL;
}
"""
    executable = tmp_path / "runtime_abi"
    compiled = subprocess.run(
        ["gcc", "-std=c89", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         "-x", "c", "-", "-o", str(executable)],
        input=source + msc6_runtime_support_source(), capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    assert subprocess.run([str(executable)], check=False).returncode == 0
