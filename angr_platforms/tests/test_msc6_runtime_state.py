"""Recompiled C must link against the emitted architectural GP state ABI."""

import subprocess

from scripts import build_msc6_examples as build
from scripts.msc6_runtime_support import msc6_runtime_support_source

GP_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")


def test_msc6_runtime_defines_shared_gp_state(monkeypatch, tmp_path):
    """Use the real runtime writer, then link a separate C state consumer."""
    monkeypatch.setattr(
        build, "_run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    build._compile_and_link_unlocked(
        tmp_path / "consumer.c", tmp_path, kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path, obj_name="TEST.OBJ", exe_name="TEST.EXE",
        map_name="TEST.MAP", runtime_support=True,
    )
    consumer = tmp_path / "consumer.c"
    declarations = "\n".join(f"extern unsigned long inertia_{name};" for name in GP_REGISTERS)
    checks = "\n".join(
        f"inertia_{name} = 0xabcd1234UL;\n"
        f"inertia_{name} = (inertia_{name} & 0xffff0000UL) | 0x8173UL;\n"
        f"if (inertia_{name} != 0xabcd8173UL) return 1;"
        for name in GP_REGISTERS
    )
    consumer.write_text(declarations + "\nint main(void) {\n" + checks + "\nreturn 0; }\n")
    executable = tmp_path / "runtime_state"
    compiled = subprocess.run(
        ["gcc", "-std=c89", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         "-x", "c", str(tmp_path / "INERTIA.C"), str(consumer), "-o", str(executable)],
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
extern unsigned long inertia_esi;
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
