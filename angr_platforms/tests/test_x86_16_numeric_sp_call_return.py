"""Returning calls must not leak their return-frame decrement into numeric SP."""

import io
import shutil
import subprocess

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16


@pytest.mark.parametrize(
    ("encoded", "callee"),
    [
        pytest.param("55 89 e5 50 e8 09 00 83 c4 02 89 e0 89 ec 5d c3 c3", 0x1010, id="near"),
        pytest.param("55 89 e5 50 9a 12 10 00 00 83 c4 02 89 e0 89 ec 5d c3 cb", 0x1012, id="far"),
        pytest.param("55 89 e5 50 0e e8 09 00 83 c4 02 89 e0 89 ec 5d c3 cb", 0x1011, id="push-cs-near"),
        pytest.param("55 89 e5 50 0e e8 09 00 83 c4 04 89 e0 89 ec 5d c3 c3", 0x1011, id="cs-argument"),
        pytest.param("55 89 e5 66 50 e8 09 00 83 c4 04 89 e0 89 ec 5d c3 c3", 0x1011, id="dword-argument"),
    ],
)
@pytest.mark.parametrize("upper_esp", [0, 0x12340000], ids=["zero-upper", "live-upper"])
def test_numeric_sp_after_returning_call_matches_machine_stack(tmp_path, encoded, callee, upper_esp):
    compiler = shutil.which("gcc")
    assert compiler is not None, "gcc is required for generated-C return-value execution"
    # PUSH BP; MOV BP,SP; PUSH AX; CALL callee; ADD SP,2; MOV AX,SP;
    # MOV SP,BP; POP BP; RET. The callee consists solely of RET or RETF.
    code = bytes.fromhex(encoded)
    project = angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    state = project.factory.blank_state(addr=0x1000)
    state.regs.esp, state.regs.ebp, state.regs.eax = upper_esp | 0x8000, 0x1234, 7
    state.regs.ss, state.regs.cs = 0, 0
    state.memory.store(0x8000, 0x2000, size=2, endness="Iend_LE")
    execution_model = project.factory.simgr(state)
    execution_model.explore(find=0x2000, n=32)
    assert len(execution_model.found) == 1
    machine_return = execution_model.found[0].solver.eval(execution_model.found[0].regs.ax)
    assert machine_return == 0x7FFE
    assert execution_model.found[0].solver.eval(execution_model.found[0].regs.esp) >> 16 == upper_esp >> 16
    cfg = project.analyses.CFGFast(normalize=True)
    result = project.analyses.Decompiler(cfg.kb.functions[0x1000], cfg=cfg.model)
    assert result.codegen is not None
    generated = result.codegen.text
    assert generated is not None
    # The RET-only callee ignores arguments and does not change GP values.
    # Rename the blob entry through the harness preprocessor, not C recovery.
    source = (
        "#include <stdint.h>\n#include <stdio.h>\n"
        f"uint32_t inertia_esp = {upper_esp | 0x8000}, inertia_ebp = 0x1234, inertia_eax = 7;\n"
        "uint16_t inertia_cs = 0;\n"
        "unsigned calls = 0;\n"
        f"void sub_{callee:x}() {{ ++calls; }}\n#define _start recovered_entry\n"
        + generated
        + "\nint main(void) { unsigned result = recovered_entry();"
        + " printf(\"%u %u %u\\n\", result, inertia_esp >> 16, calls); return 0; }\n"
    )
    executable = tmp_path / "numeric-sp"
    compiled = subprocess.run(
        [compiler, "-std=c99", "-Werror", "-O2", "-x", "c", "-", "-o", str(executable)],
        input=source, text=True, capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + source
    execution = subprocess.run([str(executable)], text=True, capture_output=True, check=False)
    assert execution.returncode == 0, execution.stderr
    # The saved BP is the only remaining word when MOV AX,SP executes.
    assert tuple(map(int, execution.stdout.split())) == (machine_return, upper_esp >> 16, 1), generated
