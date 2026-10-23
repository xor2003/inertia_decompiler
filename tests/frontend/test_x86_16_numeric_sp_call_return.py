"""Returning calls must not leak their return-frame decrement into numeric SP.

Layer: Frontend regression tests.
Responsibility: compare native returning calls with executed generated C.
"""

import io
import json
import shutil
import subprocess
from pathlib import Path

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.frontend.x86_16.simos_86_16 import SimDOS86_16  # noqa: F401
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.numeric_stack_pointer_returns import numeric_stack_pointer_return_inventory_8616
from inertia.validation.tail_validation import (
    extract_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_snapshot_passed,
)
from inertia.validation.validation_call_stack_inputs import validate_call_stack_inputs_8616


@pytest.mark.parametrize(
    ("encoded", "callee", "callee_sp_delta"),
    [
        pytest.param("55 89 e5 50 e8 09 00 83 c4 02 89 e0 89 ec 5d c3 c3", 0x1010, 0, id="near"),
        pytest.param("55 89 e5 50 9a 12 10 00 00 83 c4 02 89 e0 89 ec 5d c3 cb", 0x1012, 0, id="far"),
        pytest.param("55 89 e5 50 0e e8 09 00 83 c4 02 89 e0 89 ec 5d c3 cb", 0x1011, 0, id="push-cs-near"),
        pytest.param("55 89 e5 50 0e e8 09 00 83 c4 04 89 e0 89 ec 5d c3 c3", 0x1011, 0, id="cs-argument"),
        pytest.param("55 89 e5 66 50 e8 09 00 83 c4 04 89 e0 89 ec 5d c3 c3", 0x1011, 0, id="dword-argument"),
        pytest.param("55 89e5 50 e8 0900 83c406 89e0 89ec 5d c3 58 89e3 83eb04 89dc 50 c3", 0x1010, -4, id="affine-register"),
        pytest.param("55 89e5 50 e8 0900 83c406 89e0 89ec 5d c3 58 89e3 eb01 90 83eb04 89dc 50 c3", 0x1010, -4, id="affine-register-block"),
    ],
)
@pytest.mark.parametrize("upper_esp", [0, 0x12340000], ids=["zero-upper", "live-upper"])
def test_numeric_sp_after_returning_call_matches_machine_stack(
    tmp_path: Path, encoded: str, callee: int, upper_esp: int, callee_sp_delta: int,
) -> None:
    """Preserve numeric SP and the upper register half across actual calls."""
    apply_x86_16_bootstrap()
    compiler = shutil.which("gcc")
    assert compiler is not None, "gcc is required for generated-C return-value execution"
    # PUSH BP; MOV BP,SP; PUSH AX; CALL callee; ADD SP,2; MOV AX,SP;
    # MOV SP,BP; POP BP; RET. Caller cleanup also releases any callee allocation.
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
    try:
        result = project.analyses.Decompiler(cfg.kb.functions[0x1000], cfg=cfg.model)
    except PipelineHardError as error:
        (tmp_path / "numeric-sp-pipeline-failure.json").write_text(json.dumps(error.details, indent=2))
        raise
    assert result.codegen is not None
    inventory = numeric_stack_pointer_return_inventory_8616(result.codegen)
    assert inventory is not None, "the authenticated prefix must publish numeric return evidence"
    (tmp_path / "numeric-sp-source-proof.json").write_text(json.dumps(inventory.to_dict(), indent=2))
    assert inventory.stats.classified_fact_count == inventory.stats.materialized_count == 1, inventory.to_dict()
    assert inventory.stats.failure_count == 0, inventory.to_dict()
    generated = result.codegen.text
    assert generated is not None
    (tmp_path / "numeric-sp-generated.c").write_text(generated)
    validation = extract_x86_16_tail_validation_snapshot(cfg.kb.functions[0x1000].info)
    (tmp_path / "numeric-sp-tail-validation.json").write_text(json.dumps(validation, indent=2))
    # The harness models the independently executed callee SP transfer.
    # The caller overwrites AX after the call and never reads the spoiled BX.
    # Rename the blob entry through the harness preprocessor, not C recovery.
    source = (
        "#include <stdint.h>\n#include <stdio.h>\n"
        f"uint32_t inertia_esp = {upper_esp | 0x8000}, inertia_ebp = 0x1234, inertia_eax = 7;\n"
        "uint16_t inertia_cs = 0;\n"
        "unsigned calls = 0;\n"
        f"void sub_{callee:x}() {{ ++calls; inertia_esp = (inertia_esp & 0xffff0000u) | "
        f"((inertia_esp + ({callee_sp_delta})) & 0xffffu); }}\n#define _start recovered_entry\n"
        + generated
        + "\nint main(void) { unsigned result = recovered_entry();"
        + " printf(\"%u %u %u\\n\", result, inertia_esp >> 16, calls); return 0; }\n"
    )
    (tmp_path / "numeric-sp-harness.c").write_text(source)
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
    assert x86_16_tail_validation_snapshot_passed(validation), validation
    inputs = validate_call_stack_inputs_8616(result.codegen, result.codegen.cfunc.statements)
    assert not inputs.issues, inputs.issue_tokens()
    assert inputs.raw_fact_count == inputs.materialized_count == 1


def _nested_sp_machine_result(project: angr.Project, entry_esp: int) -> tuple[int, int]:
    """Run the machine body with an AX16 return and a concrete caller sentinel."""
    state = project.factory.blank_state(addr=0x1000)
    state.regs.esp, state.regs.ebp, state.regs.eax = entry_esp, 0x1234, 7
    state.regs.ss, state.regs.cs = 0, 0
    state.memory.store(entry_esp & 0xffff, 0x2000, size=2, endness="Iend_LE")
    execution = project.factory.simgr(state)
    execution.explore(find=0x2000, n=32)
    assert len(execution.found) == 1
    returned = execution.found[0]
    return returned.solver.eval(returned.regs.ax), returned.solver.eval(returned.regs.esp) >> 16


def test_numeric_sp_input_crosses_generated_c_call_boundary(tmp_path: Path) -> None:
    """A generated callee must observe its own physical entry SP, not its caller's."""
    apply_x86_16_bootstrap()
    compiler = shutil.which("gcc")
    assert compiler is not None
    # CALL callee; ADD AX,1; RET; NOP; callee: MOV AX,SP; RET.
    project = angr.Project(
        io.BytesIO(bytes.fromhex("e80500 83c001 c3 90 89e0 c3")),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    initial_esp = 0x12348000
    expected, expected_upper = _nested_sp_machine_result(project, initial_esp)
    assert expected == 0x7fff
    machine_oracles = [
        (entry_esp, *_nested_sp_machine_result(project, entry_esp))
        for entry_esp in (0x12340000, 0x12340001, 0x12349000, 0x1234ffff)
    ]
    (tmp_path / "nested-sp-machine-oracles.json").write_text(json.dumps(machine_oracles, indent=2))
    cfg = project.analyses.CFGFast(normalize=True)
    generated = []
    validations = {}
    for address in (0x1008, 0x1000):
        try:
            decompiled = project.analyses.Decompiler(cfg.kb.functions[address], cfg=cfg.model)
        except PipelineHardError as error:
            (tmp_path / "nested-sp-pipeline-failure.json").write_text(json.dumps(error.details, indent=2))
            raise
        assert decompiled.codegen is not None and decompiled.codegen.text is not None
        generated.append(decompiled.codegen.text)
        validations[address] = extract_x86_16_tail_validation_snapshot(cfg.kb.functions[address].info)
        inputs = validate_call_stack_inputs_8616(decompiled.codegen, decompiled.codegen.cfunc.statements)
        assert not inputs.issues, inputs.issue_tokens()
        assert inputs.raw_fact_count == inputs.materialized_count == int(address == 0x1000)
    body = "\n".join(generated)
    (tmp_path / "nested-sp-generated.c").write_text(body)
    (tmp_path / "nested-sp-tail-validation.json").write_text(json.dumps(validations, indent=2))
    boundary_checks = "".join(
        f"inertia_esp={entry}u; "
        f"if ((uint16_t)recovered_entry()!={ax}u || inertia_esp>>16!={upper}u) return 2;\n"
        for entry, ax, upper in machine_oracles
    )
    harness = (
        "#include <stdint.h>\n#include <stdio.h>\n"
        f"uint32_t inertia_esp={initial_esp}, inertia_ebp=0x1234, inertia_eax=7;\n"
        "uint16_t inertia_cs=0;\n#define _start recovered_entry\n"
        + body
        + "\nint main(void) { unsigned value = recovered_entry();"
        + " printf(\"%u %u\\n\", value, inertia_esp >> 16);\n"
        + boundary_checks
        + "for (uint32_t word=0; word<65536; ++word) {\n"
        + "inertia_esp=0x12340000u | word;\n"
        + "if ((uint16_t)recovered_entry()!=(uint16_t)(word-1u) || inertia_esp>>16!=0x1234u) return 3;\n"
        + "} return 0; }\n"
    )
    (tmp_path / "nested-sp-harness.c").write_text(harness)
    program = tmp_path / "nested-sp"
    compiled = subprocess.run([compiler, "-std=c99", "-Werror", "-O2", "-x", "c", "-", "-o", str(program)],
                              input=harness, text=True, capture_output=True, check=False)
    assert compiled.returncode == 0, compiled.stderr + harness
    result = subprocess.run([str(program)], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert expected_upper == initial_esp >> 16
    assert tuple(map(int, result.stdout.split())) == (expected, expected_upper), body
    assert all(x86_16_tail_validation_snapshot_passed(value) for value in validations.values()), validations


def test_stack_word_argument_survives_call_context_replay(tmp_path: Path) -> None:
    """Real PUSH-word recovery keeps its capture and tail proof through replay."""
    apply_x86_16_bootstrap()
    compiler = shutil.which("gcc")
    assert compiler is not None
    caller = bytes.fromhex("683412 e80a00 83c402 c3")
    callee = bytes.fromhex("55 89e5 8b4604 5d c3")
    project = angr.Project(io.BytesIO(caller + b"\x90" * (0x10 - len(caller)) + callee),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False)
    expected = _nested_sp_machine_result(project, 0x12348000)
    assert expected == (0x1234, 0x1234)
    cfg = project.analyses.CFGFast(normalize=True)
    generated, validations, inputs = [], {}, {}
    for address in (0x1010, 0x1000):
        decompiled = project.analyses.Decompiler(cfg.kb.functions[address], cfg=cfg.model)
        assert decompiled.codegen is not None and decompiled.codegen.text is not None
        generated.append(decompiled.codegen.text)
        validations[address] = extract_x86_16_tail_validation_snapshot(cfg.kb.functions[address].info)
        report = validate_call_stack_inputs_8616(decompiled.codegen, decompiled.codegen.cfunc.statements)
        inputs[address] = {'raw': report.raw_fact_count, 'materialized': report.materialized_count,
                           'issues': list(report.issue_tokens())}
    body = "\n".join(generated)
    (tmp_path / 'stack-word-generated.c').write_text(body)
    (tmp_path / 'stack-word-tail.json').write_text(json.dumps(validations, indent=2))
    (tmp_path / 'stack-word-inputs.json').write_text(json.dumps(inputs, indent=2))
    source = tmp_path / 'stack-word-harness.c'
    source.write_text('#include <stdint.h>\n#include <stdio.h>\n'
        'uint32_t inertia_esp=0x12348000, inertia_ebp=0x1234, inertia_eax=7;\n'
        'uint16_t inertia_cs=0;\n#define _start recovered_entry\n' + body
        + '\nint main(void) { unsigned ax=(uint16_t)recovered_entry();'
        + ' printf("%u %u\\n",ax,inertia_esp>>16); }\n')
    compiled = subprocess.run([compiler, '-std=c11', '-O0', str(source), '-o', str(tmp_path/'stack-word')],
        capture_output=True, text=True, check=False)
    (tmp_path / 'stack-word-gcc.log').write_text(compiled.stdout + compiled.stderr)
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(tmp_path/'stack-word')], capture_output=True, text=True, check=True)
    assert tuple(map(int, executed.stdout.split())) == expected
    assert inputs[0x1000] == {'raw': 1, 'materialized': 1, 'issues': []}, inputs
    assert inputs[0x1010] == {'raw': 0, 'materialized': 0, 'issues': []}, inputs
    assert all(x86_16_tail_validation_snapshot_passed(value) for value in validations.values()), validations
