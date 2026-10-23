"""Cleanup must retain a captured value when its underlying memory changes."""

import shutil
import subprocess

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CReturn, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimTemporaryVariable

from inertia.postprocess.decompiler_postprocess_simplify import _inline_single_assignment_virtual_expressions_8616
from tests.postprocess.test_x86_16_decompiler_postprocess_simplify import _codegen, _const

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("global_name", ["g_counter", "inertia_eax"])
def test_inline_preserves_memory_snapshot_across_write(tmp_path, global_name):
    """A side-effect-free global read is not an invariant value across writes."""
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("host gcc is required to execute the cleaned C expression")
    codegen = _codegen([])
    codegen.display_block_addrs = False
    codegen.display_vvar_ids = False
    codegen.use_compound_assignments = False
    codegen.show_casts = False
    codegen.const_formats = {}
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    state = CVariable(SimMemoryVariable(0x2000, 2, name=global_name), variable_type=word, codegen=codegen)
    temporary = CVariable(SimTemporaryVariable(1, 2), variable_type=word, codegen=codegen)
    temporary.variable.name = "tmp_1"
    captured = CAssignment(temporary, CBinaryOp("Add", state, _const(1, codegen), codegen=codegen), codegen=codegen)
    overwritten = CAssignment(state, _const(20, codegen), codegen=codegen)
    returned = CReturn(temporary, codegen=codegen)
    codegen.cfunc.statements.statements = [captured, overwritten, returned]

    _inline_single_assignment_virtual_expressions_8616(codegen)
    rendered = "".join(text for text, _ in codegen.cfunc.statements.c_repr_chunks())
    source = tmp_path / "snapshot.c"
    source.write_text(
        "unsigned short " + global_name + "=1;\n"
        "unsigned short run(void) { unsigned short tmp_1;\n" + rendered + "}\n"
        "int main(void) { return run()!=2; }\n"
    )
    executable = tmp_path / "snapshot"
    subprocess.run([compiler, str(source), "-o", str(executable)], check=True, capture_output=True, timeout=15)
    subprocess.run([str(executable)], check=True, capture_output=True, timeout=5)
    assert captured in codegen.cfunc.statements.statements
    assert returned.retval is temporary


def test_inline_still_consumes_constant_virtual_value():
    """A literal has no mutable memory dependency and remains eligible."""
    codegen = _codegen([])
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    temporary = CVariable(SimTemporaryVariable(1, 2), variable_type=word, codegen=codegen)
    temporary.variable.name = "tmp_1"
    returned = CReturn(temporary, codegen=codegen)
    codegen.cfunc.statements.statements = [CAssignment(temporary, _const(7, codegen), codegen=codegen), returned]
    assert _inline_single_assignment_virtual_expressions_8616(codegen)
    assert codegen.cfunc.statements.statements == [returned]
    assert returned.retval.value == 7
