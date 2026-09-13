"""Project typed pointer sources before architectural integer register writes."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CVariable
from angr.sim_type import SimTypeChar, SimTypePointer
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.c_ast_utils import _iter_c_nodes_deep_8616
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_assignment_8616
from test_x86_16_segmented_runtime_lowering import _project


@pytest.mark.parametrize(("register", "helper"), [
    ("al", "PTR_U16"), ("ah", "PTR_U16"), ("si", "PTR_U16"),
    ("eax", "PTR_U32"), ("edi", "PTR_U32"),
])
def test_gp_pointer_write_projects_storage_before_masking(register, helper):
    project, codegen = _project()
    pointer = CVariable(
        SimStackVariable(4, 2, base="bp", name="pointer", region=0x4010),
        variable_type=SimTypePointer(SimTypeChar(False)).with_arch(project.arch),
        codegen=codegen,
    )

    assignment = runtime_gp_state_assignment_8616(
        register, pointer, codegen=codegen, function_addr=0x4010,
    )

    assert assignment is not None
    projections = [node for node in _iter_c_nodes_deep_8616(assignment)
                   if isinstance(node, CFunctionCall)]
    assert len(projections) == 1
    assert projections[0].callee_target == helper
    assert projections[0].args == [pointer]
