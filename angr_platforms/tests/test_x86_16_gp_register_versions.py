"""Architectural register publication must not merge distinct captured values."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeChar, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from angr_platforms.X86_16.lowering.gp_register_state import lower_architectural_gp_register_state_8616
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from test_x86_16_gp_register_state import _gp_live_in_artifact


def _fixture(register):
    arch = Arch86_16()
    address = 0x10E85
    project = SimpleNamespace(
        arch=arch, _inertia_function_ssa_artifacts_8616={address: _gp_live_in_artifact(register)},
        _inertia_function_ssa_stages_8616={address: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(project=project, cstyle_null_cmp=False, next_idx=lambda _: 1,
                              next_node_idx=lambda: 1, next_ident=lambda name: name)
    offset, width = arch.registers[register]
    type_ = (SimTypeLong(False) if width == arch.bytes else SimTypeShort(False)).with_arch(arch)
    before = CVariable(SimRegisterVariable(offset, width, ident="before", region=address), variable_type=type_, codegen=codegen)
    after = CVariable(SimRegisterVariable(offset, width, ident="after", region=address), variable_type=type_, codegen=codegen)
    first = CAssignment(before, CConstant(0x1234, type_, codegen=codegen), codegen=codegen)
    second = CAssignment(after, CConstant(0x5678, type_, codegen=codegen), codegen=codegen)
    returned = CReturn(before, codegen=codegen)
    types = {}
    codegen.cfunc = SimpleNamespace(
        addr=address, statements=CStatements([first, second, returned], codegen=codegen),
        variables_in_use={before.variable: before, after.variable: after}, unified_local_vars={},
        variable_manager=SimpleNamespace(set_variable_type=lambda variable, type_: types.__setitem__(variable, type_)),
        refresh=lambda: None,
    )
    return codegen, returned, types


@pytest.mark.parametrize("register", ["si", "di", "ax", "eax"])
def test_defined_register_value_survives_later_version(register):
    codegen, returned, types = _fixture(register)
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval, CVariable)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)
    assert returned.retval.variable in types
    assert returned.retval.variable in codegen.cfunc.variables_in_use
    capture, publication, restore, _ = codegen.cfunc.statements.statements
    assert capture.lhs is returned.retval
    assert isinstance(publication.lhs.variable, SimMemoryVariable)
    assert publication.lhs.variable == restore.lhs.variable
    stats = codegen._inertia_gp_register_version_capture_stats_8616
    assert stats.raw_fact_count == stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0
    first_snapshot = returned.retval.variable
    lower_architectural_gp_register_state_8616(codegen)
    assert returned.retval.variable is first_snapshot


def test_version_capture_refuses_use_before_definition_without_mutation():
    codegen, returned, _ = _fixture("si")
    statements = codegen.cfunc.statements.statements
    statements.insert(0, CReturn(returned.retval, codegen=codegen))
    original = tuple(statements)
    with pytest.raises(PipelineHardError, match=r"function=0x10e85.*does not dominate"):
        lower_architectural_gp_register_state_8616(codegen)
    assert tuple(codegen.cfunc.statements.statements) == original
    assert isinstance(returned.retval.variable, SimRegisterVariable)
    assert codegen._inertia_gp_register_version_capture_stats_8616.failure_count == 1


def test_version_capture_proves_order_through_nested_statement_groups():
    codegen, returned, _ = _fixture("si")
    statements = codegen.cfunc.statements.statements
    codegen.cfunc.statements.statements = [CStatements(statements[:-1], codegen=codegen), returned]
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)


def test_version_capture_keeps_value_across_call_and_preserves_call_order():
    codegen, returned, _ = _fixture("si")
    call = CExpressionStatement(CFunctionCall("opaque", None, args=[], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.insert(1, call)
    assert lower_architectural_gp_register_state_8616(codegen)
    capture, publication, observed_call, restore, _ = codegen.cfunc.statements.statements
    assert observed_call is call
    assert capture.lhs is returned.retval
    assert publication.lhs.variable == restore.lhs.variable


def test_word_snapshot_survives_high_byte_architectural_write():
    codegen, returned, _ = _fixture("ax")
    register, size = codegen.project.arch.registers["ah"]
    byte_type = SimTypeChar(False).with_arch(codegen.project.arch)
    byte = CVariable(SimRegisterVariable(register, size, ident="high", region=codegen.cfunc.addr),
                     variable_type=byte_type, codegen=codegen)
    codegen.cfunc.statements.statements[1] = CAssignment(
        byte, CConstant(0x56, byte_type, codegen=codegen), codegen=codegen,
    )
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)
    assert returned.retval.variable.size == codegen.project.arch.registers["ax"][1]


@pytest.mark.parametrize("loop", [False, True])
def test_version_capture_proves_branch_or_loop_local_definition(loop):
    codegen, returned, _ = _fixture("si")
    body = codegen.cfunc.statements
    condition = CConstant(1, returned.retval.variable_type, codegen=codegen)
    nested = (CWhileLoop(condition, body, codegen=codegen) if loop
              else CIfElse([(condition, body)], codegen=codegen))
    codegen.cfunc.statements = CStatements([nested], codegen=codegen)
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)


def test_version_capture_refuses_branch_local_definition_with_escaping_read():
    codegen, returned, _ = _fixture("si")
    statements = codegen.cfunc.statements.statements
    condition = CConstant(1, returned.retval.variable_type, codegen=codegen)
    branch = CIfElse([(condition, CStatements(statements[:-1], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([branch, returned], codegen=codegen)
    with pytest.raises(PipelineHardError, match="GP version capture"):
        lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimRegisterVariable)


def test_pointer_capture_projects_guest_offset_before_scalar_assignment():
    codegen, returned, _ = _fixture("si")
    pointer_type = SimTypePointer(SimTypeChar(False)).with_arch(codegen.project.arch)
    pointer = CVariable(SimStackVariable(4, 2, base="bp"), variable_type=pointer_type, codegen=codegen)
    codegen.cfunc.statements.statements[0].rhs = pointer
    assert lower_architectural_gp_register_state_8616(codegen)
    capture = codegen.cfunc.statements.statements[0]
    assert capture.lhs is returned.retval
    assert isinstance(capture.rhs, CFunctionCall)
    assert capture.rhs.callee_target == "PTR_U16"
    assert capture.rhs.args == [pointer]


def test_version_consumed_before_overwrite_does_not_need_snapshot():
    codegen, returned, _ = _fixture("si")
    first, restore, _ = codegen.cfunc.statements.statements
    local = CVariable(SimStackVariable(-2, 2, base="bp"),
                      variable_type=returned.retval.variable_type, codegen=codegen)
    use = CAssignment(local, returned.retval, codegen=codegen)
    codegen.cfunc.statements.statements = [first, use, restore]
    assert lower_architectural_gp_register_state_8616(codegen)
    assert codegen._inertia_gp_register_version_capture_stats_8616.materialized_count == 0


def test_loop_local_version_consumed_before_restore_needs_no_snapshot():
    codegen, returned, _ = _fixture("si")
    first, restore, _ = codegen.cfunc.statements.statements
    local = CVariable(SimStackVariable(-2, 2, base="bp"),
                      variable_type=returned.retval.variable_type, codegen=codegen)
    use = CAssignment(local, returned.retval, codegen=codegen)
    loop = CWhileLoop(CConstant(1, local.type, codegen=codegen),
                      CStatements([first, use], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements = [loop, restore]
    assert lower_architectural_gp_register_state_8616(codegen)
    assert codegen._inertia_gp_register_version_capture_stats_8616.materialized_count == 0
