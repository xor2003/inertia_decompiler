"""Constant restore projections require exact word-byte ownership."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.gp_stack_local_reload import has_materialized_gp_local_reload_8616
from angr_platforms.X86_16.lowering.gp_stack_restore import materialize_gp_stack_restores_8616
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.postprocess.optimization.dce import _dead_code_elimination_8616
from test_x86_16_gp_stack_local_reload import _fixture as reload_fixture
from test_x86_16_gp_stack_restore import _artifact, _Codegen


@pytest.mark.parametrize("offset", [-4, -2, -1, 0])
def test_intervening_byte_store_requires_disjoint_stack_coordinates(offset):
    """Distinct variable objects at overlapping coordinates must still refuse."""
    codegen, container, local, fact = reload_fixture()
    other = c.CVariable(SimStackVariable(offset, 2, base="bp"), variable_type=local.variable_type, codegen=codegen)
    reference = c.CUnaryOp("Reference", other, codegen=codegen)
    pointer = c.CTypeCast(None, SimTypePointer(SimTypeChar(False)).with_arch(codegen.project.arch),
                         reference, codegen=codegen)
    zero = c.CConstant(0, local.variable_type, codegen=codegen)
    target = c.CIndexedVariable(pointer, zero, codegen=codegen)
    container.statements.insert(2, c.CAssignment(target, zero, codegen=codegen))

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (offset not in {-2, -1})


def _fixture(value=0, shift=8, offset=-2):
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    word = SimTypeShort(False)
    byte = SimTypeChar(False)
    local = c.CVariable(SimStackVariable(offset, 2, base="bp", name="local"),
                        variable_type=word, codegen=codegen)
    low = c.CTypeCast(word, byte, local, codegen=codegen)
    high = c.CTypeCast(word, byte, c.CBinaryOp("Shr", local,
                       c.CConstant(shift, word, codegen=codegen), codegen=codegen), codegen=codegen)
    expression = c.CBinaryOp("Or", low, c.CBinaryOp("Shl", high,
                             c.CConstant(8, word, codegen=codegen), codegen=codegen), codegen=codegen)
    terminal = c.CReturn(expression, codegen=codegen, tags={"ins_addr": 0x1008})
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=c.CStatements([terminal], codegen=codegen),
                                   unified_local_vars={}, variables_in_use={})
    artifact = _artifact()
    codegen._inertia_stack_register_restore_artifact_8616 = replace(
        artifact, facts=(replace(artifact.facts[0], constant_value=value),),
    )
    return codegen, terminal


@pytest.mark.parametrize("value", [0, 0x1234, 0xffff])
def test_constant_restore_never_snapshots_stale_runtime_register(value):
    codegen, terminal = _fixture(value)
    assert materialize_gp_stack_restores_8616(codegen)
    snapshot, observed = codegen.cfunc.statements.statements
    assert observed is terminal
    assert isinstance(snapshot.rhs, c.CConstant)
    assert snapshot.rhs.value == value
    assert isinstance(terminal.retval, c.CVariable)
    assert terminal.retval.variable == snapshot.lhs.variable


@pytest.mark.parametrize("kwargs", [{"value": None}, {"shift": 7}, {"offset": -3}])
def test_unproved_word_view_remains_a_hard_refusal(kwargs):
    codegen, terminal = _fixture(**kwargs)
    with pytest.raises(PipelineHardError, match="classified but none materialized"):
        materialize_gp_stack_restores_8616(codegen)
    assert codegen.cfunc.statements.statements == [terminal]


def test_live_save_identity_survives_stale_snapshot_metadata():
    """AST cloning/rebinding must not invalidate the earlier protected definition."""
    codegen, _terminal = _fixture()
    assert materialize_gp_stack_restores_8616(codegen)
    snapshot = codegen.cfunc.statements.statements[0]
    codegen.cfunc.statements.statements[-1] = c.CReturn(
        c.CConstant(3, SimTypeShort(False), codegen=codegen), codegen=codegen,
    )
    codegen._inertia_gp_stack_restore_snapshots_8616 = ()
    _dead_code_elimination_8616(codegen)
    assert snapshot in codegen.cfunc.statements.statements
    assert materialize_gp_stack_restores_8616(codegen) is False
