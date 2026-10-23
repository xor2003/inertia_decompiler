"""Require exact input-version evidence before retaining segment snapshots."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CExpressionStatement, CFunctionCall
from angr.sim_variable import SimMemoryVariable, SimTemporaryVariable

from inertia.lowering.segment_register_state import (
    _capture_segment_entry_versions_8616,
    _SegmentInputCaptureFailure8616,
)
from inertia.pipeline.errors import PipelineHardError
from tests.lowering.test_x86_16_gp_register_versions import _fixture


@pytest.mark.parametrize("register", ["es", "ds"])
@pytest.mark.parametrize("proven_input", [True, False])
def test_entry_snapshot_requires_exact_input_registry_identity(register: str, proven_input: bool) -> None:
    """A read-only alias input survives writes; an unproven version is untouched."""
    codegen, returned, types = _fixture(register)
    function = codegen.cfunc
    old_value = returned.retval
    written = function.statements.statements[1]
    function.statements.statements = [written, returned]
    function.variable_manager.input_variables = lambda: [old_value.variable] if proven_input else []
    captured = _capture_segment_entry_versions_8616(
        codegen, function, codegen.project, frozenset({register}),
    )
    if not proven_input:
        assert not captured
        assert returned.retval is old_value
        assert function.statements.statements == [written, returned]
        return
    assert id(old_value) in captured
    snapshot, publication, _ = function.statements.statements
    assert isinstance(snapshot, CAssignment)
    assert isinstance(snapshot.lhs.variable, SimTemporaryVariable)
    assert isinstance(snapshot.rhs.variable, SimMemoryVariable)
    assert snapshot.rhs.variable.name == f"inertia_{register}"
    assert returned.retval is snapshot.lhs
    assert publication is written
    assert snapshot.lhs.variable in types
    assert not _capture_segment_entry_versions_8616(
        codegen, function, codegen.project, frozenset({register}),
    )
    assert len(function.statements.statements) == 3


@pytest.mark.parametrize("local_write", [True, False])
def test_call_boundary_does_not_authorize_an_entry_snapshot(local_write: bool) -> None:
    """A register read after CALL may observe a callee write, not function entry."""
    codegen, returned, _ = _fixture("es")
    function = codegen.cfunc
    old_value = returned.retval
    call = CExpressionStatement(CFunctionCall("opaque", None, args=[], codegen=codegen), codegen=codegen)
    written = function.statements.statements[1]
    function.statements.statements = [call, *([written] if local_write else []), returned]
    original_statements = tuple(function.statements.statements)
    function.variable_manager.input_variables = lambda: [old_value.variable]
    if local_write:
        with pytest.raises(PipelineHardError) as refused:
            _capture_segment_entry_versions_8616(codegen, function, codegen.project, frozenset({"es"}))
        assert refused.value.details is _SegmentInputCaptureFailure8616.CALL_BOUNDARY_UNPROVEN
    else:
        assert not _capture_segment_entry_versions_8616(
            codegen, function, codegen.project, frozenset({"es"}),
        )
    assert tuple(function.statements.statements) == original_statements
    assert returned.retval is old_value
