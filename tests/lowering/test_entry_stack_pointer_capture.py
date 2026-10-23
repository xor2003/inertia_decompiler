"""Independent source consumers must share one authenticated architectural input."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen import c

from inertia.alias.call_stack_positions import prove_call_stack_position_8616
from inertia.lowering.entry_stack_pointer_capture import (
    EntryStackPointerCapture8616,
    EntryStackPointerCaptureFailure8616,
    prepare_entry_stack_pointer_capture_8616,
)
from inertia.lowering.numeric_stack_pointer_returns import lower_numeric_stack_pointer_returns_8616
from tests.lowering.test_numeric_stack_pointer_returns import _fixture


def _call_use(artifact):
    """Obtain a real source positional requirement, independent of return use."""
    block, index = next(
        (block, index) for block in artifact.blocks for index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL"
    )
    proof = prove_call_stack_position_8616(artifact, block.addr, index).proof
    assert proof is not None
    return proof


@pytest.mark.parametrize("call_first", [False, True])
def test_return_and_call_uses_share_one_immutable_capture(call_first):
    """Consumer order cannot grow locals or produce competing input values."""
    _, codegen, returned, _ = _fixture()
    source = codegen._inertia_vex_ir_artifact
    call = _call_use(source)
    if call_first:
        first = prepare_entry_stack_pointer_capture_8616(codegen, source, (call,))
        assert first is not None and first.value is not None
    lower_numeric_stack_pointer_returns_8616(codegen)
    result = prepare_entry_stack_pointer_capture_8616(codegen, source, (call, call))
    assert result is not None and result.failure is None
    assignment, final_return = codegen.cfunc.statements.statements
    assert final_return is returned
    assert isinstance(assignment, c.CAssignment)
    assert assignment.lhs is result.value
    assert returned.retval.lhs.lhs is result.value
    assert len(codegen.cfunc.variables_in_use) == 1
    markers = [value for value in assignment.tags.values() if isinstance(value, EntryStackPointerCapture8616)]
    assert len(markers) == 1 and len(markers[0].uses) == 2
    before = tuple(codegen.cfunc.statements.statements)
    repeated = lower_numeric_stack_pointer_returns_8616(codegen)
    assert repeated is not None and not repeated.changed
    observed = prepare_entry_stack_pointer_capture_8616(codegen, source, ())
    assert observed is not None and observed.value is result.value and observed.changed_count == 0
    assert tuple(codegen.cfunc.statements.statements) == before
    assert len(codegen.cfunc.variables_in_use) == 1


def test_empty_capture_request_does_not_create_a_local():
    """A function without a proved use retains its original C sequence."""
    _, codegen, returned, _ = _fixture()
    result = prepare_entry_stack_pointer_capture_8616(codegen, codegen._inertia_vex_ir_artifact, ())
    assert result is None
    assert codegen.cfunc.statements.statements == [returned]
    assert not codegen.cfunc.variables_in_use


def test_capture_rejects_an_offered_source_replaced_on_codegen():
    """An old valid artifact is not authority after native publication changes."""
    _, codegen, returned, _ = _fixture()
    old_source = codegen._inertia_vex_ir_artifact
    call = _call_use(old_source)
    codegen._inertia_vex_ir_artifact = replace(old_source)
    result = prepare_entry_stack_pointer_capture_8616(codegen, old_source, (call,))
    assert result is not None and result.value is None
    assert result.failure is EntryStackPointerCaptureFailure8616.SOURCE_CHANGED
    assert codegen.cfunc.statements.statements == [returned]
    assert not codegen.cfunc.variables_in_use


def test_retained_call_use_revalidates_when_return_consumer_reuses_capture():
    """Invalidating a prior caller requirement prevents reuse by another consumer."""
    project, codegen, _, _ = _fixture()
    source = codegen._inertia_vex_ir_artifact
    call = _call_use(source)
    first = prepare_entry_stack_pointer_capture_8616(codegen, source, (call,))
    assert first is not None and first.value is not None
    project.loader.memory.store(0x1010, b"\xcb")
    result = prepare_entry_stack_pointer_capture_8616(codegen, source, ())
    assert result is not None and result.value is None
    assert result.failure is EntryStackPointerCaptureFailure8616.SOURCE_CHANGED
    assert result.to_dict()["failure_count"] == 1
    assert len(codegen.cfunc.variables_in_use) == 1


def test_unproved_requested_use_does_not_allocate_a_capture():
    """A forged positional value cannot become a new structural input proof."""
    _, codegen, returned, _ = _fixture()
    source = codegen._inertia_vex_ir_artifact
    call = replace(_call_use(source), callee_entry_offset=0)
    result = prepare_entry_stack_pointer_capture_8616(codegen, source, (call,))
    assert result is not None and result.value is None
    assert result.failure is EntryStackPointerCaptureFailure8616.SOURCE_CHANGED
    assert codegen.cfunc.statements.statements == [returned]
    assert not codegen.cfunc.variables_in_use


def test_unknown_retained_use_is_a_typed_capture_refusal():
    """A marker containing foreign metadata must not reach source proof code."""
    _, codegen, _, _ = _fixture()
    source = codegen._inertia_vex_ir_artifact
    first = prepare_entry_stack_pointer_capture_8616(codegen, source, (_call_use(source),))
    assert first is not None and first.value is not None
    assignment = codegen.cfunc.statements.statements[0]
    key = next(key for key, value in assignment.tags.items() if isinstance(value, EntryStackPointerCapture8616))
    assignment.tags[key] = EntryStackPointerCapture8616(0x1000, (object(),))
    result = prepare_entry_stack_pointer_capture_8616(codegen, source, ())
    assert result is not None and result.value is None
    assert result.failure is EntryStackPointerCaptureFailure8616.INVALID_CAPTURE


def test_capture_marker_cannot_claim_a_different_function():
    """Source uses and initialization cannot authorize a foreign capture scope."""
    _, codegen, _, _ = _fixture()
    source = codegen._inertia_vex_ir_artifact
    first = prepare_entry_stack_pointer_capture_8616(codegen, source, (_call_use(source),))
    assert first is not None and first.value is not None
    assignment = codegen.cfunc.statements.statements[0]
    key, marker = next((key, value) for key, value in assignment.tags.items()
                      if isinstance(value, EntryStackPointerCapture8616))
    assignment.tags[key] = replace(marker, function_addr=0x2000)
    result = prepare_entry_stack_pointer_capture_8616(codegen, source, ())
    assert result is not None and result.value is None
    assert result.failure is EntryStackPointerCaptureFailure8616.INVALID_CAPTURE
