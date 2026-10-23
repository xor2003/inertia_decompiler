"""Keep authenticated C call contexts coherent during source-backed Lowering replay.

Local transformation controls; these do not claim binary argument recovery.
"""
from dataclasses import replace
from pathlib import Path

import pytest
from angr.analyses.decompiler.structured_codegen import c

from inertia.lowering.call_stack_input_contracts import (
    CALL_STACK_INPUT_BINDING_TAG_8616,
    call_stack_context_layout_8616,
)
from inertia.lowering.call_stack_input_replay import run_call_stack_input_aware_lowering_8616
from inertia.lowering.call_stack_inputs import apply_call_stack_input_lowering_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.validation.validation_call_stack_inputs import validate_call_stack_inputs_8616
from tests.lowering.test_call_stack_argument_values import ArgumentKind, _argument_fixture, _compile_and_run
from tests.lowering.test_call_stack_inputs import _wrapper


def test_changed_arguments_are_recaptured_before_sp_input(tmp_path: Path) -> None:
    """Late word argument projection replaces the capture RHS, never its consumer."""
    codegen, call = _argument_fixture(ArgumentKind.SCALAR)
    original_argument = call.args[0]
    apply_call_stack_input_lowering_8616(codegen)
    original_wrapper = _wrapper(codegen)

    def consume() -> bool:
        assert call.args[0] is original_argument
        call.args = [c.CConstant(4660, original_argument.type, codegen=codegen)]
        return True

    assert run_call_stack_input_aware_lowering_8616(codegen, consume)
    layout = call_stack_context_layout_8616(_wrapper(codegen))
    assert layout is not None and _wrapper(codegen) is not original_wrapper
    assert layout.call is call and layout.original_arguments[0].value == 4660
    report = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert report.materialized_count == 1 and not report.issues
    assert _compile_and_run(codegen, ArgumentKind.SCALAR, tmp_path/'recaptured.c') == (4661, 1, 0x7ffe, 0x1234)


@pytest.mark.parametrize('kind', list(ArgumentKind))
def test_unchanged_replay_preserves_tree_and_local_ids(kind: ArgumentKind) -> None:
    """Repeated consumption sees original C values without accumulating temporaries."""
    codegen, call = _argument_fixture(kind)
    original_argument = call.args[0]
    apply_call_stack_input_lowering_8616(codegen)
    root = codegen.cfunc.statements
    captured = call.args[0]
    variables = tuple(codegen.cfunc.variables_in_use)

    def consume() -> bool:
        assert call.args[0] is original_argument
        return False

    for _ in range(2):
        assert not run_call_stack_input_aware_lowering_8616(codegen, consume)
        assert codegen.cfunc.statements is root and call.args[0] is captured
        assert tuple(codegen.cfunc.variables_in_use) == variables
        report = validate_call_stack_inputs_8616(codegen, root)
        assert report.materialized_count == 1 and not report.issues


def test_corrupted_context_refuses_before_consumer() -> None:
    """A stale capture identity cannot be normalized into a fresh accepted context."""
    codegen, _call = _argument_fixture(ArgumentKind.SCALAR)
    apply_call_stack_input_lowering_8616(codegen)
    wrapper = _wrapper(codegen)
    marker = wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616]
    wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616] = replace(marker, entry_tmp_id=777)
    invoked = []

    def consume() -> bool:
        invoked.append(True)
        return True

    with pytest.raises(PipelineHardError):
        run_call_stack_input_aware_lowering_8616(codegen, consume)
    assert not invoked and _wrapper(codegen) is wrapper
    assert validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements).issues


def test_consumer_exception_preserves_cause_and_owned_projection() -> None:
    """Restore this owner's temporary projection without swallowing consumer errors."""
    codegen, call = _argument_fixture(ArgumentKind.SCALAR)
    apply_call_stack_input_lowering_8616(codegen)
    root, arguments = codegen.cfunc.statements, call.args
    failure = ValueError('explicit consumer failure')

    def consume() -> bool:
        call.args = []
        raise failure

    with pytest.raises(ValueError) as caught:
        run_call_stack_input_aware_lowering_8616(codegen, consume)
    assert caught.value is failure
    assert codegen.cfunc.statements is root and call.args is arguments
    assert not validate_call_stack_inputs_8616(codegen, root).issues


def test_unrecorded_argument_mutation_fails_loudly() -> None:
    """A false no-change verdict cannot silently erase an argument mutation."""
    codegen, call = _argument_fixture(ArgumentKind.SCALAR)
    apply_call_stack_input_lowering_8616(codegen)

    def consume() -> bool:
        call.args = []
        return False

    with pytest.raises(PipelineHardError, match='without recording a mutation'):
        run_call_stack_input_aware_lowering_8616(codegen, consume)
