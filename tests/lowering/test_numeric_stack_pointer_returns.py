"""Exact source-owned numeric return projection and immutable entry capture."""
from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeLong

from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.lowering.codegen_return_origin import ReturnValueOrigin8616
from inertia.lowering.numeric_stack_pointer_returns import (
    NumericStackPointerLoweringFailure8616,
    NumericStackPointerLoweringStatus8616,
    apply_numeric_stack_pointer_return_lowering_8616,
    lower_numeric_stack_pointer_returns_8616,
)
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616
from inertia.semantics.numeric_stack_pointer_returns import apply_numeric_stack_pointer_return_inventory_8616
from tests.semantics.test_call_stack_coordinates import _world


def _fixture():
    apply_x86_16_bootstrap()
    project, _, source, summary = _world(
        bytes.fromhex("55 89e5 50 e80900 83c402 89e0 89ec 5d c3 c3"), 0x1004,
    )
    artifact = materialize_call_stack_effects_8616(source, {0x1004: summary}, project=project).function
    indices = count()
    codegen = SimpleNamespace(project=project, next_node_idx=lambda: next(indices),
                              next_ident=lambda name: name, display_vvar_ids=False, cstyle_null_cmp=False)
    returned = c.CReturn(c.CConstant(-2, SimTypeLong(False), codegen=codegen), codegen=codegen,
                         tags={"inertia_x86_16_return_value_origin":
                               ReturnValueOrigin8616(0x1007, 0x1007, 16, 0x100f, 0x1007)})
    root = c.CStatements([returned], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, variables_in_use={},
                                   variable_manager=project.kb.variables[0x1000], refresh=lambda: None)
    codegen._inertia_vex_ir_artifact = artifact
    apply_numeric_stack_pointer_return_inventory_8616(codegen)
    return project, codegen, returned, source


def test_entry_capture_dominates_exact_unsigned_word_return():
    _, codegen, returned, _ = _fixture()
    result = lower_numeric_stack_pointer_returns_8616(codegen)
    assert result is not None and result.status is NumericStackPointerLoweringStatus8616.MATERIALIZED
    assert (result.stats.classified_fact_count, result.stats.materialized_count, result.stats.failure_count) == (1, 1, 0)
    assignment, final_return = codegen.cfunc.statements.statements
    assert final_return is returned
    assert isinstance(assignment, c.CAssignment)
    assert assignment.rhs.op == "And" and assignment.rhs.rhs.value == 0xffff
    assert returned.retval.op == "And" and returned.retval.rhs.value == 0xffff
    assert returned.retval.lhs.lhs is assignment.lhs
    assert returned.retval.lhs.rhs.value == 0xfffe


def test_repeated_lowering_does_not_grow_entry_captures():
    _, codegen, returned, _ = _fixture()
    lower_numeric_stack_pointer_returns_8616(codegen)
    before = tuple(codegen.cfunc.statements.statements)
    expression = returned.retval
    repeated = lower_numeric_stack_pointer_returns_8616(codegen)
    assert repeated is not None and repeated.status is NumericStackPointerLoweringStatus8616.STABLE
    assert not repeated.changed
    assert tuple(codegen.cfunc.statements.statements) == before
    assert returned.retval is expression


def test_live_callee_mutation_invalidates_published_source_proof():
    project, codegen, returned, _ = _fixture()
    original = returned.retval
    project.loader.memory.store(0x1010, b"\xcb")
    result = lower_numeric_stack_pointer_returns_8616(codegen)
    assert result is not None and result.failure is NumericStackPointerLoweringFailure8616.SOURCE_CHANGED
    assert result.stats.failure_count == 1 and result.stats.materialized_count == 0
    assert returned.retval is original


@pytest.mark.parametrize("mutation", ["initializer", "later_write", "entry_order"])
def test_mutated_capture_is_not_reused(mutation):
    _, codegen, returned, _ = _fixture()
    lower_numeric_stack_pointer_returns_8616(codegen)
    root = codegen.cfunc.statements
    assignment = root.statements[0]
    if mutation == "initializer":
        assignment.rhs = c.CConstant(0, SimTypeLong(False), codegen=codegen)
    elif mutation == "later_write":
        root.statements.insert(1, c.CAssignment(assignment.lhs, assignment.rhs, codegen=codegen))
    else:
        root.statements = [returned, assignment]
    result = lower_numeric_stack_pointer_returns_8616(codegen)
    assert result is not None and result.failure is NumericStackPointerLoweringFailure8616.INVALID_CAPTURE
    assert result.stats.materialized_count == 0 and result.stats.failure_count == 1


def test_unknown_call_preserves_existing_return_expression():
    _, codegen, returned, source = _fixture()
    codegen._inertia_vex_ir_artifact = source
    apply_numeric_stack_pointer_return_inventory_8616(codegen)
    original = returned.retval
    result = lower_numeric_stack_pointer_returns_8616(codegen)
    assert result is not None and result.status is NumericStackPointerLoweringStatus8616.REFUSED
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert returned.retval is original
    assert codegen.cfunc.statements.statements == [returned]


def test_return_projection_does_not_erase_a_nested_call():
    """A source value proof cannot authorize deleting C-side call execution."""
    _, codegen, returned, _ = _fixture()
    call = c.CFunctionCall(c.CConstant(0x1010, SimTypeLong(False), codegen=codegen),
                           None, [], codegen=codegen)
    returned.retval = call
    result = lower_numeric_stack_pointer_returns_8616(codegen)
    assert result is not None and result.status is NumericStackPointerLoweringStatus8616.REFUSED
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert returned.retval is call
    assert codegen.cfunc.statements.statements == [returned]


def test_source_function_scope_must_match_native_function():
    """Return coordinates alone cannot transfer proof into another C function."""
    _, codegen, returned, _ = _fixture()
    codegen.cfunc.addr = 0x2000
    original = returned.retval
    result = lower_numeric_stack_pointer_returns_8616(codegen)
    assert result is not None and result.status is NumericStackPointerLoweringStatus8616.REFUSED
    assert result.stats.materialized_count == 0 and result.stats.failure_count == 1
    assert returned.retval is original
    assert codegen.cfunc.statements.statements == [returned]


def test_pipeline_failure_retains_typed_diagnostics_and_function_scope():
    """A refused classified materialization must surface its owned failure record."""
    project, codegen, _, _ = _fixture()
    project.loader.memory.store(0x1010, b"\xcb")
    with pytest.raises(PipelineHardError) as caught:
        apply_numeric_stack_pointer_return_lowering_8616(codegen)
    error = caught.value
    assert error.function_addr == 0x1000
    assert error.layer == "types:numeric_stack_pointer_returns"
    result = codegen._inertia_numeric_stack_pointer_return_lowering_8616
    assert result.failure is NumericStackPointerLoweringFailure8616.SOURCE_CHANGED
    assert error.details == result.to_dict()


def test_equivalent_branch_reordering_preserves_entry_capture():
    """Proof ownership is a set of RET scopes, independent of C traversal order."""
    from inertia.cli.project_loading import _build_project_from_bytes
    from inertia.ir.vex_import import build_x86_16_ir_function_artifact

    _, codegen, _, _ = _fixture()
    project = _build_project_from_bytes(
        bytes.fromhex("55 89e5 83f800 7406 89e0 89ec 5d c3 53 89e0 89ec 5d c3"),
        base_addr=0x1000, entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True)
    artifact = build_x86_16_ir_function_artifact(project, cfg.functions[0x1000])
    codegen.project = project
    codegen.cfunc.variable_manager = project.kb.variables[0x1000]
    codegen._inertia_vex_ir_artifact = artifact
    inventory = apply_numeric_stack_pointer_return_inventory_8616(codegen)
    assert inventory.stats.classified_fact_count == 2
    returned = []
    for item in inventory.observations:
        assert item.proof is not None
        origin = ReturnValueOrigin8616(item.proof.assignment.instruction_addr, item.block_addr,
                                      16, item.return_addr, item.block_addr)
        returned.append(c.CReturn(c.CConstant(0, SimTypeLong(False), codegen=codegen),
                                 codegen=codegen, tags={"inertia_x86_16_return_value_origin": origin}))
    left = c.CStatements([returned[0]], codegen=codegen)
    right = c.CStatements([returned[1]], codegen=codegen)
    conditional = c.CIfElse([(c.CConstant(1, SimTypeLong(False), codegen=codegen), left)], right, codegen=codegen)
    codegen.cfunc.statements = c.CStatements([conditional], codegen=codegen)
    first = lower_numeric_stack_pointer_returns_8616(codegen)
    assert first.stats.materialized_count == 2
    capture = codegen.cfunc.statements.statements[0]
    conditional.condition_and_nodes = [(c.CConstant(0, SimTypeLong(False), codegen=codegen), right)]
    conditional.else_node = left
    repeated = lower_numeric_stack_pointer_returns_8616(codegen)
    assert repeated.failure is None
    assert repeated.status is NumericStackPointerLoweringStatus8616.STABLE
    assert codegen.cfunc.statements.statements[0] is capture
