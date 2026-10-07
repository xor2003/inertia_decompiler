"""Tests for typed call-return condition materialization."""

from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.rustylib.ailment import Tags
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.semantics.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
    structured_callsite_addr_8616,
)
from inertia.postprocess.decompiler_postprocess_calls import _callsite_materialization_signature_8616
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from archinfo import ArchX86

from inertia.structuring.call_return_conditions import (
    materialize_call_return_conditions_8616,
)
from inertia.validation.tail_validation_condition_context import (
    _owned_materialized_condition_fingerprint_8616,
)


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x100A3,
        target_addr=0x10010,
        return_addr=0x100A6,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )


def _condition() -> ConditionIR:
    return ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name="ax", offset=8, size=2),
        rhs=IRValue(MemSpace.CONST, name="const", const=0, size=2),
        src_insn=0x100AC,
        block_addr=0x100A6,
        producer_insn=0x100A9,
    )


def _surface() -> tuple[SimpleNamespace, SimpleNamespace, CIfElse]:
    callee = SimpleNamespace(addr=0x10010, name="sub_10010")
    functions = SimpleNamespace(function=lambda *, addr, create: callee if addr == 0x10010 and not create else None)
    project = SimpleNamespace(arch=ArchX86(), kb=SimpleNamespace(functions=functions))
    next_node_idx = iter(range(1, 1000))
    next_ident_idx = iter(range(1, 1000))
    codegen = SimpleNamespace(
        next_ident=lambda name: f"{name}_{next(next_ident_idx)}",
        next_node_idx=lambda: next(next_node_idx),
        project=project,
        cstyle_null_cmp=False,
    )
    condition = CBinaryOp(
        "CmpNE",
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100AC, "vex_block_addr": 0x100A6},
    )
    branch = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([branch], codegen=codegen))
    codegen._inertia_typed_conditions = (_condition(),)
    codegen._inertia_callsite_summary_inventory_8616 = {0x100A3: _summary()}
    codegen._inertia_callsite_summaries = {}
    return project, codegen, branch


def _stored_surface() -> tuple[SimpleNamespace, SimpleNamespace, CAssignment, CIfElse, CReturn]:
    """Build a value-return store followed by an AX zero condition."""
    project, codegen, branch = _surface()
    summary = replace(
        _summary(),
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
        return_store_destination=("bp", -2),
        return_store_width=2,
        return_store_instruction_addr=0x100A9,
    )
    callee = project.kb.functions.function(addr=0x10010, create=False)
    call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    return_variable = SimRegisterVariable(8, 2, name="ax")
    assignment = CAssignment(
        CVariable(return_variable, variable_type=SimTypeShort(False), codegen=codegen),
        call,
        codegen=codegen,
    )
    returned = CReturn(
        CVariable(return_variable, variable_type=SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x10000,
        statements=CStatements([assignment, branch, returned], codegen=codegen),
        variables_in_use={},
        unified_local_vars={},
        sort_local_vars=lambda: None,
    )
    identity_variable = SimStackVariable(-2, 2, base="bp", name="err")
    identity_cvar = CVariable(
        identity_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[identity_variable] = identity_cvar
    codegen.cfunc.unified_local_vars[identity_variable] = {
        (identity_cvar, identity_cvar.variable_type)
    }
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=identity_variable,
        cvar=identity_cvar,
        bp_offset=-2,
        entry_sp_offset=-2,
        size=2,
        display_name="err",
    )
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    return project, codegen, assignment, branch, returned


def test_materializes_exact_call_return_condition() -> None:
    project, codegen, branch = _surface()

    assert materialize_call_return_conditions_8616(project, codegen)

    expression = branch.condition_and_nodes[0][0]
    assert isinstance(expression, CBinaryOp)
    assert isinstance(expression.lhs, CFunctionCall)
    assert expression.lhs.callee_target == "sub_10010"
    assert structured_callsite_addr_8616(expression.lhs) == 0x100A3
    assert codegen._inertia_callsite_summaries[id(expression.lhs)].target_addr == 0x10010
    assert codegen._inertia_call_return_condition_stats_8616.materialized_count == 1


def test_rebinds_stale_condition_tags_from_structured_callsite_identity() -> None:
    project, codegen, branch = _surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    expression = branch.condition_and_nodes[0][0]
    expression.tags = {"ins_addr": 0x9999, "vex_block_addr": 0x9990}

    assert not materialize_call_return_conditions_8616(project, codegen)

    assert expression.tags["ins_addr"] == 0x100AC
    assert expression.tags["vex_block_addr"] == 0x100A6
    assert expression.tags["condition_producer_insn"] == 0x100A9


def test_reuses_adjacent_call_assignment_for_return_condition() -> None:
    """Keep one side-effecting call when its exact AX carrier is adjacent."""
    project, codegen, branch = _surface()
    summary = _summary()
    callee = project.kb.functions.function(addr=summary.target_addr, create=False)
    call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    bind_structured_callsite_identity_8616(call, summary)
    assignment = CAssignment(
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        call,
        codegen=codegen,
        tags={"ins_addr": _condition().producer_insn},
    )
    codegen.cfunc.statements = CStatements([assignment, branch], codegen=codegen)
    assert materialize_call_return_conditions_8616(project, codegen)

    assert tuple(codegen.cfunc.statements.statements) == (branch,)
    assert branch.condition_and_nodes[0][0].lhs is call
    assert structured_callsite_addr_8616(call) == summary.callsite_addr
    assert codegen._inertia_callsite_summaries[id(call)] == summary
    stats = codegen._inertia_call_return_condition_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_consumes_adjacent_assignment_when_condition_reuses_same_call() -> None:
    """Count one shared AST call occurrence at each rendered evaluation site."""
    project, codegen, branch = _surface()
    summary = _summary()
    callee = project.kb.functions.function(addr=summary.target_addr, create=False)
    call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    bind_structured_callsite_identity_8616(call, summary)
    assignment = CAssignment(
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        call,
        codegen=codegen,
        tags={"ins_addr": _condition().producer_insn},
    )
    branch.condition_and_nodes[0][0].lhs = call
    codegen.cfunc.statements = CStatements([assignment, branch], codegen=codegen)

    assert materialize_call_return_conditions_8616(project, codegen)

    assert tuple(codegen.cfunc.statements.statements) == (branch,)
    assert branch.condition_and_nodes[0][0].lhs is call
    stats = codegen._inertia_call_return_condition_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_consumes_adjacent_assignment_before_unbound_same_target_call() -> None:
    """Replace one unbound condition clone with its exact machine call."""
    project, codegen, branch = _surface()
    summary = _summary()
    callee = project.kb.functions.function(addr=summary.target_addr, create=False)
    exact_call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    bind_structured_callsite_identity_8616(exact_call, summary)
    assignment = CAssignment(
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        exact_call,
        codegen=codegen,
        tags={"ins_addr": _condition().producer_insn},
    )
    unbound_call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    branch.condition_and_nodes[0][0].lhs = unbound_call
    codegen.cfunc.statements = CStatements([assignment, branch], codegen=codegen)

    assert materialize_call_return_conditions_8616(project, codegen)

    assert tuple(codegen.cfunc.statements.statements) == (branch,)
    assert branch.condition_and_nodes[0][0].lhs is exact_call
    assert branch.condition_and_nodes[0][0].lhs is not unbound_call
    stats = codegen._inertia_call_return_condition_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_consumes_adjacent_compare_tagged_call_assignment_clone() -> None:
    """Collapse the producer and compare clones into one condition evaluation."""
    project, codegen, branch = _surface()
    summary = _summary()
    callee = project.kb.functions.function(addr=summary.target_addr, create=False)
    exact_call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    compare_call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    bind_structured_callsite_identity_8616(exact_call, summary)
    bind_structured_callsite_identity_8616(compare_call, summary)
    producer = CAssignment(
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        exact_call,
        codegen=codegen,
        tags={"ins_addr": _condition().producer_insn},
    )
    compare_clone = CAssignment(
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        compare_call,
        codegen=codegen,
        tags={"ins_addr": _condition().src_insn},
    )
    unbound_call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    branch.condition_and_nodes[0][0].lhs = unbound_call
    assignment_group = CStatements([producer, compare_clone], codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment_group, branch], codegen=codegen)

    assert materialize_call_return_conditions_8616(project, codegen)

    assert tuple(assignment_group.statements) == ()
    assert branch.condition_and_nodes[0][0].lhs is exact_call
    assert branch.condition_and_nodes[0][0].lhs is not compare_call
    assert branch.condition_and_nodes[0][0].lhs is not unbound_call
    stats = codegen._inertia_call_return_condition_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_refuses_nonadjacent_bound_call_without_duplicating_it() -> None:
    """Do not inline an existing exact call across an intervening statement."""
    project, codegen, branch = _surface()
    summary = _summary()
    callee = project.kb.functions.function(addr=summary.target_addr, create=False)
    call = CFunctionCall("sub_10010", callee, [], codegen=codegen)
    bind_structured_callsite_identity_8616(call, summary)
    assignment = CAssignment(
        CVariable(SimRegisterVariable(8, 2), codegen=codegen),
        call,
        codegen=codegen,
        tags={"ins_addr": _condition().producer_insn},
    )
    barrier = CAssignment(
        CVariable(SimRegisterVariable(20, 2), codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([assignment, barrier, branch], codegen=codegen)
    original_condition_lhs = branch.condition_and_nodes[0][0].lhs

    assert not materialize_call_return_conditions_8616(project, codegen)

    assert assignment.rhs is call
    assert branch.condition_and_nodes[0][0].lhs is original_condition_lhs
    assert not isinstance(original_condition_lhs, CFunctionCall)
    stats = codegen._inertia_call_return_condition_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_materializes_condition_with_rust_backed_tags() -> None:
    project, codegen, branch = _surface()
    condition = branch.condition_and_nodes[0][0]
    condition.tags = Tags(condition.tags)

    assert materialize_call_return_conditions_8616(project, codegen)

    expression = branch.condition_and_nodes[0][0]
    assert isinstance(expression, CBinaryOp)
    assert isinstance(expression.lhs, CFunctionCall)
    assert structured_callsite_addr_8616(expression.lhs) == 0x100A3


def test_materializes_value_return_store_before_exact_condition() -> None:
    """Bind the call assignment, condition, and return to the proven BP local."""
    project, codegen, assignment, branch, returned = _stored_surface()

    assert materialize_call_return_conditions_8616(project, codegen)

    condition = branch.condition_and_nodes[0][0]
    assert isinstance(assignment.lhs, CVariable)
    assert isinstance(assignment.lhs.variable, SimStackVariable)
    assert assignment.lhs.variable.offset == -2
    assert condition.lhs is assignment.lhs
    assert returned.retval is assignment.lhs
    call = assignment.rhs
    assert structured_callsite_addr_8616(call) == 0x100A3
    assert codegen._inertia_callsite_summaries[id(call)].return_store_destination == ("bp", -2)


def test_materializes_value_return_store_through_entry_sp_projection() -> None:
    """Reuse the exact BP-2 object represented by angr at entry-SP-4."""
    project, codegen, assignment, branch, returned = _stored_surface()
    projected = CVariable(
        SimStackVariable(-4, 2, base="bp", name="err"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[projected.variable] = projected
    codegen.cfunc.unified_local_vars[projected.variable] = {
        (projected, projected.variable_type)
    }
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected.variable,
        cvar=projected,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="err",
    )

    assert materialize_call_return_conditions_8616(project, codegen)

    assert assignment.lhs is projected
    assert branch.condition_and_nodes[0][0].lhs is projected
    assert returned.retval is projected
    assert projected.variable.offset == -4


def test_binds_adjacent_dirty_call_assignment_to_proven_return_store() -> None:
    """Replace unrelated dirty carriers only from exact call/store evidence."""
    project, codegen, assignment, branch, returned = _stored_surface()
    call = assignment.rhs
    destination = CVariable(
        SimStackVariable(-2, 2, base="bp", name="result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stored_assignment = CAssignment(
        destination,
        CDirtyExpression(SimpleNamespace(varid=596), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100A9},
    )
    setup = CAssignment(
        CDirtyExpression(SimpleNamespace(varid=129), codegen=codegen),
        CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    dirty_call_assignment = CAssignment(
        CDirtyExpression(SimpleNamespace(varid=130), codegen=codegen),
        call,
        codegen=codegen,
        tags={"ins_addr": 0x100A3},
    )
    call_group = CStatements([setup, dirty_call_assignment], codegen=codegen)
    store_group = CStatements([stored_assignment], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [call_group, store_group, branch, returned],
        codegen=codegen,
    )

    assert materialize_call_return_conditions_8616(project, codegen)

    statements = tuple(codegen.cfunc.statements.statements)
    assert statements == (call_group, store_group, branch, returned)
    assert tuple(call_group.statements) == (setup,)
    assert stored_assignment.rhs is call
    condition = branch.condition_and_nodes[0][0]
    assert condition.lhs is destination
    assert returned.retval is destination


def test_binds_source_tagged_call_result_bridge_and_reused_carriers() -> None:
    """Consume the current angr call/store bridge without duplicating the call."""
    project, codegen, assignment, branch, returned = _stored_surface()
    call = assignment.rhs
    source = CDirtyExpression(SimpleNamespace(varid=434), codegen=codegen)
    assignment.lhs = source
    assignment.tags = Tags(
        {"ins_addr": 0x100A9, "vex_block_addr": 0x100A6, "vex_stmt_idx": 73}
    )
    destination = CVariable(
        SimStackVariable(-2, 2, base="bp", name="result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    store = CAssignment(
        destination,
        CDirtyExpression(SimpleNamespace(varid=434), codegen=codegen),
        codegen=codegen,
        tags=Tags({"ins_addr": 0x100A9, "vex_block_addr": 0x100A6, "vex_stmt_idx": 81}),
    )
    aliases = [
        CAssignment(
            CDirtyExpression(SimpleNamespace(varid=varid), codegen=codegen),
            call,
            codegen=codegen,
            tags=Tags({"ins_addr": 0x100AC, "vex_block_addr": 0x100A6, "vex_stmt_idx": stmt_idx}),
        )
        for varid, stmt_idx in ((435, 83), (436, 84))
    ]
    codegen.cfunc.statements = CStatements(
        [assignment, store, *aliases, branch, returned],
        codegen=codegen,
    )

    assert materialize_call_return_conditions_8616(project, codegen)

    assert assignment not in codegen.cfunc.statements.statements
    assert store.rhs is call
    assert all(alias.rhs is destination for alias in aliases)
    assert branch.condition_and_nodes[0][0].lhs is destination
    assert returned.retval is destination
    stats = codegen._inertia_call_return_condition_stats_8616
    assert stats.store_bridge_materialized_count == 1
    assert stats.store_bridge_reused_carrier_count == 2
    assert stats.store_bridge_return_registers == ("ax",)

    assert not materialize_call_return_conditions_8616(project, codegen)
    replay_stats = codegen._inertia_call_return_condition_stats_8616
    assert replay_stats.store_bridge_materialized_count == 1
    assert replay_stats.store_bridge_reused_carrier_count == 2
    assert replay_stats.store_bridge_return_registers == ("ax",)
    assert structured_callsite_addr_8616(call) == 0x100A3


def test_refuses_nonadjacent_standalone_call_return_store() -> None:
    """Keep a separated call when another statement breaks exact placement."""
    project, codegen, assignment, branch, returned = _stored_surface()
    call = assignment.rhs
    destination = CVariable(
        SimStackVariable(-2, 2, base="bp", name="result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stored_assignment = CAssignment(
        destination,
        CVariable(SimRegisterVariable(20, 2), codegen=codegen),
        codegen=codegen,
    )
    barrier = CAssignment(
        CVariable(SimStackVariable(-4, 2, base="bp"), codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [call, barrier, stored_assignment, branch, returned],
        codegen=codegen,
    )

    assert not materialize_call_return_conditions_8616(project, codegen)

    assert tuple(codegen.cfunc.statements.statements) == (
        call,
        barrier,
        stored_assignment,
        branch,
        returned,
    )
    assert codegen._inertia_call_return_condition_stats_8616.failure_count == 1


def test_value_return_store_materialization_is_idempotent() -> None:
    """Keep an already-bound stack condition stable on replay."""
    project, codegen, assignment, branch, returned = _stored_surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    destination = assignment.lhs

    assert not materialize_call_return_conditions_8616(project, codegen)
    assert assignment.lhs is destination
    assert branch.condition_and_nodes[0][0].lhs is destination
    assert returned.retval is destination


def test_materializes_when_ast_summary_carrier_is_not_initialized() -> None:
    project, codegen, branch = _surface()
    del codegen._inertia_callsite_summaries

    assert materialize_call_return_conditions_8616(project, codegen)

    call = branch.condition_and_nodes[0][0].lhs
    assert codegen._inertia_callsite_summaries[id(call)] == _summary()


def test_materialization_is_idempotent() -> None:
    project, codegen, branch = _surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    first = branch.condition_and_nodes[0][0].lhs

    assert not materialize_call_return_conditions_8616(project, codegen)
    assert branch.condition_and_nodes[0][0].lhs is first
    assert codegen._inertia_call_return_condition_stats_8616.materialized_count == 1


def test_refuses_condition_without_exact_return_register() -> None:
    project, codegen, branch = _surface()
    branch.condition_and_nodes[0][0].lhs = CVariable(SimRegisterVariable(2, 2), codegen=codegen)

    assert not materialize_call_return_conditions_8616(project, codegen)
    assert codegen._inertia_call_return_condition_stats_8616.failure_count == 1
    assert not codegen._inertia_callsite_summaries


def test_rebinds_unique_regenerated_target_call() -> None:
    project, codegen, branch = _surface()
    condition = branch.condition_and_nodes[0][0]
    condition.lhs = CFunctionCall("sub_10010", project.kb.functions.function(addr=0x10010, create=False), [], codegen=codegen)

    assert materialize_call_return_conditions_8616(project, codegen)

    call = condition.lhs
    assert structured_callsite_addr_8616(call) == 0x100A3
    assert codegen._inertia_callsite_summaries[id(call)].callsite_addr == 0x100A3


def test_replaces_repeated_callee_clone_without_inheriting_other_callsite_arguments() -> None:
    project, codegen, branch = _surface()
    condition = branch.condition_and_nodes[0][0]
    stale_call = CFunctionCall(
        "sub_10010",
        project.kb.functions.function(addr=0x10010, create=False),
        [CConstant(9, SimTypeShort(False), codegen=codegen)],
        tags={"ins_addr": 0x100B3},
        codegen=codegen,
    )
    condition.lhs = stale_call
    stale_summary = replace(_summary(), callsite_addr=0x100B3, return_addr=0x100B6)
    codegen._inertia_callsite_summary_inventory_8616[stale_summary.callsite_addr] = stale_summary

    assert materialize_call_return_conditions_8616(project, codegen)

    call = condition.lhs
    assert call is not stale_call
    assert call.args == []
    assert structured_callsite_addr_8616(call) == 0x100A3


def test_materializes_original_target_against_rebased_project_callee() -> None:
    project, codegen, branch = _surface()
    original_target = 0x1016E
    local_target = 0x0FC7
    delta = original_target - local_target
    callee = SimpleNamespace(addr=local_target, name="sub_fc7")
    project.kb.functions.function = (
        lambda *, addr, create: callee if addr == local_target and not create else None
    )
    project.loader = SimpleNamespace(
        main_object=SimpleNamespace(linked_base=0, max_addr=0x1FFF)
    )
    project._inertia_original_project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x1FFF)
        )
    )
    project._inertia_original_linear_delta = delta
    summary = replace(_summary(), target_addr=original_target)
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    assert materialize_call_return_conditions_8616(project, codegen)

    call = branch.condition_and_nodes[0][0].lhs
    assert call.callee_func is callee
    assert structured_callsite_addr_8616(call) == summary.callsite_addr


def test_callsite_cache_signature_detects_lost_arguments() -> None:
    project, codegen, branch = _surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    call = branch.condition_and_nodes[0][0].lhs
    call.args = [CConstant(104, SimTypeShort(False), codegen=codegen)]
    materialized_signature = _callsite_materialization_signature_8616(codegen)

    call.args = []

    assert _callsite_materialization_signature_8616(codegen) != materialized_signature


def test_callsite_cache_signature_orders_optional_targets_and_ignores_clone_identity() -> None:
    project, codegen, _branch = _surface()
    callee = project.kb.functions.function(addr=0x10010, create=False)
    first = CFunctionCall(
        "sub_10010",
        callee,
        [CConstant(7, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    second = CFunctionCall(
        "sub_10010",
        callee,
        [CConstant(9, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x10000,
        statements=CStatements([first, second], codegen=codegen),
    )
    codegen._inertia_callsite_summaries = {
        id(first): _summary(),
        id(second): replace(_summary(), target_addr=None),
    }

    signature = _callsite_materialization_signature_8616(codegen)
    first.args = [CConstant(7, SimTypeShort(False), codegen=codegen)]

    assert signature is not None
    assert _callsite_materialization_signature_8616(codegen) == signature


def test_validation_keeps_materialized_call_with_register_backed_argument() -> None:
    project, codegen, branch = _surface()
    assert materialize_call_return_conditions_8616(project, codegen)
    condition = branch.condition_and_nodes[0][0]
    condition.tags["inertia_structuring_condition_cfg_materialized_8616"] = True
    ds_offset, ds_size = project.arch.registers["ds"]
    condition.lhs.args = [
        CVariable(SimRegisterVariable(ds_offset, ds_size), codegen=codegen)
    ]

    fingerprint = _owned_materialized_condition_fingerprint_8616(condition, project)

    assert isinstance(fingerprint, str)
    assert "call:" in fingerprint
    assert "reg:ds" in fingerprint
