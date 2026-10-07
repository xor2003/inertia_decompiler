"""Regressions for structured branch-carried call arguments."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CConstant,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.ir.condition_ir import ConditionIR
import inertia.structuring.call_argument_join_conditions as join_conditions
from archinfo import ArchX86

from inertia.alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsiteRegisterJoin8616,
    CallsiteRegisterJoinTrace8616,
)
from inertia.structuring.call_argument_joins import (
    CallArgumentJoinDecision8616,
    materialize_call_argument_joins_8616,
)


def _constant(value: int, codegen: object) -> CConstant:
    """Build one unsigned 16-bit test constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _summary() -> CallsiteSummary8616:
    """Build exact two-predecessor PUSH evidence for one callsite."""
    join = CallsiteRegisterJoin8616(
        register="ax",
        push_instruction_addr=0x102B,
        traces=(
            CallsiteRegisterJoinTrace8616(0x101B, "ax", ("imm", 0x7002)),
            CallsiteRegisterJoinTrace8616(0x1024, "ax", ("imm", 0x7004)),
        ),
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    merge = CallsitePredecessorStackMerge8616(
        widths=(2,),
        sources=(("imm", 5),),
        representative_instruction_addrs=(0x101E,),
        alternative_instruction_addrs=((0x101E, 0x1027),),
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        register_join=join,
    )
    return CallsiteSummary8616(
        callsite_addr=0x102C,
        target_addr=0x1034,
        return_addr=0x102F,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("imm", 5), None),
        push_arg_instruction_addrs=(0x101E, 0x102B),
        predecessor_stack_merge=merge,
    )


def _branch(
    codegen: object,
    variable: SimRegisterVariable,
) -> CIfElse:
    """Build an existing structured two-arm assignment to one carrier."""
    true_body = CStatements(
        [
            CAssignment(
                CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen),
                _constant(0x7002, codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    false_body = CStatements(
        [
            CAssignment(
                CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen),
                _constant(0x7004, codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    return CIfElse(
        [(_constant(1, codegen), true_body)],
        else_node=false_body,
        cstyle_ifs=True,
        codegen=codegen,
    )


def _surface() -> tuple[SimpleNamespace, CFunctionCall, SimRegisterVariable, CIfElse]:
    """Build a call after one branch-carried register join."""
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=ArchX86()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    carrier_variable = SimRegisterVariable(8, 2, name="joined_ax")
    branch = _branch(codegen, carrier_variable)
    call = CFunctionCall(
        "Message",
        None,
        [_constant(0x7002, codegen), _constant(0x7002, codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([branch, CReturn(call, codegen=codegen)], codegen=codegen)
    )
    codegen._inertia_callsite_summaries = {id(call): _summary()}
    return codegen, call, carrier_variable, branch


def test_materializes_unique_branch_carrier_in_c_argument_order() -> None:
    """The sink register PUSH becomes argument zero and the earlier PUSH becomes one."""
    codegen, call, carrier_variable, _branch_node = _surface()

    assert materialize_call_argument_joins_8616(codegen.project, codegen)

    assert len(call.args) == 2
    assert isinstance(call.args[0], CVariable)
    assert call.args[0].variable is carrier_variable
    assert isinstance(call.args[1], CConstant)
    assert call.args[1].value == 5
    stats = codegen._inertia_call_argument_join_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert stats.decisions == (CallArgumentJoinDecision8616.MATERIALIZED,)


def test_materializes_join_from_two_condition_arms_before_terminal_else() -> None:
    """An else-if branch may carry both join values while its final else exits."""
    codegen, call, carrier_variable, branch = _surface()
    true_body = branch.condition_and_nodes[0][1]
    false_body = branch.else_node
    branch.condition_and_nodes = [
        (_constant(1, codegen), true_body),
        (_constant(0, codegen), false_body),
    ]
    branch.else_node = CStatements([CReturn(None, codegen=codegen)], codegen=codegen)

    assert materialize_call_argument_joins_8616(codegen.project, codegen)

    assert isinstance(call.args[0], CVariable)
    assert call.args[0].variable is carrier_variable
    assert isinstance(call.args[1], CConstant)
    assert call.args[1].value == 5


def test_accepts_an_already_materialized_join_without_ast_churn() -> None:
    """A repeated structuring replay counts consumed evidence but stays unchanged."""
    codegen, call, carrier_variable, _branch_node = _surface()
    call.args = [
        CVariable(carrier_variable, variable_type=SimTypeShort(False), codegen=codegen),
        _constant(5, codegen),
    ]

    assert not materialize_call_argument_joins_8616(codegen.project, codegen)

    stats = codegen._inertia_call_argument_join_stats_8616
    assert stats.materialized_count == 1
    assert stats.decisions == (CallArgumentJoinDecision8616.ALREADY_MATERIALIZED,)


def test_recovers_regenerated_call_identity_from_authoritative_inventory() -> None:
    """AST regeneration must not disconnect a call from its machine summary."""
    codegen, call, carrier_variable, _branch_node = _surface()
    summary = codegen._inertia_callsite_summaries.pop(id(call))
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    call.tags = {"ins_addr": summary.callsite_addr}

    assert materialize_call_argument_joins_8616(codegen.project, codegen)

    assert isinstance(call.args[0], CVariable)
    assert call.args[0].variable is carrier_variable
    assert isinstance(call.args[1], CConstant)
    assert call.args[1].value == 5


def test_refuses_ambiguous_structured_branch_carriers() -> None:
    """Two matching branch shapes cannot identify one machine register join."""
    codegen, call, carrier_variable, branch = _surface()
    duplicate = _branch(codegen, SimRegisterVariable(10, 2, name="other_join"))
    codegen.cfunc.statements = CStatements(
        [branch, duplicate, CReturn(call, codegen=codegen)],
        codegen=codegen,
    )
    before = tuple(call.args)

    assert not materialize_call_argument_joins_8616(codegen.project, codegen)

    assert tuple(call.args) == before
    stats = codegen._inertia_call_argument_join_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.failure_count == 1
    assert stats.decisions == (CallArgumentJoinDecision8616.REFUSED_CONDITION,)
    assert carrier_variable is not None


def test_refuses_carrier_redefinition_between_branch_and_call() -> None:
    """A later write invalidates the selected branch carrier before its PUSH use."""
    codegen, call, carrier_variable, branch = _surface()
    overwrite = CAssignment(
        CVariable(carrier_variable, variable_type=SimTypeShort(False), codegen=codegen),
        _constant(9, codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [branch, overwrite, CReturn(call, codegen=codegen)],
        codegen=codegen,
    )
    before = tuple(call.args)

    assert not materialize_call_argument_joins_8616(codegen.project, codegen)

    assert tuple(call.args) == before
    stats = codegen._inertia_call_argument_join_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.failure_count == 1
    assert stats.decisions == (CallArgumentJoinDecision8616.REFUSED_ORDER,)


def test_materializes_conditional_argument_from_exact_cfg_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typed taken/fallthrough partition replaces an absent structured branch."""
    codegen, call, _carrier_variable, _branch_node = _surface()
    codegen.cfunc.statements = CStatements([CReturn(call, codegen=codegen)], codegen=codegen)
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="zero",
            lhs=object(),
            src_insn=0x1019,
            block_addr=0x1014,
            taken_target=0x1024,
            fallthrough_target=0x101B,
        ),
    )
    monkeypatch.setattr(
        join_conditions,
        "materialize_condition_ir_expression_8616",
        lambda _project, _codegen, _condition: _constant(1, codegen),
    )

    assert materialize_call_argument_joins_8616(codegen.project, codegen)

    assert isinstance(call.args[0], CITE)
    assert isinstance(call.args[0].iftrue, CConstant)
    assert isinstance(call.args[0].iffalse, CConstant)
    assert call.args[0].iftrue.value == 0x7004
    assert call.args[0].iffalse.value == 0x7002
    assert isinstance(call.args[1], CConstant)
    assert call.args[1].value == 5
