"""Regressions for multi-predecessor structured call arguments."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CConstant,
    CFunctionCall,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.ir.condition_ir import ConditionIR
import inertia.structuring.call_argument_path_conditions as path_conditions
from archinfo import ArchX86

from inertia.alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsitePushTrace8616,
    CallsiteRegisterJoin8616,
    CallsiteRegisterJoinTrace8616,
)
from inertia.structuring.call_argument_joins import (
    CallArgumentJoinDecision8616,
    materialize_call_argument_joins_8616,
)
from inertia.structuring.call_argument_path_joins import (
    CallArgumentPathJoinDecision8616,
    materialize_call_argument_path_join_8616,
)


def _constant(value: int, codegen: object) -> CConstant:
    """Build one unsigned 16-bit test constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _condition(
    block_addr: int,
    taken_target: int,
    fallthrough_target: int,
) -> ConditionIR:
    """Build one typed selector condition with exact CFG targets."""
    return ConditionIR(
        op="eq",
        lhs=object(),
        rhs=object(),
        src_insn=block_addr + 1,
        block_addr=block_addr,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
    )


def _summary() -> CallsiteSummary8616:
    """Build three predecessor paths with three varying physical lanes."""
    traces = (
        CallsitePushTrace8616((2, 2), (("imm", 10), ("imm", 100)), (0x1101, 0x1102), 0x1100),
        CallsitePushTrace8616((2, 2), (("imm", 20), ("imm", 200)), (0x1201, 0x1202), 0x1200),
        CallsitePushTrace8616((2, 2), (("imm", 30), ("imm", 300)), (0x1301, 0x1302), 0x1300),
    )
    register_join = CallsiteRegisterJoin8616(
        register="ax",
        push_instruction_addr=0x2001,
        traces=(
            CallsiteRegisterJoinTrace8616(0x1100, "ax", ("imm", 1000)),
            CallsiteRegisterJoinTrace8616(0x1200, "ax", ("imm", 2000)),
            CallsiteRegisterJoinTrace8616(0x1300, "ax", ("imm", 3000)),
        ),
        raw_fact_count=3,
        normalized_fact_count=3,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    merge = CallsitePredecessorStackMerge8616(
        widths=(2, 2),
        sources=(None, None),
        representative_instruction_addrs=(0x1101, 0x1102),
        alternative_instruction_addrs=((0x1101, 0x1201, 0x1301), (0x1102, 0x1202, 0x1302)),
        raw_fact_count=3,
        normalized_fact_count=3,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        register_join=register_join,
        traces=traces,
    )
    return CallsiteSummary8616(
        callsite_addr=0x2004,
        target_addr=0x3000,
        return_addr=0x2007,
        kind="near",
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        return_register="ax",
        return_used=True,
        push_arg_sources=(None, None, None, ("imm", 7)),
        push_arg_instruction_addrs=(0x1101, 0x1102, 0x2001, 0x2002),
        predecessor_stack_merge=merge,
    )


def _surface() -> tuple[SimpleNamespace, CFunctionCall, CallsiteSummary8616]:
    """Build a structured call carrying default-path arguments."""
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
        project=SimpleNamespace(arch=ArchX86()),
    )
    common = _constant(7, codegen)
    call = CFunctionCall(
        "ScaleRotate",
        None,
        [common, _constant(3000, codegen), _constant(300, codegen), _constant(30, codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements([CReturn(call, codegen=codegen)], codegen=codegen),
    )
    summary = _summary()
    codegen._inertia_callsite_summaries = {id(call): summary}
    codegen._inertia_typed_conditions = (
        _condition(0x1000, 0x1100, 0x1004),
        _condition(0x1004, 0x1200, 0x1008),
        _condition(0x1008, 0x1500, 0x1300),
    )
    return codegen, call, summary


def _successors() -> dict[int, tuple[int, ...]]:
    """Return a selector ladder whose final taken edge bypasses the call."""
    return {
        0x1000: (0x1100, 0x1004),
        0x1004: (0x1200, 0x1008),
        0x1008: (0x1500, 0x1300),
        0x1100: (0x2000,),
        0x1200: (0x2000,),
        0x1300: (0x2000,),
        0x1500: (),
        0x2000: (),
    }


def _install_condition_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    codegen: object,
    successors: dict[int, tuple[int, ...]],
) -> None:
    """Provide deterministic CFG and ConditionIR materialization boundaries."""
    monkeypatch.setattr(
        path_conditions,
        "condition_chain_successors_8616",
        lambda _project, _codegen: successors,
    )
    monkeypatch.setattr(
        path_conditions,
        "materialize_condition_ir_expression_8616",
        lambda _project, _codegen, condition: _constant(condition.block_addr, codegen),
    )


def test_materializes_all_varying_lanes_from_one_typed_path_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every path-varying lane uses the same exact selector partition."""
    codegen, call, summary = _surface()
    common = call.args[0]
    _install_condition_boundaries(monkeypatch, codegen, _successors())

    result = materialize_call_argument_path_join_8616(codegen, codegen, call, summary)

    assert result.decision is CallArgumentPathJoinDecision8616.MATERIALIZED
    assert result.changed
    assert call.args[0] is common
    assert all(isinstance(argument, CITE) for argument in call.args[1:])
    lane_zero = call.args[3]
    assert isinstance(lane_zero, CITE)
    assert isinstance(lane_zero.iftrue, CConstant) and lane_zero.iftrue.value == 10
    assert isinstance(lane_zero.iffalse, CITE)
    assert lane_zero.iffalse.iftrue.value == 20
    assert lane_zero.iffalse.iffalse.value == 30


def test_top_level_join_pass_accounts_for_path_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shared pass publishes the same closed evidence loop for N paths."""
    codegen, call, _summary_value = _surface()
    _install_condition_boundaries(monkeypatch, codegen, _successors())

    assert materialize_call_argument_joins_8616(codegen, codegen)

    stats = codegen._inertia_call_argument_join_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert stats.decisions == (CallArgumentJoinDecision8616.MATERIALIZED,)
    assert isinstance(call.args[1], CITE)


def test_refuses_an_unaccounted_call_block_predecessor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Complete Alias traces must equal the direct CFG predecessor set."""
    codegen, call, summary = _surface()
    before = tuple(call.args)
    successors = _successors()
    successors[0x1400] = (0x2000,)
    _install_condition_boundaries(monkeypatch, codegen, successors)

    result = materialize_call_argument_path_join_8616(codegen, codegen, call, summary)

    assert result.decision is CallArgumentPathJoinDecision8616.REFUSED_EVIDENCE
    assert result.failure_count == 1
    assert tuple(call.args) == before
