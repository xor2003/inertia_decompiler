"""Regressions for structured path selection of already-typed call values."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CITE, CConstant
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.structuring import call_argument_path_conditions as path_conditions
from archinfo import ArchX86


def _summary() -> CallsiteSummary8616:
    """Describe a call after two branch-specific predecessor blocks."""
    return CallsiteSummary8616(
        callsite_addr=0x2004,
        target_addr=0x3000,
        return_addr=0x2007,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
    )


def _condition() -> ConditionIR:
    """Describe the typed selector whose edges reach both call paths."""
    return ConditionIR(
        op="eq",
        lhs=object(),
        rhs=object(),
        src_insn=0x1001,
        block_addr=0x1000,
        taken_target=0x1100,
        fallthrough_target=0x1200,
    )


def _successors() -> dict[int, tuple[int, ...]]:
    """Give each path one exact direct edge to the shared call block."""
    return {
        0x1000: (0x1100, 0x1200),
        0x1100: (0x2000,),
        0x1200: (0x2000,),
        0x2000: (),
    }


def _surface(
    monkeypatch: pytest.MonkeyPatch,
    *,
    conditions: tuple[ConditionIR, ...] | None = None,
    successors: dict[int, tuple[int, ...]] | None = None,
    condition_materializes: bool = True,
) -> tuple[SimpleNamespace, dict[int, CConstant]]:
    """Install deterministic CFG and ConditionIR materialization boundaries."""
    codegen = SimpleNamespace(
        _inertia_typed_conditions=conditions if conditions is not None else (_condition(),),
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=ArchX86()),
    )
    leaves = {
        0x1100: CConstant(0, SimTypeShort(False), codegen=codegen),
        0x1200: CConstant(0x1A, SimTypeShort(False), codegen=codegen),
    }
    monkeypatch.setattr(
        path_conditions,
        "condition_chain_successors_8616",
        lambda _project, _codegen: successors if successors is not None else _successors(),
    )
    monkeypatch.setattr(
        path_conditions,
        "materialize_condition_ir_expression_8616",
        lambda _project, _codegen, _condition: (
            CConstant(1, SimTypeShort(False), codegen=codegen)
            if condition_materializes
            else None
        ),
    )
    return codegen, leaves


def test_materializes_exact_typed_leaves_without_retyping_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The selected branch uses the supplied expressions by object identity."""
    codegen, leaves = _surface(monkeypatch)

    result = path_conditions.materialize_call_argument_typed_path_expression_8616(
        codegen, codegen, _summary(), leaves
    )

    assert result.status is path_conditions.CallArgumentPathConditionStatus8616.MATERIALIZED
    assert len(result.expressions) == 1
    expression = result.expressions[0]
    assert isinstance(expression, CITE)
    assert expression.iftrue is leaves[0x1100]
    assert expression.iffalse is leaves[0x1200]


@pytest.mark.parametrize("missing", [True, False])
def test_refuses_missing_or_extra_predecessor(
    monkeypatch: pytest.MonkeyPatch, *, missing: bool
) -> None:
    """Leaf evidence must equal the direct predecessor census exactly."""
    codegen, leaves = _surface(monkeypatch)
    if missing:
        del leaves[0x1200]
    else:
        leaves[0x1300] = CConstant(3, SimTypeShort(False), codegen=codegen)

    result = path_conditions.materialize_call_argument_typed_path_expression_8616(
        codegen, codegen, _summary(), leaves
    )

    assert result.status is path_conditions.CallArgumentPathConditionStatus8616.REFUSED_TOPOLOGY
    assert not result.expressions


@pytest.mark.parametrize("duplicate", [False, True])
def test_refuses_missing_or_ambiguous_typed_condition(
    monkeypatch: pytest.MonkeyPatch, *, duplicate: bool
) -> None:
    """A branch with no unique typed ConditionIR cannot select typed leaves."""
    conditions = (_condition(), _condition()) if duplicate else ()
    codegen, leaves = _surface(monkeypatch, conditions=conditions)

    result = path_conditions.materialize_call_argument_typed_path_expression_8616(
        codegen, codegen, _summary(), leaves
    )

    assert result.status is path_conditions.CallArgumentPathConditionStatus8616.REFUSED_CONDITION
    assert not result.expressions


def test_refuses_condition_target_disagreeing_with_cfg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A corrupted edge orientation cannot be laundered into a ternary."""
    successors = _successors()
    successors[0x1000] = (0x1100, 0x1300)
    codegen, leaves = _surface(monkeypatch, successors=successors)

    result = path_conditions.materialize_call_argument_typed_path_expression_8616(
        codegen, codegen, _summary(), leaves
    )

    assert result.status is path_conditions.CallArgumentPathConditionStatus8616.REFUSED_CONDITION
    assert not result.expressions


def test_refuses_condition_expression_that_cannot_materialize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Topology alone cannot replace the missing typed branch condition."""
    codegen, leaves = _surface(monkeypatch, condition_materializes=False)

    result = path_conditions.materialize_call_argument_typed_path_expression_8616(
        codegen, codegen, _summary(), leaves
    )

    assert result.status is path_conditions.CallArgumentPathConditionStatus8616.REFUSED_CONDITION
    assert not result.expressions
