from __future__ import annotations

from types import SimpleNamespace

import inertia.ir.vex_import as vex_import
from inertia.ir.core import IRInstr
from inertia.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
    collect_vex_condition_demand_8616,
)
from pytest import MonkeyPatch


def test_binary_temporary_normalizes_each_operand_once(monkeypatch: MonkeyPatch) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=3))
    binary = SimpleNamespace(
        tag="Iex_Binop",
        op="Iop_Add16",
        args=(left, right),
    )
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=0, data=binary)
    converted: list[object] = []
    original = vex_import._expr_to_value

    def tracked(expr: object, *args: object, **kwargs: object):
        converted.append(expr)
        return original(expr, *args, **kwargs)

    monkeypatch.setattr(vex_import, "_expr_to_value", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(), VexConditionDemandStats8616()
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert instruction.op == "Iop_Add16"
    assert converted == [left, right]


def test_condition_demand_collects_only_direct_exit_guard_temporaries() -> None:
    statements = (
        SimpleNamespace(tag="Ist_WrTmp", tmp=4, data=object()),
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_RdTmp", tmp=4),
        ),
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_Binop", args=()),
        ),
    )

    demand = collect_vex_condition_demand_8616(statements)

    assert demand.complete
    assert demand.eager_tmp_ids == frozenset({4})
    assert demand.stats.raw_fact_count == 1
    assert demand.stats.materialized_count == 1
    assert demand.stats.failure_count == 0


def test_invalid_direct_exit_guard_disables_condition_suppression() -> None:
    statements = (
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_RdTmp", tmp="invalid"),
        ),
    )

    demand = collect_vex_condition_demand_8616(statements)

    assert not demand.complete
    assert demand.stats.raw_fact_count == 1
    assert demand.stats.failure_count == 1
    assert demand.requires_eager_condition(99)


def test_non_exit_logical_tmp_skips_eager_condition_classification(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_And16", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=7, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("nonzero", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(), VexConditionDemandStats8616()
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == []


def test_exit_guard_logical_tmp_retains_eager_condition_classification(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_And16", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=7, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("nonzero", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset({7}),
            VexConditionDemandStats8616(1, 1, 1, 1, 0),
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == [binary]


def test_comparison_retains_eager_classification_without_exit_demand(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_CmpLT16S", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=8, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("slt", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(), VexConditionDemandStats8616()
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == [binary]


def test_incomplete_condition_demand_retains_legacy_eager_behavior(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_Or16", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=9, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("nonzero", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(),
            VexConditionDemandStats8616(1, 0, 0, 0, 1),
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == [binary]
