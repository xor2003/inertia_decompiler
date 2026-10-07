from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.canonical_for_loops import (
    canonical_loop_validation_shape_8616,
    recover_canonical_for_loops_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _const(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _local(offset: int, codegen: _Codegen) -> CVariable:
    variable = SimStackVariable(offset, 2, base="bp", name=f"local_{-offset}", region=0x4010)
    return CVariable(variable, codegen=codegen)


def _candidate_loop(
    codegen: _Codegen,
    *,
    continue_body: bool = False,
    expanded_guard: bool = False,
    comparison_guard: str | None = None,
    mismatched_iterator: bool = False,
):
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(3, codegen), codegen=codegen)
    if comparison_guard == "eq":
        guard_condition = CBinaryOp("CmpEQ", induction, _const(0, codegen), codegen=codegen)
    elif comparison_guard == "not-ne":
        guard_condition = CUnaryOp(
            "Not",
            CBinaryOp("CmpNE", induction, _const(0, codegen), codegen=codegen),
            codegen=codegen,
        )
    else:
        guard_condition = CUnaryOp("Not", induction, codegen=codegen)
    guard = (
        CIfElse(
            [
                (
                    guard_condition,
                    CBreak(codegen=codegen),
                )
            ],
            codegen=codegen,
        )
        if expanded_guard
        else CIfBreak(guard_condition, codegen=codegen)
    )
    payload = CContinue(codegen=codegen) if continue_body else CAssignment(
        _local(-8, codegen),
        induction,
        codegen=codegen,
    )
    iterator_lhs = _local(-6 if mismatched_iterator else -4, codegen)
    iterator = CAssignment(
        iterator_lhs,
        CBinaryOp("Sub", iterator_lhs, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([guard, payload, iterator], addr=0x4020, codegen=codegen),
        codegen=codegen,
    )
    return initializer, loop


def _codegen_with_nested_candidate(
    *,
    continue_body: bool = False,
    comparison_guard: str | None = None,
    expanded_guard: bool = False,
    mismatched_iterator: bool = False,
    wrapped_sequence: bool = False,
):
    codegen = _Codegen()
    initializer, inner = _candidate_loop(
        codegen,
        comparison_guard=comparison_guard,
        continue_body=continue_body,
        expanded_guard=expanded_guard,
        mismatched_iterator=mismatched_iterator,
    )
    if wrapped_sequence:
        inner.body.statements = [
            CStatements([], codegen=codegen),
            inner.body.statements[0],
            CStatements([inner.body.statements[1]], codegen=codegen),
            CStatements([inner.body.statements[2]], codegen=codegen),
        ]
        outer_body = [CStatements([initializer], codegen=codegen), inner]
    else:
        outer_body = [initializer, inner]
    outer = CWhileLoop(
        _const(1, codegen),
        CStatements(outer_body, codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([outer], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    return codegen, outer


def test_recovers_nested_descending_pretest_loop_as_for() -> None:
    codegen, outer = _codegen_with_nested_candidate()

    assert recover_canonical_for_loops_8616(codegen) is True

    assert isinstance(outer.body, CStatements)
    assert len(outer.body.statements) == 1
    recovered = outer.body.statements[0]
    assert isinstance(recovered, CForLoop)
    assert isinstance(recovered.body, CStatements)
    assert len(recovered.body.statements) == 1
    stats = codegen._inertia_canonical_for_loop_recovery_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_refuses_loop_with_continue_targeting_candidate() -> None:
    codegen, outer = _codegen_with_nested_candidate(continue_body=True)

    assert recover_canonical_for_loops_8616(codegen) is False

    assert isinstance(outer.body, CStatements)
    assert len(outer.body.statements) == 2
    assert isinstance(outer.body.statements[1], CWhileLoop)
    stats = codegen._inertia_canonical_for_loop_recovery_stats_8616
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_recovers_expanded_one_arm_break_guard() -> None:
    codegen, outer = _codegen_with_nested_candidate(expanded_guard=True)

    assert recover_canonical_for_loops_8616(codegen) is True

    assert isinstance(outer.body, CStatements)
    assert len(outer.body.statements) == 1
    assert isinstance(outer.body.statements[0], CForLoop)


def test_recovers_across_nested_sequence_containers() -> None:
    codegen, outer = _codegen_with_nested_candidate(
        expanded_guard=True,
        wrapped_sequence=True,
    )

    assert recover_canonical_for_loops_8616(codegen) is True

    assert isinstance(outer.body, CStatements)
    projected = [
        statement
        for container in outer.body.statements
        for statement in (container.statements if isinstance(container, CStatements) else [container])
    ]
    assert len(projected) == 1
    assert isinstance(projected[0], CForLoop)


def test_recovers_typed_zero_comparison_guards() -> None:
    for comparison_guard in ("eq", "not-ne"):
        codegen, outer = _codegen_with_nested_candidate(
            comparison_guard=comparison_guard,
            expanded_guard=True,
            wrapped_sequence=True,
        )

        assert recover_canonical_for_loops_8616(codegen) is True
        assert isinstance(outer.body, CStatements)
        projected = [
            statement
            for container in outer.body.statements
            for statement in (
                container.statements
                if isinstance(container, CStatements)
                else [container]
            )
        ]
        assert len(projected) == 1
        assert isinstance(projected[0], CForLoop)


def test_recovers_exact_comparison_pretest_loop_as_for() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(0, codegen), codegen=codegen)
    guard = CIfBreak(
        CBinaryOp(
            "CmpLE",
            _const(8, codegen),
            induction,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp(
            "Add",
            _local(-4, codegen),
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    payload = CAssignment(_local(-8, codegen), induction, codegen=codegen)
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([guard, payload, iterator], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is True
    assert len(root.statements) == 1
    recovered = root.statements[0]
    assert isinstance(recovered, CForLoop)
    assert isinstance(recovered.condition, CBinaryOp)
    assert recovered.condition.op == "CmpGT"
    assert recovered.body.statements == [payload]


def test_recovers_unary_negated_ordered_pretest_loop_as_for() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(0, codegen), codegen=codegen)
    continuation = CBinaryOp(
        "CmpGT",
        _const(8, codegen),
        induction,
        codegen=codegen,
    )
    guard = CIfElse(
        [(CUnaryOp("Not", continuation, codegen=codegen), CBreak(codegen=codegen))],
        codegen=codegen,
    )
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp("Add", _local(-4, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    payload = CAssignment(_local(-8, codegen), induction, codegen=codegen)
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([guard, payload, iterator], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    validation_shape = canonical_loop_validation_shape_8616(loop)
    assert validation_shape is not None
    assert validation_shape.condition is continuation
    assert recover_canonical_for_loops_8616(codegen) is True
    assert isinstance(root.statements[0], CForLoop)
    assert root.statements[0].condition is continuation


def test_refuses_comparison_pretest_guard_without_induction_variable() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(0, codegen), codegen=codegen)
    guard = CIfBreak(
        CBinaryOp(
            "CmpLE",
            _local(-8, codegen),
            _local(-10, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp(
            "Add",
            _local(-4, codegen),
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([guard, iterator], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is False
    assert root.statements == [initializer, loop]


def test_recovers_conditional_loop_with_exact_inverse_leading_break() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(0, codegen), codegen=codegen)
    continuation = CBinaryOp(
        "CmpGT",
        _const(8, codegen),
        induction,
        codegen=codegen,
    )
    guard = CIfBreak(
        CBinaryOp(
            "CmpLE",
            _const(8, codegen),
            induction,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp(
            "Add",
            _local(-4, codegen),
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    payload = CAssignment(_local(-8, codegen), induction, codegen=codegen)
    loop = CWhileLoop(
        continuation,
        CStatements([guard, payload, iterator], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is True
    assert len(root.statements) == 1
    recovered = root.statements[0]
    assert isinstance(recovered, CForLoop)
    assert recovered.condition is continuation
    assert recovered.body.statements == [payload]


def test_recovers_direct_conditional_loop_after_pretest_guard_promotion() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(0, codegen), codegen=codegen)
    continuation = CBinaryOp(
        "CmpGT",
        _const(8, codegen),
        induction,
        codegen=codegen,
    )
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp("Add", _local(-4, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    payload = CAssignment(_local(-8, codegen), induction, codegen=codegen)
    loop = CWhileLoop(
        continuation,
        CStatements([payload, iterator], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    validation_shape = canonical_loop_validation_shape_8616(loop)
    assert validation_shape is not None
    assert validation_shape.condition is continuation
    assert validation_shape.suppressed_control_node_ids == frozenset()
    assert recover_canonical_for_loops_8616(codegen) is True
    assert len(root.statements) == 1
    recovered = root.statements[0]
    assert isinstance(recovered, CForLoop)
    assert recovered.condition is continuation
    assert recovered.body.statements == [payload]


def test_refuses_conditional_loop_with_noninverse_leading_break() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(0, codegen), codegen=codegen)
    loop = CWhileLoop(
        CBinaryOp("CmpGT", _const(8, codegen), induction, codegen=codegen),
        CStatements(
            [
                CIfBreak(
                    CBinaryOp(
                        "CmpLT",
                        _const(8, codegen),
                        induction,
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                CAssignment(
                    _local(-4, codegen),
                    CBinaryOp(
                        "Add",
                        _local(-4, codegen),
                        _const(1, codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is False
    assert root.statements == [initializer, loop]


def test_refuses_mismatched_iterator_storage() -> None:
    codegen, outer = _codegen_with_nested_candidate(mismatched_iterator=True)

    assert recover_canonical_for_loops_8616(codegen) is False

    assert isinstance(outer.body, CStatements)
    assert isinstance(outer.body.statements[1], CWhileLoop)
    stats = codegen._inertia_canonical_for_loop_recovery_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 0
    assert stats.classified_fact_count == 0


def test_recovers_nested_loop_from_current_switch_case_list() -> None:
    codegen = _Codegen()
    initializer, loop = _candidate_loop(codegen)
    case_body = CStatements([initializer, loop], codegen=codegen)
    switch = CSwitchCase(
        _local(-8, codegen),
        [(1, case_body)],
        None,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([switch], addr=0x4010, codegen=codegen)
    )

    assert recover_canonical_for_loops_8616(codegen) is True
    assert len(case_body.statements) == 1
    assert isinstance(case_body.statements[0], CForLoop)


def test_attaches_adjacent_initializer_to_existing_for_loop() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(3, codegen), codegen=codegen)
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp("Sub", _local(-4, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CForLoop(
        None,
        _local(-4, codegen),
        iterator,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is True
    assert root.statements == [loop]
    assert loop.initializer is initializer
    stats = codegen._inertia_canonical_for_loop_recovery_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_attaches_initializer_to_existing_for_with_nonzero_comparison() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(3, codegen), codegen=codegen)
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp("Sub", _local(-4, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CForLoop(
        None,
        CBinaryOp("CmpNE", _local(-4, codegen), _const(0, codegen), codegen=codegen),
        iterator,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([CStatements([initializer], codegen=codegen), loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is True
    assert loop.initializer is initializer
    assert root.statements[0].statements == []


def test_refuses_zero_comparison_as_for_continuation_condition() -> None:
    codegen = _Codegen()
    induction = _local(-4, codegen)
    initializer = CAssignment(induction, _const(3, codegen), codegen=codegen)
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp("Sub", _local(-4, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CForLoop(
        None,
        CBinaryOp("CmpEQ", _local(-4, codegen), _const(0, codegen), codegen=codegen),
        iterator,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is False
    assert root.statements == [initializer, loop]
    assert loop.initializer is None


def test_refuses_adjacent_initializer_for_different_for_induction() -> None:
    codegen = _Codegen()
    initializer = CAssignment(_local(-6, codegen), _const(3, codegen), codegen=codegen)
    iterator = CAssignment(
        _local(-4, codegen),
        CBinaryOp("Sub", _local(-4, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CForLoop(
        None,
        _local(-4, codegen),
        iterator,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([initializer, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert recover_canonical_for_loops_8616(codegen) is False
    assert root.statements == [initializer, loop]
    assert loop.initializer is None
