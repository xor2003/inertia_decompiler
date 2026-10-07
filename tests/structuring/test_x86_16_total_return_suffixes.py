from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CFunctionCall,
    CIfElse,
    CLabel,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeShort
from archinfo import ArchX86

from inertia.structuring.identical_return_guards import (
    IdenticalReturnGuardRefusalReason8616,
    IdenticalReturnGuardShape8616,
    collapse_pure_identical_return_guards_8616,
)
from inertia.structuring.total_return_suffixes import (
    prune_unreachable_total_return_suffixes_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _return_body(codegen: _Codegen, value: int) -> CStatements:
    expression = CConstant(value, SimTypeShort(False), codegen=codegen)
    return CStatements([CReturn(expression, codegen=codegen)], codegen=codegen)


def _total_return_chain(codegen: _Codegen) -> CIfElse:
    conditions = [
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
    ]
    for condition in conditions:
        condition.tags[
            "inertia_structuring_multi_arm_return_chain_materialized_8616"
        ] = True
    return CIfElse(
        [
            (conditions[0], _return_body(codegen, 10)),
            (conditions[1], _return_body(codegen, 20)),
        ],
        else_node=_return_body(codegen, 30),
        cstyle_ifs=True,
        codegen=codegen,
    )


def _single_return_guard(
    codegen: _Codegen,
    condition: object,
    value: int,
) -> CIfElse:
    return CIfElse(
        [(condition, _return_body(codegen, value))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )


def test_total_return_suffix_prunes_unreachable_register_return() -> None:
    codegen = _Codegen()
    chain = _total_return_chain(codegen)
    unreachable = CReturn(
        CConstant(99, SimTypeShort(False), codegen=codegen), codegen=codegen
    )
    root = CStatements([chain, unreachable], codegen=codegen)

    result = prune_unreachable_total_return_suffixes_8616(root)

    assert root.statements == [chain]
    assert result.removed_statement_count == 1
    assert result.stats.raw_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_total_return_suffix_refuses_labeled_entry() -> None:
    codegen = _Codegen()
    chain = _total_return_chain(codegen)
    label = CLabel("reachable_target", codegen=codegen)
    root = CStatements([chain, label], codegen=codegen)

    result = prune_unreachable_total_return_suffixes_8616(root)

    assert root.statements == [chain, label]
    assert result.removed_statement_count == 0
    assert result.stats.failure_count == 1


def test_pure_identical_return_guard_collapses() -> None:
    codegen = _Codegen()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    guard = _single_return_guard(codegen, condition, 7)
    fallthrough = _return_body(codegen, 7).statements[0]
    root = CStatements([guard, fallthrough], codegen=codegen)

    result = collapse_pure_identical_return_guards_8616(root)

    assert root.statements == [fallthrough]
    assert result.changed
    assert result.stats.complete
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_pure_identical_if_else_returns_collapse() -> None:
    codegen = _Codegen()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    guard = CIfElse(
        [(condition, _return_body(codegen, 7))],
        else_node=_return_body(codegen, 7),
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([guard], codegen=codegen)

    result = collapse_pure_identical_return_guards_8616(root)

    assert len(root.statements) == 1
    assert isinstance(root.statements[0], CStatements)
    assert isinstance(root.statements[0].statements[0], CReturn)
    assert result.changed
    assert result.stats.complete
    assert result.stats.materialized_count == 1
    assert result.materializations[0].shape is (
        IdenticalReturnGuardShape8616.ELSE_RETURN
    )


def test_identical_return_guard_refuses_mismatched_returns() -> None:
    codegen = _Codegen()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    guard = _single_return_guard(codegen, condition, 7)
    fallthrough = _return_body(codegen, 8).statements[0]
    root = CStatements([guard, fallthrough], codegen=codegen)

    result = collapse_pure_identical_return_guards_8616(root)

    assert root.statements == [guard, fallthrough]
    assert not result.changed
    assert result.stats.complete
    assert result.stats.failure_count == 1
    assert result.refusals[0].reason is (
        IdenticalReturnGuardRefusalReason8616.RETURN_EXPRESSION_MISMATCH
    )


def test_identical_return_guard_refuses_call_condition() -> None:
    codegen = _Codegen()
    condition = CFunctionCall("has_side_effect", None, [], codegen=codegen)
    guard = _single_return_guard(codegen, condition, 7)
    fallthrough = _return_body(codegen, 7).statements[0]
    root = CStatements([guard, fallthrough], codegen=codegen)

    result = collapse_pure_identical_return_guards_8616(root)

    assert root.statements == [guard, fallthrough]
    assert not result.changed
    assert result.stats.complete
    assert result.stats.failure_count == 1
    assert result.refusals[0].reason is (
        IdenticalReturnGuardRefusalReason8616.CONDITION_PURITY_UNPROVEN
    )
