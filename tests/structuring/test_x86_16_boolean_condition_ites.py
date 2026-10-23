"""Regression tests for exact Boolean ITE normalization in structuring."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CUnaryOp,
)
from angr.rustylib.ailment import Tags
from angr.sim_type import SimTypeShort
from archinfo import ArchX86

from inertia.structuring.boolean_condition_ites import (
    normalize_boolean_condition_ites_8616,
)


class _Codegen:
    """Minimal structured-codegen boundary for C AST construction."""

    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.cfunc: object | None = None
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        """Return a stable node index."""
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        """Return a stable structured-node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return the requested stable identifier."""
        return name


def _constant(codegen: _Codegen, value: int) -> CConstant:
    """Build one word-sized C constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _branch_with_ite(
    true_value: int,
    false_value: int,
) -> tuple[_Codegen, CIfElse, CBinaryOp, CITE]:
    """Build one branch controlled by a tagged comparison-result ITE."""
    codegen = _Codegen()
    comparison = CBinaryOp(
        "CmpLE",
        _constant(codegen, 1),
        _constant(codegen, 2),
        codegen=codegen,
    )
    comparison.tags = Tags({"vex_stmt_idx": 7})
    encoded = CITE(
        comparison,
        _constant(codegen, true_value),
        _constant(codegen, false_value),
        codegen=codegen,
    )
    encoded.tags = Tags({"ins_addr": 0x100C})
    branch = CIfElse(
        [(encoded, CStatements([], codegen=codegen))],
        else_node=None,
        codegen=codegen,
    )
    codegen.cfunc = CStatements([branch], codegen=codegen)
    return codegen, branch, comparison, encoded


def test_zero_one_boolean_ite_inverts_comparison_and_preserves_tags() -> None:
    """A false/true numeric encoding becomes the exact inverse predicate."""
    codegen, branch, _comparison, _encoded = _branch_with_ite(0, 1)

    stats = normalize_boolean_condition_ites_8616(codegen)

    condition = branch.condition_and_nodes[0][0]
    assert isinstance(condition, CBinaryOp)
    assert condition.op == "CmpGT"
    assert condition.tags["ins_addr"] == 0x100C
    assert condition.tags["vex_stmt_idx"] == 7
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_one_zero_boolean_ite_keeps_comparison_polarity() -> None:
    """A true/false numeric encoding becomes its direct predicate."""
    codegen, branch, comparison, _encoded = _branch_with_ite(1, 0)

    stats = normalize_boolean_condition_ites_8616(codegen)

    assert branch.condition_and_nodes[0][0] is comparison
    assert stats.materialized_count == 1


def _wrap_condition_in_logical_nots(
    codegen: _Codegen,
    branch: CIfElse,
    not_count: int,
) -> CUnaryOp:
    """Wrap the branch condition in ``not_count`` logical Not operators."""
    condition, body = branch.condition_and_nodes[0]
    for _ in range(not_count):
        condition = CUnaryOp("Not", condition, codegen=codegen)
        condition.tags = Tags({"ins_addr": 0x100C, "wrapper_marker": True})
    branch.condition_and_nodes = [(condition, body)]
    return condition


def test_logical_not_wrapped_boolean_ite_recovers_direct_guard() -> None:
    """Not(CITE(P, 0, 1)) normalizes to the identical inner guard P."""
    codegen, branch, comparison, _encoded = _branch_with_ite(0, 1)
    wrapper = _wrap_condition_in_logical_nots(codegen, branch, 1)

    stats = normalize_boolean_condition_ites_8616(codegen)

    condition = branch.condition_and_nodes[0][0]
    assert condition is comparison
    assert condition is not wrapper
    assert condition.tags["ins_addr"] == 0x100C
    assert condition.tags["vex_stmt_idx"] == 7
    assert condition.tags["wrapper_marker"] is True
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_logical_not_wrapped_one_zero_ite_inverts_guard() -> None:
    """Not(CITE(P, 1, 0)) normalizes to the exact inverse predicate."""
    codegen, branch, _comparison, _encoded = _branch_with_ite(1, 0)
    _wrap_condition_in_logical_nots(codegen, branch, 1)

    stats = normalize_boolean_condition_ites_8616(codegen)

    condition = branch.condition_and_nodes[0][0]
    assert isinstance(condition, CBinaryOp)
    assert condition.op == "CmpGT"
    assert stats.materialized_count == 1


def test_outer_condition_origin_wins_over_inner_encoding_tags() -> None:
    """The outer control origin survives conflicting nested encoding locations."""
    codegen, branch, comparison, encoded = _branch_with_ite(1, 0)
    inner = CUnaryOp("Not", encoded, codegen=codegen)
    inner.tags = Tags({"ins_addr": 0x100D, "inner_marker": True})
    outer = CUnaryOp("Not", inner, codegen=codegen)
    outer.tags = Tags({"ins_addr": 0x100E, "outer_marker": True})
    branch.condition_and_nodes = [(outer, branch.condition_and_nodes[0][1])]

    stats = normalize_boolean_condition_ites_8616(codegen)

    result = branch.condition_and_nodes[0][0]
    assert result is comparison
    assert result.tags["ins_addr"] == 0x100E
    assert result.tags["vex_stmt_idx"] == 7
    assert result.tags["inner_marker"] is True
    assert result.tags["outer_marker"] is True
    assert stats.materialized_count == 1


def test_double_logical_not_boolean_ite_inverts_guard() -> None:
    """Not(Not(CITE(P, 0, 1))) keeps odd parity and inverts the guard."""
    codegen, branch, _comparison, _encoded = _branch_with_ite(0, 1)
    _wrap_condition_in_logical_nots(codegen, branch, 2)

    stats = normalize_boolean_condition_ites_8616(codegen)

    condition = branch.condition_and_nodes[0][0]
    assert isinstance(condition, CBinaryOp)
    assert condition.op == "CmpGT"
    assert stats.materialized_count == 1


def test_logical_not_wrapped_non_boolean_ite_refused() -> None:
    """Not(CITE(P, 0, 2)) stays untouched; arbitrary constants are not Boolean."""
    codegen, branch, _comparison, _encoded = _branch_with_ite(0, 2)
    wrapper = _wrap_condition_in_logical_nots(codegen, branch, 1)

    stats = normalize_boolean_condition_ites_8616(codegen)

    assert branch.condition_and_nodes[0][0] is wrapper
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_logical_not_wrapped_non_constant_ite_arm_refused() -> None:
    """Not(CITE(P, 1, Q)) preserves Q; merged guards must never collapse."""
    codegen, branch, comparison, _encoded = _branch_with_ite(1, 0)
    other = CBinaryOp("CmpNE", _constant(codegen, 3), _constant(codegen, 4), codegen=codegen)
    compound = CITE(comparison, _constant(codegen, 1), other, codegen=codegen)
    wrapper = CUnaryOp("Not", compound, codegen=codegen)
    body = branch.condition_and_nodes[0][1]
    branch.condition_and_nodes = [(wrapper, body)]

    stats = normalize_boolean_condition_ites_8616(codegen)

    condition = branch.condition_and_nodes[0][0]
    assert condition is wrapper
    assert isinstance(condition, CUnaryOp) and condition.op == "Not"
    inner = condition.operand
    assert isinstance(inner, CITE)
    assert inner.iffalse is other
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 0
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_bitwise_neg_wrapper_around_ite_untouched() -> None:
    """BitwiseNeg is not a logical Not; its ITE operand is never normalized."""
    codegen, branch, _comparison, encoded = _branch_with_ite(0, 1)
    wrapper = CUnaryOp("BitwiseNeg", encoded, codegen=codegen)
    body = branch.condition_and_nodes[0][1]
    branch.condition_and_nodes = [(wrapper, body)]

    stats = normalize_boolean_condition_ites_8616(codegen)

    assert branch.condition_and_nodes[0][0] is wrapper
    assert stats.raw_fact_count == 0
    assert stats.materialized_count == 0


def test_logical_not_without_ite_untouched() -> None:
    """A logical Not over a plain comparison is not an ITE candidate."""
    codegen, branch, comparison, _encoded = _branch_with_ite(0, 1)
    wrapper = CUnaryOp("Not", comparison, codegen=codegen)
    body = branch.condition_and_nodes[0][1]
    branch.condition_and_nodes = [(wrapper, body)]

    stats = normalize_boolean_condition_ites_8616(codegen)

    assert branch.condition_and_nodes[0][0] is wrapper
    assert stats.raw_fact_count == 0


def test_logical_not_chain_beyond_bound_refused() -> None:
    """An unbounded wrapper chain is not normalized; the bound keeps it honest."""
    codegen, branch, _comparison, _encoded = _branch_with_ite(0, 1)
    wrapper = _wrap_condition_in_logical_nots(codegen, branch, 5)

    stats = normalize_boolean_condition_ites_8616(codegen)

    assert branch.condition_and_nodes[0][0] is wrapper
    assert stats.raw_fact_count == 0
    assert stats.materialized_count == 0


def test_non_boolean_ite_is_refused_without_ast_mutation() -> None:
    """Numeric ITE outcomes outside zero/one remain honest C expressions."""
    codegen, branch, _comparison, encoded = _branch_with_ite(0, 2)

    stats = normalize_boolean_condition_ites_8616(codegen)

    assert branch.condition_and_nodes[0][0] is encoded
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
