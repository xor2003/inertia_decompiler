"""Regression tests for exact Boolean ITE normalization in structuring."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
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
