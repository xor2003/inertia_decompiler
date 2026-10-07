"""Regressions for provenance-backed composite branch validation."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from archinfo import ArchX86

from inertia.structuring.condition_chain_provenance import (
    bind_condition_chain_provenance_8616,
)
from inertia.validation.validation_branch_conditions import (
    BranchConditionIssueKind8616,
    validate_materialized_branch_conditions_8616,
)
from inertia.validation.validation_condition_precision import (
    ConditionPrecisionEvidence8616,
)


class _Codegen:
    """Minimal codegen boundary for branch-condition validation."""

    def __init__(self, conditions: tuple[ConditionIR, ...]) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False
        self._inertia_typed_conditions = conditions
        self._inertia_condition_precision_evidence_8616 = ()

    def next_idx(self, _kind: str) -> int:
        """Return one deterministic C-AST node index."""
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        """Return one deterministic C-AST node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep test identifiers stable."""
        return name


def _fact(jcc_addr: int, block_addr: int) -> ConditionIR:
    """Build one exact typed equality fact."""
    return ConditionIR(
        "eq",
        IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=jcc_addr,
        block_addr=block_addr,
    )


def _leaf(codegen: _Codegen, jcc_addr: int) -> CBinaryOp:
    """Build one terminal comparison with exact Structuring identity."""
    return CBinaryOp(
        "CmpEQ",
        CConstant(jcc_addr, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": jcc_addr},
    )


def _validated_root(
    codegen: _Codegen,
    facts: tuple[ConditionIR, ...],
    *,
    keep_third_leaf: bool,
) -> tuple[CStatements, CBinaryOp]:
    """Build one composite condition with complete or deliberately stale leaves."""
    leaves = tuple(_leaf(codegen, fact.src_insn) for fact in facts)
    rhs = (
        CBinaryOp("LogicalOr", leaves[1], leaves[2], codegen=codegen)
        if keep_third_leaf
        else leaves[1]
    )
    condition = CBinaryOp(
        "LogicalOr",
        leaves[0],
        rhs,
        codegen=codegen,
        tags={
            "ins_addr": facts[0].src_insn,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )
    assert bind_condition_chain_provenance_8616(condition, facts) is not None
    root = CStatements(
        [
            CIfElse(
                [(condition, CStatements([], codegen=codegen))],
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    return root, condition


def _precision_evidence(actual: str, root_jcc: int) -> tuple[ConditionPrecisionEvidence8616, ...]:
    """Return competing final/intermediate fingerprints for one exact JCC."""
    return (
        ConditionPrecisionEvidence8616("before", actual, root_jcc),
        ConditionPrecisionEvidence8616("before", "exact-stack-composite", root_jcc),
    )


def test_complete_composite_accepts_non_singleton_precision_evidence() -> None:
    """Accept all and only the JCC leaves Structuring recorded."""
    facts = (_fact(0x4015, 0x4010), _fact(0x4025, 0x4020), _fact(0x4035, 0x4030))
    codegen = _Codegen(facts)
    root, condition = _validated_root(codegen, facts, keep_third_leaf=True)
    actual = "LogicalOr(final-field-a,LogicalOr(final-field-b,final-field-c))"
    codegen._inertia_condition_precision_evidence_8616 = _precision_evidence(
        actual,
        facts[0].src_insn,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=lambda candidate: actual if candidate is condition else "leaf",
        condition_ir_fingerprint=lambda _fact: "CmpNE(exact-root,const:0)",
    )

    assert report.passed
    assert report.materialized_count == 1


def test_composite_refuses_precision_evidence_after_leaf_loss() -> None:
    """Reject a final condition that lost one recorded short-circuit JCC."""
    facts = (_fact(0x4015, 0x4010), _fact(0x4025, 0x4020), _fact(0x4035, 0x4030))
    codegen = _Codegen(facts)
    root, condition = _validated_root(codegen, facts, keep_third_leaf=False)
    actual = "LogicalOr(final-field-a,final-field-b)"
    codegen._inertia_condition_precision_evidence_8616 = _precision_evidence(
        actual,
        facts[0].src_insn,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=lambda candidate: actual if candidate is condition else "leaf",
        condition_ir_fingerprint=lambda _fact: "CmpNE(exact-root,const:0)",
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH
