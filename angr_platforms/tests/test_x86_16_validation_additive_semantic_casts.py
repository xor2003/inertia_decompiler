"""Regression tests for semantic casts in additive validation fingerprints.

Layer: Validation tests.
Responsibility: ensure additive canonicalization retains typed value views while
ordinary codegen casts remain cosmetic.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CTypeCast,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeInt, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRValue, MemSpace
from angr_platforms.X86_16.lowering.semantic_cast import (
    CSemanticCast8616,
    is_identity_semantic_variable_cast_8616,
)
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint
from angr_platforms.X86_16.validation_branch_conditions import (
    BranchConditionIssueKind8616,
    validate_materialized_branch_conditions_8616,
)
from angr_platforms.X86_16.validation_condition_identity import project_identity_semantic_casts_8616


class _Codegen:
    """Minimal structured-codegen boundary needed by C expression nodes."""

    def __init__(self) -> None:
        """Create one DOS16 project and deterministic node-index source."""
        self._next_index = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._inertia_typed_conditions: tuple[ConditionIR, ...] = ()
        self._inertia_condition_precision_evidence_8616: tuple[object, ...] = ()

    def next_idx(self, _kind: str) -> int:
        """Return the next deterministic C-node index."""
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        """Return the next deterministic node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep test identifiers stable."""
        return name


def _stack(
    codegen: _Codegen,
    offset: int,
    name: str,
    *,
    signed: bool = False,
) -> CVariable:
    """Build one typed 16-bit BP-relative storage expression."""
    return CVariable(
        SimStackVariable(offset, 2, base="bp", name=name),
        variable_type=SimTypeShort(signed),
        codegen=codegen,
    )


def _constant(codegen: _Codegen, value: int) -> CConstant:
    """Build one unsigned 16-bit constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _semantic_view(
    codegen: _Codegen,
    expression: CVariable,
    *,
    signed: bool,
) -> CSemanticCast8616:
    """Build one same-width signedness view over unchanged stack bits."""
    return CSemanticCast8616(
        expression.variable_type,
        SimTypeShort(signed),
        expression,
        codegen=codegen,
    )


def test_additive_fingerprint_preserves_nested_semantic_cast() -> None:
    """A signed comparison view inside addition remains validation-visible."""
    codegen = _Codegen()
    local = _stack(codegen, -6, "local_6")
    expression = CBinaryOp(
        "Add",
        _semantic_view(codegen, local, signed=True),
        _constant(codegen, 1),
        codegen=codegen,
    )

    fingerprint = _expr_fingerprint(expression, codegen.project)

    assert fingerprint.startswith("Add(SemanticCast(")
    assert "signed=false->SimTypeShort:bits=16:signed=true" in fingerprint
    assert "stack_slot:SS:BP-0x6:size2" in fingerprint


def test_subtraction_fingerprint_preserves_both_unsigned_views() -> None:
    """Both operands of a subtraction retain their explicit unsigned domain."""
    codegen = _Codegen()
    left = _stack(codegen, 6, "arg_6", signed=True)
    right = _stack(codegen, 4, "arg_4", signed=True)
    expression = CBinaryOp(
        "Sub",
        _semantic_view(codegen, left, signed=False),
        _semantic_view(codegen, right, signed=False),
        codegen=codegen,
    )

    fingerprint = _expr_fingerprint(expression, codegen.project)

    operand_count = 2
    assert fingerprint.count("SemanticCast(") == operand_count
    assert fingerprint.count("signed=true->SimTypeShort:bits=16:signed=false") == operand_count
    assert "stack_slot:SS:BP+0x6:size2" in fingerprint
    assert "stack_slot:SS:BP+0x4:size2" in fingerprint


def test_additive_fingerprint_strips_only_cosmetic_casts() -> None:
    """Ordinary casts stay cosmetic while a wrong semantic view stays distinct."""
    codegen = _Codegen()
    local = _stack(codegen, -6, "local_6")
    plain = CBinaryOp(
        "Add",
        local,
        _constant(codegen, 1),
        codegen=codegen,
    )
    cosmetic = CBinaryOp(
        "Add",
        CTypeCast(
            SimTypeShort(False),
            SimTypeShort(True),
            local,
            codegen=codegen,
        ),
        _constant(codegen, 1),
        codegen=codegen,
    )
    semantic = CBinaryOp(
        "Add",
        _semantic_view(codegen, local, signed=True),
        _constant(codegen, 1),
        codegen=codegen,
    )

    plain_fingerprint = _expr_fingerprint(plain, codegen.project)

    assert _expr_fingerprint(cosmetic, codegen.project) == plain_fingerprint
    assert _expr_fingerprint(semantic, codegen.project) != plain_fingerprint


def _percolate_fact() -> ConditionIR:
    """Build a generic signed additive comparison fact."""
    local = IRValue(MemSpace.SS, name="bp", offset=-6, size=2)
    one = IRValue(MemSpace.CONST, const=1, size=2)
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    return ConditionIR(
        "sle",
        IRBinaryValue("add", local, one, size=2),
        argument,
        src_insn=0x4015,
        block_addr=0x4010,
    )


def _branch_root(codegen: _Codegen, condition: CBinaryOp) -> CStatements:
    """Wrap one Structuring-owned condition in a minimal final AST."""
    condition.tags = {
        "ins_addr": 0x4015,
        "inertia_structuring_condition_cfg_materialized_8616": True,
    }
    return CStatements(
        [
            CIfElse(
                [(condition, CStatements([], codegen=codegen))],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )


def test_branch_validation_requires_semantic_cast_on_exact_additive_operand() -> None:
    """A cast on the compared argument cannot cover a missing additive cast."""
    codegen = _Codegen()
    fact = _percolate_fact()
    codegen._inertia_typed_conditions = (fact,)
    local = _stack(codegen, -6, "local_6")
    argument = _stack(codegen, 4, "arg_4")
    expected = (
        "CmpLE(Add(SemanticCast(SimTypeShort:bits=16:signed=false->"
        "SimTypeShort:bits=16:signed=true,stack_slot:SS:BP-0x6:size2),"
        "const:1),stack_slot:SS:BP+0x4:size2)"
    )
    exact = CBinaryOp(
        "CmpLE",
        CBinaryOp(
            "Add",
            _semantic_view(codegen, local, signed=True),
            _constant(codegen, 1),
            codegen=codegen,
        ),
        argument,
        codegen=codegen,
    )
    exact_report = validate_materialized_branch_conditions_8616(
        codegen,
        _branch_root(codegen, exact),
        condition_fingerprint=lambda expression: _expr_fingerprint(
            expression, codegen.project
        ),
        condition_ir_fingerprint=lambda _condition: expected,
    )

    misplaced = CBinaryOp(
        "CmpLE",
        CBinaryOp("Add", local, _constant(codegen, 1), codegen=codegen),
        _semantic_view(codegen, argument, signed=True),
        codegen=codegen,
    )
    misplaced_report = validate_materialized_branch_conditions_8616(
        codegen,
        _branch_root(codegen, misplaced),
        condition_fingerprint=lambda expression: _expr_fingerprint(
            expression, codegen.project
        ),
        condition_ir_fingerprint=lambda _condition: expected,
    )

    assert exact_report.passed
    assert not misplaced_report.passed
    assert (
        misplaced_report.issues[0].kind
        is BranchConditionIssueKind8616.PREDICATE_MISMATCH
    )


@pytest.mark.parametrize("current_signed", [False, True])
@pytest.mark.parametrize("source_is_byte", [False, True])
def test_additive_cast_identity_uses_current_operand_type(
    current_signed: bool, source_is_byte: bool,
) -> None:
    """Only a proven same-width identity may discard stale cast source metadata."""
    codegen = _Codegen()
    local = _stack(codegen, -8, "local_8", signed=current_signed)
    plain = CBinaryOp("Sub", local, _constant(codegen, 1), codegen=codegen)
    converted = CBinaryOp(
        "Sub",
        CSemanticCast8616(
            SimTypeChar(False) if source_is_byte else SimTypeShort(False),
            SimTypeShort(True),
            local,
            codegen=codegen,
        ),
        _constant(codegen, 1),
        codegen=codegen,
    )

    identical = (
        _expr_fingerprint(project_identity_semantic_casts_8616(converted), codegen.project)
        == _expr_fingerprint(plain, codegen.project)
    )

    assert identical is (current_signed and not source_is_byte)
    assert isinstance(converted.lhs, CSemanticCast8616)
    assert "SemanticCast(" in _expr_fingerprint(converted, codegen.project)


@pytest.mark.parametrize(
    "current_type", [None, SimTypeBottom(), SimTypePointer(SimTypeShort()), SimTypeInt(True)],
)
def test_semantic_cast_identity_refuses_unknown_or_pointer_operand(current_type) -> None:
    """Missing, non-integer and unbound-width type evidence cannot prove identity."""
    codegen = _Codegen()
    local = _stack(codegen, -8, "local_8", signed=True)
    local.variable_type = current_type
    expression = CSemanticCast8616(
        SimTypeShort(False), SimTypeShort(True), local, codegen=codegen,
    )

    assert not is_identity_semantic_variable_cast_8616(expression)


@pytest.mark.parametrize("conflicting", [False, True])
def test_semantic_cast_identity_requires_unique_exact_declaration(conflicting: bool) -> None:
    """A stale expression view follows its declaration, but conflicting types refuse."""
    codegen = _Codegen()
    local = _stack(codegen, -8, "local_8")
    entries = {(local, SimTypeShort(True).with_arch(codegen.project.arch))}
    if conflicting:
        entries.add((local, SimTypeShort(False).with_arch(codegen.project.arch)))
    codegen.cfunc = SimpleNamespace(arg_list=[], unified_local_vars={local.variable: entries})
    expression = _semantic_view(codegen, local, signed=True)

    assert is_identity_semantic_variable_cast_8616(expression) is not conflicting
    assert local.variable_type.signed is False

    other = _stack(codegen, -10, "local_8")
    assert not is_identity_semantic_variable_cast_8616(_semantic_view(codegen, other, signed=True))


@pytest.mark.parametrize("current_signed", [False, True])
def test_identity_projection_visits_arithmetic_inside_required_cast(current_signed: bool) -> None:
    """An outer truncation survives while nested declaration identities project."""
    codegen = _Codegen()
    local = _stack(codegen, -8, "local_8", signed=current_signed)
    inner = _semantic_view(codegen, local, signed=True)
    arithmetic = CBinaryOp("Sub", inner, _constant(codegen, 1), codegen=codegen)
    outer = CSemanticCast8616(
        SimTypeShort(True), SimTypeChar(True), arithmetic, codegen=codegen,
    )
    before = _expr_fingerprint(outer, codegen.project)
    projected = project_identity_semantic_casts_8616(outer, required_signedness=True)

    assert isinstance(projected, CSemanticCast8616)
    assert projected.src_type == outer.src_type and projected.dst_type == outer.dst_type
    assert (projected.expr.lhs is local) is current_signed
    assert (projected is outer) is not current_signed
    assert outer.expr is arithmetic and arithmetic.lhs is inner
    assert _expr_fingerprint(outer, codegen.project) == before
