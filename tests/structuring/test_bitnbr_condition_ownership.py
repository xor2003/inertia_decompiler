"""Shared-return tags cannot replace proof of structured guard ownership.

These native-node controls cover the shared tails observed at BITNBR JCCs
1dcf/1e08 and the actual single-branch materialization consumer. They do not
claim binary acceptance or prove the unresolved original branch conditions.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CFunctionCall,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.rustylib.ailment import Tags
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from archinfo import ArchX86

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.structuring import condition_materialization as owner


class _Codegen:
    """Minimal native C-node frontend boundary."""

    def __init__(self) -> None:
        self._index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._index
        self._index += 1
        return index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _condition(block: int = 0x1000, taken: int = 0x1030, fallthrough: int = 0x1004) -> ConditionIR:
    return ConditionIR(
        op="ne", lhs=IRValue(MemSpace.REG, "ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=5, size=2), width_bits=16,
        src_insn=block + 2, block_addr=block,
        taken_target=taken, fallthrough_target=fallthrough,
    )


def _constant(codegen: _Codegen, value: int) -> CConstant:
    return CConstant(value, SimTypeShort(False).with_arch(codegen.project.arch), codegen=codegen)


_SRC_INSN = 0x1002


def _comparison(
    codegen: _Codegen,
    offset: int,
    value: int,
    op: str = "CmpNE",
    *,
    size: int = 2,
    ident: str | None = "",
    ins_addr: int | None = None,
) -> CBinaryOp:
    register = CVariable(
        SimRegisterVariable(
            offset,
            size,
            ident=ident if ident != "" else f"ssa_{offset}",
            region=0x1000,
        ),
        variable_type=(SimTypeShort(False) if size == 2 else SimTypeLong(False)).with_arch(
            codegen.project.arch
        ),
        codegen=codegen,
    )
    comparison = CBinaryOp(op, register, _constant(codegen, value), codegen=codegen)
    if ins_addr is not None:
        comparison.tags = Tags({"ins_addr": ins_addr})
    return comparison


def _boolean_guard(codegen: _Codegen, predicate: CExpression) -> CUnaryOp:
    """Spell the observed ``Not(CITE(P,0,1))`` Boolean guard surface."""
    return CUnaryOp(
        "Not",
        CITE(predicate, _constant(codegen, 0), _constant(codegen, 1), codegen=codegen),
        codegen=codegen,
    )


def _body(codegen: _Codegen, addr: int = 0x1030) -> CStatements:
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local"),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    statement = CAssignment(local, _constant(codegen, 7), codegen=codegen)
    statement.tags = Tags({"ins_addr": addr, "vex_block_addr": addr})
    return CStatements([statement], codegen=codegen)


def _materialize(
    codegen: _Codegen,
    root: CExpression | None,
    guard: CExpression,
    *,
    shared: bool,
    body_addr: int = 0x1030,
    successors: dict[int, tuple[int, ...]] | None = None,
) -> CExpression | None:
    condition = _condition()
    if successors is None:
        successors = {0x1000: (0x1030, 0x1004), 0x1004: (0x1030, 0x1040) if shared else (0x1040,)}
    # The root-expression frontend faithfully returns native P. Only external
    # replay logging is suppressed; orientation, chain builder and fallback run.
    with (
        patch.object(owner, "materialize_condition_ir_expression_8616", return_value=root),
        patch.object(owner, "record_condition_replay_fact_8616"),
    ):
        return owner._materialize_cfg_single_branch_expr_8616(
            codegen.project, codegen, condition, guard, _body(codegen, body_addr),
            {0x1000: condition}, successors,
        )


@pytest.mark.parametrize("block,taken,fallthrough", [(0x1DC6, 0x1DE3, 0x1DD1), (0x1DFF, 0x1E20, 0x1E0A)])
def test_bitnbr_shared_direct_return_target_is_ambiguous(block: int, taken: int, fallthrough: int) -> None:
    condition = _condition(block, taken, fallthrough)
    assert owner._single_branch_orientation_8616(condition, taken, {fallthrough: (taken, 0x2000)}) is None


@pytest.mark.parametrize("corruption", ["reversed", "changed", "compound"])
def test_consumer_refuses_shared_body_without_guard_equivalence(corruption: str) -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5)
    if corruption == "reversed":
        guard = CITE(root, _constant(codegen, 0), _constant(codegen, 1), codegen=codegen)
    elif corruption == "changed":
        guard = _comparison(codegen, 8, 6)
    else:
        guard = CITE(root, _constant(codegen, 1), _comparison(codegen, 20, 0), codegen=codegen)
        # ax=5,bx=1: original CITE(P,1,Q)=true, replacement P=false.
        assert (1 if 5 != 5 else int(1 != 0)) == 1
        assert int(5 != 5) == 0
    assert _materialize(codegen, root, guard, shared=True) is None


def test_consumer_materializes_unique_body_with_matching_root_guard() -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5)
    assert _materialize(codegen, root, root, shared=False) is root


@pytest.mark.parametrize("body,expected", [(0x1030, True), (0x1004, False), (0x9999, None)])
def test_distinct_edge_or_unreachable_body_orientation(body: int, expected: bool | None) -> None:
    assert owner._single_branch_orientation_8616(_condition(), body, {}) is expected


def test_degenerate_same_target_edges_refuse() -> None:
    assert owner._single_branch_orientation_8616(_condition(taken=0x1030, fallthrough=0x1030), 0x1030, {}) is None


def test_one_hop_shared_target_without_edge_identity_refuses() -> None:
    assert owner._single_branch_orientation_8616(_condition(), 0x2000, {0x1030: (0x2000,), 0x1004: (0x2000,)}) is None


def test_consumer_binds_boolean_guard_with_exact_typed_identity() -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
    guard = _boolean_guard(codegen, _comparison(codegen, 8, 5, ins_addr=_SRC_INSN))
    assert _materialize(codegen, root, guard, shared=True) is root


def test_consumer_binds_boolean_ite_guard_on_corroborated_fallthrough() -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
    guard = CITE(
        _comparison(codegen, 8, 5, ins_addr=_SRC_INSN),
        _constant(codegen, 0), _constant(codegen, 1), codegen=codegen,
    )
    bound = _materialize(
        codegen, root, guard,
        shared=False,
        body_addr=0x1004,
        successors={0x1000: (0x1030, 0x1004), 0x1030: (0x1004, 0x1040)},
    )
    assert isinstance(bound, CBinaryOp) and bound.op == "CmpEQ"


@pytest.mark.parametrize(
    "corruption",
    ["immediate", "ident", "width", "no_ident", "tag", "cast", "double_negated", "compound_not"],
)
def test_consumer_refuses_guard_identity_corruptions(corruption: str) -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
    if corruption == "immediate":
        predicate = _comparison(codegen, 8, 6, ins_addr=_SRC_INSN)
    elif corruption == "ident":
        predicate = _comparison(codegen, 8, 5, ident="ssa_9", ins_addr=_SRC_INSN)
    elif corruption == "width":
        predicate = _comparison(codegen, 8, 5, size=4, ins_addr=_SRC_INSN)
    elif corruption == "no_ident":
        predicate = _comparison(codegen, 8, 5, ident=None, ins_addr=_SRC_INSN)
    elif corruption == "tag":
        predicate = _comparison(codegen, 8, 5, ins_addr=0x9999)
    elif corruption == "cast":
        predicate = CBinaryOp(
            "CmpNE",
            CTypeCast(
                SimTypeShort(True), SimTypeInt(True),
                _comparison(codegen, 8, 5).lhs, codegen=codegen,
            ),
            _constant(codegen, 5), codegen=codegen,
        )
        predicate.tags = Tags({"ins_addr": _SRC_INSN})
    elif corruption == "double_negated":
        predicate = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
        guard = CUnaryOp("Not", _boolean_guard(codegen, predicate), codegen=codegen)
        assert _materialize(codegen, root, guard, shared=True) is None
        return
    else:
        predicate = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
        guard = CUnaryOp(
            "Not",
            CITE(
                predicate, _constant(codegen, 1),
                _comparison(codegen, 20, 0, ins_addr=_SRC_INSN), codegen=codegen,
            ),
            codegen=codegen,
        )
        assert _materialize(codegen, root, guard, shared=True) is None
        return
    assert _materialize(codegen, root, _boolean_guard(codegen, predicate), shared=True) is None


def _guard_orientation(codegen: _Codegen, root: CExpression | None, guard: CExpression, body_addr: int) -> bool | None:
    """Evaluate the shared-guard certificate with the production edge map."""
    condition = _condition()
    successors = {0x1000: (0x1030, 0x1004), 0x1004: (0x1030, 0x1040)}
    with patch.object(
        owner, "materialize_condition_ir_expression_8616", return_value=root
    ):
        return owner._shared_guard_identity_orientation_8616(
            codegen.project, codegen, condition, guard, _body(codegen, body_addr),
            {0x1000: condition}, successors,
        )


def test_certificate_withholds_orientation_on_contradictory_body_edge() -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
    guard = _boolean_guard(codegen, _comparison(codegen, 8, 5, ins_addr=_SRC_INSN))
    assert _guard_orientation(codegen, root, guard, 0x1004) is None


def test_certificate_withholds_orientation_on_unrelated_body_provenance() -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
    guard = _boolean_guard(codegen, _comparison(codegen, 8, 5, ins_addr=_SRC_INSN))
    assert _guard_orientation(codegen, root, guard, 0x9999) is None


def test_certificate_withholds_orientation_on_fallthrough_side_effect() -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
    guard = _boolean_guard(codegen, _comparison(codegen, 8, 5, ins_addr=_SRC_INSN))
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local"),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    effect = CAssignment(local, _constant(codegen, 7), codegen=codegen)
    effect.tags = Tags({"ins_addr": 0x1004, "vex_block_addr": 0x1004})
    tail = CAssignment(local, _constant(codegen, 9), codegen=codegen)
    tail.tags = Tags({"ins_addr": 0x1030, "vex_block_addr": 0x1030})
    body = CStatements([effect, tail], codegen=codegen)
    condition = _condition()
    successors = {0x1000: (0x1030, 0x1004), 0x1004: (0x1030, 0x1040)}
    with patch.object(
        owner, "materialize_condition_ir_expression_8616", return_value=root
    ):
        assert owner._shared_guard_identity_orientation_8616(
            codegen.project, codegen, condition, guard, body,
            {0x1000: condition}, successors,
        ) is None


def test_consumer_refuses_boolean_guard_without_root_premise() -> None:
    codegen = _Codegen()
    guard = _boolean_guard(codegen, _comparison(codegen, 8, 5, ins_addr=_SRC_INSN))
    assert _materialize(codegen, None, guard, shared=True) is None


def test_consumer_preserves_multi_statement_shared_body_on_bind() -> None:
    codegen = _Codegen()
    root = _comparison(codegen, 8, 5, ins_addr=_SRC_INSN)
    guard = _boolean_guard(codegen, _comparison(codegen, 8, 5, ins_addr=_SRC_INSN))
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local"),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    first = CAssignment(local, _constant(codegen, 7), codegen=codegen)
    first.tags = Tags({"ins_addr": 0x1030, "vex_block_addr": 0x1030})
    second = CAssignment(local, _constant(codegen, 9), codegen=codegen)
    second.tags = Tags({"ins_addr": 0x1031, "vex_block_addr": 0x1030})
    body = CStatements([first, second], codegen=codegen)
    condition = _condition()
    successors = {0x1000: (0x1030, 0x1004), 0x1004: (0x1030, 0x1040)}
    with (
        patch.object(owner, "materialize_condition_ir_expression_8616", return_value=root),
        patch.object(owner, "record_condition_replay_fact_8616"),
    ):
        assert owner._materialize_cfg_single_branch_expr_8616(
            codegen.project, codegen, condition, guard, body,
            {0x1000: condition}, successors,
        ) is root
    assert body.statements == [first, second]


@pytest.mark.parametrize("right_type", [SimTypeChar(False), SimTypeShort(True)])
def test_guard_constant_identity_preserves_width_and_signedness(right_type) -> None:
    """The same literal cannot authenticate a different machine value type."""
    codegen = _Codegen()
    left = CConstant(255, SimTypeShort(False).with_arch(codegen.project.arch), codegen=codegen)
    right = CConstant(255, right_type.with_arch(codegen.project.arch), codegen=codegen)
    assert not owner._strict_guard_expression_identity_8616(left, right)


def test_guard_type_identity_checks_architecture_dependent_width() -> None:
    """C int is sixteen bits on the DOS architecture and thirty-two on x86."""
    narrow = SimTypeInt(False).with_arch(Arch86_16())
    wide = SimTypeInt(False).with_arch(ArchX86())
    assert narrow.size == 16 and wide.size == 32
    assert not owner._strict_sim_type_identity_8616(narrow, wide)


def test_guard_type_identity_refuses_unresolved_width() -> None:
    """An absent architecture is not evidence that two C widths agree."""
    assert not owner._strict_sim_type_identity_8616(SimTypeInt(False), SimTypeInt(False))


def test_guard_identity_does_not_merge_distinct_call_occurrences() -> None:
    """Repeated calls can observe different state even with identical arguments."""
    codegen = _Codegen()
    first = CFunctionCall("next_value", None, [], codegen=codegen)
    second = CFunctionCall("next_value", None, [], codegen=codegen)
    assert not owner._strict_guard_expression_identity_8616(first, second)


def test_guard_identity_does_not_merge_stack_definitions() -> None:
    """A stack coordinate can hold different values at different definitions."""
    codegen = _Codegen()
    value_type = SimTypeShort(False).with_arch(codegen.project.arch)
    first = CVariable(
        SimStackVariable(-2, 2, base="bp", ident="first"),
        variable_type=value_type, codegen=codegen,
    )
    second = CVariable(
        SimStackVariable(-2, 2, base="bp", ident="second"),
        variable_type=value_type, codegen=codegen,
    )
    assert not owner._strict_guard_expression_identity_8616(first, second)
