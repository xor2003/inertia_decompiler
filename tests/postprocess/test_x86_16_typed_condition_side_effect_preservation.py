from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CMultiStatementExpression,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

import inertia.postprocess.decompiler_postprocess_jcc as decompiler_postprocess_jcc
import inertia.structuring.condition_materialization as condition_materialization
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.c_ast_utils import _same_c_expression_8616
from inertia.postprocess.decompiler_postprocess_typed_conditions import (
    _apply_typed_conditions_to_codegen_8616,
)
from inertia.structuring.condition_call_effects import (
    ConditionCallEffectKind8616,
    classify_condition_call_effects_8616,
)
from inertia.structuring.condition_comparison_polarity import (
    ConditionComparisonPolarity8616,
    condition_comparison_polarity_8616,
)
from inertia.widening.segmented_load_identity import segmented_load_identity_8616


class _Graph:
    def __init__(self, edges: tuple[tuple[int, int], ...]) -> None:
        self._successors: dict[int, list[int]] = {}
        for source, target in edges:
            self._successors.setdefault(source, []).append(target)
            self._successors.setdefault(target, [])
        self.nodes = tuple(self._successors)

    def successors(self, node: int) -> tuple[int, ...]:
        return tuple(self._successors[node])


def _codegen() -> SimpleNamespace:
    project = SimpleNamespace(arch=Arch86_16())
    node_ids = iter(range(1, 100))
    return SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: next(node_ids),
        next_node_idx=lambda: next(node_ids),
        next_ident=lambda name: name,
    )


def _semantic_call(codegen: object, *, callsite: int = 0x101D4) -> CFunctionCall:
    return CFunctionCall(
        "sub_10010",
        SimpleNamespace(
            addr=0x10010,
            name="sub_10010",
            prototype=SimTypeFunction([], SimTypeShort(False)),
            prototype_libname=None,
        ),
        [],
        codegen=codegen,
        tags={"ins_addr": callsite},
    )


def test_inverted_typed_carrier_retains_condition_origin(monkeypatch):
    """The negative wrapper must keep the typed owner's exact JCC coordinates."""
    codegen = _codegen()
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    tags = {"ins_addr": 0x101DA, "vex_block_addr": 0x101D7}
    condition = CITE(one, zero, one, codegen=codegen, tags=tags)
    branch = CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root, body=root)
    codegen._inertia_typed_conditions = (
        ConditionIR("ne", IRValue(MemSpace.REG, name="ax", offset=8, size=2),
                    IRValue(MemSpace.CONST, const=0, size=2), src_insn=0x101DA, block_addr=0x101D7),
    )
    predicate = CBinaryOp("CmpNE", one, zero, codegen=codegen, tags=tags)
    monkeypatch.setattr(condition_materialization._legacy_typed_conditions,
                        "_build_c_condition_expr", lambda *_args: predicate)
    assert _apply_typed_conditions_to_codegen_8616(codegen.project, codegen)
    replacement = branch.condition_and_nodes[0][0]
    assert isinstance(replacement, CUnaryOp)
    assert replacement.op == "Not"
    assert replacement.operand is predicate
    assert replacement.tags == tags


@pytest.mark.parametrize("kind", ["LogicalAnd", "LogicalOr", "statements"])
@pytest.mark.parametrize("wrapper", ["comparison", "not", "cast"])
@pytest.mark.parametrize("consumer", ["typed", "jcc"])
def test_single_typed_fact_cannot_replace_wrapped_condition_chain(kind, wrapper, consumer, monkeypatch) -> None:
    """A tag on a wrapper does not prove ownership of all nested predicates."""
    codegen = _codegen()
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    flags_offset, flags_size = codegen.project.arch.registers["flags"]
    flags = CVariable(SimRegisterVariable(flags_offset, flags_size, name="flags"),
                      variable_type=SimTypeShort(False), codegen=codegen)
    inner = (
        CMultiStatementExpression(CStatements([], codegen=codegen), flags, codegen=codegen)
        if kind == "statements" else CBinaryOp(kind, flags, zero, codegen=codegen)
    )
    if wrapper == "comparison":
        condition = CBinaryOp("CmpEQ", inner, zero, codegen=codegen)
    elif wrapper == "not":
        condition = CUnaryOp("Not", CBinaryOp("CmpEQ", inner, zero, codegen=codegen), codegen=codegen)
    else:
        condition = CTypeCast(SimTypeShort(False), SimTypeShort(False),
                              CBinaryOp("CmpEQ", inner, zero, codegen=codegen), codegen=codegen)
    condition.tags = {"ins_addr": 0x101DA, "vex_block_addr": 0x101D7}
    branch = CIfElse([(condition, CStatements([], codegen=codegen))], else_node=None,
                     cstyle_ifs=True, codegen=codegen)
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root, body=root)
    codegen._inertia_typed_conditions = (
        ConditionIR("ne", IRValue(MemSpace.REG, name="ax", offset=8, size=2),
                    IRValue(MemSpace.CONST, const=0, size=2), src_insn=0x101DA, block_addr=0x101D7),
    )
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp("CmpNE", one, zero, codegen=codegen),
    )
    monkeypatch.setattr(
        decompiler_postprocess_jcc, "_translate_cmp_jcc_guard_8616",
        lambda *_args: decompiler_postprocess_jcc._DecodedCmpGuard8616(lhs=one, rhs=zero, op="CmpNE"),
    )
    apply = (_apply_typed_conditions_to_codegen_8616 if consumer == "typed" else
             decompiler_postprocess_jcc._rewrite_decoded_jcc_conditions_8616)
    assert apply(codegen.project, codegen) is False
    assert branch.condition_and_nodes[0][0] is condition


@pytest.mark.parametrize("operator,constant,refused", [
    ("LogicalAnd", 1, False), ("LogicalOr", 0, False),
    ("LogicalAnd", 0, True), ("LogicalOr", 1, True),
])
@pytest.mark.parametrize("constant_on_left", [False, True])
def test_composite_ownership_distinguishes_neutral_root_from_wrapped_guard(
    operator, constant, refused, constant_on_left,
):
    from inertia.structuring.condition_ownership import requires_composite_condition_ownership_8616

    codegen = _codegen()
    literal = CConstant(constant, SimTypeShort(False), codegen=codegen)
    predicate = CBinaryOp("CmpEQ", literal, literal, codegen=codegen)
    operands = (literal, predicate) if constant_on_left else (predicate, literal)
    root = CBinaryOp(operator, *operands, codegen=codegen)
    assert requires_composite_condition_ownership_8616(root) is refused
    wrapped = CUnaryOp("Not", root, codegen=codegen)
    assert requires_composite_condition_ownership_8616(wrapped)


def test_typed_condition_cleanup_preserves_side_effecting_call_predicate() -> None:
    """Do not replace a Structuring-owned call predicate with raw register IR."""
    codegen = _codegen()
    project = codegen.project
    call = _semantic_call(codegen)
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x101DA, "vex_block_addr": 0x101D7},
    )
    branch = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root, body=root)
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="ne",
            lhs=IRValue(MemSpace.REG, name="ax", offset=8, size=2),
            rhs=IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x101DA,
            block_addr=0x101D7,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert branch.condition_and_nodes[0][0] is condition


def test_condition_call_effects_distinguish_runtime_access_from_semantic_call() -> None:
    codegen = _codegen()
    runtime_access = CFunctionCall(
        "SEG_U16",
        None,
        [CConstant(0, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )

    runtime_evidence = classify_condition_call_effects_8616(runtime_access)
    semantic_evidence = classify_condition_call_effects_8616(
        _semantic_call(codegen)
    )

    assert runtime_evidence.kind is ConditionCallEffectKind8616.TRANSPARENT_RUNTIME_ACCESS
    assert runtime_evidence.has_semantic_call is False
    assert semantic_evidence.kind is ConditionCallEffectKind8616.SEMANTIC_CALL
    assert semantic_evidence.has_semantic_call is True


def test_jcc_refresh_preserves_side_effecting_call_predicate(monkeypatch) -> None:
    codegen = _codegen()
    project = codegen.project
    flags_offset = project.arch.registers["flags"][0]
    flags = CConstant(flags_offset, SimTypeShort(False), codegen=codegen)
    call = _semantic_call(codegen)
    condition = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, call, codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x101DA, "vex_block_addr": 0x101D7},
    )
    branch = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root, body=root)
    replacement = CConstant(1, SimTypeShort(False), codegen=codegen)
    monkeypatch.setattr(
        decompiler_postprocess_jcc,
        "_translate_cmp_jcc_guard_8616",
        lambda *_args: decompiler_postprocess_jcc._DecodedCmpGuard8616(
            lhs=replacement,
            rhs=CConstant(0, SimTypeShort(False), codegen=codegen),
            op="CmpNE",
        ),
    )

    changed = decompiler_postprocess_jcc._rewrite_decoded_jcc_conditions_8616(
        project,
        codegen,
    )

    assert changed is False
    assert branch.condition_and_nodes[0][0] is condition


def test_structuring_condition_chain_preserves_side_effecting_call(
    monkeypatch,
) -> None:
    codegen = _codegen()
    call = _semantic_call(codegen)
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x101DA, "vex_block_addr": 0x101D7},
    )
    body = CStatements([], codegen=codegen)
    body.tags = {"ins_addr": 0x101E0, "vex_block_addr": 0x101E0}
    branch = CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    graph = _Graph(
        (
            (0x101D7, 0x101E0),
            (0x101D7, 0x101DC),
            (0x101DC, 0x101D7),
            (0x101E0, 0x101E8),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes),
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: function)
        )
    )
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root)
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="ne",
            lhs=IRValue(MemSpace.REG, name="ax", offset=8, size=2),
            rhs=IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x101DA,
            block_addr=0x101D7,
            producer_insn=0x101D9,
            taken_target=0x101E0,
            fallthrough_target=0x101DC,
        ),
    )
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CConstant(1, SimTypeShort(False), codegen=codegen),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(
        project,
        codegen,
    )

    assert changed is False
    assert branch.condition_and_nodes[0][0] is condition
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.preserved_side_effect_count == 1


def _memory_cvar(codegen: object, offset: int, size: int = 2) -> CVariable:
    """A plain segmented-memory comparison operand with exact storage."""
    return CVariable(
        SimMemoryVariable(offset, size),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _typed_branch(codegen: object, condition: object):
    """Wrap one guard in the CIfElse/CStatements harness used by this module."""
    branch = CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root, body=root)
    return branch


def _sge_memory_condition() -> ConditionIR:
    """Native-like signed taken predicate: JGE over DS:[0x132] vs 0."""
    return ConditionIR(
        "sge",
        IRValue(MemSpace.DS, offset=0x132, size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x4020,
        block_addr=0x4000,
    )


def test_typed_replacement_preserves_inverted_comparison_guard_truth() -> None:
    """An inverted CmpLT fallthrough guard must not republish the JGE taken predicate."""
    codegen = _codegen()
    tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    condition = CBinaryOp(
        "CmpLT",
        _memory_cvar(codegen, 0x132),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    branch = _typed_branch(codegen, condition)
    codegen._inertia_typed_conditions = (_sge_memory_condition(),)

    changed = _apply_typed_conditions_to_codegen_8616(codegen.project, codegen)

    assert changed is True
    replacement = branch.condition_and_nodes[0][0]
    assert isinstance(replacement, CUnaryOp)
    assert replacement.op == "Not"
    predicate = replacement.operand
    assert isinstance(predicate, CBinaryOp)
    assert predicate.op == "CmpGE"
    identity = segmented_load_identity_8616(predicate.lhs)
    assert identity is not None
    assert identity.space is MemSpace.DS
    assert identity.offset == 0x132
    assert identity.width == 2
    assert predicate.rhs.value == 0
    assert codegen._inertia_semantic_condition_materialized_count == 1


def test_typed_replacement_keeps_direct_comparison_guard_truth() -> None:
    """A direct CmpGE guard receives the proven typed views without inversion."""
    codegen = _codegen()
    tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    condition = CBinaryOp(
        "CmpGE",
        _memory_cvar(codegen, 0x132),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    branch = _typed_branch(codegen, condition)
    codegen._inertia_typed_conditions = (_sge_memory_condition(),)

    changed = _apply_typed_conditions_to_codegen_8616(codegen.project, codegen)

    assert changed is True
    replacement = branch.condition_and_nodes[0][0]
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "CmpGE"
    identity = segmented_load_identity_8616(replacement.lhs)
    assert identity is not None and identity.offset == 0x132


def test_typed_replacement_inverts_equality_guard_truth() -> None:
    """CmpEQ matched to a typed NE fact stays inverse, never a bare NE."""
    codegen = _codegen()
    tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    condition = CBinaryOp(
        "CmpEQ",
        _memory_cvar(codegen, 0x132),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    branch = _typed_branch(codegen, condition)
    codegen._inertia_typed_conditions = (
        ConditionIR(
            "ne",
            IRValue(MemSpace.DS, offset=0x132, size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x4020,
            block_addr=0x4000,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(codegen.project, codegen)

    assert changed is True
    replacement = branch.condition_and_nodes[0][0]
    assert isinstance(replacement, CUnaryOp)
    assert replacement.op == "Not"
    assert replacement.operand.op == "CmpNE"


@pytest.mark.parametrize("structured", ["swapped", "unmatched", "opaque"])
def test_typed_replacement_refuses_unproven_comparison_orientation(structured) -> None:
    """Swapped, unmatched, or opaque operands must not invent guard polarity."""
    codegen = _codegen()
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    if structured == "swapped":
        condition = CBinaryOp(
            "CmpLT",
            _memory_cvar(codegen, 0x134),
            _memory_cvar(codegen, 0x132),
            codegen=codegen,
            tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
        )
        codegen._inertia_typed_conditions = (
            ConditionIR(
                "sge",
                IRValue(MemSpace.DS, offset=0x132, size=2),
                IRValue(MemSpace.DS, offset=0x134, size=2),
                src_insn=0x4020,
                block_addr=0x4000,
            ),
        )
    elif structured == "unmatched":
        condition = CBinaryOp(
            "CmpLE",
            _memory_cvar(codegen, 0x200),
            zero,
            codegen=codegen,
            tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
        )
        codegen._inertia_typed_conditions = (_sge_memory_condition(),)
    else:
        condition = CBinaryOp(
            "CmpLT",
            CBinaryOp("Add", _memory_cvar(codegen, 0x132), CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            zero,
            codegen=codegen,
            tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
        )
        codegen._inertia_typed_conditions = (_sge_memory_condition(),)
    branch = _typed_branch(codegen, condition)

    changed = _apply_typed_conditions_to_codegen_8616(codegen.project, codegen)

    assert changed is False
    assert branch.condition_and_nodes[0][0] is condition


def test_explicit_not_and_compound_guards_are_not_reoriented() -> None:
    """Not-wrapped and call-effectful guards keep their structured expression."""
    codegen = _codegen()
    wrapped = CUnaryOp(
        "Not",
        CBinaryOp(
            "CmpGE",
            _memory_cvar(codegen, 0x132),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    not_branch = _typed_branch(codegen, wrapped)
    codegen._inertia_typed_conditions = (_sge_memory_condition(),)

    assert _apply_typed_conditions_to_codegen_8616(codegen.project, codegen) is False
    assert not_branch.condition_and_nodes[0][0] is wrapped

    codegen = _codegen()
    call_guard = CBinaryOp(
        "CmpLT",
        _semantic_call(codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    call_branch = _typed_branch(codegen, call_guard)
    codegen._inertia_typed_conditions = (_sge_memory_condition(),)

    assert _apply_typed_conditions_to_codegen_8616(codegen.project, codegen) is False
    assert call_branch.condition_and_nodes[0][0] is call_guard


def test_comparison_polarity_contract_uses_ordered_operand_identity() -> None:
    """Polarity is proven only by complete ordered operand correspondence."""
    codegen = _codegen()
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    a = _memory_cvar(codegen, 0x132)
    a_again = _memory_cvar(codegen, 0x132)
    b = _memory_cvar(codegen, 0x134)
    zero_again = CConstant(0, SimTypeShort(False), codegen=codegen)

    def _polarity(left: object, right: object) -> ConditionComparisonPolarity8616:
        return condition_comparison_polarity_8616(left, right, same_expression=_same_c_expression_8616)

    assert _polarity(
        CBinaryOp("CmpLT", a, zero, codegen=codegen),
        CBinaryOp("CmpLT", a_again, zero_again, codegen=codegen),
    ) is ConditionComparisonPolarity8616.DIRECT
    assert _polarity(
        CBinaryOp("CmpLT", a, zero, codegen=codegen),
        CBinaryOp("CmpGE", a_again, zero_again, codegen=codegen),
    ) is ConditionComparisonPolarity8616.INVERTED
    assert _polarity(
        CUnaryOp("Not", CBinaryOp("CmpGE", a, zero, codegen=codegen), codegen=codegen),
        CBinaryOp("CmpGE", a_again, zero_again, codegen=codegen),
    ) is ConditionComparisonPolarity8616.INVERTED
    assert _polarity(
        CBinaryOp("CmpNE", a, zero, codegen=codegen),
        CBinaryOp("CmpEQ", a_again, zero_again, codegen=codegen),
    ) is ConditionComparisonPolarity8616.INVERTED
    assert _polarity(
        CBinaryOp("CmpLT", b, a, codegen=codegen),
        CBinaryOp("CmpLT", a_again, b, codegen=codegen),
    ) is ConditionComparisonPolarity8616.UNKNOWN
    assert _polarity(
        CBinaryOp("CmpLE", _memory_cvar(codegen, 0x200), zero, codegen=codegen),
        CBinaryOp("CmpGE", a_again, zero_again, codegen=codegen),
    ) is ConditionComparisonPolarity8616.UNKNOWN
    assert _polarity(
        CBinaryOp("CmpLT", CBinaryOp("Add", a, zero, codegen=codegen), zero, codegen=codegen),
        CBinaryOp("CmpGE", a_again, zero_again, codegen=codegen),
    ) is ConditionComparisonPolarity8616.UNKNOWN
    assert _polarity(
        CBinaryOp("And", a, zero, codegen=codegen),
        CBinaryOp("CmpGE", a_again, zero_again, codegen=codegen),
    ) is ConditionComparisonPolarity8616.UNKNOWN
