"""Regress typed loop-guard identity across segmented-memory lowering."""

from __future__ import annotations

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIfBreak,
    CIndexedVariable,
    CStatements,
    CStructField,
    CVariable,
    CVariableField,
    CWhileLoop,
)
from angr.sim_type import SimStruct, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.structuring.loop_break_jcc import LoopBranchGuardFact8616
from angr_platforms.X86_16.tail_validation import (
    _canonicalize_linear_ds_deref_condition_fingerprint_8616,
)
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint
from angr_platforms.X86_16.validation_condition_identity import (
    condition_ir_semantic_fingerprint_8616,
)
from angr_platforms.X86_16.validation_condition_storage_views import condition_storage_views_match_8616
from angr_platforms.X86_16.validation_control_flow import (
    LoopBranchGuardIssueKind8616,
    validate_structured_control_flow_8616,
)
from archinfo import ArchX86


class _Project:
    """Minimal project boundary with proven DS linear lowering."""

    def __init__(self) -> None:
        self.arch = ArchX86()
        self._inertia_segmented_memory_lowering = {
            "DS": {"allow_linear_lowering": True}
        }


class _Codegen:
    """Minimal structured-codegen boundary used by C AST constructors."""

    def __init__(self, project: _Project) -> None:
        self.project = project
        self.cstyle_null_cmp = False
        self._next_index = 0

    def next_idx(self, _kind: str) -> int:
        """Return a stable C AST node index."""
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _condition_ir(
    *,
    global_offset: int = 0xBA2,
    stack_offset: int = -2,
    global_space: MemSpace = MemSpace.DS,
) -> ConditionIR:
    """Build the binary-proven InitBars-style unsigned loop condition."""
    return ConditionIR(
        op="ugt",
        lhs=IRValue(global_space, offset=global_offset, size=2),
        rhs=IRValue(MemSpace.SS, offset=stack_offset, size=2),
        src_insn=0x4005,
        block_addr=0x4000,
        taken_target=0x4010,
        fallthrough_target=0x4007,
    )


def _indexed_condition_ir(
    *,
    global_offset: int = 0xB4C,
    index_offset: int = -6,
) -> ConditionIR:
    """Build a typed indexed-DS comparison matching QuickSort's scan guard."""
    indexed_word = IRValue(
        MemSpace.DS,
        offset=global_offset,
        size=2,
        index=IRValue(MemSpace.SS, name="bp", offset=index_offset, size=2),
        index_shift=1,
        memory_access_size=2,
    )
    return ConditionIR(
        op="sle",
        lhs=indexed_word,
        rhs=IRValue(MemSpace.SS, offset=-4, size=2),
        src_insn=0x4005,
        block_addr=0x4000,
        taken_target=0x4010,
        fallthrough_target=0x4007,
    )


def _fact(condition: ConditionIR) -> LoopBranchGuardFact8616:
    """Build one loop obligation retaining typed condition evidence."""
    raw_lhs = "Dereference(Add(Mul(reg:ds,const:16),const:2978))"
    raw_rhs = "stack_slot:SS:BP-0x2:size2"
    return LoopBranchGuardFact8616(
        jcc_addr=0x4005,
        block_addr=0x4000,
        body_target=0x4010,
        fallthrough_target=0x4007,
        false_target=0x4020,
        decoded_condition_fingerprint=f"CmpGT({raw_lhs},{raw_rhs})",
        guard_condition_fingerprint=f"CmpLE({raw_lhs},{raw_rhs})",
        condition_ir=condition,
    )


def _indexed_fact(condition: ConditionIR) -> LoopBranchGuardFact8616:
    """Build the indexed loop obligation while retaining typed evidence."""
    raw_lhs = (
        "Dereference(Add(Mul(reg:ds,const:16),"
        "Shl(stack_slot:SS:BP-0x6:size2,const:1),const:2892))"
    )
    raw_rhs = "stack_slot:SS:BP-0x4:size2"
    return LoopBranchGuardFact8616(
        jcc_addr=0x4005,
        block_addr=0x4000,
        body_target=0x4010,
        fallthrough_target=0x4007,
        false_target=0x4020,
        decoded_condition_fingerprint=f"CmpLE({raw_lhs},{raw_rhs})",
        guard_condition_fingerprint=f"CmpGT({raw_lhs},{raw_rhs})",
        condition_ir=condition,
    )


def _legacy_fact(
    *,
    global_offset: int = 0xBA2,
    stack_offset: int = -2,
) -> LoopBranchGuardFact8616:
    """Build one legacy obligation without retained typed condition evidence."""
    raw_lhs = (
        "Dereference(Add(Mul(reg:ds,const:16),"
        f"const:{global_offset}))"
    )
    raw_rhs = f"stack_slot:SS:BP-0x{abs(stack_offset):x}:size2"
    return LoopBranchGuardFact8616(
        jcc_addr=0x4005,
        block_addr=0x4000,
        body_target=0x4010,
        fallthrough_target=0x4007,
        false_target=0x4020,
        decoded_condition_fingerprint=f"CmpGT({raw_lhs},{raw_rhs})",
        guard_condition_fingerprint=f"CmpLE({raw_lhs},{raw_rhs})",
    )


def _final_loop(codegen: _Codegen) -> CStatements:
    """Build the final lowered loop with one untagged inverted break guard."""
    global_value = CVariable(
        SimMemoryVariable(0xBA2, 2, name="g_0BA2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    local_value = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    guard = CIfBreak(
        CBinaryOp("CmpLE", global_value, local_value, codegen=codegen),
        codegen=codegen,
    )
    body_target = CConstant(
        1,
        SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    body = CStatements([guard, body_target], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), body, codegen=codegen)
    return CStatements([loop], codegen=codegen)


def _indexed_final_loop(codegen: _Codegen) -> CStatements:
    """Build the lowered indexed-field form of QuickSort's scan guard."""
    element_type = SimStruct({"field_0": SimTypeShort(True)}, name="bar_t")
    base = CVariable(
        SimMemoryVariable(0xB4C, 2, name="g_0B4C"),
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_6"),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    indexed = CIndexedVariable(base, index, variable_type=element_type, codegen=codegen)
    field = CVariableField(
        indexed,
        CStructField(element_type, 0, "field_0", codegen=codegen),
        codegen=codegen,
    )
    pivot = CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_4"),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    guard = CIfBreak(CBinaryOp("CmpGT", field, pivot, codegen=codegen), codegen=codegen)
    body_target = CConstant(
        1,
        SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    body = CStatements([guard, body_target], codegen=codegen)
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), body, codegen=codegen)
    return CStatements([loop], codegen=codegen)


def _validate(condition: ConditionIR) -> object:
    """Validate one typed obligation against the final lowered loop."""
    project = _Project()
    codegen = _Codegen(project)
    return validate_structured_control_flow_8616(
        _final_loop(codegen),
        loop_branch_facts=(_fact(condition),),
        condition_fingerprint=lambda expression: _expr_fingerprint(expression, project),
        condition_ir_fingerprint=lambda typed: condition_ir_semantic_fingerprint_8616(
            project, codegen, typed
        ),
    )


def _validate_indexed(condition: ConditionIR) -> object:
    """Validate indexed typed evidence against its final struct-field form."""
    project = _Project()
    codegen = _Codegen(project)
    return validate_structured_control_flow_8616(
        _indexed_final_loop(codegen),
        loop_branch_facts=(_indexed_fact(condition),),
        condition_fingerprint=lambda expression: _expr_fingerprint(expression, project),
        condition_ir_fingerprint=lambda typed: condition_ir_semantic_fingerprint_8616(
            project, codegen, typed
        ),
        condition_storage_matcher=lambda typed, candidate, inverted: condition_storage_views_match_8616(
            project, codegen, typed, candidate, inverted,
        ),
    )


def _validate_legacy(fact: LoopBranchGuardFact8616) -> object:
    """Validate one legacy obligation through semantic DS canonicalization."""
    project = _Project()
    codegen = _Codegen(project)
    return validate_structured_control_flow_8616(
        _final_loop(codegen),
        loop_branch_facts=(fact,),
        condition_fingerprint=lambda expression: _expr_fingerprint(expression, project),
        condition_fingerprint_normalizer=(
            _canonicalize_linear_ds_deref_condition_fingerprint_8616
        ),
    )


def test_control_flow_accepts_typed_condition_after_ds_global_lowering() -> None:
    """Treat proven raw DS and final named-global storage as one location."""
    report = _validate(_condition_ir())

    assert report.passed
    assert report.materialized_count == 1


def test_control_flow_accepts_indexed_ds_condition_after_field_lowering() -> None:
    """Join exact indexed DS evidence to the final typed field guard."""
    report = _validate_indexed(_indexed_condition_ir())

    assert report.passed
    assert report.materialized_count == 1


@pytest.mark.parametrize(
    ("global_offset", "index_offset"),
    ((0xB4E, -6), (0xB4C, -2)),
)
def test_control_flow_refuses_wrong_indexed_ds_condition_storage(
    global_offset: int,
    index_offset: int,
) -> None:
    """Reject indexed guards with a different base or stack index."""
    report = _validate_indexed(
        _indexed_condition_ir(
            global_offset=global_offset,
            index_offset=index_offset,
        )
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD


@pytest.mark.parametrize(
    ("global_offset", "stack_offset", "global_space"),
    ((0xBA4, -2, MemSpace.DS), (0xBA2, -4, MemSpace.DS), (0xBA2, -2, MemSpace.ES)),
)
def test_control_flow_refuses_wrong_typed_condition_storage(
    global_offset: int,
    stack_offset: int,
    global_space: MemSpace,
) -> None:
    """Reject a loop guard when either typed storage identity is different."""
    report = _validate(
        _condition_ir(
            global_offset=global_offset,
            stack_offset=stack_offset,
            global_space=global_space,
        )
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD


def test_control_flow_accepts_exact_legacy_ds_condition_after_lowering() -> None:
    """Join an exact legacy DS dereference to its lowered global location."""
    report = _validate_legacy(_legacy_fact())

    assert report.passed
    assert report.materialized_count == 1


@pytest.mark.parametrize(
    ("global_offset", "stack_offset"),
    ((0xBA4, -2), (0xBA2, -4)),
)
def test_control_flow_refuses_wrong_legacy_condition_storage(
    global_offset: int,
    stack_offset: int,
) -> None:
    """Reject nearby legacy locations despite semantic canonicalization."""
    report = _validate_legacy(
        _legacy_fact(global_offset=global_offset, stack_offset=stack_offset)
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD
