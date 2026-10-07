"""Branch-execution ownership regressions for carry/borrow Lowering."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.carry_borrow_bit_contracts import (
    CarryBorrowBitLoweringFact8616,
    CarryBorrowBitLoweringFailure8616,
    CarryBorrowBitLoweringVerdict8616,
)
from inertia.lowering.carry_borrow_bit_placement import (
    materialize_carry_borrow_bit_value_8616,
)
from inertia.lowering.carry_borrow_bit_predicate import (
    carry_bit_predicate_8616,
    carry_bit_predicate_from_arithmetic_8616,
)
from inertia.lowering.carry_borrow_bit_values import lower_carry_borrow_bit_values_8616
from inertia.pipeline.errors import PipelineHardError

from inertia.lowering.c_ast_utils import _same_c_expression_8616
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.carry_borrow_pipeline import CarryBorrowWideningPipeline8616
from inertia.widening.carry_borrow_values import WideCarryBorrowValue8616
from tests.lowering.x86_16_carry_borrow_bit_fixtures import build_test_cfg_ownership_8616

_ENTRY = 0x2000
_ARM_A = 0x2010
_LOW_A = 0x2011
_HIGH_A = 0x2014
_ARM_B = 0x2020
_LOW_B = 0x2021
_HIGH_B = 0x2024


class _FakeCodegen(SimpleNamespace):
    """Minimal structured-C boundary for branch-owned predicate tests."""

    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        """Return a deterministic C-AST node identity."""
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        """Return a deterministic C-AST node identity."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep fixture identifiers stable."""
        return name


def _vvar(codegen: _FakeCodegen, register: str, name: str, vvar_id: int) -> structured_c.CVariable:
    """Create one register-backed C-SSA variable."""
    offset = codegen.project.arch.registers[register][0]
    return structured_c.CVariable(
        SimRegisterVariable(offset, 2, name=name),
        variable_type=SimTypeShort(False),
        vvar_id=vvar_id,
        codegen=codegen,
    )


def _constant(codegen: _FakeCodegen, value: int) -> structured_c.CConstant:
    """Create one unsigned-word C constant."""
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _arm(
    codegen: _FakeCodegen,
    *,
    block_addr: int,
    low_addr: int,
    high_addr: int,
    operand_base: int,
    split_low_result: bool = False,
) -> tuple[structured_c.CStatements, structured_c.CVariable, structured_c.CVariable, structured_c.CAssignment]:
    """Build one exact SUB/borrow carrier and use in a branch arm."""
    lhs = _vvar(codegen, "ax", f"lhs_{operand_base}", operand_base)
    rhs = _vvar(codegen, "bx", f"rhs_{operand_base}", operand_base + 1)
    tags = {"vex_block_addr": block_addr, "ins_addr": low_addr}
    arithmetic = structured_c.CBinaryOp("Sub", lhs, rhs, codegen=codegen, tags=tags)
    predicate = structured_c.CBinaryOp("CmpLT", lhs, rhs, codegen=codegen, tags=tags)
    low = structured_c.CAssignment(
        _vvar(codegen, "flags", "shared_flags_definition", 5),
        predicate if split_low_result else structured_c.CBinaryOp("Or", arithmetic, predicate, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    low_statements = (
        [
            structured_c.CAssignment(
                _vvar(codegen, "ax", f"low_{operand_base}", operand_base + 3),
                arithmetic,
                codegen=codegen,
                tags=tags,
            ),
            low,
        ]
        if split_low_result
        else [low]
    )
    carry = structured_c.CBinaryOp(
        "And",
        _vvar(codegen, "flags", "shared_flags_use", 5),
        _constant(codegen, 1),
        codegen=codegen,
        tags={"vex_block_addr": block_addr, "ins_addr": high_addr},
    )
    high = structured_c.CAssignment(
        _vvar(codegen, "dx", f"high_{operand_base}", operand_base + 2),
        carry,
        codegen=codegen,
    )
    return structured_c.CStatements([*low_statements, high], codegen=codegen), lhs, rhs, high


def _fact(block_addr: int, low_addr: int, high_addr: int) -> CarryBorrowBitLoweringFact8616:
    """Create one exact branch-owned SUB_WITH_BORROW fact."""
    return CarryBorrowBitLoweringFact8616(
        function_addr=_ENTRY,
        kind=CarryBorrowKind8616.SUB_WITH_BORROW,
        low_block_addr=block_addr,
        low_ins_addr=low_addr,
        high_block_addr=block_addr,
        high_ins_addr=high_addr,
    )


def test_symmetric_addition_carry_predicates_share_one_low_site() -> None:
    """Treat ``sum < lhs`` and ``sum < rhs`` as one carry meaning."""
    codegen = _FakeCodegen()
    lhs = _vvar(codegen, "ax", "lhs", 10)
    rhs = _vvar(codegen, "bx", "rhs", 11)
    tags = {"vex_block_addr": _ARM_A, "ins_addr": _LOW_A}
    addition = structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen, tags=tags)
    symmetric_addition = structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen, tags=tags)
    candidates = (
        structured_c.CBinaryOp("CmpLT", addition, lhs, codegen=codegen, tags=tags),
        structured_c.CBinaryOp(
            "CmpLT",
            symmetric_addition,
            rhs,
            codegen=codegen,
            tags=tags,
        ),
    )
    fact = CarryBorrowBitLoweringFact8616(
        function_addr=_ENTRY,
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        low_block_addr=_ARM_A,
        low_ins_addr=_LOW_A,
        high_block_addr=_ARM_A,
        high_ins_addr=_HIGH_A,
    )

    predicate = carry_bit_predicate_8616(
        ((candidates[0], addition), (candidates[1], symmetric_addition)),
        fact,
        build_test_cfg_ownership_8616({_ARM_A: (_LOW_A, _HIGH_A)}),
    )

    assert not isinstance(predicate, CarryBorrowBitLoweringFailure8616)
    assert predicate.op == "CmpLT"


def test_same_site_flag_additions_do_not_compete_with_proven_carry() -> None:
    """Ignore tagged flag bookkeeping outside the coherent carry comparison."""
    codegen = _FakeCodegen()
    lhs = _vvar(codegen, "ax", "lhs", 10)
    rhs = _vvar(codegen, "bx", "rhs", 11)
    tags = {"vex_block_addr": _ARM_A, "ins_addr": _LOW_A}
    addition = structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen, tags=tags)
    candidate = structured_c.CBinaryOp("CmpLT", addition, lhs, codegen=codegen, tags=tags)
    flag_offset = structured_c.CBinaryOp(
        "Add",
        _constant(codegen, 0),
        _constant(codegen, 4),
        codegen=codegen,
        tags=tags,
    )
    flag_bit = structured_c.CBinaryOp(
        "Add",
        flag_offset,
        _constant(codegen, 1),
        codegen=codegen,
        tags=tags,
    )
    fact = CarryBorrowBitLoweringFact8616(
        function_addr=_ENTRY,
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        low_block_addr=_ARM_A,
        low_ins_addr=_LOW_A,
        high_block_addr=_ARM_A,
        high_ins_addr=_HIGH_A,
    )

    predicate = carry_bit_predicate_8616(
        ((candidate, addition, flag_offset, flag_bit),),
        fact,
        build_test_cfg_ownership_8616({_ARM_A: (_LOW_A, _HIGH_A)}),
    )

    assert not isinstance(predicate, CarryBorrowBitLoweringFailure8616)
    assert predicate.op == "CmpLT"


def test_arithmetic_fallback_selects_unique_direct_low_result() -> None:
    """Select the assigned low result when tagged flag additions survive."""
    codegen = _FakeCodegen()
    lhs = _vvar(codegen, "ax", "lhs", 10)
    rhs = _vvar(codegen, "bx", "rhs", 11)
    tags = {"vex_block_addr": _ARM_A, "ins_addr": _LOW_A}
    addition = structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen, tags=tags)
    low_assignment = structured_c.CAssignment(
        _vvar(codegen, "ax", "low_result", 12),
        addition,
        codegen=codegen,
        tags=tags,
    )
    flag_offset = structured_c.CBinaryOp(
        "Add",
        _constant(codegen, 0),
        _constant(codegen, 4),
        codegen=codegen,
        tags=tags,
    )
    flag_bit = structured_c.CBinaryOp(
        "Add",
        flag_offset,
        _constant(codegen, 1),
        codegen=codegen,
        tags=tags,
    )
    fact = CarryBorrowBitLoweringFact8616(
        function_addr=_ENTRY,
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        low_block_addr=_ARM_A,
        low_ins_addr=_LOW_A,
        high_block_addr=_ARM_A,
        high_ins_addr=_HIGH_A,
    )

    predicate = carry_bit_predicate_from_arithmetic_8616(
        (low_assignment, addition, flag_offset, flag_bit),
        fact,
        build_test_cfg_ownership_8616({_ARM_A: (_LOW_A, _HIGH_A)}),
    )

    assert not isinstance(predicate, CarryBorrowBitLoweringFailure8616)
    assert predicate.op == "CmpLT"
    assert _same_c_expression_8616(predicate.lhs.expr, low_assignment.lhs)


def test_branch_owned_borrow_sites_do_not_cross_select_shared_flags_identity() -> None:
    """Each branch must consume only the machine definition that can reach it."""
    codegen = _FakeCodegen()
    arm_a, lhs_a, rhs_a, high_a = _arm(
        codegen, block_addr=_ARM_A, low_addr=_LOW_A, high_addr=_HIGH_A, operand_base=10
    )
    arm_b, lhs_b, rhs_b, high_b = _arm(
        codegen, block_addr=_ARM_B, low_addr=_LOW_B, high_addr=_HIGH_B, operand_base=20
    )
    branch = structured_c.CIfElse(
        [
            (
                structured_c.CBinaryOp(
                    "CmpNE", _vvar(codegen, "si", "branch", 30), _constant(codegen, 0), codegen=codegen
                ),
                arm_a,
            )
        ],
        else_node=arm_b,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = structured_c.CStatements([branch], codegen=codegen)
    ownership = build_test_cfg_ownership_8616(
        {
            _ENTRY: (),
            _ARM_A: (_LOW_A, _HIGH_A),
            _ARM_B: (_LOW_B, _HIGH_B),
        },
        ((_ENTRY, _ARM_A), (_ENTRY, _ARM_B)),
    )
    source = cast(WideCarryBorrowValue8616, object())
    fact_a = _fact(_ARM_A, _LOW_A, _HIGH_A)
    fact_b = _fact(_ARM_B, _LOW_B, _HIGH_B)

    resolution_a = materialize_carry_borrow_bit_value_8616(root, source, fact_a, ownership)
    resolution_b = materialize_carry_borrow_bit_value_8616(root, source, fact_b, ownership)

    assert resolution_a.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert resolution_b.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert isinstance(high_a.rhs, structured_c.CBinaryOp) and high_a.rhs.op == "CmpLT"
    assert isinstance(high_b.rhs, structured_c.CBinaryOp) and high_b.rhs.op == "CmpLT"
    assert _same_c_expression_8616(high_a.rhs.lhs, lhs_a)
    assert _same_c_expression_8616(high_a.rhs.rhs, rhs_a)
    assert _same_c_expression_8616(high_b.rhs.lhs, lhs_b)
    assert _same_c_expression_8616(high_b.rhs.rhs, rhs_b)
    assert high_a.rhs.tags["inertia_x86_16_carry_borrow_bit_lowering"] == fact_a
    assert high_b.rhs.tags["inertia_x86_16_carry_borrow_bit_lowering"] == fact_b


def test_single_borrow_use_joins_sibling_low_arithmetic() -> None:
    """Resolve one flags closure whose exact low subtraction is a sibling."""
    codegen = _FakeCodegen()
    root, lhs, rhs, high = _arm(
        codegen,
        block_addr=_ARM_A,
        low_addr=_LOW_A,
        high_addr=_HIGH_A,
        operand_base=10,
        split_low_result=True,
    )
    ownership = build_test_cfg_ownership_8616({_ARM_A: (_LOW_A, _HIGH_A)})

    resolution = materialize_carry_borrow_bit_value_8616(
        root,
        cast(WideCarryBorrowValue8616, object()),
        _fact(_ARM_A, _LOW_A, _HIGH_A),
        ownership,
    )

    assert resolution.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED
    assert isinstance(high.rhs, structured_c.CBinaryOp) and high.rhs.op == "CmpLT"
    assert _same_c_expression_8616(high.rhs.lhs.expr, lhs)
    assert _same_c_expression_8616(high.rhs.rhs.expr, rhs)


def test_production_lowering_requires_prejoin_cfg_ownership() -> None:
    """The main path must stop clearly if Structuring did not publish ownership."""
    opaque = cast(Any, object())
    pipeline = CarryBorrowWideningPipeline8616(
        source_ssa=cast(Any, SimpleNamespace(function_addr=_ENTRY)),
        source_stack_alias=None,
        semantics=opaque,
        aliases=opaque,
        widening=opaque,
        destination_aliases=opaque,
        storage_widening=opaque,
    )
    codegen = SimpleNamespace(_inertia_carry_borrow_widening_pipeline_8616=pipeline)

    with pytest.raises(PipelineHardError) as error:
        lower_carry_borrow_bit_values_8616(codegen)

    assert error.value.layer == "lowering"
    assert str(error.value) == "carry-bit Lowering requires pre-join Structuring CFG ownership"
