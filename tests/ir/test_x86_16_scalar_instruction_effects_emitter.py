"""Independent actual-emitter comparison and malformed-effect controls.

Layer: IR regression tests.
Responsibility: prove the custom-emitter domain with real Binop/result-type
evidence and retain destination, operand-width and malformed-shape refusals.
"""

from __future__ import annotations

from dataclasses import replace

import archinfo
import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.ir.scalar_instruction_effects as _EFFECTS
from inertia.ir.core import IRCondition, IRInstr, IRValue, MemSpace
from inertia.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
)
from inertia.ir.vex_import import _stmt_to_instr
from pyvex.const import vex_int_class
from pyvex.lifting.util.vex_helper import IRSBCustomizer


def test_native_neg_widening_product_has_only_explicit_effects() -> None:
    """The real NEG lift closes every scalar row, including its signed wide product."""
    address = 0x1000
    block = pyvex.IRSB(b"\xf7\xdb", address, Arch86_16(), num_inst=1, opt_level=0)
    views, conditions, expressions = {}, {}, {}
    demand = VexConditionDemand8616(frozenset(), VexConditionDemandStats8616())
    rows = []
    for statement in block.statements:
        row = _stmt_to_instr(
            statement, views, conditions, instruction_addr=address,
            segment_hints={}, tmp_exprs=expressions, type_environment=block.tyenv,
            condition_demand=demand,
        )
        if row is not None:
            rows.append(row)
    products = [row for row in rows if row.op == "Iop_MullS16"]
    assert len(products) == 1
    product = products[0]
    assert product.size == 4
    assert tuple(value.size for value in product.args) == (2, 2)
    assert _EFFECTS.scalar_instruction_effect_8616(product).clobber is (
        _EFFECTS.ScalarInstructionClobber8616.NONE
    )
    assert all(
        _EFFECTS.scalar_instruction_effect_8616(row).kind is (
            _EFFECTS.ScalarInstructionEffectKind8616.CLOSED_DESTINATION
        ) for row in rows
    )


def test_native_repne_scasb_lift_has_only_closed_effects() -> None:
    """The real REPNE SCASB lift closes every row, including the one-bit ZF test."""
    address = 0x10000
    block = pyvex.IRSB(b"\xf2\xae", address, Arch86_16(), num_inst=1, opt_level=0)
    views, conditions, expressions = {}, {}, {}
    demand = VexConditionDemand8616(frozenset(), VexConditionDemandStats8616())
    rows = []
    for statement in block.statements:
        row = _stmt_to_instr(
            statement, views, conditions, instruction_addr=address,
            segment_hints={}, tmp_exprs=expressions, type_environment=block.tyenv,
            condition_demand=demand,
        )
        if row is not None:
            rows.append(row)
    ops = {row.op for row in rows}
    assert "LOAD" in ops
    assert "CJMP" in ops
    assert "Iop_CmpEQ1" in ops
    effects = {id(row): _EFFECTS.scalar_instruction_effect_8616(row) for row in rows}
    assert [
        row.op for row in rows
        if effects[id(row)].kind is _EFFECTS.ScalarInstructionEffectKind8616.UNKNOWN
    ] == []
    clobbered_registers = {
        row.dst.name for row in rows
        if effects[id(row)].clobber is _EFFECTS.ScalarInstructionClobber8616.DATA_REGISTER
        and isinstance(row.dst, IRValue) and row.dst.name is not None
    }
    assert {"cx", "di", "flags"} <= clobbered_registers
    assert "cs" not in clobbered_registers


@pytest.mark.parametrize("bits", [8, 16, 32])
@pytest.mark.parametrize("signedness", ["S", "U"])
def test_widening_product_closes_only_double_width_destination(
    bits: int, signedness: str,
) -> None:
    """Real VEX widening products write twice the operand width, without hidden effects."""
    op = f"Iop_Mull{signedness}{bits}"
    const_type = vex_int_class(bits)
    expression = pyvex.expr.Binop(op, [
        pyvex.expr.Const(const_type(1)), pyvex.expr.Const(const_type(2)),
    ])
    env = pyvex.IRTypeEnv(archinfo.ArchX86())
    assert expression.result_size(env) == bits * 2
    width = bits // 8
    instruction = IRInstr(
        op, IRValue(MemSpace.TMP, source_tmp=1, size=width * 2),
        (IRValue(MemSpace.CONST, const=1, size=width),
         IRValue(MemSpace.CONST, const=2, size=width)), size=width * 2,
    )
    effect = _EFFECTS.scalar_instruction_effect_8616(instruction)
    assert effect.kind is _EFFECTS.ScalarInstructionEffectKind8616.CLOSED_DESTINATION
    assert effect.clobber is _EFFECTS.ScalarInstructionClobber8616.NONE
    assert isinstance(instruction.dst, IRValue)
    corruptions = (
        replace(instruction, size=width),
        replace(instruction, dst=replace(instruction.dst, size=width)),
        replace(instruction, args=instruction.args[:1]),
        replace(instruction, args=(replace(instruction.args[0], size=width * 2), instruction.args[1])),
        replace(instruction, dst=replace(instruction.dst, offset=1)),
        replace(instruction, op=f"Iop_Mull{bits}{signedness}"),
    )
    for corrupted in corruptions:
        assert _EFFECTS.scalar_instruction_effect_8616(corrupted).kind is (
            _EFFECTS.ScalarInstructionEffectKind8616.UNKNOWN
        )


def _comparison(op: str, width: int) -> IRInstr:
    """Build a pure comparison of two exact same-width integer literals."""
    return IRInstr(
        op, IRValue(MemSpace.TMP, name="t1", source_tmp=1, size=1),
        (IRValue(MemSpace.CONST, const=1, size=width),
         IRValue(MemSpace.CONST, const=2, size=width)), size=1,
    )


@pytest.mark.parametrize("bits", [8, 16, 32, 64])
@pytest.mark.parametrize("relation", ["LT", "LE", "GT", "GE"])
@pytest.mark.parametrize("signedness", ["S", "U"])
def test_custom_emitter_integer_comparison_spelling_closes(
    bits: int, relation: str, signedness: str,
) -> None:
    """Use an actual customizer Binop, not the incomplete stock registry."""
    emitters = {
        ("LT", "S"): IRSBCustomizer.op_cmp_slt,
        ("LT", "U"): IRSBCustomizer.op_cmp_ult,
        ("LE", "S"): IRSBCustomizer.op_cmp_sle,
        ("LE", "U"): IRSBCustomizer.op_cmp_ule,
        ("GT", "S"): IRSBCustomizer.op_cmp_sgt,
        ("GT", "U"): IRSBCustomizer.op_cmp_ugt,
        ("GE", "S"): IRSBCustomizer.op_cmp_sge,
        ("GE", "U"): IRSBCustomizer.op_cmp_uge,
    }
    block = pyvex.IRSB.empty_block(archinfo.ArchX86(), addr=0)
    emitter = IRSBCustomizer(block)
    operand_type = vex_int_class(bits).type
    emitters[relation, signedness](
        emitter, emitter.mkconst(1, operand_type), emitter.mkconst(2, operand_type),
    )
    binops = [statement.data for statement in block.statements
              if isinstance(statement, pyvex.stmt.WrTmp)
              and isinstance(statement.data, pyvex.expr.Binop)]
    assert len(binops) == 1
    op = f"Iop_Cmp{relation}{bits}{signedness}"
    assert binops[0].op == op
    assert binops[0].result_type(block.tyenv) == "Ity_I1"
    assert _EFFECTS.scalar_instruction_effect_8616(_comparison(op, bits // 8)).kind is (
        _EFFECTS.ScalarInstructionEffectKind8616.CLOSED_DESTINATION
    )


@pytest.mark.parametrize("op,width", [
    ("Iop_CmpLTU16", 2), ("Iop_CmpLTS16", 2), ("Iop_CmpLEU32", 4),
    ("Iop_CmpGTU32", 4), ("Iop_CmpGES64", 8),
])
def test_non_emitter_comparison_spelling_refuses(op: str, width: int) -> None:
    """Incorrect signedness placement is not an emitter operation."""
    assert op not in pyvex.enums.enums_to_ints
    assert _EFFECTS.scalar_instruction_effect_8616(_comparison(op, width)).kind is (
        _EFFECTS.ScalarInstructionEffectKind8616.UNKNOWN
    )


def test_binary_destination_width_mismatch_refuses() -> None:
    """A 16-bit operation cannot close a declared 32-bit destination effect."""
    instruction = IRInstr(
        "Iop_Add16", IRValue(MemSpace.REG, name="ecx", size=4),
        (IRValue(MemSpace.CONST, const=1, size=2),
         IRValue(MemSpace.CONST, const=2, size=2)), size=4,
    )
    assert _EFFECTS.scalar_instruction_effect_8616(instruction).kind is (
        _EFFECTS.ScalarInstructionEffectKind8616.UNKNOWN
    )


@pytest.mark.parametrize("size", [1, 4])
def test_registered_comparison_operand_width_conflict_refuses(size: int) -> None:
    """An equality name fixes operand width independently of predicate width."""
    instruction = _comparison("Iop_CmpEQ16", size)
    assert _EFFECTS.scalar_instruction_effect_8616(instruction).kind is (
        _EFFECTS.ScalarInstructionEffectKind8616.UNKNOWN
    )


@pytest.mark.parametrize("field", ["source_tmp", "zero_width"])
def test_contradictory_register_destination_refuses(field: str) -> None:
    """A read-capture identity or zero width cannot describe a register write."""
    destination = IRValue(MemSpace.REG, name="cx", size=2)
    if field == "source_tmp":
        destination = replace(destination, source_tmp=99)
    else:
        destination = replace(destination, size=0)
    instruction = IRInstr(
        "MOV", destination,
        (IRValue(MemSpace.CONST, const=1, size=destination.size),),
        size=destination.size,
    )
    assert _EFFECTS.scalar_instruction_effect_8616(instruction).kind is (
        _EFFECTS.ScalarInstructionEffectKind8616.UNKNOWN
    )


def _control(target: IRValue) -> IRInstr:
    """Build one condition-bearing transfer with an exact supplied target."""
    return IRInstr(
        "CJMP", None, (IRCondition("eq", ()), target), size=0,
    )


def test_control_target_is_owned_by_effect_descriptor() -> None:
    """A consumer must not create a second branch-target decoding truth."""
    effect = _EFFECTS.scalar_instruction_effect_8616(_control(
        IRValue(MemSpace.CONST, const=0x12345, size=2),
    ))
    assert effect.control_target == 0x12345


@pytest.mark.parametrize("case", ["offset", "capture", "decoration", "zero_width"])
def test_contradictory_control_target_refuses(case: str) -> None:
    """A literal with a conflicting value view is not an exact CFG target."""
    target = IRValue(MemSpace.CONST, const=0x12345, size=2)
    if case == "offset":
        target = replace(target, offset=1)
    elif case == "capture":
        target = replace(target, source_tmp=99)
    elif case == "decoration":
        target = replace(target, expr=("Iop_32to16",))
    else:
        target = replace(target, size=0)
    assert _EFFECTS.scalar_instruction_effect_8616(_control(target)).kind is (
        _EFFECTS.ScalarInstructionEffectKind8616.UNKNOWN
    )
