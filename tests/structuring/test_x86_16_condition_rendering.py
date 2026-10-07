from __future__ import annotations

from dataclasses import dataclass

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace

from inertia.structuring.condition_rendering import (
    render_condition_ir_8616,
    render_condition_ir_native_8616,
    render_condition_operand_8616,
)


@dataclass(frozen=True, slots=True)
class _OperandMapping:
    payload: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return self.payload


def test_x86_16_condition_rendering_uses_explicit_helpers_for_ordering() -> None:
    assert render_condition_ir_8616(ConditionIR("slt", "ax", "bx")) == "s16_lt(ax, bx)"
    assert render_condition_ir_8616(ConditionIR("ule", "ax", "0x10")) == "u16_le(ax, 0x10)"


def test_x86_16_condition_rendering_uses_native_operators_after_type_proof() -> None:
    assert render_condition_ir_native_8616(ConditionIR("slt", "ax", "bx")) == "ax < bx"
    assert render_condition_ir_native_8616(ConditionIR("uge", "ax", "bx")) == "ax >= bx"


def test_x86_16_condition_rendering_handles_zero_and_equality_conditions() -> None:
    assert render_condition_ir_8616(ConditionIR("zero", "ax")) == "ax == 0"
    assert render_condition_ir_8616(ConditionIR("nonzero", "ax")) == "ax != 0"
    assert render_condition_ir_8616(ConditionIR("eq", "ax", "bx")) == "ax == bx"
    assert render_condition_ir_native_8616(ConditionIR("ne", "ax", "bx")) == "ax != bx"


def test_x86_16_condition_rendering_formats_operands_from_typed_ir_values() -> None:
    assert render_condition_operand_8616(IRValue(MemSpace.REG, name="ax", size=2)) == "ax"
    assert render_condition_operand_8616(IRValue(MemSpace.CONST, const=7, size=2)) == "7"


def test_x86_16_condition_rendering_formats_plain_operands() -> None:
    assert render_condition_operand_8616(None) == "0"
    assert render_condition_operand_8616(16) == "0x10"
    assert render_condition_operand_8616(-2) == "-2"


def test_x86_16_condition_rendering_formats_protocol_operands() -> None:
    assert render_condition_operand_8616(_OperandMapping({"space": "reg", "name": "cx"})) == "cx"
    assert render_condition_operand_8616(_OperandMapping({"space": "const", "const": 3})) == "3"
    assert render_condition_operand_8616(_OperandMapping({"space": "ds", "offset": 0x20})) == (
        "{'space': 'ds', 'offset': 32}"
    )


def test_x86_16_condition_rendering_refuses_unsupported_ops() -> None:
    assert render_condition_ir_8616(ConditionIR("and", "ax", "bx")) is None
    assert render_condition_ir_native_8616(ConditionIR("or", "ax", "bx")) is None
