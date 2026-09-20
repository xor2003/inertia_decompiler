from __future__ import annotations

import operator
from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.ir.condition_value_extensions import sign_extend_condition_value_8616
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRValue, MemSpace
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY, _ConditionRegisterValueState8616

DWORD_BYTES = 4


def _evaluate(value, memory_value):
    if isinstance(value, IRValue):
        if value.space is MemSpace.CONST:
            return value.const
        assert value.space is MemSpace.DS
        return memory_value & ((1 << (value.size * 8)) - 1)
    assert isinstance(value, IRBinaryValue)
    operation = {"and": operator.and_, "xor": operator.xor, "sub": operator.sub}[value.op]
    return operation(_evaluate(value.lhs, memory_value), _evaluate(value.rhs, memory_value))


def _widen(monkeypatch, source_size, destination):
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4012
    instruction.cs = SimpleNamespace(size=1)
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)
    source = IRValue(MemSpace.DS, offset=0x200, size=source_size,
                     memory_access_size=source_size, memory_access_insn=0x4010)
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {
        (0x4000, "ax"): _ConditionRegisterValueState8616(source, 0x4012),
    })
    instruction._widen_condition_reg_value_state_8616(destination)
    return Instruction_ANY._inertia_condition_reg_value_state_8616.get((0x4000, destination))


def test_cbw_preserves_signed_value_and_byte_access(monkeypatch):
    state = _widen(monkeypatch, 1, "ax")
    assert state is not None
    for byte in range(256):
        expected = int.from_bytes(bytes([byte]), byteorder="little", signed=True)
        # A nonzero neighboring byte must not become part of the original load.
        assert _evaluate(state.value, 0x5A00 | byte) == expected


@pytest.mark.parametrize("word", [0, 1, 0x7FFF, 0x8000, 0xFFFF])
def test_cwde_uses_ax_provenance_and_preserves_sign(monkeypatch, word):
    state = _widen(monkeypatch, 2, "eax")
    assert state is not None
    assert state.value.size == DWORD_BYTES
    expected = int.from_bytes(word.to_bytes(2, "little"), "little", signed=True)
    assert _evaluate(state.value, word) == expected


def test_cbw_refuses_word_provenance(monkeypatch):
    assert _widen(monkeypatch, 2, "ax") is None


def test_chained_cbw_cwde_preserves_negative_value(monkeypatch):
    state = _widen(monkeypatch, 1, "ax")
    assert state is not None
    extended = sign_extend_condition_value_8616(state.value, DWORD_BYTES)
    assert extended is not None
    for byte in range(256):
        expected = int.from_bytes(bytes([byte]), "little", signed=True)
        assert _evaluate(extended, byte) == expected


@pytest.mark.parametrize("source_size,destination_size", [(0, 2), (1, 1), (2, 1), (4, 2), (1, 4)])
def test_unproven_width_conversion_is_refused(source_size, destination_size):
    value = IRValue(MemSpace.REG, name="ax", size=source_size)
    assert sign_extend_condition_value_8616(value, destination_size) is None


@pytest.mark.parametrize("source_size,destination_size", [(1, 2), (2, 4)])
def test_signed_extension_ir_projects_to_exact_casts(source_size, destination_size):
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CTypeCast
    from angr.sim_type import SimTypeShort
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.structuring.condition_binary_value import materialize_binary_ir_value_8616

    source = IRValue(MemSpace.DS, offset=0x200, size=source_size, memory_access_size=source_size)
    value = sign_extend_condition_value_8616(source, destination_size)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), next_ident=lambda name: name,
        next_node_idx=lambda: 0, cstyle_null_cmp=False,
    )
    projected_source = CConstant(255, SimTypeShort(False), codegen=codegen)
    visited = []

    def lower(operand):
        visited.append(operand)
        if isinstance(operand, IRBinaryValue):
            return materialize_binary_ir_value_8616(operand, codegen, lower)
        return projected_source if operand is source else CConstant(operand.const, SimTypeShort(False), codegen=codegen)

    result = materialize_binary_ir_value_8616(value, codegen, lower)
    assert isinstance(result, CTypeCast), type(result)
    assert result.dst_type.size == destination_size * 8
    assert result.dst_type.signed
    assert isinstance(result.expr, CTypeCast)
    assert result.expr.dst_type.size == source_size * 8
    assert result.expr.dst_type.signed
    assert result.expr.expr is projected_source
    assert visited == [source]
    assert not isinstance(result, CBinaryOp)


@pytest.mark.parametrize("mutation", ["sign", "mask", "operation", "width", "source_width"])
def test_signed_extension_proof_refuses_near_matches(mutation):
    from angr_platforms.X86_16.ir.condition_value_extensions import signed_extension_source_8616

    source = IRValue(MemSpace.DS, offset=0x200, size=1)
    value = sign_extend_condition_value_8616(source, 2)
    if mutation == "sign":
        value = replace(value, rhs=replace(value.rhs, const=127))
    elif mutation == "mask":
        mask = replace(value.lhs.lhs, rhs=replace(value.lhs.lhs.rhs, const=127))
        value = replace(value, lhs=replace(value.lhs, lhs=mask))
    elif mutation == "operation":
        value = replace(value, op="add")
    elif mutation == "width":
        value = replace(value, size=4)
    else:
        mask = replace(value.lhs.lhs, lhs=replace(source, size=2))
        value = replace(value, lhs=replace(value.lhs, lhs=mask))
    assert signed_extension_source_8616(value) is None


def test_readability_oracle_rejects_legacy_arithmetic(monkeypatch):
    from angr_platforms.X86_16.structuring import condition_binary_value

    monkeypatch.setattr(condition_binary_value, "materialize_signed_condition_value_8616", lambda *_args: None)
    with pytest.raises(AssertionError, match="CBinaryOp"):
        test_signed_extension_ir_projects_to_exact_casts(1, 2)
