"""Exact captured bit producer and corrupted unary census controls."""
from dataclasses import replace

import pytest
from inertia.ir.core import IRActiveUnary8616, IRInstr, IRValue, MemSpace
from inertia.ir.scalar_definitions import ScalarDefinition8616, scalar_definition_key_8616
from inertia.ir.stack_argument_modular_use_flow import _scalar_use_tainted_8616


def _case():
    word = IRValue(MemSpace.TMP, size=4, source_tmp=3)
    bit = IRValue(MemSpace.TMP, size=1, expr=("Iop_32to1",), active_unary=IRActiveUnary8616("Iop_32to1", word, 1))
    captured = replace(bit, source_tmp=4, active_unary=None)
    definition = ScalarDefinition8616(0x1000, 1, IRInstr("MOV", captured, (bit,), size=1))
    value = IRValue(MemSpace.TMP, size=2, active_unary=IRActiveUnary8616("Iop_1Uto16", captured, 16))
    return value, definition, {scalar_definition_key_8616(captured): (definition,)}


def test_captured_bit_reaches_exact_tainted_producer():
    value, _definition, definitions = _case()
    assert _scalar_use_tainted_8616(value, definitions, {(0x1000, 1)}, block_addr=0x1000, before_index=2) == (True, True)


@pytest.mark.parametrize("corruption", ["missing", "foreign_block", "wrong_width", "wrong_operand", "conflict", "decoration"])
def test_corrupt_bit_proof_refuses(corruption):
    value, definition, definitions = _case()
    key = next(iter(definitions))
    if corruption == "missing":
        definitions = {}
    elif corruption == "foreign_block":
        definitions[key] = (replace(definition, block_addr=0x2000),)
    elif corruption == "conflict":
        definitions[key] = (definition, definition)
    else:
        source = definition.instruction.args[0]
        if corruption == "wrong_width":
            source = replace(source, active_unary=replace(source.active_unary, result_bits=8))
        elif corruption == "wrong_operand":
            source = replace(source, active_unary=replace(source.active_unary, operand=replace(source.active_unary.operand, size=2)))
        else:
            source = replace(source, expr=("Iop_Not8",))
        definitions[key] = (replace(definition, instruction=replace(definition.instruction, args=(source,))),)
    assert _scalar_use_tainted_8616(value, definitions, {(0x1000, 1)}, block_addr=0x1000, before_index=2) == (False, False)


@pytest.mark.parametrize("corruption", [None, "wrong_operand_width", "wrong_result_width", "wrong_operation", "missing_producer"])
def test_comparison_bit_width_requires_exact_producer(corruption):
    captured = IRValue(MemSpace.TMP, size=1, expr=("Iop_CmpEQ16",), source_tmp=9)
    source = IRValue(MemSpace.REG, size=2, name="ax", version=0)
    instruction = IRInstr("Iop_CmpEQ16", captured, (source, source), size=1)
    if corruption == "wrong_operand_width":
        instruction = replace(instruction, args=(replace(source, size=1), source))
    elif corruption == "wrong_result_width":
        instruction = replace(instruction, dst=replace(captured, size=2))
    elif corruption == "wrong_operation":
        instruction = replace(instruction, op="Iop_Add16")
    definition = ScalarDefinition8616(0x1000, 1, instruction)
    definitions = {scalar_definition_key_8616(captured): (definition,)}
    if corruption == "missing_producer":
        definitions = {}
    value = IRValue(MemSpace.TMP, size=2, active_unary=IRActiveUnary8616("Iop_1Uto16", captured, 16))
    expected = (True, True) if corruption is None else (False, False)
    assert _scalar_use_tainted_8616(value, definitions, {(0x1000, 1)}, block_addr=0x1000, before_index=2) == expected


@pytest.mark.parametrize("corruption", [None, "wrong_result_width", "wrong_operand_width", "pinned_wrapper", "wrong_decoration"])
def test_bitwise_not_is_dependency_not_identity(corruption):
    source = IRValue(MemSpace.TMP, size=1, source_tmp=7)
    value = IRValue(MemSpace.TMP, size=1, active_unary=IRActiveUnary8616("Iop_Not8", source, 8))
    definition = ScalarDefinition8616(0x1000, 1, IRInstr("MOV", source, (IRValue(MemSpace.CONST, size=1, const=0),), size=1))
    if corruption == "wrong_result_width":
        value = replace(value, size=2)
    elif corruption == "wrong_operand_width":
        value = replace(value, active_unary=replace(value.active_unary, operand=replace(source, size=2)))
    elif corruption == "pinned_wrapper":
        value = replace(value, source_tmp=7)
    elif corruption == "wrong_decoration":
        value = replace(value, expr=("Iop_8Uto16",))
    definitions = {scalar_definition_key_8616(source): (definition,)}
    expected = (True, True) if corruption is None else (False, False)
    assert _scalar_use_tainted_8616(value, definitions, {(0x1000, 1)}, block_addr=0x1000, before_index=2) == expected
