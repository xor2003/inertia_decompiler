"""Exact pending extraction remains connected to its captured source definition."""
from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import IRActiveUnary8616, IRValue, MemSpace
from angr_platforms.X86_16.ir.indexed_address_copy_contracts import (
    IndexedAddressCopyStep8616,
    IndexedAddressCopyStepKind8616,
)


def _step():
    source = IRValue(MemSpace.TMP, size=2, source_tmp=7)
    expression = IRValue(MemSpace.TMP, size=1, expr=("Iop_16to8",), active_unary=IRActiveUnary8616("Iop_16to8", source, 8))
    destination = IRValue(MemSpace.TMP, size=1, source_tmp=8)
    return IndexedAddressCopyStep8616(0x1000, 2, 0x1000, "MOV", IndexedAddressCopyStepKind8616.LOW_BYTE_EXTRACT, destination, expression, source)


def test_pending_extraction_retains_capture_identity():
    step = _step()
    assert step.complete
    assert step.source_expression.source_tmp is None
    assert step.source_expression.active_unary.operand is step.source_definition


@pytest.mark.parametrize("corruption", ["source", "source_width", "result_width", "bits", "pin", "op", "move"])
def test_corrupt_projection_step_refuses(corruption):
    step = _step()
    expression = step.source_expression
    if corruption == "source":
        step = replace(step, source_definition=replace(step.source_definition, source_tmp=99))
    elif corruption == "source_width":
        step = replace(step, source_definition=replace(step.source_definition, size=4))
    elif corruption == "result_width":
        step = replace(step, defined_value=replace(step.defined_value, size=2))
    elif corruption == "bits":
        step = replace(step, source_expression=replace(expression, active_unary=replace(expression.active_unary, result_bits=16)))
    elif corruption == "pin":
        step = replace(step, source_expression=replace(expression, source_tmp=7))
    elif corruption == "op":
        step = replace(step, source_expression=replace(expression, active_unary=replace(expression.active_unary, op="Iop_Not8")))
    else:
        step = replace(step, kind=IndexedAddressCopyStepKind8616.MOVE, defined_value=replace(step.defined_value, size=2))
    assert not step.complete
