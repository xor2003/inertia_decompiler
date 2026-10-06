"""Capture identity and pending byte projection refusal controls."""
from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import IRActiveUnary8616, IRValue, MemSpace
from angr_platforms.X86_16.lowering.interprocedural_storage_physical_defs import (
    _logical_source_slice_8616,
    _same_logical_root_8616,
    logical_push_value_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_reaching_contracts import (
    PhysicalCallArgumentPiece8616,
    SSAInstructionSite8616,
)
from x86_16_native_call_fixtures import lift_native_call_fixture_8616


@pytest.fixture(scope="module")
def traced_push():
    artifact = lift_native_call_fixture_8616(bytes.fromhex("8d46fc50e80000")).ssa
    sites = tuple(SSAInstructionSite8616(block, index, instr) for block in artifact.blocks for index, instr in enumerate(block.instrs))
    logical, failure = logical_push_value_8616(sites, PhysicalCallArgumentPiece8616(width=2, source=(), push_addr=0x1003))
    assert failure is None and logical is not None and logical.complete
    low, high = logical.slices
    left = _logical_source_slice_8616(low.site, low.value, 2)
    right = _logical_source_slice_8616(high.site, high.value, 2)
    assert left is not None and right is not None
    return left[0], right[0], low.site, high.site


def test_same_captured_producer_survives_incidental_ssa_version(traced_push):
    left, right, low_site, high_site = traced_push
    assert left.source_tmp == right.source_tmp and left.source_tmp is not None
    assert _same_logical_root_8616(left, replace(right, version=123), 2, low_site, high_site)


@pytest.mark.parametrize("corruption", ["missing_capture", "different_capture", "displaced", "wrong_width", "false_decoration", "active", "missing_producer", "foreign_producer"])
def test_capture_identity_needs_closed_exact_producer(traced_push, corruption):
    left, right, low_site, high_site = traced_push
    if corruption == "missing_capture":
        right = replace(right, source_tmp=None)
    elif corruption == "different_capture":
        right = replace(right, source_tmp=99999)
    elif corruption == "displaced":
        right = replace(right, offset=right.offset + 1)
    elif corruption == "wrong_width":
        right = replace(right, size=1)
    elif corruption == "false_decoration":
        right = replace(right, expr=("Iop_Not16",))
    elif corruption == "active":
        right = replace(right, active_unary=IRActiveUnary8616("Iop_Not16", right, 16))
    else:
        instructions = tuple(
            (replace(instr) if corruption == "foreign_producer" else replace(instr, dst=None))
            if instr.dst is not None and instr.dst.source_tmp == right.source_tmp else instr
            for instr in high_site.block.instrs
        )
        high_site = replace(high_site, block=replace(high_site.block, instrs=instructions))
    assert not _same_logical_root_8616(left, right, 2, low_site, high_site)


@pytest.mark.parametrize("corruption", ["pinned", "wrong_width", "not", "widen", "missing_operand"])
def test_pending_store_projection_never_fabricates_producer(traced_push, corruption):
    left, _, site, _ = traced_push
    value = IRValue(MemSpace.TMP, size=1, expr=("Iop_16to8",), active_unary=IRActiveUnary8616("Iop_16to8", left, 8))
    if corruption == "pinned":
        value = replace(value, source_tmp=left.source_tmp)
    elif corruption == "wrong_width":
        value = replace(value, active_unary=replace(value.active_unary, result_bits=16))
    elif corruption == "not":
        value = replace(value, expr=("Iop_Not8",), active_unary=replace(value.active_unary, op="Iop_Not8"))
    elif corruption == "widen":
        value = replace(value, size=4, expr=("Iop_16Uto32",), active_unary=replace(value.active_unary, op="Iop_16Uto32", result_bits=32))
    else:
        value = replace(value, active_unary=replace(value.active_unary, operand=IRValue(MemSpace.TMP, size=2, source_tmp=99999)))
    assert _logical_source_slice_8616(site, value, 2) is None
