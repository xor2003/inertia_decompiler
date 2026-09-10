from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.ailment.expression import StackBaseOffset, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.ssailification.rewriting_engine import SimEngineSSARewriting
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.ir.native_stack_anchor import (
    NATIVE_ENTRY_SP_ANCHOR_TAG8616,
    native_stack_anchor_8616,
)
from angr_platforms.X86_16.lowering.stack_address_coordinates import machine_bp_offset_for_native_anchor_8616
from angr_platforms.X86_16.stack_anchor_compat import (
    apply_native_stack_anchor_compatibility_8616,
    publish_native_stack_anchor_8616,
)
from test_x86_16_stack_address_coordinates import _Codegen, _frame


@pytest.mark.parametrize("offset", [-2, 0, 65535])
def test_exact_native_reference_publishes_source_coordinate(offset):
    source = StackBaseOffset(1, 16, offset)
    variable = VirtualVariable(2, 7, 16, VirtualVariableCategory.STACK, oident=source.offset)
    result = UnaryOp(3, "Reference", variable, bits=16)
    assert publish_native_stack_anchor_8616(source, result)
    anchor = native_stack_anchor_8616(result.tags)
    assert anchor is not None and anchor.entry_sp_offset == source.offset
    assert result.operand == variable


@pytest.mark.parametrize("kind,offset,op", [
    (VirtualVariableCategory.REGISTER, -2, "Reference"),
    (VirtualVariableCategory.STACK, -4, "Reference"),
    (VirtualVariableCategory.STACK, -2, "Neg"),
])
def test_nonexact_replacements_are_not_annotated(kind, offset, op):
    result = UnaryOp(3, op, VirtualVariable(2, 7, 16, kind, oident=offset), bits=16)
    assert not publish_native_stack_anchor_8616(StackBaseOffset(1, 16, -2), result)
    assert native_stack_anchor_8616(result.tags) is None


@pytest.mark.parametrize("value", [None, True, "-2", -2.0])
def test_malformed_provenance_is_refused(value):
    assert native_stack_anchor_8616({NATIVE_ENTRY_SP_ANCHOR_TAG8616: value}) is None


def test_incomplete_frame_cannot_translate_native_anchor():
    frame = _frame()
    stats = replace(frame.bp_coordinate.stats, materialized_count=0)
    frame = replace(frame, bp_coordinate=replace(frame.bp_coordinate, stats=stats))
    codegen = _Codegen(_inertia_vex_ir_frame=frame)
    variable = SimStackVariable(-2, 1, base="bp")
    reference = structured_c.CUnaryOp(
        "Reference", structured_c.CVariable(variable, codegen=codegen), codegen=codegen,
        tags={NATIVE_ENTRY_SP_ANCHOR_TAG8616: -2},
    )
    assert machine_bp_offset_for_native_anchor_8616(codegen, reference) is None


@pytest.mark.parametrize("arch_name", ["86_16", "AMD64"])
def test_hook_is_architecture_scoped_and_idempotent(monkeypatch, arch_name):
    source = StackBaseOffset(1, 16, -2)
    result = UnaryOp(3, "Reference", VirtualVariable(
        2, 7, 16, VirtualVariableCategory.STACK, oident=-2,
    ), bits=16)
    calls = []

    def original(engine, expr):
        calls.append(expr)
        return result

    monkeypatch.setattr(SimEngineSSARewriting, "_handle_expr_StackBaseOffset", original)
    apply_native_stack_anchor_compatibility_8616()
    installed = SimEngineSSARewriting._handle_expr_StackBaseOffset
    apply_native_stack_anchor_compatibility_8616()
    assert SimEngineSSARewriting._handle_expr_StackBaseOffset is installed
    engine = SimpleNamespace(project=SimpleNamespace(arch=SimpleNamespace(name=arch_name)))
    assert installed(engine, source) is result
    assert calls == [source]
    assert (native_stack_anchor_8616(result.tags) is not None) == (arch_name == "86_16")
    if arch_name == "86_16":
        stats = engine._inertia_native_anchor_stats_8616
        assert (stats.raw_fact_count, stats.normalized_fact_count, stats.classified_fact_count,
                stats.materialized_count, stats.failure_count) == (1, 1, 1, 1, 0)
