from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import stack_prototype_materialization as prototype_lowering
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    reconcile_exact_stack_argument_prototype_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    StackCoordinateProducer8616,
    bind_stack_variable_coordinate_cvar_8616,
    publish_selected_stack_cvar_projection_8616,
    refresh_stack_variable_coordinate_cvar_8616,
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.widening.stack_argument_widths import WideStackArgumentWidthEvidence8616
from test_x86_16_stack_argument_widths import (
    _closed_one_long_argument_evidence,
    _short_parameter_fixture,
    _surplus_long_parameter_fixture,
)

FUNCTION_ADDRESS = 0x1000
FIRST_ARGUMENT_BP_OFFSET = 4
FIRST_ARGUMENT_ENTRY_SP_OFFSET = 2
WIDE_ARGUMENT_BYTES = 4


@pytest.mark.parametrize("entry_sp_offset", [2, 0, -2])
def test_reconcile_uses_registered_bp_coordinate_for_width_and_name(monkeypatch, entry_sp_offset):
    project, codegen, function = _short_parameter_fixture()
    cvar = codegen.cfunc.arg_list[0]
    cvar.variable.offset = entry_sp_offset
    cvar.variable.name = "arg_2"
    codegen.cfunc.functy.arg_names = ("arg_2",)
    assert publish_selected_stack_cvar_projection_8616(
        codegen, cvar, bp_offset=4, size=2, entry_sp_offset=entry_sp_offset,
    ) is not None
    bind_stack_variable_coordinate_cvar_8616(
        codegen, bp_offset=4, size=2, cvar=cvar,
        producer=StackCoordinateProducer8616.CALL_OUTPUT_OBJECT,
    )
    monkeypatch.setattr(
        prototype_lowering, "collect_wide_stack_argument_width_evidence_8616",
        lambda *_args: WideStackArgumentWidthEvidence8616(1, 1, (4,)),
    )
    assert reconcile_exact_stack_argument_prototype_8616(project, codegen)
    assert isinstance(function.prototype.args[0], SimTypeLong)
    assert cvar.variable.offset == entry_sp_offset
    assert cvar.variable.size == WIDE_ARGUMENT_BYTES
    assert cvar.variable.name == "arg_4"
    assert codegen._inertia_function_parameter_width_facts_8616[0].stack_offset == FIRST_ARGUMENT_BP_OFFSET
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(cvar.variable)
    assert projection is not None
    assert projection.size == cvar.variable.size
    assert projection.display_name == cvar.variable.name
    assert projection.entry_sp_offset == entry_sp_offset
    assert projection.producer is StackCoordinateProducer8616.CALL_OUTPUT_OBJECT


@pytest.mark.parametrize("surplus_is_read", [False, True])
def test_incoming_selection_uses_bp_registry_and_keeps_uncovered_reads(monkeypatch, surplus_is_read):
    project, codegen, _function = _surplus_long_parameter_fixture()
    for bp_offset, cvar in zip((4, 8), codegen.cfunc.arg_list, strict=True):
        cvar.variable.offset = bp_offset - 2
        assert publish_selected_stack_cvar_projection_8616(
            codegen, cvar, bp_offset=bp_offset, size=4, entry_sp_offset=bp_offset - 2,
        ) is not None
    monkeypatch.setattr(
        prototype_lowering, "collect_callee_argument_width_evidence_8616",
        lambda *_args: _closed_one_long_argument_evidence(),
    )
    monkeypatch.setattr(
        prototype_lowering, "collect_wide_stack_argument_width_evidence_8616",
        lambda *_args: WideStackArgumentWidthEvidence8616(1, 1, (4,)),
    )
    accesses = {4: 2, 6: 2} | ({8: 2} if surplus_is_read else {})
    monkeypatch.setattr(
        prototype_lowering, "collect_bp_stack_access_widths_from_instructions_8616",
        lambda *_args: accesses,
    )
    assert reconcile_exact_stack_argument_prototype_8616(project, codegen) is (not surplus_is_read)
    assert len(codegen.cfunc.arg_list) == (2 if surplus_is_read else 1)
    assert codegen.cfunc.arg_list[0].variable.offset == FIRST_ARGUMENT_ENTRY_SP_OFFSET


def test_equal_argument_count_does_not_prove_matching_incoming_layout(monkeypatch):
    project, codegen, function = _surplus_long_parameter_fixture()
    original_prototype = function.prototype
    original_sizes = tuple(cvar.variable.size for cvar in codegen.cfunc.arg_list)
    monkeypatch.setattr(
        prototype_lowering, "accepted_stack_input_layout_8616",
        lambda *_args: ((4, 2), (6, 4)),
    )
    monkeypatch.setattr(
        prototype_lowering, "collect_bp_stack_access_widths_from_instructions_8616",
        lambda *_args: {4: 2, 6: 2, 8: 2},
    )
    assert not reconcile_exact_stack_argument_prototype_8616(project, codegen)
    assert function.prototype is original_prototype
    assert tuple(cvar.variable.size for cvar in codegen.cfunc.arg_list) == original_sizes


def test_narrowing_cannot_orphan_a_decoded_body_read(monkeypatch):
    project, codegen, function = _surplus_long_parameter_fixture()
    original_prototype = function.prototype
    original_sizes = tuple(cvar.variable.size for cvar in codegen.cfunc.arg_list)
    monkeypatch.setattr(prototype_lowering, "_callsite_stack_arg_widths_8616", lambda *_args: {4: 2})
    monkeypatch.setattr(
        prototype_lowering, "collect_bp_stack_access_widths_from_instructions_8616",
        lambda *_args: {4: 2, 6: 2},
    )
    assert not reconcile_exact_stack_argument_prototype_8616(project, codegen)
    assert function.prototype is original_prototype
    assert tuple(cvar.variable.size for cvar in codegen.cfunc.arg_list) == original_sizes


def test_narrow_value_refresh_preserves_its_physical_argument_slot():
    project, codegen, _function = _short_parameter_fixture()
    cvar = codegen.cfunc.arg_list[0]
    slot_size = cvar.variable.size
    assert publish_selected_stack_cvar_projection_8616(codegen, cvar, bp_offset=4, size=slot_size) is not None
    cvar.variable_type = SimTypeChar().with_arch(project.arch)
    cvar.variable.size = 1
    refresh_stack_variable_coordinate_cvar_8616(codegen, cvar)
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(cvar.variable)
    assert projection is not None
    assert projection.size == slot_size
    assert projection.value_size == cvar.variable.size


def test_reconcile_refuses_wrapped_negative_local_byte_carriers_as_arguments() -> None:
    arch = Arch86_16()
    char_type = SimTypeChar().with_arch(arch)
    prototype = SimTypeFunction(
        [char_type, char_type],
        SimTypeShort(False),
        arg_names=("carrier_lo", "carrier_hi"),
    ).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: function if addr == FUNCTION_ADDRESS else None,
            )
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    carriers = [
        structured_c.CVariable(
            SimStackVariable(offset, 1, base="bp", name=name, region=0x1000),
            variable_type=char_type,
            codegen=c_codegen,
        )
        for offset, name in ((0xFFF8, "carrier_lo"), (0xFFF9, "carrier_hi"))
    ]
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=carriers,
        functy=prototype,
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_callsite_summaries={})

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is False
    assert not hasattr(codegen, "_inertia_function_parameter_width_facts_8616")
    assert tuple(cfunc.functy.args) == (char_type, char_type)
