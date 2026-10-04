"""Binary-only callback-address evidence for direct stack moves."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
    _direct_stack_near_function_pointer_expr_8616,
)

from inertia_decompiler.project_loading import _build_project_from_bytes


def _binary_project(*, indirect_callee: bool = True, far_callee: bool = False):
    """Build a tiny source-free code image with one callback consumer."""
    image = bytearray(0x100)
    if far_callee:
        callee = "55 8b ec ff 76 0a ff 5e 06 83 c4 02 5d cb"
    elif indirect_callee:
        callee = "55 8b ec ff 76 06 ff 56 04 83 c4 02 5d c3"
    else:
        callee = "55 8b ec 8b 46 06 83 c4 02 5d c3 90 90 90"
    image[0x40:0x4e] = bytes.fromhex(callee)
    image[0x80:0x89] = bytes.fromhex("55 8b ec 8b 46 04 40 5d c3")
    return _build_project_from_bytes(bytes(image), base_addr=0x1000, entry_point=0x1040)


def _callback_assignment_inputs(project):
    """Expose one exact stack value passed as the callee's first argument."""
    summary = CallsiteSummary8616(
        callsite_addr=0x1020,
        target_addr=0x1040,
        return_addr=0x1023,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("bp", 6, 2), ("bp", -2, 2)),
    )
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=0x1010),
        _inertia_callsite_summary_inventory_8616={summary.callsite_addr: summary},
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
    )
    variable = SimStackVariable(-2, 2, base="bp", name="fn", region=0x1010)
    destination = CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    fact = DirectStackMoveFact8616(
        dst_offset=-2,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
        ins_addr=0x1018,
        source_value=0x80,
    )
    return codegen, destination, fact


def test_source_free_callback_immediate_becomes_function_identity() -> None:
    """A proven indirect-call parameter must rebind its near code offset."""
    codegen, destination, fact = _callback_assignment_inputs(_binary_project())

    expression = _direct_stack_near_function_pointer_expr_8616(codegen, fact, destination)

    assert isinstance(expression, CVariable)
    assert expression.variable.name == "sub_1080"
    assert expression.variable.addr == 0x1080
    assert isinstance(destination.variable_type, SimTypePointer)
    assert isinstance(destination.variable_type.pts_to, SimTypeFunction)
    assert len(destination.variable_type.pts_to.args) == 1
    assert isinstance(destination.variable_type.pts_to.args[0], SimTypeShort)
    assert isinstance(destination.variable_type.pts_to.returnty, SimTypeShort)


def test_immediate_code_address_refuses_without_indirect_callee_proof() -> None:
    """Executable-looking bytes alone do not prove a callback type."""
    codegen, destination, fact = _callback_assignment_inputs(_binary_project(indirect_callee=False))

    assert _direct_stack_near_function_pointer_expr_8616(codegen, fact, destination) is None
    assert isinstance(destination.variable_type, SimTypeShort)


def test_near_stack_constant_refuses_far_indirect_callee() -> None:
    """A far callee parameter cannot justify a two-byte near callback value."""
    codegen, destination, fact = _callback_assignment_inputs(_binary_project(far_callee=True))

    assert _direct_stack_near_function_pointer_expr_8616(codegen, fact, destination) is None
    assert isinstance(destination.variable_type, SimTypeShort)
