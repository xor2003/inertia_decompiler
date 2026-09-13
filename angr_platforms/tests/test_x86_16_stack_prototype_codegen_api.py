"""Regression tests for the current angr structured-codegen allocator API."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import stack_prototype_materialization
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_cvar_for_machine_bp_range_8616,
)
from x86_16_frame_coordinate_fixtures import proven_frame_coordinate


class _CurrentAngrCodegen:
    """Expose current `next_ident`/`next_node_idx` without legacy `next_idx`."""

    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            functy=None,
            unified_local_vars={},
            variables_in_use={},
        )

    def next_ident(self, name: str) -> str:
        """Return a stable class display identity."""
        return name

    def next_node_idx(self) -> int:
        """Return one unique C AST node identity."""
        self._idx += 1
        return self._idx


def test_stack_argument_materialization_uses_current_angr_node_allocator() -> None:
    """A new BP argument must not require angr's removed `next_idx` method."""
    codegen = _CurrentAngrCodegen()

    cvar, changed = stack_prototype_materialization._ensure_arg_cvar_8616(
        codegen=codegen,
        offset=4,
        name="value",
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        width=2,
    )

    assert changed is True
    assert cvar is not None
    assert cvar.variable.offset == 4
    assert codegen.cfunc.variables_in_use[cvar.variable] is cvar


def test_stack_argument_materialization_keeps_formals_in_entry_sp_coordinates() -> None:
    """Machine-BP formals must preserve angr's distinct entry-SP coordinates."""
    codegen = _CurrentAngrCodegen()
    codegen._inertia_vex_ir_frame = proven_frame_coordinate(-2)
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    body_variable = SimStackVariable(4, 1, base="bp", name="local_6", ident="is_6")
    body_cvar = structured_c.CVariable(
        body_variable,
        variable_type=word,
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[body_variable] = body_cvar
    codegen.cfunc.arg_list = [body_cvar]
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=body_variable,
        cvar=body_cvar,
        bp_offset=6,
        entry_sp_offset=4,
        size=1,
    )

    first_formal, first_changed = stack_prototype_materialization._ensure_arg_cvar_8616(
        codegen=codegen,
        offset=4,
        name="first",
        variable_type=word,
        width=2,
    )
    formal, changed = stack_prototype_materialization._ensure_arg_cvar_8616(
        codegen=codegen,
        offset=6,
        name="second",
        variable_type=word,
        width=2,
    )

    assert first_changed is True
    assert first_formal is not None and first_formal is not body_cvar
    assert changed is True
    assert formal is body_cvar
    assert first_formal.variable.offset == 2
    assert formal.variable.offset == 4
    assert body_variable.offset == 4
    assert body_variable.size == 2
    assert machine_bp_offset_for_stack_variable_8616(codegen, first_formal.variable) == 4
    assert machine_bp_offset_for_stack_variable_8616(codegen, body_variable) == 6
    assert machine_bp_offset_for_stack_variable_8616(codegen, formal.variable) == 6
    assert stack_cvar_for_machine_bp_range_8616(codegen, 4, 2) is first_formal
    assert stack_cvar_for_machine_bp_range_8616(codegen, 6, 2) is body_cvar
    assert first_formal not in stack_prototype_materialization._iter_existing_stack_cvars_at_offset_8616(
        codegen,
        6,
    )

    codegen.cfunc.arg_list = [formal]
    replayed, replay_changed = stack_prototype_materialization._ensure_arg_cvar_8616(
        codegen=codegen,
        offset=6,
        name="second",
        variable_type=word,
        width=2,
    )

    assert replayed is formal
    assert replay_changed is False
