from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.stack_argument_identity import (
    unify_positive_bp_argument_identity_8616,
)
from angr_platforms.X86_16.lowering.stack_declaration_identity import (
    prune_unreferenced_pre_argument_declarations_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)


def _stack_cvar(
    codegen: SimpleNamespace,
    *,
    offset: int,
    size: int,
    name: str,
    base: str = "bp",
) -> CVariable:
    variable_type = SimTypeShort(False).with_arch(Arch86_16())
    return CVariable(
        SimStackVariable(offset, size, base=base, name=name, region=0x1000),
        variable_type=variable_type,
        codegen=codegen,
    )


def test_unify_prunes_unreferenced_control_slot_but_keeps_negative_local() -> None:
    codegen = _codegen()
    local = _stack_cvar(codegen, offset=-2, size=2, name="local_2")
    stale_control = _stack_cvar(codegen, offset=2, size=2, name="local_2")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([local], codegen=codegen),
        variables_in_use={
            local.variable: local,
            stale_control.variable: stale_control,
        },
        unified_local_vars={
            local.variable: {(local, local.variable_type)},
            stale_control.variable: {
                (stale_control, stale_control.variable_type)
            },
        },
    )

    declaration_count = len(codegen.cfunc.variables_in_use)
    assert unify_positive_bp_argument_identity_8616(codegen) is True
    assert list(codegen.cfunc.variables_in_use.values()) == [local]
    assert tuple(codegen.cfunc.unified_local_vars) == (local.variable,)
    stats = codegen._inertia_pre_argument_declaration_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == declaration_count
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == stats.refusal_count == 0
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_control_slot_referenced_by_body_is_retained() -> None:
    codegen = _codegen()
    control = _stack_cvar(codegen, offset=2, size=2, name="control")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([control], codegen=codegen),
        variables_in_use={control.variable: control},
        unified_local_vars={control.variable: {(control, control.variable_type)}},
    )

    assert prune_unreferenced_pre_argument_declarations_8616(codegen) is False
    assert codegen.cfunc.variables_in_use == {control.variable: control}
    stats = codegen._inertia_pre_argument_declaration_stats_8616
    assert stats.classified_fact_count == stats.materialized_count == 0


def test_control_slot_owned_by_function_header_is_retained() -> None:
    codegen = _codegen()
    header = _stack_cvar(codegen, offset=2, size=2, name="header")
    codegen.cfunc = SimpleNamespace(
        arg_list=[header],
        statements=CStatements([], codegen=codegen),
        variables_in_use={header.variable: header},
        unified_local_vars={},
    )

    assert prune_unreferenced_pre_argument_declarations_8616(codegen) is False
    assert codegen.cfunc.variables_in_use == {header.variable: header}


def test_overlapping_body_subview_refuses_owner_removal() -> None:
    codegen = _codegen()
    byte_view = _stack_cvar(codegen, offset=2, size=1, name="byte_view")
    word_owner = _stack_cvar(codegen, offset=2, size=2, name="word_owner")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([byte_view], codegen=codegen),
        variables_in_use={
            byte_view.variable: byte_view,
            word_owner.variable: word_owner,
        },
        unified_local_vars={word_owner.variable: {(word_owner, word_owner.variable_type)}},
    )

    assert prune_unreferenced_pre_argument_declarations_8616(codegen) is False
    assert word_owner.variable in codegen.cfunc.variables_in_use
    assert word_owner.variable in codegen.cfunc.unified_local_vars


def test_abi_argument_range_is_not_declaration_cleanup_owned() -> None:
    codegen = _codegen()
    argument = _stack_cvar(codegen, offset=4, size=2, name="arg_4")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([], codegen=codegen),
        variables_in_use={argument.variable: argument},
        unified_local_vars={},
    )

    assert prune_unreferenced_pre_argument_declarations_8616(codegen) is False
    assert codegen.cfunc.variables_in_use == {argument.variable: argument}


def test_positive_sp_storage_is_not_treated_as_bp_argument_identity() -> None:
    codegen = _codegen()
    header = _stack_cvar(codegen, offset=6, size=2, name="header", base="sp")
    body = _stack_cvar(codegen, offset=6, size=2, name="body", base="sp")
    statements = CStatements([body], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[header],
        statements=statements,
        variables_in_use={body.variable: body},
        unified_local_vars={},
    )

    assert unify_positive_bp_argument_identity_8616(codegen) is False
    assert statements.statements == [body]
    assert codegen.cfunc.variables_in_use == {body.variable: body}


def test_control_slot_crossing_abi_boundary_is_unknown_and_retained() -> None:
    codegen = _codegen()
    crossing = _stack_cvar(codegen, offset=3, size=2, name="crossing")
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([], codegen=codegen),
        variables_in_use={crossing.variable: crossing},
        unified_local_vars={},
    )

    assert prune_unreferenced_pre_argument_declarations_8616(codegen) is False
    assert codegen.cfunc.variables_in_use == {crossing.variable: crossing}
    stats = codegen._inertia_pre_argument_declaration_stats_8616
    assert stats.refusal_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 0


@pytest.mark.parametrize("bp_offset,entry_offset,remove", [(1, -1, True), (4, 2, False), (-1, 1, False)])
@pytest.mark.parametrize("referenced", [False, True])
def test_control_slot_cleanup_consumes_projected_coordinate(bp_offset, entry_offset, remove, referenced):
    """A negative entry-SP offset can be a control byte, not a local."""
    codegen = _codegen()
    value = _stack_cvar(codegen, offset=entry_offset, size=1, name="slot")
    codegen.cfunc = SimpleNamespace(
        arg_list=[], statements=CStatements([value] if referenced else [], codegen=codegen),
        variables_in_use={value.variable: value},
        unified_local_vars={value.variable: {(value, value.variable_type)}},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=value.variable, cvar=value, bp_offset=bp_offset,
        entry_sp_offset=entry_offset, size=1,
    )
    expected_removal = remove and not referenced
    assert prune_unreferenced_pre_argument_declarations_8616(codegen) is expected_removal
    assert (value.variable not in codegen.cfunc.variables_in_use) is expected_removal
    assert (value.variable not in codegen.cfunc.unified_local_vars) is expected_removal
