"""Types/Lowering regressions for projected stack argument identity."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import (
    CallsiteReturnUseKind8616,
)
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.call_return_stack_bindings import (
    CallReturnStackBindingStatus8616,
    bind_call_return_stack_assignment_8616,
)
from angr_platforms.X86_16.lowering.positive_bp_arguments import (
    materialize_positive_bp_arguments_8616,
)
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    _stack_offset_for_cvar_8616,
)
from angr_platforms.X86_16.lowering.stack_argument_identity import (
    unify_positive_bp_argument_identity_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering import (
    _canonicalize_stack_cvar_expr,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_cvar_for_machine_bp_range_8616,
)
from angr_platforms.X86_16.structuring.condition_lowering import (
    stable_stack_condition_binding_tags_8616,
)


def _codegen_boundary(arch: Arch86_16) -> SimpleNamespace:
    """Return the minimal dynamic angr codegen boundary used by these tests."""
    return SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
        next_ident=lambda name: name,
        next_node_idx=lambda: 1,
    )


@pytest.mark.parametrize("ownership", ["argument", "live_key", "unified_key", "other_member", "mixed", "empty", "malformed"])
def test_argument_member_retires_only_unowned_stale_declaration_key(ownership):
    arch = Arch86_16()
    codegen = _codegen_boundary(arch)
    word = SimTypeShort(False).with_arch(arch)
    argument = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6", region=0x1000),
        variable_type=word, codegen=codegen,
    )
    stale = SimStackVariable(6, 1, base="bp", name="arg_6", region=0x1000)
    local = structured_c.CVariable(stale, variable_type=word, codegen=codegen)
    if ownership == "unified_key":
        local = structured_c.CVariable(
            SimStackVariable(-8, 1, base="bp", name="local", region=0x1000),
            unified_variable=stale, variable_type=word, codegen=codegen,
        )
    members = [(argument, word)]
    if ownership == "other_member":
        members = [(local, word)]
    elif ownership == "mixed":
        members.append((local, word))
    elif ownership == "empty":
        members = []
    elif ownership == "malformed":
        members = [(argument,)]
    body = [argument, local] if ownership in {"live_key", "unified_key"} else [argument]
    root = structured_c.CStatements(body, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument], statements=root,
        variables_in_use={argument.variable: argument},
        unified_local_vars={stale: members},
    )

    unify_positive_bp_argument_identity_8616(codegen)

    assert (stale not in codegen.cfunc.unified_local_vars) == (ownership == "argument")
    assert root.statements == body
    assert codegen.cfunc.arg_list == [argument]


def test_projected_entry_sp_argument_materializes_by_machine_bp_identity() -> None:
    """Keep one BP+4 argument when its body variable is stored at entry-SP+2."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction([word_type, word_type], word_type).with_arch(arch)
    function = SimpleNamespace(
        prototype=prototype,
        prototype_source=PrototypeSource.GUESSED,
        is_prototype_guessed=True,
    )
    codegen = _codegen_boundary(arch)
    codegen.project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr, create=False: function)
    )
    projected = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="stack_sp_p2_2", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    raw_clone = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="local_4", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    duration = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    duration_snapshot = SimStackVariable(
        4,
        2,
        base="bp",
        name="duration_snapshot",
        region=0x1000,
    )
    duration_snapshot_view = structured_c.CVariable(
        duration_snapshot,
        variable_type=word_type,
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [projected, raw_clone, duration],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[raw_clone, duration],
        functy=prototype,
        prototype=prototype,
        statements=statements,
        variables_in_use={
            projected.variable: projected,
            raw_clone.variable: raw_clone,
            duration.variable: duration,
        },
        unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected.variable,
        cvar=projected,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )

    assert materialize_positive_bp_arguments_8616(codegen.project, codegen) is True
    assert codegen.cfunc.arg_list == [raw_clone, duration]
    assert tuple(codegen.cfunc.functy.arg_names or ()) == ("arg_4", "arg_6")
    assert stack_cvar_for_machine_bp_range_8616(codegen, 4, 2) is raw_clone
    assert stack_cvar_for_machine_bp_range_8616(codegen, 6, 2) is duration
    assert machine_bp_offset_for_stack_variable_8616(codegen, duration.variable) == 6
    statements.statements[-1] = duration_snapshot_view
    codegen.cfunc.variables_in_use = {
        projected.variable: raw_clone,
        duration_snapshot: duration,
    }
    assert unify_positive_bp_argument_identity_8616(codegen) is True
    assert machine_bp_offset_for_stack_variable_8616(codegen, duration_snapshot) == 6
    assert all(
        isinstance(item, structured_c.CVariable)
        and item.variable in {raw_clone.variable, duration.variable}
        for item in statements.statements
    )


def test_near_pointer_argument_uses_projected_machine_bp_identity() -> None:
    """Join a raw entry-SP+4 C variable to the BP+6 pointer fact."""
    arch = Arch86_16()
    codegen = _codegen_boundary(arch)
    pointer_carrier = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=pointer_carrier.variable,
        cvar=pointer_carrier,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )

    assert _stack_offset_for_cvar_8616(pointer_carrier, codegen) == 6


def test_tagged_machine_bp_local_resolves_projected_entry_sp_owner() -> None:
    """Resolve an exact BP-2 binding before interpreting its raw AST offset."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    codegen = _codegen_boundary(arch)
    projected = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    raw = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="stack_sp_m2_2", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
        tags=stable_stack_condition_binding_tags_8616(-2, 2),
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        statements=raw,
        variables_in_use={projected.variable: projected, raw.variable: raw},
        unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected.variable,
        cvar=projected,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    canonical = _canonicalize_stack_cvar_expr(
        raw,
        codegen,
        unwrap_c_casts=lambda node: node,
        resolve_stack_cvar_at_offset=lambda *_args, **_kwargs: raw,
    )

    assert canonical is projected


def test_untagged_snapshot_clone_resolves_projected_machine_bp_owner() -> None:
    """Resolve an angr snapshot clone through its durable stack projection."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    codegen = _codegen_boundary(arch)
    projected = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="err", ident="is_3"),
        variable_type=word_type,
        codegen=codegen,
    )
    snapshot_clone = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2", ident="is_3"),
        variable_type=word_type,
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected.variable,
        cvar=projected,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="err",
    )

    canonical = _canonicalize_stack_cvar_expr(
        snapshot_clone,
        codegen,
        unwrap_c_casts=lambda node: node,
        resolve_stack_cvar_at_offset=lambda *_args, **_kwargs: snapshot_clone,
    )

    assert canonical is projected


def test_argumentful_call_return_store_binds_projected_local_without_rebuilding_call() -> None:
    """Preserve call arguments while joining a BP-2 return store to local_2."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    codegen = _codegen_boundary(arch)
    projected = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    register_offset, register_size = arch.registers["ax"]
    raw = structured_c.CVariable(
        SimRegisterVariable(register_offset, register_size, name="v11"),
        variable_type=word_type,
        codegen=codegen,
    )
    argument = structured_c.CConstant(97, word_type, codegen=codegen)
    call = structured_c.CFunctionCall(
        "sub_11310",
        None,
        [argument],
        codegen=codegen,
        tags={"ins_addr": 0x10ECF},
    )
    assignment = structured_c.CAssignment(
        raw,
        call,
        codegen=codegen,
        tags={"ins_addr": 0x10ED2},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        statements=assignment,
        variables_in_use={projected.variable: projected, raw.variable: raw},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summary_inventory_8616 = {
        0x10ECF: CallsiteSummary8616(
            callsite_addr=0x10ECF,
            target_addr=0x11310,
            return_addr=0x10ED2,
            kind="near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
            return_store_destination=("bp", -2),
            return_store_width=2,
            return_use_kind=CallsiteReturnUseKind8616.VALUE,
            return_store_instruction_addr=0x10ED2,
        )
    }
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected.variable,
        cvar=projected,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    result = bind_call_return_stack_assignment_8616(assignment, codegen)

    assert result.status is CallReturnStackBindingStatus8616.BOUND
    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 1
    assert result.materialized_count == 1
    assert result.failure_count == 0
    assert isinstance(result.node, structured_c.CStatements)
    call_assignment, store_assignment = result.node.statements
    assert isinstance(call_assignment, structured_c.CAssignment)
    assert call_assignment.lhs is raw
    assert call_assignment.rhs is call
    assert isinstance(store_assignment, structured_c.CAssignment)
    assert store_assignment.lhs is projected
    assert store_assignment.rhs is raw
    assert (
        bind_call_return_stack_assignment_8616(call_assignment, codegen).status
        is CallReturnStackBindingStatus8616.ALREADY_BOUND
    )
    assert call.args == [argument]
