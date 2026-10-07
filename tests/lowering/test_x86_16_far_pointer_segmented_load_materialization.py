from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.far_pointer_segmented_load_evidence import (
    FarPointerSegmentedLoadEvidence8616,
    FarPointerSegmentRegister8616,
    FarPointerStackSource8616,
    FarPointerStackValueSource8616,
)
from inertia.lowering.far_pointer_segmented_load_materialization import (
    _materialized_offset_expr_8616,
    materialize_far_pointer_segmented_loads_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


def _stack_cvar(
    codegen: object,
    *,
    entry_sp_offset: int,
    name: str,
) -> tuple[SimStackVariable, structured_c.CVariable]:
    variable = SimStackVariable(entry_sp_offset, 2, base="bp", name=name)
    cvar = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    return variable, cvar


def test_far_pointer_materialization_resolves_machine_bp_coordinates() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    segment_variable, segment_cvar = _stack_cvar(
        codegen,
        entry_sp_offset=4,
        name="segment",
    )
    pointer_variable, pointer_cvar = _stack_cvar(
        codegen,
        entry_sp_offset=-10,
        name="pointer_offset",
    )
    decoy_variable, decoy_cvar = _stack_cvar(
        codegen,
        entry_sp_offset=-8,
        name="decoy",
    )
    index_variable, index_cvar = _stack_cvar(
        codegen,
        entry_sp_offset=6,
        name="index",
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(segment_cvar, index_cvar),
        variables_in_use={
            segment_variable: segment_cvar,
            pointer_variable: pointer_cvar,
            decoy_variable: decoy_cvar,
            index_variable: index_cvar,
        },
        unified_local_vars={},
    )
    for variable, cvar, bp_offset in (
        (segment_variable, segment_cvar, 4),
        (pointer_variable, pointer_cvar, -8),
        (decoy_variable, decoy_cvar, -6),
        (index_variable, index_cvar, 6),
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=variable.offset,
            size=2,
        )
    fact = FarPointerSegmentedLoadEvidence8616(
        FarPointerSegmentRegister8616.ES,
        FarPointerStackSource8616(
            offset_stack_offset=-8,
            segment_stack_offset=-6,
            segment_value_source=FarPointerStackValueSource8616(4, 2),
        ),
        width=2,
        displacement=24,
        ins_addr=0x1029,
        index_stack_offset=6,
        index_shift=1,
    )

    expressions = _materialized_offset_expr_8616(codegen, fact)

    assert expressions is not None
    segment, offset = expressions
    assert segment is segment_cvar
    assert isinstance(offset, structured_c.CBinaryOp)
    assert offset.op == "Add"
    indexed_offset = offset.lhs
    assert isinstance(indexed_offset, structured_c.CBinaryOp)
    assert indexed_offset.lhs is pointer_cvar
    assert indexed_offset.lhs is not decoy_cvar
    assert isinstance(indexed_offset.rhs, structured_c.CBinaryOp)
    assert indexed_offset.rhs.lhs is index_cvar

    constant_fact = replace(
        fact,
        pointer_source=replace(fact.pointer_source, offset_constant=36),
    )
    constant_expressions = _materialized_offset_expr_8616(codegen, constant_fact)

    assert constant_expressions is not None
    constant_segment, constant_offset = constant_expressions
    assert constant_segment is segment_cvar
    assert isinstance(constant_offset, structured_c.CBinaryOp)
    constant_indexed_offset = constant_offset.lhs
    assert isinstance(constant_indexed_offset, structured_c.CBinaryOp)
    assert isinstance(constant_indexed_offset.lhs, structured_c.CConstant)
    assert constant_indexed_offset.lhs.value == 36
    assert isinstance(constant_indexed_offset.rhs, structured_c.CBinaryOp)
    assert constant_indexed_offset.rhs.lhs is index_cvar


def test_far_pointer_word_load_preserves_enclosing_wide_return() -> None:
    """Replace the exact byte-pair load without consuming its DX:AX owner."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    segment_variable, segment_cvar = _stack_cvar(
        codegen,
        entry_sp_offset=4,
        name="segment",
    )
    pointer_variable, pointer_cvar = _stack_cvar(
        codegen,
        entry_sp_offset=-10,
        name="pointer_offset",
    )
    index_variable, index_cvar = _stack_cvar(
        codegen,
        entry_sp_offset=6,
        name="index",
    )
    short_type = SimTypeShort(False).with_arch(project.arch)
    low_byte = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CConstant(0, short_type, codegen=codegen),
        codegen=codegen,
    )
    high_byte = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CConstant(1, short_type, codegen=codegen),
        codegen=codegen,
    )
    word_load = structured_c.CBinaryOp(
        "Or",
        low_byte,
        structured_c.CBinaryOp(
            "Shl",
            high_byte,
            structured_c.CConstant(8, short_type, codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"inertia_source_instruction_addrs": (0x1023,)},
    )
    high_word = structured_c.CBinaryOp(
        "Shl",
        structured_c.CConstant(3, short_type, codegen=codegen),
        structured_c.CConstant(16, short_type, codegen=codegen),
        codegen=codegen,
    )
    wide_return = structured_c.CBinaryOp(
        "Or",
        high_word,
        word_load,
        codegen=codegen,
    )
    return_node = structured_c.CReturn(wide_return, codegen=codegen)
    root = structured_c.CStatements([return_node], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=(segment_cvar, index_cvar),
        variables_in_use={
            segment_variable: segment_cvar,
            pointer_variable: pointer_cvar,
            index_variable: index_cvar,
        },
        unified_local_vars={},
        statements=root,
    )
    for variable, cvar, bp_offset in (
        (segment_variable, segment_cvar, 4),
        (pointer_variable, pointer_cvar, -8),
        (index_variable, index_cvar, 6),
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=variable.offset,
            size=2,
        )
    fact = FarPointerSegmentedLoadEvidence8616(
        FarPointerSegmentRegister8616.ES,
        FarPointerStackSource8616(
            offset_stack_offset=-8,
            segment_stack_offset=-6,
            segment_value_source=FarPointerStackValueSource8616(4, 2),
        ),
        width=2,
        displacement=0,
        ins_addr=0x1023,
        index_stack_offset=6,
        index_shift=1,
    )

    result = materialize_far_pointer_segmented_loads_8616(codegen, (fact,))

    assert result.changed is True
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert return_node.retval is wide_return
    assert wide_return.lhs is high_word
    assert isinstance(wide_return.rhs, structured_c.CFunctionCall)
    assert wide_return.rhs.callee_target == "SEG_U16"
