from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIndexedVariable,
    CTypeCast,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimTypeChar, SimTypeShort, TypeRef
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from angr_platforms.X86_16.lowering.global_declarations import (
    NamedAggregateDeclarationCType8616,
    reconcile_strong_global_declaration_specs_8616,
    replace_global_declaration_spec_from_stronger_typed_evidence_8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    AggregateTypeIdentityStrength8616,
    IndexedSegmentedGlobalEvidence8616,
    NamedGlobalAggregateTypeFact8616,
    _augment_indexed_evidence_with_project_layouts_8616,
    _preferred_named_global_aggregate_type_8616,
    _project_two_byte_aggregate_char_casts_8616,
    _record_named_global_aggregate_type_fact_8616,
    _two_byte_global_struct_declaration_ctype_8616,
    _two_byte_global_struct_type_8616,
    reapply_proven_named_global_aggregate_types_8616,
    stack_aggregate_field_projection_facts_8616,
)
from angr_platforms.X86_16.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)


def _layout_evidence() -> GlobalObjectLayoutEvidence8616:
    layout = GlobalObjectLayout8616(
        IRAddress(
            space=MemSpace.DS,
            offset=0x200,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        2,
        (0, 1),
        0x200,
    )
    return GlobalObjectLayoutEvidence8616((layout,), 1, 1, 1, 1)


def test_lowering_augments_only_current_exact_storage_identity() -> None:
    layouts = _layout_evidence()
    current = (
        IndexedSegmentedGlobalEvidence8616(
            base_offset=0x200,
            name="g_0200",
            relative_disp=0,
            width=2,
        ),
    )

    augmented = _augment_indexed_evidence_with_project_layouts_8616(current, layouts)

    assert tuple((item.base_offset, item.width, item.relative_disp) for item in augmented) == (
        (0x200, 2, 0),
        (0x200, 1, 0),
        (0x201, 1, 1),
    )
    assert {item.aggregate_type_name for item in augmented} == {"g_0200"}
    byte_augmented = _augment_indexed_evidence_with_project_layouts_8616(
        (IndexedSegmentedGlobalEvidence8616(0x200, "g_0200", 0, 1),),
        layouts,
    )
    assert tuple((item.base_offset, item.width) for item in byte_augmented) == (
        (0x200, 1),
        (0x201, 1),
    )
    assert {item.aggregate_type_name for item in byte_augmented} == {"g_0200"}
    assert _augment_indexed_evidence_with_project_layouts_8616((), layouts) == ()


@pytest.mark.parametrize("wrapper", ["mask", "cast"])
@pytest.mark.parametrize("operation,shift,field", [
    (None, 0, "field_0"), ("Shr", 0, "field_0"), ("Shr", 8, "field_1"),
    ("Shr", 1, None), ("Shr", 16, None), ("Shr", -8, None), ("Add", 8, None),
    ("Shr", 8.0, None),
])
def test_lowering_projects_exact_aggregate_byte_view(wrapper, operation, shift, field) -> None:
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    struct_type = _two_byte_global_struct_type_8616("g_0200")
    base = CVariable(
        SimMemoryVariable(0x200, 2, name="g_0200"),
        variable_type=struct_type,
        codegen=codegen,
    )
    indexed = CIndexedVariable(
        base,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        variable_type=struct_type,
        codegen=codegen,
    )
    indexed.variable_type = TypeRef(struct_type.name, struct_type)
    operand = indexed if operation is None else CBinaryOp(
        operation, indexed, CConstant(shift, SimTypeShort(False), codegen=codegen), codegen=codegen,
    )
    expression = CBinaryOp(
        "And",
        operand,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    if wrapper == "cast":
        expression = CTypeCast(operand.type, SimTypeChar(True), operand, codegen=codegen)

    projected = _project_two_byte_aggregate_char_casts_8616(codegen, expression)

    result = expression.lhs if wrapper == "mask" else expression.expr
    if field is None:
        assert projected == 0
        assert result is operand
    else:
        assert projected == 1
        assert isinstance(result, CVariableField)
        assert result.variable is indexed
        assert result.field.field == field


def test_stack_high_byte_projection_publishes_matching_field_fact() -> None:
    codegen = SimpleNamespace(
        cstyle_null_cmp=False, next_idx=lambda _name: 0,
        next_ident=lambda name: f"{name}_0", next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    )
    struct_type = _two_byte_global_struct_type_8616("pair")
    source = CVariable(SimStackVariable(-4, 2, base="bp"), variable_type=struct_type, codegen=codegen)
    destination = CVariable(SimStackVariable(-6, 2, base="bp"),
                            variable_type=SimTypeShort(True), codegen=codegen)
    shifted = CBinaryOp("Shr", source, CConstant(8, SimTypeShort(False), codegen=codegen), codegen=codegen)
    conversion = CTypeCast(struct_type, SimTypeChar(True), shifted, codegen=codegen)
    assignment = CAssignment(destination, conversion, codegen=codegen)

    assert _project_two_byte_aggregate_char_casts_8616(codegen, assignment) == 1
    fact, = stack_aggregate_field_projection_facts_8616(codegen)
    assert fact.field_offset == 1
    assert fact.struct_type.name == struct_type.name
    assert fact.struct_type == conversion.expr.field.struct_type
    assert conversion.expr.variable is source
    assert conversion.expr.field.offset == fact.field_offset


def test_named_aggregate_replay_restores_expression_type_before_low_byte_projection() -> None:
    struct_type = _two_byte_global_struct_type_8616("g_0200")
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
        _inertia_global_declaration_specs_8616=(("unsigned short", "g_0200", 1),),
        _inertia_named_global_aggregate_type_facts_8616=(
            NamedGlobalAggregateTypeFact8616("g_0200", struct_type, 1),
        ),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    base = CVariable(
        SimMemoryVariable(0x200, 2, name="g_0200"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    indexed = CIndexedVariable(
        base,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expression = CBinaryOp(
        "And",
        indexed,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        body=expression,
        variable_manager=SimpleNamespace(types={}),
    )

    assert reapply_proven_named_global_aggregate_types_8616(codegen) is True

    assert isinstance(indexed.type, TypeRef)
    assert isinstance(expression.lhs, CVariableField)
    assert expression.lhs.field.field == "field_0"
    stats = codegen._inertia_named_global_aggregate_expression_replay_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.field_projection_count == 1


def test_stronger_family_fact_replaces_weaker_local_type_and_declaration() -> None:
    local_type = _two_byte_global_struct_type_8616("g_0300")
    family_type = _two_byte_global_struct_type_8616("g_0200")
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(("g_0300_entry", "g_0300", 1),),
        _inertia_named_global_aggregate_type_facts_8616=(
            NamedGlobalAggregateTypeFact8616("g_0300", local_type, 1),
        ),
    )

    upgraded = _record_named_global_aggregate_type_fact_8616(
        codegen,
        "g_0300",
        family_type,
        1,
        allow_layout_equivalent_type_upgrade=True,
    )
    replace_global_declaration_spec_from_stronger_typed_evidence_8616(
        codegen,
        ctype=_two_byte_global_struct_declaration_ctype_8616(
            "g_0200",
            registered=True,
        ),
        name="g_0300",
        array_len=1,
    )

    assert upgraded is True
    assert codegen._inertia_named_global_aggregate_type_facts_8616 == (
        NamedGlobalAggregateTypeFact8616(
            "g_0300",
            family_type,
            1,
            AggregateTypeIdentityStrength8616.PROJECT_COPY_FAMILY,
        ),
    )
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("g_0200_entry", "g_0300", 1),
    )

    assert (
        _preferred_named_global_aggregate_type_8616(codegen, "g_0300", local_type)
        is family_type
    )
    assert (
        _record_named_global_aggregate_type_fact_8616(
            codegen,
            "g_0300",
            local_type,
            1,
        )
        is False
    )
    assert codegen._inertia_named_global_aggregate_type_facts_8616[0].struct_type is family_type


def test_stronger_typed_global_declaration_replays_after_weaker_alias_shape() -> None:
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(("unsigned short", "rin", 7),),
    )
    aggregate = NamedAggregateDeclarationCType8616(
        type_name="REGS",
        inline_definition="typedef union REGS { unsigned short ax; } REGS;",
        registered=True,
    )
    replace_global_declaration_spec_from_stronger_typed_evidence_8616(
        codegen,
        ctype=aggregate,
        name="rin",
        array_len=None,
    )
    codegen._inertia_global_declaration_specs_8616 = (
        ("unsigned short", "rin", 7),
    )

    changed = reconcile_strong_global_declaration_specs_8616(codegen)

    assert changed is True
    assert codegen._inertia_global_declaration_specs_8616 == (("REGS", "rin", None),)
