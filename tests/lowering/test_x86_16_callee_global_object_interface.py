from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimStruct, SimTypeChar, SimTypeShort, TypeRef
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.ir.core import IRAddress, MemSpace
from inertia.lowering.callee_global_object_evidence import (
    CalleeGlobalObjectInterfaceVerdict8616,
    recover_callee_global_object_interface_evidence_8616,
)
from inertia.lowering.callee_global_object_type_surface import (
    is_named_struct_type_8616,
    materialize_local_struct_declarations_8616,
)
from inertia.lowering.callee_pointer_evidence import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_indices_at_address_8616,
)

from inertia.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)


def _summary(
    callsite_addr: int,
    *sources: tuple[object, ...],
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=0x107B8,
        return_addr=callsite_addr + 3,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        push_arg_sources=sources,
    )


def _indexed_source(base_offset: int, stack_offset: int = -2) -> tuple[object, ...]:
    return (
        "expr",
        ("stack", "bp", stack_offset),
        (("shl", 1), ("add", base_offset)),
    )


def _layout_evidence() -> GlobalObjectLayoutEvidence8616:
    layouts = (
        GlobalObjectLayout8616(
            address=IRAddress(space=MemSpace.DS, offset=0x08F0, size=2),
            element_width=2,
            field_offsets=(0, 1),
            family_base_offset=0x08F0,
        ),
        GlobalObjectLayout8616(
            address=IRAddress(space=MemSpace.DS, offset=0x0B4C, size=2),
            element_width=2,
            field_offsets=(0, 1),
            family_base_offset=0x08F0,
        ),
    )
    return GlobalObjectLayoutEvidence8616(
        layouts=layouts,
        raw_fact_count=6,
        normalized_fact_count=6,
        classified_fact_count=2,
        materialized_count=2,
    )


def test_callee_object_interface_joins_exact_and_adjacent_family_sources() -> None:
    evidence = recover_callee_global_object_interface_evidence_8616(
        0x107B8,
        (
            _summary(
                0x10929,
                _indexed_source(0x0B4E),
                _indexed_source(0x0B4C),
            ),
            _summary(
                0x109C1,
                _indexed_source(0x0B4C),
                ("imm", 0x0B4C),
            ),
        ),
        _layout_evidence(),
        (0, 1),
    )

    assert evidence.family_base_offset == 0x08F0
    assert evidence.pointer_argument_indices == (0, 1)
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 4
    assert evidence.classified_fact_count == 2
    assert evidence.materialized_count == 0
    assert evidence.failure_count == 0
    assert evidence.callsite_addrs == (0x10929, 0x109C1)
    assert tuple(
        (fact.callsite_addr, fact.argument_index, fact.base_offset)
        for fact in evidence.source_facts
    ) == (
        (0x10929, 0, 0x0B4C),
        (0x10929, 1, 0x0B4E),
        (0x109C1, 0, 0x0B4C),
        (0x109C1, 1, 0x0B4C),
    )
    assert all(fact.family_base_offset == 0x08F0 for fact in evidence.source_facts)


def test_callee_object_interface_refuses_adjacent_source_with_different_index() -> None:
    evidence = recover_callee_global_object_interface_evidence_8616(
        0x107B8,
        (
            _summary(
                0x10929,
                _indexed_source(0x0B4E, -4),
                _indexed_source(0x0B4C, -2),
            ),
        ),
        _layout_evidence(),
        (0, 1),
    )

    assert evidence.family_base_offset is None
    assert evidence.pointer_argument_indices == ()
    assert evidence.classified_fact_count == 0
    assert evidence.materialized_count == 0
    assert evidence.failure_count > 0


def test_callee_object_interface_anchors_known_global_calls_with_unknown_callers() -> None:
    evidence = recover_callee_global_object_interface_evidence_8616(
        0x107B8,
        (
            _summary(0x10353),
            _summary(
                0x10929,
                _indexed_source(0x0B4E),
                _indexed_source(0x0B4C),
            ),
        ),
        _layout_evidence(),
        (0, 1),
    )

    assert (
        evidence.verdict
        is CalleeGlobalObjectInterfaceVerdict8616.ANCHORED_WITH_UNKNOWN_CALLERS
    )
    assert evidence.family_base_offset == 0x08F0
    assert evidence.pointer_argument_indices == (0, 1)
    assert tuple(fact.callsite_addr for fact in evidence.source_facts) == (
        0x10929,
        0x10929,
    )
    assert evidence.failure_count == 2


def test_callee_object_interface_refuses_incomplete_callee_pointer_contract() -> None:
    evidence = recover_callee_global_object_interface_evidence_8616(
        0x107B8,
        (_summary(0x10929, _indexed_source(0x0B4C), _indexed_source(0x0B4C)),),
        _layout_evidence(),
        (2,),
    )

    assert evidence.family_base_offset is None
    assert evidence.pointer_argument_indices == ()
    assert evidence.classified_fact_count == 0
    assert evidence.materialized_count == 0


def test_callee_object_interface_selects_pointer_from_mixed_arguments() -> None:
    evidence = recover_callee_global_object_interface_evidence_8616(
        0x107B8,
        (_summary(0x10929, ("imm", 7), ("imm", 0x0B4C)),),
        _layout_evidence(),
        (0,),
    )

    assert evidence.verdict is CalleeGlobalObjectInterfaceVerdict8616.COMPLETE
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 1
    assert evidence.failure_count == 0
    assert tuple(
        (fact.argument_index, fact.base_offset)
        for fact in evidence.source_facts
    ) == ((0, 0x0B4C),)


def test_callee_object_interface_consumes_closed_binary_pointer_evidence() -> None:
    pointer_evidence = CalleePointerArgumentEvidence8616(
        target_addr=0x107B8,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        pointer_stack_offsets=(4, 6),
        pointer_argument_indices=(0, 1),
        ambiguous_displaced_stack_offsets=(),
    )
    project = type(
        "Project",
        (),
        {"_inertia_callee_pointer_argument_evidence_8616": {0x107B8: pointer_evidence}},
    )()

    assert callee_pointer_argument_indices_at_address_8616(project, 0x107B8) == (0, 1)


def test_callee_object_interface_refuses_failed_binary_pointer_evidence() -> None:
    pointer_evidence = CalleePointerArgumentEvidence8616(
        target_addr=0x107B8,
        raw_fact_count=2,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=1,
        pointer_stack_offsets=(4,),
        pointer_argument_indices=(0,),
        ambiguous_displaced_stack_offsets=(6,),
    )
    project = type(
        "Project",
        (),
        {"_inertia_callee_pointer_argument_evidence_8616": {0x107B8: pointer_evidence}},
    )()

    assert callee_pointer_argument_indices_at_address_8616(project, 0x107B8) == ()


def test_callee_object_interface_joins_replayed_named_struct_type() -> None:
    expected = SimStruct(
        {"field_0": SimTypeChar(), "field_1": SimTypeChar()},
        name="g_08F0_entry",
    )
    replayed = SimStruct(
        {"field_0": SimTypeChar(), "field_1": SimTypeChar()},
        name="g_08F0_entry",
    )

    assert expected is not replayed
    assert is_named_struct_type_8616(
        TypeRef("g_08F0_entry", replayed),
        expected,
    )
    assert not is_named_struct_type_8616(
        TypeRef("g_0B4C_entry", replayed),
        SimStruct({}, name="g_0B4C_entry"),
    )


def test_callee_object_interface_updates_replayed_local_declaration_type() -> None:
    local = SimStackVariable(-2, 2, base="bp", name="local_2")
    scalar_type = SimTypeShort(False)
    codegen = SimpleNamespace(
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    expression_cvar = CVariable(
        local,
        variable_type=scalar_type,
        codegen=codegen,
    )
    declaration_cvar = CVariable(
        local,
        variable_type=scalar_type,
        codegen=codegen,
    )
    struct_type = SimStruct(
        {"field_0": SimTypeChar(), "field_1": SimTypeChar()},
        name="g_08F0_entry",
    )
    registered_type = TypeRef(struct_type.name, struct_type)
    cfunc = SimpleNamespace(
        variables_in_use={local: expression_cvar},
        unified_local_vars={local: {(declaration_cvar, scalar_type)}},
    )

    assert materialize_local_struct_declarations_8616(
        cfunc,
        (local,),
        registered_type,
        struct_type,
    )
    assert is_named_struct_type_8616(expression_cvar.variable_type, struct_type)
    assert is_named_struct_type_8616(declaration_cvar.variable_type, struct_type)
    assert cfunc.unified_local_vars[local] == {
        (declaration_cvar, registered_type),
    }
