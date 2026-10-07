from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIndexedVariable,
    CStatements,
    CStructField,
    CTypeCast,
    CVariable,
    CVariableField,
)
from angr.sim_type import (
    SimStruct,
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypeShort,
    TypeRef,
)
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from inertia.ir.core import MemSpace
from inertia.lowering.segmented_global_loads import (
    IndexedGlobalStackAggregateCopyFact8616,
    NamedGlobalAggregateTypeFact8616,
    StackAggregateFieldProjectionFact8616,
    indexed_global_stack_aggregate_copy_facts_8616,
    stack_aggregate_field_projection_facts_8616,
)
from inertia.lowering.stack_aggregate_objects import (
    StackAggregateEvidenceKind8616,
    StackAggregateObjectFact8616,
    stack_aggregate_object_facts_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from inertia.lowering.storage_identity_facts import (
    GlobalStorageIdentityFact8616,
    StorageIdentityEvidenceKind8616,
    global_storage_identity_facts_8616,
    record_global_storage_identity_fact_8616,
)
from archinfo import ArchX86

from inertia.validation.tail_validation import (
    X86_16TailValidationSummary,
    build_x86_16_tail_validation_cached_result,
    refresh_x86_16_final_semantic_validation_8616,
    x86_16_tail_validation_snapshot_passed,
)
from inertia.validation.validation_storage import (
    validate_storage_identities_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())
        root = CStatements([], codegen=self)
        self.cfunc = SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            statements=root,
            variables_in_use={},
            unified_local_vars={},
        )

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _fact(
    *,
    space: MemSpace = MemSpace.DS,
    offset: int = 0x1234,
    width: int = 2,
    name: str = "counter",
    evidence_addr: int = 0x4018,
) -> GlobalStorageIdentityFact8616:
    return GlobalStorageIdentityFact8616(
        space=space,
        offset=offset,
        width=width,
        name=name,
        evidence_addr=evidence_addr,
        kind=StorageIdentityEvidenceKind8616.DIRECT_GLOBAL_UPDATE,
    )


def _global(
    codegen: _Codegen,
    *,
    offset: int = 0x1234,
    width: int = 2,
    name: str = "counter",
) -> CVariable:
    variable = SimMemoryVariable(offset, width, name=name, region=0x1000)
    cvar = CVariable(
        variable,
        unified_variable=variable,
        variable_type=SimTypeShort(False) if width == 2 else SimTypeChar(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[variable] = {
        (cvar, cvar.variable_type),
    }
    return cvar


def _local(
    codegen: _Codegen,
    *,
    offset: int = -2,
    width: int = 2,
    name: str = "counter",
) -> CVariable:
    variable = SimStackVariable(offset, width, base="bp", name=name)
    cvar = CVariable(
        variable,
        unified_variable=variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[variable] = {
        (cvar, cvar.variable_type),
    }
    return cvar


def _stack_aggregate_fact(
    *,
    base_offset: int = -8,
    byte_size: int = 8,
    element_width: int = 2,
    evidence_kind: StackAggregateEvidenceKind8616 = (
        StackAggregateEvidenceKind8616.INDEXED_PARTITION
    ),
) -> StackAggregateObjectFact8616:
    return StackAggregateObjectFact8616(
        base_offset=base_offset,
        byte_size=byte_size,
        element_width=element_width,
        frame_allocation_size=16,
        address_taken_count=1,
        indexed_access_count=2,
        indexed_offsets=(base_offset,),
        scalar_boundary_offset=-10,
        scalar_boundary_width=2,
        evidence_kind=evidence_kind,
    )


def _stack_array(
    codegen: _Codegen,
    *,
    base_offset: int = -8,
    byte_size: int = 8,
    element_width: int = 2,
    storage_width: int | None = None,
    name: str = "items",
) -> CVariable:
    element_type = (
        SimTypeChar(False)
        if element_width == 1
        else SimTypeShort(False)
    )
    array_type = SimTypeFixedSizeArray(
        element_type,
        byte_size // element_width,
    ).with_arch(codegen.project.arch)
    variable = SimStackVariable(
        base_offset,
        byte_size if storage_width is None else storage_width,
        base="bp",
        name=name,
        region=codegen.cfunc.addr,
    )
    cvar = CVariable(
        variable,
        unified_variable=variable,
        variable_type=array_type,
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[variable] = {(cvar, array_type)}
    return cvar


def _stack_field_fact(
    struct_type: SimStruct,
    *,
    source_base: str = "bp",
    source_offset: int = -8,
    destination_offset: int = -6,
    field_offset: int = 0,
) -> StackAggregateFieldProjectionFact8616:
    return StackAggregateFieldProjectionFact8616(
        source_base=source_base,
        source_offset=source_offset,
        destination_base="bp",
        destination_offset=destination_offset,
        field_offset=field_offset,
        struct_type=struct_type,
        cast_source_type=SimTypeShort(False),
        cast_destination_type=SimTypeChar(False),
    )


def _stack_field_assignment(
    codegen: _Codegen,
    struct_type: SimStruct,
    *,
    source_offset: int = -8,
    destination_offset: int = -6,
    field_offset: int = 0,
) -> CAssignment:
    source_variable = SimStackVariable(
        source_offset,
        2,
        base="bp",
        name="entry",
        region=codegen.cfunc.addr,
    )
    destination_variable = SimStackVariable(
        destination_offset,
        2,
        base="bp",
        name="value",
        region=codegen.cfunc.addr,
    )
    source = CVariable(
        source_variable,
        unified_variable=source_variable,
        variable_type=struct_type,
        codegen=codegen,
    )
    destination = CVariable(
        destination_variable,
        unified_variable=destination_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    field = CVariableField(
        source,
        CStructField(
            struct_type,
            field_offset,
            f"field_{field_offset}",
            codegen=codegen,
        ),
        codegen=codegen,
    )
    rhs = CTypeCast(
        SimTypeShort(False),
        SimTypeChar(False),
        field,
        codegen=codegen,
    )
    return CAssignment(destination, rhs, codegen=codegen)


def _stack_field_struct(codegen: _Codegen, name: str = "work_entry") -> SimStruct:
    return SimStruct(
        {
            "field_0": SimTypeChar(False),
            "field_1": SimTypeChar(False),
        },
        name=name,
        pack=True,
    ).with_arch(codegen.project.arch)


def _aggregate_copy_fact(
    struct_type: SimStruct,
    *,
    source_global_offset: int = 0x42,
    source_index_base: str = "bp",
    source_index_offset: int = -2,
    source_index_adjustment: int = 0,
    destination_offset: int = -8,
    width: int = 2,
    load_ins_addr: int = 0x4010,
    store_ins_addr: int = 0x4014,
) -> IndexedGlobalStackAggregateCopyFact8616:
    return IndexedGlobalStackAggregateCopyFact8616(
        source_global_offset=source_global_offset,
        source_index_base=source_index_base,
        source_index_offset=source_index_offset,
        source_index_adjustment=source_index_adjustment,
        destination_base="bp",
        destination_offset=destination_offset,
        width=width,
        struct_type=struct_type,
        load_ins_addr=load_ins_addr,
        store_ins_addr=store_ins_addr,
    )


def _aggregate_copy_assignment(
    codegen: _Codegen,
    source_struct: SimStruct,
    *,
    destination_struct: SimStruct | None = None,
    source_global_offset: int = 0x42,
    source_index_offset: int = -2,
    source_index_adjustment: int = 0,
    destination_offset: int = -8,
    source_width: int = 2,
    destination_width: int = 2,
) -> CAssignment:
    source_variable = SimMemoryVariable(
        source_global_offset,
        source_width,
        name="work",
        region=codegen.cfunc.addr,
    )
    index_variable = SimStackVariable(
        source_index_offset,
        2,
        base="bp",
        name="iRow",
        region=codegen.cfunc.addr,
    )
    destination_variable = SimStackVariable(
        destination_offset,
        destination_width,
        base="bp",
        name="barTemp",
        region=codegen.cfunc.addr,
    )
    source = CVariable(
        source_variable,
        unified_variable=source_variable,
        variable_type=source_struct,
        codegen=codegen,
    )
    index = CVariable(
        index_variable,
        unified_variable=index_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index_expression: object = index
    if source_index_adjustment:
        index_expression = CBinaryOp(
            "Add" if source_index_adjustment > 0 else "Sub",
            index,
            CConstant(
                abs(source_index_adjustment),
                SimTypeShort(False),
                codegen=codegen,
            ),
            codegen=codegen,
        )
    indexed_source = CIndexedVariable(
        source,
        index_expression,
        variable_type=source_struct,
        codegen=codegen,
    )
    resolved_destination_struct = destination_struct or source_struct
    destination = CVariable(
        destination_variable,
        unified_variable=destination_variable,
        variable_type=resolved_destination_struct,
        codegen=codegen,
    )
    return CAssignment(destination, indexed_source, codegen=codegen)


def _empty_summary(
    *,
    storage_identity_issues: tuple[str, ...] = (),
) -> X86_16TailValidationSummary:
    return X86_16TailValidationSummary(
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        storage_identity_issues=storage_identity_issues,
    )


def test_storage_identity_fact_recording_is_typed_deterministic_and_idempotent() -> None:
    codegen = _Codegen()
    later = _fact(offset=0x2000, name="later", evidence_addr=0x4020)
    earlier = _fact()

    assert record_global_storage_identity_fact_8616(codegen, later)
    assert record_global_storage_identity_fact_8616(codegen, earlier)
    assert record_global_storage_identity_fact_8616(codegen, earlier) is False
    assert global_storage_identity_facts_8616(codegen) == (earlier, later)


def test_storage_validation_accepts_exact_ds_global_identity() -> None:
    codegen = _Codegen()
    global_cvar = _global(codegen)
    codegen.cfunc.statements.statements.append(global_cvar)
    record_global_storage_identity_fact_8616(codegen, _fact())

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_storage_validation_accepts_access_covered_by_wider_global() -> None:
    codegen = _Codegen()
    global_cvar = _global(codegen, width=4, name="wide_counter")
    codegen.cfunc.statements.statements.append(global_cvar)
    record_global_storage_identity_fact_8616(
        codegen,
        _fact(width=2, name="g_1234"),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_accepts_access_inside_wider_global() -> None:
    codegen = _Codegen()
    global_cvar = _global(
        codegen,
        offset=0x1232,
        width=4,
        name="wide_counter",
    )
    codegen.cfunc.statements.statements.append(global_cvar)
    record_global_storage_identity_fact_8616(
        codegen,
        _fact(offset=0x1234, width=2, name="g_1234"),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_refuses_local_shadow_even_with_exact_global() -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.append(_global(codegen))
    _local(codegen)
    record_global_storage_identity_fact_8616(codegen, _fact())

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.materialized_count == 1
    assert report.issue_tokens() == (
        "storage-identity:local-shadow:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018:shadows=SS:BP-0x2:size2",
    )


def test_storage_validation_uses_covering_global_name_for_shadow_detection() -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.append(
        _global(codegen, width=4, name="wide_counter")
    )
    _local(codegen, name="wide_counter")
    record_global_storage_identity_fact_8616(
        codegen,
        _fact(width=2, name="g_1234"),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.materialized_count == 1
    assert report.issue_tokens() == (
        "storage-identity:local-shadow:space=ds:offset=0x1234:width=2:"
        "name=g_1234:evidence=0x4018:shadows=SS:BP-0x2:size2",
    )


def test_storage_validation_refuses_missing_global_and_local_substitution() -> None:
    codegen = _Codegen()
    _local(codegen)
    record_global_storage_identity_fact_8616(codegen, _fact())

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 2
    assert report.issue_tokens() == (
        "storage-identity:local-shadow:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018:shadows=SS:BP-0x2:size2",
        "storage-identity:missing-global:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018",
    )


def test_storage_validation_does_not_accept_stale_global_declaration_metadata() -> None:
    codegen = _Codegen()
    _global(codegen)
    record_global_storage_identity_fact_8616(codegen, _fact())

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "storage-identity:missing-global:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018",
    )


def test_storage_validation_refuses_global_width_mismatch() -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.append(_global(codegen, width=1))
    record_global_storage_identity_fact_8616(codegen, _fact(width=2))

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.issue_tokens() == (
        "storage-identity:width-mismatch:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018:actual-widths=1",
    )


def test_storage_validation_refuses_containing_global_that_ends_inside_access() -> None:
    codegen = _Codegen()
    codegen.cfunc.statements.statements.append(
        _global(codegen, offset=0x1232, width=3)
    )
    record_global_storage_identity_fact_8616(
        codegen,
        _fact(offset=0x1234, width=2),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "storage-identity:width-mismatch:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018:actual-widths=3",
    )


def test_storage_validation_refuses_conflicting_widths_for_one_instruction() -> None:
    codegen = _Codegen()
    record_global_storage_identity_fact_8616(codegen, _fact(width=1))
    record_global_storage_identity_fact_8616(codegen, _fact(width=2))

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 2
    assert report.classified_fact_count == 2
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "storage-identity:conflicting-evidence-width:space=ds:offset=0x1234:"
        "width=1:name=counter:evidence=0x4018:actual-widths=1,2",
    )


def test_stack_aggregate_fact_reader_requires_typed_tuple() -> None:
    codegen = _Codegen()
    fact = _stack_aggregate_fact()
    codegen._inertia_stack_aggregate_object_facts_8616 = (fact,)

    assert stack_aggregate_object_facts_8616(codegen) == (fact,)

    codegen._inertia_stack_aggregate_object_facts_8616 = [fact]
    try:
        stack_aggregate_object_facts_8616(codegen)
    except TypeError as exc:
        assert "must be a tuple" in str(exc)
    else:
        raise AssertionError("untyped aggregate fact container was accepted")


def test_storage_validation_accepts_exact_stack_aggregate_shape() -> None:
    codegen = _Codegen()
    array = _stack_array(codegen)
    codegen.cfunc.statements.statements.append(array)
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_accepts_array_type_over_stale_narrow_backing_view() -> None:
    codegen = _Codegen()
    array = _stack_array(codegen, storage_width=1)
    codegen.cfunc.statements.statements.append(array)
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_accepts_projected_stack_aggregate_shape() -> None:
    codegen = _Codegen()
    array = _stack_array(codegen, base_offset=-10, storage_width=1)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=array.variable,
        cvar=array,
        bp_offset=-8,
        entry_sp_offset=-10,
        size=8,
        display_name="items",
    )
    codegen.cfunc.statements.statements.append(array)
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_refuses_missing_stack_aggregate() -> None:
    codegen = _Codegen()
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.issue_tokens() == (
        "storage-object:missing-object:space=ss:base=BP-0x8:bytes=8:"
        "stride=2:evidence=indexed_partition:indexed=-0x8",
    )


def test_storage_validation_refuses_stale_stack_aggregate_declaration() -> None:
    codegen = _Codegen()
    _stack_array(codegen)
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.issue_tokens() == (
        "storage-object:missing-object:space=ss:base=BP-0x8:bytes=8:"
        "stride=2:evidence=indexed_partition:indexed=-0x8",
    )


def test_storage_validation_refuses_stack_aggregate_width_mismatch() -> None:
    codegen = _Codegen()
    array = _stack_array(
        codegen,
        byte_size=6,
        element_width=1,
    )
    codegen.cfunc.statements.statements.append(array)
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(element_width=1),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.issue_tokens() == (
        "storage-object:width-mismatch:space=ss:base=BP-0x8:bytes=8:"
        "stride=1:evidence=indexed_partition:indexed=-0x8:"
        "actual-shapes=6/6/1",
    )


def test_storage_validation_refuses_stack_aggregate_stride_mismatch() -> None:
    codegen = _Codegen()
    array = _stack_array(
        codegen,
        byte_size=8,
        element_width=1,
    )
    codegen.cfunc.statements.statements.append(array)
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(element_width=2),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.issue_tokens() == (
        "storage-object:element-stride-mismatch:space=ss:base=BP-0x8:"
        "bytes=8:stride=2:evidence=indexed_partition:indexed=-0x8:"
        "actual-shapes=8/8/1",
    )


def test_storage_validation_refuses_conflicting_stack_aggregate_shapes() -> None:
    codegen = _Codegen()
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(element_width=1),
        _stack_aggregate_fact(element_width=2),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.raw_fact_count == 2
    assert report.classified_fact_count == 2
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "storage-object:conflicting-evidence-shape:space=ss:"
        "base=BP-0x8:bytes=8:stride=1:evidence=indexed_partition:"
        "indexed=-0x8:evidence-shapes=8/1,8/2",
    )


def test_stack_field_projection_fact_reader_requires_typed_tuple() -> None:
    codegen = _Codegen()
    fact = _stack_field_fact(_stack_field_struct(codegen))
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (fact,)

    assert stack_aggregate_field_projection_facts_8616(codegen) == (fact,)

    codegen._inertia_stack_aggregate_field_projection_facts_8616 = [fact]
    try:
        stack_aggregate_field_projection_facts_8616(codegen)
    except TypeError as exc:
        assert "must be a tuple" in str(exc)
    else:
        raise AssertionError("untyped field projection fact container was accepted")


def test_storage_validation_accepts_exact_stack_field_projection() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen.cfunc.statements.statements.append(
        _stack_field_assignment(codegen, struct_type)
    )
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_refuses_missing_stack_field_projection() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed is False
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "storage-field:missing-projection:source=bp:-0x8:"
        "destination=bp:-0x6:field=0x0:struct=work_entry",
    )


def test_storage_validation_refuses_stack_field_offset_mismatch() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen.cfunc.statements.statements.append(
        _stack_field_assignment(codegen, struct_type, field_offset=1)
    )
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-field:field-offset-mismatch:source=bp:-0x8:"
        "destination=bp:-0x6:field=0x0:struct=work_entry:"
        "actual-projections=bp:-0x8/0x1/work_entry",
    )


def test_storage_validation_refuses_stack_field_source_mismatch() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen.cfunc.statements.statements.append(
        _stack_field_assignment(codegen, struct_type, source_offset=-10)
    )
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-field:source-identity-mismatch:source=bp:-0x8:"
        "destination=bp:-0x6:field=0x0:struct=work_entry:"
        "actual-projections=bp:-0xa/0x0/work_entry",
    )


def test_storage_validation_refuses_stack_field_struct_mismatch() -> None:
    codegen = _Codegen()
    expected_struct = _stack_field_struct(codegen)
    actual_struct = _stack_field_struct(codegen, "other_entry")
    codegen.cfunc.statements.statements.append(
        _stack_field_assignment(codegen, actual_struct)
    )
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(expected_struct),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-field:struct-type-mismatch:source=bp:-0x8:"
        "destination=bp:-0x6:field=0x0:struct=work_entry:"
        "actual-projections=bp:-0x8/0x0/other_entry",
    )


def test_storage_validation_refuses_conflicting_stack_field_evidence() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(struct_type),
        _stack_field_fact(struct_type, field_offset=1),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.classified_fact_count == 2
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "storage-field:conflicting-evidence:source=bp:-0x8:"
        "destination=bp:-0x6:field=0x0:struct=work_entry:"
        "evidence-projections=0x0/work_entry,0x1/work_entry",
    )


def test_storage_validation_refuses_invalid_stack_field_evidence() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(struct_type, source_base="sp"),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-field:invalid-evidence:source=sp:-0x8:"
        "destination=bp:-0x6:field=0x0:struct=work_entry",
    )


def test_indexed_global_stack_copy_fact_reader_requires_typed_tuple() -> None:
    codegen = _Codegen()
    fact = _aggregate_copy_fact(_stack_field_struct(codegen))
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (fact,)

    assert indexed_global_stack_aggregate_copy_facts_8616(codegen) == (fact,)

    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = [fact]
    try:
        indexed_global_stack_aggregate_copy_facts_8616(codegen)
    except TypeError as exc:
        assert "must be a tuple" in str(exc)
    else:
        raise AssertionError("untyped whole-copy fact container was accepted")


def test_storage_validation_accepts_exact_indexed_global_stack_copy() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen.cfunc.statements.statements.append(
        _aggregate_copy_assignment(codegen, struct_type)
    )
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_accepts_copy_type_from_durable_global_base() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    assignment = _aggregate_copy_assignment(codegen, struct_type)
    assert isinstance(assignment.rhs, CIndexedVariable)
    assignment.rhs.variable_type = None
    assert isinstance(assignment.rhs.variable, CVariable)
    assignment.rhs.variable.variable_type = None
    registered_struct = _stack_field_struct(codegen)
    codegen.cfunc.variable_manager = SimpleNamespace(
        types={
            "work_entry": TypeRef("work_entry", registered_struct),
        }
    )
    codegen._inertia_named_global_aggregate_type_facts_8616 = (
        NamedGlobalAggregateTypeFact8616(
            global_name="work",
            struct_type=struct_type,
            array_len=1,
        ),
    )
    codegen.cfunc.statements.statements.append(assignment)
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.passed
    assert report.materialized_count == 1
    assert report.issue_tokens() == ()


def test_storage_validation_refuses_missing_indexed_global_stack_copy() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-copy:missing-copy:source=ds:0x42[bp:-0x2+0]:"
        "destination=bp:-0x8:width=2:struct=work_entry:"
        "evidence=0x4010/0x4014",
    )


def test_storage_validation_refuses_indexed_global_copy_source_mismatch() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen.cfunc.statements.statements.append(
        _aggregate_copy_assignment(
            codegen,
            struct_type,
            source_global_offset=0x44,
        )
    )
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-copy:source-identity-mismatch:"
        "source=ds:0x42[bp:-0x2+0]:destination=bp:-0x8:"
        "width=2:struct=work_entry:evidence=0x4010/0x4014:"
        "actual-copies=ds:0x44[bp:-0x2+0]/2->2/"
        "work_entry/work_entry",
    )


def test_storage_validation_refuses_indexed_global_copy_index_mismatch() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen.cfunc.statements.statements.append(
        _aggregate_copy_assignment(
            codegen,
            struct_type,
            source_index_offset=-4,
            source_index_adjustment=1,
        )
    )
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-copy:source-index-mismatch:"
        "source=ds:0x42[bp:-0x2+0]:destination=bp:-0x8:"
        "width=2:struct=work_entry:evidence=0x4010/0x4014:"
        "actual-copies=ds:0x42[bp:-0x4+1]/2->2/"
        "work_entry/work_entry",
    )


def test_storage_validation_refuses_indexed_global_copy_width_mismatch() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen.cfunc.statements.statements.append(
        _aggregate_copy_assignment(
            codegen,
            struct_type,
            source_width=1,
            destination_width=1,
        )
    )
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-copy:width-mismatch:source=ds:0x42[bp:-0x2+0]:"
        "destination=bp:-0x8:width=2:struct=work_entry:"
        "evidence=0x4010/0x4014:"
        "actual-copies=ds:0x42[bp:-0x2+0]/1->1/"
        "work_entry/work_entry",
    )


def test_storage_validation_refuses_indexed_global_copy_struct_mismatch() -> None:
    codegen = _Codegen()
    expected_struct = _stack_field_struct(codegen)
    actual_struct = _stack_field_struct(codegen, "other_entry")
    codegen.cfunc.statements.statements.append(
        _aggregate_copy_assignment(
            codegen,
            actual_struct,
        )
    )
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(expected_struct),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-copy:struct-type-mismatch:"
        "source=ds:0x42[bp:-0x2+0]:destination=bp:-0x8:"
        "width=2:struct=work_entry:evidence=0x4010/0x4014:"
        "actual-copies=ds:0x42[bp:-0x2+0]/2->2/"
        "other_entry/other_entry",
    )


def test_storage_validation_refuses_conflicting_indexed_global_copy_evidence() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
        _aggregate_copy_fact(struct_type, source_global_offset=0x44),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.classified_fact_count == 2
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "storage-copy:conflicting-evidence:"
        "source=ds:0x42[bp:-0x2+0]:destination=bp:-0x8:"
        "width=2:struct=work_entry:evidence=0x4010/0x4014:"
        "evidence-variants=0x42/-0x2/+0/-0x8/work_entry,"
        "0x44/-0x2/+0/-0x8/work_entry",
    )


def test_storage_validation_refuses_invalid_indexed_global_copy_evidence() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type, source_index_base="sp"),
    )

    report = validate_storage_identities_8616(
        codegen,
        codegen.cfunc.statements,
    )

    assert report.issue_tokens() == (
        "storage-copy:invalid-evidence:source=ds:0x42[sp:-0x2+0]:"
        "destination=bp:-0x8:width=2:struct=work_entry:"
        "evidence=0x4010/0x4014",
    )


def test_tail_validation_refuses_storage_loss_already_present_in_baseline() -> None:
    issue = (
        "storage-identity:missing-global:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018"
    )

    result = build_x86_16_tail_validation_cached_result(
        owner={},
        stage="postprocess",
        mode="live_out",
        before_fingerprint="same-missing-global",
        after_fingerprint="same-missing-global",
        before_summary=_empty_summary(storage_identity_issues=(issue,)),
        after_summary=_empty_summary(storage_identity_issues=(issue,)),
    )

    assert result["changed"] is True
    assert result["status"] == "failed"
    assert result["semantic_failures"] == {"storage_identities": (issue,)}


def test_final_semantic_refresh_promotes_absolute_storage_identity_failure() -> None:
    codegen = _Codegen()
    record_global_storage_identity_fact_8616(codegen, _fact())
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    issue = (
        "storage-identity:missing-global:space=ds:offset=0x1234:width=2:"
        "name=counter:evidence=0x4018"
    )
    assert report.passed is False
    assert report.storage_identities.issue_tokens() == (issue,)
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {
        "storage_identities": (issue,),
    }
    assert postprocess["final_semantic_guard"]["storage_identities"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_final_semantic_refresh_promotes_stack_aggregate_stride_failure() -> None:
    codegen = _Codegen()
    array = _stack_array(codegen, element_width=1)
    codegen.cfunc.statements.statements.append(array)
    codegen._inertia_stack_aggregate_object_facts_8616 = (
        _stack_aggregate_fact(element_width=2),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    issue = (
        "storage-object:element-stride-mismatch:space=ss:base=BP-0x8:"
        "bytes=8:stride=2:evidence=indexed_partition:indexed=-0x8:"
        "actual-shapes=8/8/1"
    )
    assert report.passed is False
    assert report.storage_identities.issue_tokens() == (issue,)
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {
        "storage_identities": (issue,),
    }
    assert postprocess["final_semantic_guard"]["storage_identities"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_final_semantic_refresh_promotes_missing_stack_field_projection() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        _stack_field_fact(struct_type),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    issue = (
        "storage-field:missing-projection:source=bp:-0x8:"
        "destination=bp:-0x6:field=0x0:struct=work_entry"
    )
    assert report.passed is False
    assert report.storage_identities.issue_tokens() == (issue,)
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {
        "storage_identities": (issue,),
    }
    assert postprocess["final_semantic_guard"]["storage_identities"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_final_semantic_refresh_promotes_missing_whole_aggregate_copy() -> None:
    codegen = _Codegen()
    struct_type = _stack_field_struct(codegen)
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        _aggregate_copy_fact(struct_type),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    issue = (
        "storage-copy:missing-copy:source=ds:0x42[bp:-0x2+0]:"
        "destination=bp:-0x8:width=2:struct=work_entry:"
        "evidence=0x4010/0x4014"
    )
    assert report.passed is False
    assert report.storage_identities.issue_tokens() == (issue,)
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {
        "storage_identities": (issue,),
    }
    assert postprocess["final_semantic_guard"]["storage_identities"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }
