from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CStructField,
    CTypeCast,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.alias.alias_model_impl import (
    AliasStorageFacts,
    _StackSlotIdentity,
    _StorageDomainSignature,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    IndexedGlobalStackAggregateCopyFact8616,
    IndexedSegmentedGlobalEvidence8616,
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    SegmentedGlobalLoadStats8616,
    StackAggregateFieldProjectionFact8616,
    _make_indexed_global_expr_8616,
    materialize_indexed_segmented_global_loads_from_evidence_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import (
    lower_stack_accesses_from_alias_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.validation_storage import validate_storage_identities_8616


class _Codegen:
    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cfunc: object | None = None
        self.cstyle_null_cmp = False
        self.max_str_len = None

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _fixture(*, record_projection: bool, signed_index: bool = False) -> tuple[_Codegen, CAssignment, SegmentedGlobalLoadStats8616]:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _Codegen(project)
    stack_index = SimStackVariable(-6, 2, base="bp", name="local_6")
    index = CVariable(stack_index, variable_type=SimTypeShort(signed_index), codegen=codegen)
    if record_projection:
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=stack_index,
            cvar=index,
            bp_offset=-2,
            entry_sp_offset=-6,
            size=2,
        )
    ds_offset, ds_size = project.arch.registers["ds"]
    ds = CVariable(
        SimRegisterVariable(ds_offset, ds_size, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    scaled_index = CBinaryOp(
        "Shl",
        CSemanticCast8616(index.type, SimTypeShort(False), index, codegen=codegen) if signed_index else index,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    offset = CBinaryOp(
        "Add",
        CConstant(0xB4C, SimTypeShort(False), codegen=codegen),
        scaled_index,
        codegen=codegen,
    )
    helper = CFunctionCall("SEG_U8", None, [ds, offset], codegen=codegen)
    assignment = CAssignment(
        CVariable(SimStackVariable(-8, 1, base="bp", name="result"), codegen=codegen),
        helper,
        codegen=codegen,
    )
    root = CStatements([assignment], addr=0x10A10, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x109E8, statements=root, body=root)
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x109E8,
        accesses=tuple(
            SegmentAccessFact(
                block_addr=0x10A02,
                instruction_addr=instruction_addr,
                kind=SegmentAccessKind.READ,
                address=IRAddress(
                    space=MemSpace.DS,
                    base=("si",),
                    offset=0xB4C,
                    size=1,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                segment_register="ds",
                physical_source="ds",
                verdict=SegmentFactVerdict.PROVEN,
            )
            for instruction_addr in (0x10A1B, 0x10A1F)
        ),
    )
    stats = SegmentedGlobalLoadStats8616()
    materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        (
            IndexedSegmentedGlobalEvidence8616(0xB4C, "g_0B4C", 0, 1, "g_08F0"),
            IndexedSegmentedGlobalEvidence8616(0xB4C, "g_0B4C", 0, 2, "g_08F0"),
        ),
        load_site_evidence=(
            IndexedSegmentedGlobalLoadSiteEvidence8616(0xB4C, 1, -2, 1, 0x10A1B),
            IndexedSegmentedGlobalLoadSiteEvidence8616(0xB4C, 1, -4, 1, 0x10A1F),
        ),
        stats=stats,
    )
    return codegen, assignment, stats


def test_indexed_global_load_joins_projected_entry_sp_index_to_bp_fact() -> None:
    _codegen, assignment, stats = _fixture(record_projection=True)

    assert isinstance(assignment.rhs, CVariableField)
    assert assignment.rhs.field.field == "field_0"
    assert isinstance(assignment.rhs.variable, CIndexedVariable)
    assert assignment.rhs.variable.index.variable.name == "local_6"
    assert stats.indexed_load_site_materialized_count == 1


def test_indexed_global_load_refuses_unprojected_coordinate_mismatch() -> None:
    _codegen, assignment, stats = _fixture(record_projection=False)

    assert isinstance(assignment.rhs, CFunctionCall)
    assert assignment.rhs.callee_target == "SEG_U8"
    assert stats.indexed_load_site_materialized_count == 0


def test_indexed_load_site_preserves_unsigned_view_of_signed_stack_index() -> None:
    """Joining an exact stack identity must not discard its address value view."""
    _codegen, assignment, stats = _fixture(record_projection=True, signed_index=True)

    assert isinstance(assignment.rhs, CVariableField)
    index = assignment.rhs.variable.index
    assert isinstance(index, CSemanticCast8616)
    assert index.dst_type.signed is False
    assert index.expr.variable_type.signed is True
    assert stats.indexed_load_site_materialized_count == 1


def test_indexed_global_scalar_expression_type_is_arch_bound() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _Codegen(project)
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )

    expression = _make_indexed_global_expr_8616(
        codegen,
        IndexedSegmentedGlobalEvidence8616(0xB4C, "g_0B4C", 0, 2),
        index,
    )

    assert isinstance(expression, CIndexedVariable)
    assert expression.type.size == 16


def test_repeated_stack_lowering_preserves_existing_bp_to_entry_sp_projection() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    codegen.cfunc = SimpleNamespace(
        addr=0x109E8,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        statements=None,
    )
    fact = AliasStorageFacts(
        domain=_StorageDomainSignature("stack", 2),
        identity=("stack", _StackSlotIdentity("bp", -2, 2)),
    )

    lower_stack_accesses_from_alias_facts_8616(
        codegen,
        [fact],
        entry_sp_offsets_by_bp_range={(-2, 2): -6},
    )
    lower_stack_accesses_from_alias_facts_8616(codegen, [fact])

    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(-2, 2)
    assert projection is not None
    assert projection.entry_sp_offset == -6
    assert projection.display_name == "local_2"
    assert all(variable.offset != -2 for variable in codegen.cfunc.variables_in_use)


def _projected_storage_validation_report(*, record_projection: bool) -> object:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = _Codegen(project)
    struct_type = SimStruct(
        {"field_0": SimTypeChar(False), "field_1": SimTypeChar(False)},
        name="g_08F0_entry",
        pack=True,
    ).with_arch(project.arch)
    index_variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    aggregate_variable = SimStackVariable(-10, 2, base="bp", name="local_8")
    field_variable = SimStackVariable(-8, 2, base="bp", name="local_6")
    index = CVariable(index_variable, variable_type=SimTypeShort(False), codegen=codegen)
    aggregate = CVariable(aggregate_variable, variable_type=struct_type, codegen=codegen)
    field_destination = CVariable(
        field_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    global_base = CVariable(
        SimMemoryVariable(0xB4C, 2, name="g_0B4C"),
        variable_type=struct_type,
        codegen=codegen,
    )
    indexed = CIndexedVariable(
        global_base,
        index,
        variable_type=struct_type,
        codegen=codegen,
    )
    field = CVariableField(
        aggregate,
        CStructField(struct_type, 0, "field_0", codegen=codegen),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(aggregate, indexed, codegen=codegen),
            CAssignment(
                field_destination,
                CTypeCast(SimTypeShort(False), SimTypeChar(False), field, codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x10808,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
    )
    if record_projection:
        for variable, cvar, bp_offset, entry_sp_offset in (
            (index_variable, index, -2, -4),
            (aggregate_variable, aggregate, -8, -10),
            (field_variable, field_destination, -6, -8),
        ):
            record_stack_variable_coordinate_projection_8616(
                codegen,
                variable=variable,
                cvar=cvar,
                bp_offset=bp_offset,
                entry_sp_offset=entry_sp_offset,
                size=2,
            )
    codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = (
        IndexedGlobalStackAggregateCopyFact8616(
            0xB4C,
            "bp",
            -2,
            0,
            "bp",
            -8,
            2,
            struct_type,
            0x1082F,
            0x10833,
        ),
    )
    codegen._inertia_stack_aggregate_field_projection_facts_8616 = (
        StackAggregateFieldProjectionFact8616(
            "bp",
            -8,
            "bp",
            -6,
            0,
            struct_type,
            SimTypeShort(False),
            SimTypeChar(False),
        ),
    )
    return validate_storage_identities_8616(codegen, root)


def test_storage_validation_projects_final_entry_sp_coordinates_to_machine_bp() -> None:
    report = _projected_storage_validation_report(record_projection=True)

    assert report.passed
    assert report.materialized_count == 2


def test_storage_validation_refuses_unprojected_coordinate_mismatch() -> None:
    report = _projected_storage_validation_report(record_projection=False)

    assert not report.passed
    assert report.materialized_count == 0
