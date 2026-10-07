from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import IRValue, MemSpace
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryFailureKind8616,
    IRLogicalMemoryRefusal8616,
    IRLogicalMemoryStats8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.carry_borrow_stack_storage import (
    WideCarryBorrowStackFailure8616,
)
from inertia.lowering.stack_memory_ssa import (
    StackMemoryObjectKind8616,
    lower_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
)

from inertia.alias.carry_borrow_destinations import (
    CarryBorrowDestinationAliasFailure8616,
    CarryBorrowDestinationAliasVerdict8616,
)
from inertia.alias.logical_stack_memory_projection import (
    LogicalStackMemoryAliasFailure8616,
    project_logical_stack_memory_alias_8616,
)
from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from inertia.widening.carry_borrow_pipeline import (
    CarryBorrowWideningPipeline8616,
    build_carry_borrow_widening_pipeline_8616,
)
from inertia.widening.carry_borrow_storage import (
    WideCarryBorrowStorageFailure8616,
    WideCarryBorrowStorageVerdict8616,
)
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)

_ADJACENT_STORES = bytes.fromhex("01 d8 11 ca 89 46 fc 89 56 fe c3")
_NONADJACENT_STORES = bytes.fromhex("01 d8 11 ca 89 46 fc 89 56 fa c3")


def _lift_with_stack_alias(
    code: bytes,
) -> tuple[SSAFunctionArtifact, StackMemorySSAAliasArtifact8616]:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    function_ssa = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    return function_ssa, build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)


def _pipeline(
    code: bytes,
) -> tuple[StackMemorySSAAliasArtifact8616, CarryBorrowWideningPipeline8616]:
    function_ssa, stack_alias = _lift_with_stack_alias(code)
    return stack_alias, build_carry_borrow_widening_pipeline_8616(function_ssa, stack_alias)


class _FakeCodegen:
    def __init__(
        self,
        stack_alias: StackMemorySSAAliasArtifact8616,
        pipeline: CarryBorrowWideningPipeline8616,
    ) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(
            addr=stack_alias.function_addr,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            sort_local_vars=lambda: None,
        )
        self._inertia_stack_memory_ssa_alias_artifact = stack_alias
        self._inertia_stack_memory_object_widening_artifact = (
            build_x86_16_stack_memory_object_widening_artifact(stack_alias)
        )
        self._inertia_carry_borrow_widening_pipeline_8616 = pipeline
        self._inertia_vex_ir_frame = FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=-2,
                detail="test fixture",
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        )
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_exact_result_stores_widen_to_one_alias_proven_stack_range() -> None:
    stack_alias, pipeline = _pipeline(_ADJACENT_STORES)

    assert pipeline.complete
    assert pipeline.source_stack_alias is stack_alias
    assert len(pipeline.source_ssa.memory_accesses) == len(stack_alias.facts) == 4
    assert len(stack_alias.logical_accesses) == 2
    raw = stack_alias.stats
    logical = stack_alias.logical_stats
    assert (raw.raw_fact_count, raw.normalized_fact_count, raw.classified_fact_count, raw.materialized_count, raw.failure_count) == (6, 4, 4, 4, 2)
    assert (logical.raw_fact_count, logical.normalized_fact_count, logical.classified_fact_count, logical.materialized_count, logical.failure_count) == (3, 2, 2, 2, 1)
    assert len(stack_alias.logical_refusals) == 1  # RET is not a BP-relative local.
    assert pipeline.destination_aliases.stats.materialized_count == 1
    destination = pipeline.destination_aliases.resolutions[0]
    assert destination.verdict is CarryBorrowDestinationAliasVerdict8616.PROVEN
    assert destination.fact is not None
    assert destination.fact.low_store.instr_index is not None
    assert destination.fact.high_store.instr_index is not None
    block = pipeline.source_ssa.blocks[0]
    assert block.instrs[destination.fact.low_store.instr_index].addr == 0x1004
    assert block.instrs[destination.fact.high_store.instr_index].addr == 0x1007

    assert pipeline.storage_widening.stats.materialized_count == 1
    resolution = pipeline.storage_widening.resolutions[0]
    assert resolution.verdict is WideCarryBorrowStorageVerdict8616.PROVEN
    assert resolution.value is not None
    wide = resolution.value
    assert (wide.address.space, wide.address.base, wide.address.offset, wide.address.size) == (
        MemSpace.SS,
        ("bp",),
        -4,
        4,
    )
    assert wide.address.version is None
    assert wide.source_versions == (1, 2, 3, 4)
    assert wide.storage.contains(destination.fact.low_store.storage)
    assert wide.storage.contains(destination.fact.high_store.storage)


def test_nonadjacent_result_stores_retain_typed_refusals() -> None:
    _stack_alias, pipeline = _pipeline(_NONADJACENT_STORES)

    assert pipeline.complete
    destination = pipeline.destination_aliases.resolutions[0]
    assert destination.verdict is CarryBorrowDestinationAliasVerdict8616.UNKNOWN_REFUSE
    assert destination.failure is CarryBorrowDestinationAliasFailure8616.DESTINATION_RANGE_MISMATCH
    storage = pipeline.storage_widening.resolutions[0]
    assert storage.verdict is WideCarryBorrowStorageVerdict8616.UNKNOWN_REFUSE
    assert storage.failure is WideCarryBorrowStorageFailure8616.ALIAS_REFUSED
    assert pipeline.destination_aliases.stats.failure_count == 1
    assert pipeline.storage_widening.stats.failure_count == 1


def test_lowering_materializes_exact_wide_stack_local() -> None:
    stack_alias, pipeline = _pipeline(_ADJACENT_STORES)
    codegen = _FakeCodegen(stack_alias, pipeline)

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete
    assert len(artifact.candidates) == 1
    candidate = artifact.candidates[0]
    assert candidate.role is StackMemoryObjectKind8616.LOCAL
    assert (candidate.address.offset, candidate.address.size) == (-4, 4)
    assert candidate.entry_sp_offset == -6
    assert candidate.versions == (1, 2, 3, 4)
    wide_stack = codegen._inertia_wide_carry_borrow_stack_artifact
    assert wide_stack.complete and len(wide_stack.candidates) == 1

    variables = {
        variable: cvar
        for variable, cvar in codegen.cfunc.variables_in_use.items()
        if isinstance(variable, SimStackVariable)
    }
    assert len(variables) == 1
    variable, cvar = next(iter(variables.items()))
    assert (variable.offset, variable.size) == (-6, 4)
    assert machine_bp_offset_for_stack_variable_8616(codegen, variable) == -4
    assert isinstance(cvar.variable_type, SimTypeLong)


def test_refused_widening_preserves_both_narrow_stack_locals() -> None:
    stack_alias, pipeline = _pipeline(_NONADJACENT_STORES)
    codegen = _FakeCodegen(stack_alias, pipeline)

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete
    assert {(item.address.offset, item.address.size) for item in artifact.candidates} == {
        (-6, 2),
        (-4, 2),
    }
    wide_stack = codegen._inertia_wide_carry_borrow_stack_artifact
    assert wide_stack.candidates == ()
    assert wide_stack.refusals[0].kind is WideCarryBorrowStackFailure8616.SOURCE_WIDENING_REFUSAL
    variables = {
        variable: cvar
        for variable, cvar in codegen.cfunc.variables_in_use.items()
        if isinstance(variable, SimStackVariable)
    }
    assert {
        (variable.offset, variable.size, machine_bp_offset_for_stack_variable_8616(codegen, variable))
        for variable in variables
    } == {(-8, 2, -6), (-6, 2, -4)}
    assert all(isinstance(cvar.variable_type, SimTypeShort) for cvar in variables.values())


def test_missing_execution_slice_refuses_logical_owner_and_keeps_raw_facts() -> None:
    function_ssa, _alias = _lift_with_stack_alias(_ADJACENT_STORES)
    logical = function_ssa.logical_memory
    assert logical is not None
    low = logical.accesses[0]
    missing = replace(low.execution_slices[0], instr_index=999)
    bad_logical = replace(
        logical,
        accesses=(replace(low, execution_slices=(missing, low.execution_slices[1])), *logical.accesses[1:]),
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(
        replace(function_ssa, logical_memory=bad_logical)
    )

    assert len(artifact.facts) == 4
    assert artifact.stats.to_dict()["materialized_count"] == 4
    assert len(artifact.logical_accesses) == 1
    assert artifact.logical_refusals[0].failure is LogicalStackMemoryAliasFailure8616.MISSING_EXECUTION_SLICE
    assert artifact.logical_stats.complete and artifact.complete


def test_logical_alias_versions_refuse_missing_identity() -> None:
    _, artifact = _lift_with_stack_alias(_ADJACENT_STORES)
    access = artifact.logical_accesses[0]
    assert access.versions == tuple(item.raw_slice.address.version for item in access.slices)
    first = access.slices[0]
    damaged = replace(first, raw_slice=replace(first.raw_slice, address=replace(first.raw_slice.address, version=None)))
    with pytest.raises(ValueError, match="requires an SSA version"):
        _ = replace(access, slices=(damaged, *access.slices[1:])).versions


def test_ambiguous_raw_site_match_refuses_logical_owner_without_dropping_raw() -> None:
    function_ssa, _alias = _lift_with_stack_alias(_ADJACENT_STORES)
    duplicated = replace(
        function_ssa,
        memory_accesses=(*function_ssa.memory_accesses, function_ssa.memory_accesses[0]),
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(duplicated)

    assert len(artifact.facts) == 5
    assert artifact.stats.complete
    assert artifact.logical_refusals[0].failure is LogicalStackMemoryAliasFailure8616.AMBIGUOUS_RAW_SITE_MATCH
    assert artifact.logical_stats.complete and artifact.complete


def test_logical_function_identity_mismatch_is_typed_and_raw_loop_stays_closed() -> None:
    function_ssa, _alias = _lift_with_stack_alias(_ADJACENT_STORES)
    logical = function_ssa.logical_memory
    assert logical is not None

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(
        replace(function_ssa, logical_memory=replace(logical, function_addr=0x2000))
    )

    assert len(artifact.facts) == 4 and artifact.stats.complete
    assert artifact.logical_accesses == ()
    assert {item.failure for item in artifact.logical_refusals} == {
        LogicalStackMemoryAliasFailure8616.FUNCTION_IDENTITY_MISMATCH
    }
    assert artifact.logical_stats.complete and artifact.complete


def test_open_and_refused_logical_inputs_close_with_typed_refusals() -> None:
    function_ssa, _alias = _lift_with_stack_alias(_ADJACENT_STORES)
    logical = function_ssa.logical_memory
    assert logical is not None
    open_source = replace(logical, stats=IRLogicalMemoryStats8616(raw_fact_count=3))
    open_artifact = build_x86_16_stack_memory_ssa_alias_artifact(
        replace(function_ssa, logical_memory=open_source)
    )
    upstream_refusal = IRLogicalMemoryRefusal8616(
        function_ssa.function_addr,
        0x1000,
        0x1007,
        1,
        IRLogicalMemoryFailureKind8616.MISSING_EXECUTION_SLICES,
        "test refusal",
    )
    refused_source = replace(
        logical,
        refusals=(upstream_refusal,),
        stats=IRLogicalMemoryStats8616(4, 4, 4, 3, 1),
    )
    refused_artifact = build_x86_16_stack_memory_ssa_alias_artifact(
        replace(function_ssa, logical_memory=refused_source)
    )

    assert len(open_artifact.facts) == 4 and len(open_artifact.logical_refusals) == 3 and open_artifact.complete
    assert {item.failure for item in open_artifact.logical_refusals} == {
        LogicalStackMemoryAliasFailure8616.UPSTREAM_LOGICAL_INCOMPLETE
    }
    assert {item.failure for item in refused_artifact.logical_refusals} == {
        LogicalStackMemoryAliasFailure8616.MISSING_EXECUTION_SLICE,
        LogicalStackMemoryAliasFailure8616.UPSTREAM_LOGICAL_REFUSAL,
    }
    assert len(refused_artifact.facts) == 4 and refused_artifact.complete


def test_logical_storage_containment_mismatch_refuses_owner() -> None:
    function_ssa, artifact = _lift_with_stack_alias(_ADJACENT_STORES)
    corrupted = replace(artifact.facts[0], storage=artifact.facts[-1].storage)

    projection = project_logical_stack_memory_alias_8616(
        function_ssa,
        (corrupted, *artifact.facts[1:]),
        artifact.accesses,
    )

    assert projection.refusals[0].failure is LogicalStackMemoryAliasFailure8616.STORAGE_CONTAINMENT_MISMATCH
    assert len(artifact.facts) == 4 and artifact.stats.complete and projection.complete


def test_corrupted_high_byte_value_flow_retains_destination_refusal() -> None:
    function_ssa, _alias = _lift_with_stack_alias(_ADJACENT_STORES)
    logical = function_ssa.logical_memory
    assert logical is not None
    high_index = logical.accesses[1].execution_slices[1].instr_index
    block = function_ssa.blocks[0]
    instructions = list(block.instrs)
    store = instructions[high_index]
    instructions[high_index] = replace(
        store,
        args=(store.args[0], IRValue(MemSpace.REG, name="dx", size=1, version=1)),
    )
    corrupted_ssa = replace(function_ssa, blocks=(replace(block, instrs=tuple(instructions)),))
    stack_alias = build_x86_16_stack_memory_ssa_alias_artifact(corrupted_ssa)

    pipeline = build_carry_borrow_widening_pipeline_8616(corrupted_ssa, stack_alias)

    resolution = pipeline.destination_aliases.resolutions[0]
    assert resolution.verdict is CarryBorrowDestinationAliasVerdict8616.UNKNOWN_REFUSE
    assert resolution.failure is CarryBorrowDestinationAliasFailure8616.VALUE_FLOW_MISMATCH
    assert len(stack_alias.facts) == 4 and stack_alias.complete
    assert pipeline.destination_aliases.stats.complete and pipeline.storage_widening.stats.complete
