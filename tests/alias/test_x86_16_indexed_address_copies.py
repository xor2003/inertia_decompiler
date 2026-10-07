from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    IndexedAddressAccessKind8616,
    IndexedAddressCopyEvidence8616,
    IndexedAddressCopyFailureKind8616,
    IndexedAddressCopyLane8616,
    IndexedAddressCopyStepKind8616,
    IndexedAddressEvidence8616,
    MemSpace,
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
    build_x86_16_ir_function_artifact,
    collect_indexed_address_copy_evidence_8616,
    collect_indexed_address_evidence_8616,
    logical_memory_register_transfer,
)
from inertia.ir.indexed_address_access_normalization import (
    _normalize_group_8616,
    normalize_indexed_address_accesses_8616,
)
from inertia.ir.indexed_address_pipeline import (
    apply_x86_16_indexed_address_evidence_8616,
)
from inertia.ir.indexed_address_range_contracts import (
    IndexedLoopRangeEvidence8616,
)

from inertia.alias.indexed_address_access_classification import (
    classify_indexed_alias_accesses_8616,
)
from inertia.alias.indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
)
from inertia.alias.indexed_address_copy_contracts import (
    IndexedAliasCopyEvidence8616,
    IndexedAliasCopyFailureKind8616,
)
from inertia.alias.indexed_address_copy_projection import (
    project_indexed_address_copies_8616,
)
from inertia.alias.indexed_address_projection import (
    apply_x86_16_indexed_address_aliases_8616,
    project_indexed_address_aliases_8616,
)

GLOBAL_WORD_COPY = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 8b 87 f0 08 "
    "8b 5e fe d1 e3 89 87 4c 0b c9 c3"
)
TRANSFORMED_GLOBAL_WORD_COPY = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 8b 87 f0 08 40 "
    "8b 5e fe d1 e3 89 87 4c 0b c9 c3"
)
POINTER_WORD_COPY = bytes.fromhex(
    "55 89 e5 8b 5e 04 8b 07 8b 5e 06 89 07 5d c3"
)
DIFFERENT_INDEX_GLOBAL_WORD_COPY = bytes.fromhex(
    "55 89 e5 83 ec 04 c7 46 fe 01 00 c7 46 fc 02 00 "
    "8b 5e fe d1 e3 8b 87 f0 08 "
    "8b 5e fc d1 e3 89 87 4c 0b c9 c3"
)


def _lift(code: bytes) -> SSAFunctionArtifact:
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
    return build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )


def _collect(
    code: bytes,
) -> tuple[SSAFunctionArtifact, IndexedAddressEvidence8616, IndexedAddressCopyEvidence8616]:
    artifact = _lift(code)
    addresses = collect_indexed_address_evidence_8616(artifact)
    return (
        artifact,
        addresses,
        collect_indexed_address_copy_evidence_8616(artifact, addresses),
    )


def _project_alias_copy(code: bytes) -> IndexedAliasCopyEvidence8616:
    _artifact, addresses, copies = _collect(code)
    aliases = project_indexed_address_aliases_8616(addresses)
    return project_indexed_address_copies_8616(
        copies,
        aliases,
        classify_indexed_alias_accesses_8616(aliases),
    )


def test_logical_register_transfer_batch_builds_one_scalar_index(monkeypatch) -> None:
    """A function-wide logical transfer batch indexes scalar SSA only once."""
    artifact = _lift(GLOBAL_WORD_COPY)
    logical_memory = artifact.logical_memory
    assert logical_memory is not None
    real_builder = logical_memory_register_transfer.build_scalar_definition_index_8616
    index_builds: list[SSAFunctionArtifact] = []

    def _build_index(active_artifact: SSAFunctionArtifact):
        index_builds.append(active_artifact)
        return real_builder(active_artifact)

    monkeypatch.setattr(
        logical_memory_register_transfer,
        "build_scalar_definition_index_8616",
        _build_index,
    )

    transfers = logical_memory_register_transfer.trace_logical_word_register_transfers_8616(
        artifact,
        logical_memory.accesses,
    )

    assert len(transfers) == len(logical_memory.accesses)
    assert index_builds == [artifact]


@pytest.mark.parametrize("invalid_site", [None, "missing", "different"])
def test_normalization_retains_both_word_store_members(invalid_site) -> None:
    artifact = _lift(GLOBAL_WORD_COPY)

    result = normalize_indexed_address_accesses_8616(artifact)

    store = next(access for access in result.accesses if access.op == "STORE")
    assert store.raw_fact_count == 2
    assert len(store.member_instr_indices) == 2
    assert store.instr_index == store.member_instr_indices[0]
    if invalid_site is not None:
        block = next(block for block in artifact.blocks if block.addr == store.block_addr)
        entries = tuple((i, block.instrs[i], block.instrs[i].args[0]) for i in store.member_instr_indices)
        index, instruction, address = entries[0]
        bad = replace(instruction, addr=None if invalid_site == "missing" else store.instr_addr + 1)
        with pytest.raises(ValueError, match="one known machine instruction"):
            _normalize_group_8616(block.addr, ((index, bad, address), *entries[1:]))


def test_real_word_copy_proves_both_lanes_to_one_indexed_load() -> None:
    _artifact, addresses, result = _collect(GLOBAL_WORD_COPY)

    assert addresses.closed
    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    fact = result.facts[0]
    assert fact.source.address.offset == 0x08F0
    assert fact.destination.address.offset == 0x0B4C
    assert fact.source.address.size == fact.destination.address.size == 2
    assert tuple(path.lane for path in fact.value_paths) == (
        IndexedAddressCopyLane8616.LOW_BYTE,
        IndexedAddressCopyLane8616.HIGH_BYTE,
    )
    assert tuple(
        step.kind
        for step in fact.value_paths[0].steps
        if step.kind is not IndexedAddressCopyStepKind8616.MOVE
    ) == (IndexedAddressCopyStepKind8616.LOW_BYTE_EXTRACT,)
    assert tuple(
        step.kind
        for step in fact.value_paths[1].steps
        if step.kind is not IndexedAddressCopyStepKind8616.MOVE
    ) == (
        IndexedAddressCopyStepKind8616.LOW_BYTE_EXTRACT,
        IndexedAddressCopyStepKind8616.HIGH_BYTE_SHIFT,
    )


def test_logical_word_copy_retains_both_exact_source_byte_lanes() -> None:
    _artifact, _addresses, result = _collect(GLOBAL_WORD_COPY)

    fact = result.facts[0]
    assert fact.source.address.space is fact.destination.address.space is MemSpace.DS
    logical_source = fact.value_paths[0].logical_source
    assert logical_source is not None
    assert logical_source.complete
    assert fact.value_paths[1].logical_source == logical_source
    logical_loads = tuple(
        site for site in logical_source.definition_path if site.op == "LOAD"
    )
    assert len(logical_loads) == 2
    assert (
        logical_loads[0].block_addr,
        logical_loads[0].instr_index,
        logical_loads[0].instr_addr,
    ) == (fact.source.block_addr, fact.source.instr_index, fact.source.instr_addr)
    assert logical_loads[1].block_addr == fact.source.block_addr
    assert logical_loads[1].instr_addr == fact.source.instr_addr


def test_word_copy_refuses_absent_logical_memory_artifact() -> None:
    artifact = _lift(GLOBAL_WORD_COPY)
    addresses = collect_indexed_address_evidence_8616(artifact)

    result = collect_indexed_address_copy_evidence_8616(
        replace(artifact, logical_memory=None),
        addresses,
    )

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is IndexedAddressCopyFailureKind8616.LOGICAL_MEMORY_EVIDENCE_UNPROVEN
    )


def test_word_copy_refuses_open_logical_memory_artifact() -> None:
    artifact = _lift(GLOBAL_WORD_COPY)
    addresses = collect_indexed_address_evidence_8616(artifact)
    logical_memory = artifact.logical_memory
    assert logical_memory is not None
    open_stats = replace(
        logical_memory.stats,
        raw_fact_count=logical_memory.stats.raw_fact_count + 1,
    )
    open_logical_memory = replace(logical_memory, stats=open_stats)
    assert not open_logical_memory.closed

    result = collect_indexed_address_copy_evidence_8616(
        replace(artifact, logical_memory=open_logical_memory),
        addresses,
    )

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is IndexedAddressCopyFailureKind8616.LOGICAL_MEMORY_EVIDENCE_UNPROVEN
    )


def test_word_copy_refuses_mismatched_logical_execution_slice() -> None:
    artifact = _lift(GLOBAL_WORD_COPY)
    addresses = collect_indexed_address_evidence_8616(artifact)
    source = next(
        fact
        for fact in addresses.facts
        if fact.kind is IndexedAddressAccessKind8616.LOAD
        and fact.address.offset == 0x08F0
    )
    logical_memory = artifact.logical_memory
    assert logical_memory is not None
    source_access = next(
        access
        for access in logical_memory.accesses
        if access.key.insn_addr == source.instr_addr
        and access.address.space is source.address.space
        and access.address.offset == source.address.offset
        and access.address.size == source.address.size
    )
    low_slice, high_slice = source_access.execution_slices
    mismatched_access = replace(
        source_access,
        execution_slices=(
            replace(low_slice, instr_index=low_slice.instr_index + 1),
            high_slice,
        ),
    )
    mismatched_logical_memory = replace(
        logical_memory,
        accesses=tuple(
            mismatched_access if access is source_access else access
            for access in logical_memory.accesses
        ),
    )
    assert mismatched_logical_memory.closed

    result = collect_indexed_address_copy_evidence_8616(
        replace(artifact, logical_memory=mismatched_logical_memory),
        addresses,
    )

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is IndexedAddressCopyFailureKind8616.LOGICAL_MEMORY_EVIDENCE_UNPROVEN
    )


def test_transformed_word_value_refuses_copy_materialization() -> None:
    _artifact, _addresses, result = _collect(TRANSFORMED_GLOBAL_WORD_COPY)

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is IndexedAddressCopyFailureKind8616.VALUE_OPERATION_UNSUPPORTED
    )


def test_pointer_copy_remains_ir_evidence_without_global_claim() -> None:
    _artifact, _addresses, result = _collect(POINTER_WORD_COPY)

    assert result.closed
    assert result.refusals == ()
    assert len(result.facts) == 1
    fact = result.facts[0]
    assert fact.source.address.offset == fact.destination.address.offset == 0
    assert fact.source.index_shift == fact.destination.index_shift == 0


def test_alias_projects_both_global_copy_endpoints_and_index_identity() -> None:
    result = _project_alias_copy(GLOBAL_WORD_COPY)

    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    fact = result.facts[0]
    assert fact.source.storage.base_offset == 0x08F0
    assert fact.destination.storage.base_offset == 0x0B4C
    assert (
        fact.source.storage.index_source_range.storage.identity
        == fact.destination.storage.index_source_range.storage.identity
    )


def test_alias_refuses_pointer_copy_as_non_global() -> None:
    result = _project_alias_copy(POINTER_WORD_COPY)

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert result.refusals[0].failure is IndexedAliasCopyFailureKind8616.NON_GLOBAL_ENDPOINT


def test_alias_refuses_global_copy_with_different_index_storage() -> None:
    result = _project_alias_copy(DIFFERENT_INDEX_GLOBAL_WORD_COPY)

    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is IndexedAliasCopyFailureKind8616.INDEX_IDENTITY_CONFLICT
    )


def test_ir_main_path_publishes_address_and_copy_evidence_atomically() -> None:
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=_lift(GLOBAL_WORD_COPY))

    assert not apply_x86_16_indexed_address_evidence_8616(None, codegen)

    addresses = codegen._inertia_indexed_address_evidence_8616
    copies = codegen._inertia_indexed_address_copy_evidence_8616
    ranges = codegen._inertia_indexed_loop_range_evidence_8616
    assert isinstance(addresses, IndexedAddressEvidence8616)
    assert isinstance(copies, IndexedAddressCopyEvidence8616)
    assert isinstance(ranges, IndexedLoopRangeEvidence8616)
    assert copies.closed
    assert copies.source is addresses
    assert ranges.closed
    assert ranges.stats.raw_fact_count == ranges.stats.failure_count == 2


def test_main_path_publishes_ir_and_alias_copy_evidence_atomically() -> None:
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=_lift(GLOBAL_WORD_COPY))

    assert not apply_x86_16_indexed_address_evidence_8616(None, codegen)
    assert not apply_x86_16_indexed_address_aliases_8616(None, codegen)

    aliases = codegen._inertia_indexed_address_alias_evidence_8616
    copies = codegen._inertia_indexed_address_alias_copy_evidence_8616
    ranges = codegen._inertia_indexed_loop_range_alias_evidence_8616
    assert isinstance(aliases, IndexedAddressAliasEvidence8616)
    assert isinstance(copies, IndexedAliasCopyEvidence8616)
    assert copies.closed
    assert copies.aliases is aliases
    assert ranges.closed
    assert ranges.stats.raw_fact_count == ranges.stats.failure_count == 2
