"""Trace exact logical word reads through byte-versioned memory SSA.

Layer: IR.
Responsibility: prove constant word values on each immediate CFG predecessor
from exact logical WRITE facts, STORE versions, and memory-phi inputs. This
owner does not infer pointer types or join separate storage objects.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import IRAddress
from .logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
)
from .logical_memory_write_value import (
    LogicalWordWriteValueArtifact8616,
    LogicalWordWriteValueFact8616,
)
from .ssa_function import SSAFunctionArtifact
from .ssa_memory_contracts import (
    SSAMemoryAccess8616,
    SSAMemoryAccessKind8616,
    SSAMemoryIncomingValue8616,
    SSAMemoryPhiNode8616,
)


class LogicalWordReadValueFailureKind8616(StrEnum):
    """Why a versioned word LOAD has no complete fixed-value proof."""

    WRITE_FACTS_OPEN = "write_facts_open"
    MEMORY_SSA_OPEN = "memory_ssa_open"
    LOAD_NOT_WORD = "load_not_word"
    WRITER_CONFLICT = "writer_conflict"
    SOURCE_MISSING = "source_missing"
    PHI_PREDECESSOR_CONFLICT = "phi_predecessor_conflict"
    NESTED_PHI_UNSUPPORTED = "nested_phi_unsupported"
    BYTE_WRITERS_DIFFER = "byte_writers_differ"
    NON_CONSTANT_WRITE = "non_constant_write"


@dataclass(frozen=True, slots=True)
class LogicalWordReadIncomingValue8616:
    """One path's word value with both exact byte-reaching chains."""

    source_block_addr: int | None
    constant: int
    writer: LogicalWordWriteValueFact8616
    store_addresses: tuple[IRAddress, IRAddress]
    phi_nodes: tuple[SSAMemoryPhiNode8616 | None, SSAMemoryPhiNode8616 | None]
    phi_inputs: tuple[SSAMemoryIncomingValue8616 | None, SSAMemoryIncomingValue8616 | None]

    def complete_for(
        self,
        load: IRLogicalMemoryAccess8616,
        read_slices: tuple[SSAMemoryAccess8616, SSAMemoryAccess8616],
    ) -> bool:
        """Check durable byte/version and selected predecessor evidence."""
        if not self.writer.complete or not self.writer.is_constant or self.constant != self.writer.constant:
            return False
        if len(load.execution_slices) != 2 or not load.complete:
            return False
        for index, read in enumerate(read_slices):
            execution = load.execution_slices[index]
            read_site_matches = (
                read.block_addr == execution.block_addr
                and read.instr_index == execution.instr_index
            )
            read_byte_matches = (
                len(read.slices) == 1
                and _same_byte_location_8616(read.address, execution.address)
            )
            if read.kind is not SSAMemoryAccessKind8616.LOAD or not read.complete or not read_site_matches or not read_byte_matches:
                return False
            load_address = read.slices[0].address
            store = self.store_addresses[index]
            source = self.writer.lanes[index].execution_slice.address
            if store.version is None or not _same_byte_location_8616(store, source):
                return False
            phi, incoming = self.phi_nodes[index], self.phi_inputs[index]
            if phi is None:
                if incoming is not None or store != load_address:
                    return False
            elif (
                incoming is None
                or phi.target != load_address
                or incoming not in phi.incoming
                or incoming.address != store
                or incoming.source_block_addr != self.source_block_addr
            ):
                return False
        return True


@dataclass(frozen=True, slots=True)
class LogicalWordReadValueFact8616:
    """One word LOAD with a fixed value on every proved incoming CFG edge."""

    load: IRLogicalMemoryAccess8616
    read_slices: tuple[SSAMemoryAccess8616, SSAMemoryAccess8616]
    incoming: tuple[LogicalWordReadIncomingValue8616, ...]

    @property
    def complete(self) -> bool:
        """Reject missing, duplicate, or corrupted path/value evidence."""
        paths = tuple(item.source_block_addr for item in self.incoming)
        phi_nodes = tuple(phi for item in self.incoming for phi in item.phi_nodes if phi is not None)
        if phi_nodes:
            expected = tuple(sorted(item.source_block_addr for item in phi_nodes[0].incoming))
            phi_paths_match = all(
                tuple(sorted(item.source_block_addr for item in phi.incoming)) == expected
                for phi in phi_nodes
            )
        else:
            expected = (None,)
            phi_paths_match = True
        return bool(
            self.load.kind is IRMemoryAccessKind8616.READ
            and self.load.address.size == 2
            and self.load.complete
            and paths == expected and phi_paths_match
            and all(item.complete_for(self.load, self.read_slices) for item in self.incoming)
        )


@dataclass(frozen=True, slots=True)
class LogicalWordReadValueRefusal8616:
    """An attempted LOAD and the typed reason its value remains unknown."""

    load: IRLogicalMemoryAccess8616
    failure: LogicalWordReadValueFailureKind8616


@dataclass(frozen=True, slots=True)
class LogicalWordReadValueArtifact8616:
    """Closed one-candidate reaching-value result for an exact word LOAD."""

    fact: LogicalWordReadValueFact8616 | None
    refusal: LogicalWordReadValueRefusal8616 | None
    stats: IRLogicalMemoryStats8616

    @property
    def closed(self) -> bool:
        """Require exactly one proved fact or typed refusal."""
        return bool(
            self.stats.closed
            and self.stats.raw_fact_count == 1
            and ((self.fact is not None and self.fact.complete and self.refusal is None
                  and self.stats.materialized_count == 1 and self.stats.failure_count == 0)
                 or (self.fact is None and self.refusal is not None
                     and self.stats.materialized_count == 0 and self.stats.failure_count == 1))
        )


@dataclass(frozen=True, slots=True)
class _ByteSource8616:
    """One STORE-version leaf and optional selected phi edge."""

    writer: LogicalWordWriteValueFact8616
    store_address: IRAddress
    phi: SSAMemoryPhiNode8616 | None
    incoming: SSAMemoryIncomingValue8616 | None


class _ProofFailure8616(Exception):
    """Internal typed proof refusal, not a substitute value."""

    def __init__(self, kind: LogicalWordReadValueFailureKind8616) -> None:
        """Keep the exact boundary condition for the public refusal."""
        super().__init__(kind.value)
        self.kind = kind


def _same_byte_location_8616(left: IRAddress, right: IRAddress) -> bool:
    """Compare one segmented byte location without treating versions as identity."""
    return bool(
        left.space is right.space and left.base == right.base
        and left.offset == right.offset and left.size == right.size == 1
    )


def _writer_versions_8616(
    artifact: SSAFunctionArtifact,
    writes: LogicalWordWriteValueArtifact8616,
    load: IRLogicalMemoryAccess8616,
) -> dict[IRAddress, LogicalWordWriteValueFact8616]:
    """Match writes to the selected segmented word, not unrelated SP effects."""
    stores = tuple(access for access in artifact.memory_accesses
                   if access.kind is SSAMemoryAccessKind8616.STORE and access.complete)
    versions: dict[IRAddress, LogicalWordWriteValueFact8616] = {}
    for fact in writes.facts:
        destination = fact.access.address
        requested = load.address
        if (
            destination.space is not requested.space or destination.base != requested.base
            or destination.offset != requested.offset or destination.size != requested.size
        ):
            continue
        for lane in fact.lanes:
            execution = lane.execution_slice
            matching = tuple(
                access.slices[0].address
                for access in stores
                if access.block_addr == execution.block_addr
                and access.instr_index == execution.instr_index
                and len(access.slices) == 1
                and _same_byte_location_8616(access.address, execution.address)
            )
            if len(matching) != 1 or matching[0] in versions:
                raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.WRITER_CONFLICT)
            versions[matching[0]] = fact
    return versions


def _read_slices_8616(
    artifact: SSAFunctionArtifact,
    load: IRLogicalMemoryAccess8616,
) -> tuple[SSAMemoryAccess8616, SSAMemoryAccess8616]:
    """Find exactly the two byte SSA LOADs owned by one logical word READ."""
    reads = tuple(access for access in artifact.memory_accesses
                  if access.kind is SSAMemoryAccessKind8616.LOAD and access.complete)
    selected: list[SSAMemoryAccess8616] = []
    for execution in load.execution_slices:
        matching = tuple(
            access for access in reads
            if access.block_addr == execution.block_addr
            and access.instr_index == execution.instr_index
            and len(access.slices) == 1
            and _same_byte_location_8616(access.address, execution.address)
        )
        if len(matching) != 1:
            raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.LOAD_NOT_WORD)
        selected.append(matching[0])
    return selected[0], selected[1]


def _byte_sources_8616(
    artifact: SSAFunctionArtifact,
    load: IRLogicalMemoryAccess8616,
    address: IRAddress,
    writers: dict[IRAddress, LogicalWordWriteValueFact8616],
) -> dict[int | None, _ByteSource8616]:
    """Resolve a direct STORE version or one complete immediate memory phi."""
    direct = writers.get(address)
    if direct is not None:
        return {None: _ByteSource8616(direct, address, None, None)}
    matching = tuple(phi for phi in artifact.memory_phi_nodes if phi.target == address)
    if len(matching) != 1:
        raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.SOURCE_MISSING)
    phi = matching[0]
    expected = artifact.predecessor_map.get(phi.block_addr)
    actual = tuple(item.source_block_addr for item in phi.incoming)
    predecessors_match = (
        expected is not None and len(expected) >= 2
        and tuple(sorted(expected)) == tuple(sorted(actual))
        and len(set(actual)) == len(actual)
    )
    phi_storage_matches = all(
        _same_byte_location_8616(item.address, address) for item in phi.incoming
    )
    if phi.block_addr != load.key.block_addr or not predecessors_match or not phi_storage_matches:
        raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.PHI_PREDECESSOR_CONFLICT)
    sources: dict[int | None, _ByteSource8616] = {}
    for item in phi.incoming:
        writer = writers.get(item.address)
        if writer is None:
            nested = any(node.target == item.address for node in artifact.memory_phi_nodes)
            kind = (LogicalWordReadValueFailureKind8616.NESTED_PHI_UNSUPPORTED if nested
                    else LogicalWordReadValueFailureKind8616.SOURCE_MISSING)
            raise _ProofFailure8616(kind)
        sources[item.source_block_addr] = _ByteSource8616(writer, item.address, phi, item)
    return sources


def _incoming_values_8616(
    load: IRLogicalMemoryAccess8616,
    read_slices: tuple[SSAMemoryAccess8616, SSAMemoryAccess8616],
    sources: tuple[dict[int | None, _ByteSource8616], dict[int | None, _ByteSource8616]],
) -> tuple[LogicalWordReadIncomingValue8616, ...]:
    """Join byte lanes only when all paths have the same logical word writer."""
    path_sets = tuple({path for path in items if path is not None} for items in sources)
    paths: set[int] = path_sets[0] | path_sets[1]
    if any(items and items != paths for items in path_sets):
        raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.PHI_PREDECESSOR_CONFLICT)
    incoming: list[LogicalWordReadIncomingValue8616] = []
    for path in sorted(paths) if paths else (None,):
        low = sources[0].get(path) or sources[0].get(None)
        high = sources[1].get(path) or sources[1].get(None)
        if low is None or high is None:
            raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.SOURCE_MISSING)
        if low.writer != high.writer:
            raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.BYTE_WRITERS_DIFFER)
        writer = low.writer
        if not writer.is_constant:
            raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.NON_CONSTANT_WRITE)
        incoming.append(LogicalWordReadIncomingValue8616(
            path, writer.constant, writer,
            (low.store_address, high.store_address),
            (low.phi, high.phi), (low.incoming, high.incoming),
        ))
    result = tuple(incoming)
    if not LogicalWordReadValueFact8616(load, read_slices, result).complete:
        raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.BYTE_WRITERS_DIFFER)
    return result


def trace_logical_word_read_values_8616(
    artifact: SSAFunctionArtifact,
    writes: LogicalWordWriteValueArtifact8616,
    load: IRLogicalMemoryAccess8616,
) -> LogicalWordReadValueArtifact8616:
    """Prove one word LOAD's fixed values per direct or immediate-phi path."""
    try:
        if not writes.closed or writes.function_addr != artifact.function_addr:
            raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.WRITE_FACTS_OPEN)
        # Unrelated SP push/return accesses may be refused; the selected BP
        # read still has its own complete version/phi proof below.
        if not artifact.memory_stats.complete:
            raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.MEMORY_SSA_OPEN)
        logical_memory = artifact.logical_memory
        belongs_to_closed_memory = (
            logical_memory is not None and logical_memory.closed
            and load in logical_memory.accesses
        )
        exact_word_read = (
            load.kind is IRMemoryAccessKind8616.READ
            and load.address.size == 2 and load.complete
            and len(load.execution_slices) == 2
            and tuple(item.source_byte_offset for item in load.execution_slices) == (0, 1)
        )
        if not belongs_to_closed_memory or not exact_word_read:
            raise _ProofFailure8616(LogicalWordReadValueFailureKind8616.LOAD_NOT_WORD)
        read_slices = _read_slices_8616(artifact, load)
        writers = _writer_versions_8616(artifact, writes, load)
        low = _byte_sources_8616(artifact, load, read_slices[0].slices[0].address, writers)
        high = _byte_sources_8616(artifact, load, read_slices[1].slices[0].address, writers)
        fact = LogicalWordReadValueFact8616(
            load, read_slices, _incoming_values_8616(load, read_slices, (low, high))
        )
    except _ProofFailure8616 as failure:
        return LogicalWordReadValueArtifact8616(
            None, LogicalWordReadValueRefusal8616(load, failure.kind),
            IRLogicalMemoryStats8616(1, 1, 1, 0, 1),
        )
    return LogicalWordReadValueArtifact8616(
        fact, None, IRLogicalMemoryStats8616(1, 1, 1, 1, 0),
    )


__all__ = [
    "LogicalWordReadIncomingValue8616", "LogicalWordReadValueArtifact8616",
    "LogicalWordReadValueFact8616", "LogicalWordReadValueFailureKind8616",
    "LogicalWordReadValueRefusal8616", "trace_logical_word_read_values_8616",
]
