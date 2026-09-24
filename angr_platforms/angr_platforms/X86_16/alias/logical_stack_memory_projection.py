"""Project logical stack operands onto exact raw SSA and Alias evidence.

Layer: Alias.
Responsibility: bind each logical SS memory operand to its exact instruction,
raw memory-SSA execution slices, versions, and canonical stack Alias owner.
Owns storage identity; raw memory-SSA and Alias projections remain unchanged.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir.core import IRAddress, MemSpace
from ..ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryRefusal8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)
from ..ir.ssa import SSABlock
from ..ir.ssa_function import SSAFunctionArtifact
from ..ir.ssa_memory_contracts import SSAMemoryAccess8616, SSAMemoryAccessKind8616, SSAMemoryAccessSlice8616
from .alias_model_impl import AliasStorageFacts, alias_facts_for_ir_address_8616
from .stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemoryAliasStats8616,
    StackMemorySSAAliasAccess8616,
    StackMemorySSAAliasAccessSlice8616,
    StackMemorySSAAliasFact8616,
)


class LogicalStackMemoryAliasVerdict8616(StrEnum):
    """Stable Alias outcome for one logical stack-memory candidate."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class LogicalStackMemoryAliasFailure8616(StrEnum):
    """Stable reason a logical operand lacks exact raw Alias ownership."""

    AMBIGUOUS_RAW_ALIAS = "ambiguous_raw_alias"
    AMBIGUOUS_RAW_SITE_MATCH = "ambiguous_raw_site_match"
    FUNCTION_IDENTITY_MISMATCH = "function_identity_mismatch"
    INCOMPLETE_LOGICAL_ACCESS = "incomplete_logical_access"
    INSTRUCTION_IDENTITY_MISMATCH = "instruction_identity_mismatch"
    MISSING_EXECUTION_SLICE = "missing_execution_slice"
    MISSING_RAW_ALIAS = "missing_raw_alias"
    NON_STACK_ADDRESS = "non_stack_address"
    STORAGE_CONTAINMENT_MISMATCH = "storage_containment_mismatch"
    UPSTREAM_LOGICAL_INCOMPLETE = "upstream_logical_incomplete"
    UPSTREAM_LOGICAL_REFUSAL = "upstream_logical_refusal"
    UPSTREAM_RAW_SSA_INCOMPLETE = "upstream_raw_ssa_incomplete"


@dataclass(frozen=True, slots=True)
class LogicalStackMemoryAliasSlice8616:
    """One logical byte bound to exact raw SSA and Alias evidence."""

    source: IRMemoryExecutionSlice8616
    raw_access: SSAMemoryAccess8616
    raw_slice: SSAMemoryAccessSlice8616
    storage: AliasStorageFacts
    raw_fact: StackMemorySSAAliasFact8616 | None = None
    raw_composed_access: StackMemorySSAAliasAccess8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Return deterministic diagnostics for the exact execution binding."""
        return {
            "source": self.source.to_dict(),
            "raw_access": self.raw_access.to_dict(),
            "raw_slice": self.raw_slice.to_dict(),
            "raw_fact": None if self.raw_fact is None else self.raw_fact.to_dict(),
            "raw_composed_access": self.raw_composed_access is not None,
        }


@dataclass(frozen=True, slots=True)
class LogicalStackMemoryAliasAccess8616:
    """One logical stack range owning all underlying raw byte executions."""

    source: IRLogicalMemoryAccess8616
    storage: AliasStorageFacts
    slices: tuple[LogicalStackMemoryAliasSlice8616, ...]
    alias_access: StackMemorySSAAliasAccess8616

    @property
    def address(self) -> IRAddress:
        """Return the canonical unversioned logical stack range."""
        return self.source.address

    @property
    def block_addr(self) -> int:
        """Return the exact machine-instruction block."""
        return int(self.source.key.block_addr)

    @property
    def instr_index(self) -> int:
        """Return the first raw execution index for deterministic ordering."""
        return int(self.slices[0].raw_access.instr_index)

    @property
    def versions(self) -> tuple[int, ...]:
        """Return every underlying raw execution version in byte order."""
        versions: list[int] = []
        for item in self.slices:
            version = item.raw_slice.address.version
            if version is None:
                raise ValueError("logical stack Alias slice requires an SSA version")
            versions.append(version)
        return tuple(versions)

    def to_dict(self) -> dict[str, object]:
        """Return deterministic logical-owner diagnostics."""
        return {
            "source": self.source.to_dict(),
            "alias_access": self.alias_access.to_dict(),
            "versions": list(self.versions),
            "slices": [item.to_dict() for item in self.slices],
        }


@dataclass(frozen=True, slots=True)
class LogicalStackMemoryAliasRefusal8616:
    """One retained logical candidate that Alias refuses to own."""

    failure: LogicalStackMemoryAliasFailure8616
    detail: str
    source: IRLogicalMemoryAccess8616 | None = None
    source_refusal: IRLogicalMemoryRefusal8616 | None = None
    verdict: LogicalStackMemoryAliasVerdict8616 = LogicalStackMemoryAliasVerdict8616.UNKNOWN_REFUSE

    def to_dict(self) -> dict[str, object]:
        """Return deterministic refusal diagnostics."""
        return {
            "verdict": self.verdict.value,
            "failure": self.failure.value,
            "detail": self.detail,
            "source": None if self.source is None else self.source.to_dict(),
            "source_refusal": None if self.source_refusal is None else self.source_refusal.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class LogicalStackMemoryAliasProjection8616:
    """Separately accounted logical Alias owners and typed refusals."""

    accesses: tuple[LogicalStackMemoryAliasAccess8616, ...]
    refusals: tuple[LogicalStackMemoryAliasRefusal8616, ...]
    stats: StackMemoryAliasStats8616

    @property
    def complete(self) -> bool:
        """Return whether every logical input has one retained outcome."""
        return (
            self.stats.complete
            and len(self.accesses) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
        )


def _same_range(left: IRAddress, right: IRAddress) -> bool:
    """Compare exact canonical segmented ranges without SSA decoration."""
    return (
        left.space is right.space
        and left.base == right.base
        and left.offset == right.offset
        and left.size == right.size
        and left.status is right.status
        and left.segment_origin is right.segment_origin
    )


def _kind_for_logical(
    source: IRLogicalMemoryAccess8616,
) -> tuple[SSAMemoryAccessKind8616, StackMemoryAliasFactKind8616] | None:
    """Map one typed logical kind to its raw SSA and Alias counterparts."""
    if source.kind is IRMemoryAccessKind8616.WRITE:
        return (SSAMemoryAccessKind8616.STORE, StackMemoryAliasFactKind8616.STORE)
    if source.kind is IRMemoryAccessKind8616.READ:
        return (SSAMemoryAccessKind8616.LOAD, StackMemoryAliasFactKind8616.LOAD)
    return None


def _raw_slice_candidates(
    execution: IRMemoryExecutionSlice8616,
    kind: SSAMemoryAccessKind8616,
    raw_accesses: tuple[SSAMemoryAccess8616, ...],
) -> tuple[tuple[SSAMemoryAccess8616, SSAMemoryAccessSlice8616], ...]:
    """Return raw accesses owning one exact logical execution byte."""
    return tuple(
        (access, item)
        for access in raw_accesses
        if access.kind is kind
        and access.block_addr == execution.block_addr
        and access.instr_index == execution.instr_index
        for item in access.slices
        if _same_range(item.address, execution.address)
    )


def _alias_slice_candidates(
    access: SSAMemoryAccess8616,
    raw_slice: SSAMemoryAccessSlice8616,
    fact_kind: StackMemoryAliasFactKind8616,
    raw_facts: tuple[StackMemorySSAAliasFact8616, ...],
    raw_composed: tuple[StackMemorySSAAliasAccess8616, ...],
) -> tuple[tuple[AliasStorageFacts, StackMemorySSAAliasFact8616 | None, StackMemorySSAAliasAccess8616 | None], ...]:
    """Return exact raw Alias evidence for one selected SSA slice."""
    fact_matches = tuple(
        (fact.storage, fact, None)
        for fact in raw_facts
        if fact.kind is fact_kind
        and fact.block_addr == access.block_addr
        and fact.instr_index == access.instr_index
        and fact.address == raw_slice.address
    )
    access_matches = tuple(
        (item.storage, None, projected)
        for projected in raw_composed
        if projected.source == access
        for item in projected.slices
        if item.source == raw_slice
    )
    return fact_matches + access_matches


def _refusal(
    failure: LogicalStackMemoryAliasFailure8616,
    detail: str,
    source: IRLogicalMemoryAccess8616 | None = None,
    source_refusal: IRLogicalMemoryRefusal8616 | None = None,
) -> LogicalStackMemoryAliasRefusal8616:
    """Build one typed logical Alias refusal."""
    return LogicalStackMemoryAliasRefusal8616(failure, detail, source, source_refusal)


def _project_execution_slice_8616(
    execution: IRMemoryExecutionSlice8616,
    kinds: tuple[SSAMemoryAccessKind8616, StackMemoryAliasFactKind8616],
    source: IRLogicalMemoryAccess8616,
    blocks: dict[int, SSABlock],
    raw_accesses: tuple[SSAMemoryAccess8616, ...],
    raw_facts: tuple[StackMemorySSAAliasFact8616, ...],
    raw_composed: tuple[StackMemorySSAAliasAccess8616, ...],
) -> LogicalStackMemoryAliasSlice8616 | LogicalStackMemoryAliasRefusal8616:
    """Bind one logical execution byte to its raw SSA site and Alias owner."""
    block = blocks.get(execution.block_addr)
    candidates = _raw_slice_candidates(execution, kinds[0], raw_accesses)
    if not candidates:
        return _refusal(LogicalStackMemoryAliasFailure8616.MISSING_EXECUTION_SLICE, "logical byte has no exact raw memory-SSA site", source)
    if len(candidates) != 1:
        return _refusal(LogicalStackMemoryAliasFailure8616.AMBIGUOUS_RAW_SITE_MATCH, "logical byte matches multiple raw memory-SSA sites", source)
    raw_access, raw_slice = candidates[0]
    if block is None or not 0 <= execution.instr_index < len(block.instrs):
        return _refusal(LogicalStackMemoryAliasFailure8616.MISSING_EXECUTION_SLICE, "logical byte points outside its SSA block", source)
    instruction = block.instrs[execution.instr_index]
    raw_address = instruction.args[0] if instruction.args else None
    if instruction.addr != execution.insn_addr or not isinstance(raw_address, IRAddress) or not _same_range(raw_address, raw_access.address):
        return _refusal(LogicalStackMemoryAliasFailure8616.INSTRUCTION_IDENTITY_MISMATCH, "raw SSA instruction does not match logical site and address", source)
    aliases = _alias_slice_candidates(raw_access, raw_slice, kinds[1], raw_facts, raw_composed)
    if not aliases:
        return _refusal(LogicalStackMemoryAliasFailure8616.MISSING_RAW_ALIAS, "raw SSA slice has no exact Alias projection", source)
    if len(aliases) != 1:
        return _refusal(LogicalStackMemoryAliasFailure8616.AMBIGUOUS_RAW_ALIAS, "raw SSA slice has multiple Alias projections", source)
    storage, fact, composed = aliases[0]
    return LogicalStackMemoryAliasSlice8616(execution, raw_access, raw_slice, storage, fact, composed)


def _project_access(
    function_ssa: SSAFunctionArtifact,
    source: IRLogicalMemoryAccess8616,
    raw_facts: tuple[StackMemorySSAAliasFact8616, ...],
    raw_composed: tuple[StackMemorySSAAliasAccess8616, ...],
) -> LogicalStackMemoryAliasAccess8616 | LogicalStackMemoryAliasRefusal8616:
    """Project one complete logical operand or retain one exact refusal."""
    if not source.complete:
        return _refusal(LogicalStackMemoryAliasFailure8616.INCOMPLETE_LOGICAL_ACCESS, "logical access contract is incomplete", source)
    if source.key.function_addr != function_ssa.function_addr:
        return _refusal(LogicalStackMemoryAliasFailure8616.FUNCTION_IDENTITY_MISMATCH, "logical access belongs to another function", source)
    if source.address.space is not MemSpace.SS:
        return _refusal(LogicalStackMemoryAliasFailure8616.NON_STACK_ADDRESS, "logical access is not in SS stack memory", source)
    kinds = _kind_for_logical(source)
    if kinds is None:
        return _refusal(LogicalStackMemoryAliasFailure8616.INCOMPLETE_LOGICAL_ACCESS, "logical access kind is not a read or write", source)
    blocks = {block.addr: block for block in function_ssa.blocks}
    projected: list[LogicalStackMemoryAliasSlice8616] = []
    for execution in source.execution_slices:
        item = _project_execution_slice_8616(
            execution,
            kinds,
            source,
            blocks,
            function_ssa.memory_accesses,
            raw_facts,
            raw_composed,
        )
        if isinstance(item, LogicalStackMemoryAliasRefusal8616):
            return item
        projected.append(item)
    owner_storage = alias_facts_for_ir_address_8616(source.address)
    if not isinstance(owner_storage, AliasStorageFacts) or any(
        not owner_storage.contains(item.storage) for item in projected
    ):
        return _refusal(LogicalStackMemoryAliasFailure8616.STORAGE_CONTAINMENT_MISMATCH, "logical stack range does not contain every raw Alias byte", source)
    alias_slices = tuple(
        StackMemorySSAAliasAccessSlice8616(
            SSAMemoryAccessSlice8616(item.source.source_byte_offset, item.raw_slice.address),
            item.storage,
        )
        for item in projected
    )
    alias_access = StackMemorySSAAliasAccess8616(
        SSAMemoryAccess8616(kinds[0], source.key.block_addr, projected[0].raw_access.instr_index, source.address, tuple(item.source for item in alias_slices)),
        owner_storage,
        alias_slices,
    )
    return LogicalStackMemoryAliasAccess8616(source, owner_storage, tuple(projected), alias_access)


def project_logical_stack_memory_alias_8616(
    function_ssa: SSAFunctionArtifact,
    raw_facts: tuple[StackMemorySSAAliasFact8616, ...],
    raw_composed: tuple[StackMemorySSAAliasAccess8616, ...],
) -> LogicalStackMemoryAliasProjection8616:
    """Project logical operands without changing raw SSA or Alias accounting."""
    source = function_ssa.logical_memory
    if source is None:
        return LogicalStackMemoryAliasProjection8616((), (), StackMemoryAliasStats8616())
    inputs = len(source.accesses) + len(source.refusals)
    missing = max(0, source.stats.raw_fact_count - inputs)
    forced_failure = None
    if source.function_addr != function_ssa.function_addr:
        forced_failure = LogicalStackMemoryAliasFailure8616.FUNCTION_IDENTITY_MISMATCH
    elif not source.closed:
        forced_failure = LogicalStackMemoryAliasFailure8616.UPSTREAM_LOGICAL_INCOMPLETE
    elif not function_ssa.memory_stats.complete:
        forced_failure = LogicalStackMemoryAliasFailure8616.UPSTREAM_RAW_SSA_INCOMPLETE
    outcomes: list[LogicalStackMemoryAliasAccess8616 | LogicalStackMemoryAliasRefusal8616] = [
        (
            _refusal(forced_failure, "upstream evidence is not coherent", access)
            if forced_failure is not None
            else _project_access(function_ssa, access, raw_facts, raw_composed)
        )
        for access in source.accesses
    ]
    outcomes.extend(
        _refusal(LogicalStackMemoryAliasFailure8616.UPSTREAM_LOGICAL_REFUSAL, refusal.detail, source_refusal=refusal)
        for refusal in source.refusals
    )
    outcomes.extend(
        _refusal(LogicalStackMemoryAliasFailure8616.UPSTREAM_LOGICAL_INCOMPLETE, "logical upstream counters contain an unrepresented candidate")
        for _ in range(missing)
    )
    accesses = tuple(item for item in outcomes if isinstance(item, LogicalStackMemoryAliasAccess8616))
    refusals = tuple(item for item in outcomes if isinstance(item, LogicalStackMemoryAliasRefusal8616))
    return LogicalStackMemoryAliasProjection8616(
        accesses,
        refusals,
        StackMemoryAliasStats8616(
            raw_fact_count=len(outcomes),
            normalized_fact_count=len(accesses),
            classified_fact_count=len(accesses),
            materialized_count=len(accesses),
            failure_count=len(refusals),
        ),
    )


__all__ = [
    "LogicalStackMemoryAliasAccess8616",
    "LogicalStackMemoryAliasFailure8616",
    "LogicalStackMemoryAliasProjection8616",
    "LogicalStackMemoryAliasRefusal8616",
    "LogicalStackMemoryAliasSlice8616",
    "LogicalStackMemoryAliasVerdict8616",
    "project_logical_stack_memory_alias_8616",
]
