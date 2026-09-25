"""Resolve captured machine memory operands into logical IR artifacts.

Layer: IR.
Responsibility: validate captures, assign exact candidates by durable identity and ordinal.
Alias identity, widening, lowering, structuring, and rewrite are out of scope.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter

from .core import IRAddress, IRBlock, MemSpace
from .logical_memory_capture import IRLogicalMemoryCaptureRecord8616
from .logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryFailureKind8616,
    IRLogicalMemoryRefusal8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
)
from .logical_memory_matching import (
    LogicalMemoryExecutionCandidate8616,
    logical_memory_candidate_failure_8616,
    logical_memory_execution_candidates_8616,
    raw_logical_memory_sites_8616,
)

_MEMORY_SPACES = frozenset({MemSpace.DS, MemSpace.ES, MemSpace.SS})


def _optional_int_key(value: int | None) -> tuple[bool, int]:
    """Return a stable ordering key that places present integers first."""
    return (value is None, -1 if value is None else value)


def _capture_sort_key(
    capture: IRLogicalMemoryCaptureRecord8616,
) -> tuple[object, ...]:
    """Order captures without provisional expression text or object identities."""
    address = capture.address
    address_key: tuple[object, ...] = ()
    if isinstance(address, IRAddress):
        address_key = (address.space.value, address.base, address.offset, address.size)
    kind = capture.kind.value if isinstance(capture.kind, IRMemoryAccessKind8616) else ""
    return (
        capture.function_addr,
        _optional_int_key(capture.block_addr),
        _optional_int_key(capture.insn_addr),
        _optional_int_key(capture.access_ordinal),
        kind,
        _optional_int_key(capture.address_bits),
        address_key,
    )


def _capture_identity(capture: IRLogicalMemoryCaptureRecord8616) -> tuple[int, int, int, int] | None:
    """Return a complete durable capture key, or ``None`` for missing identity."""
    block_addr = capture.block_addr
    insn_addr = capture.insn_addr
    access_ordinal = capture.access_ordinal
    if block_addr is None or insn_addr is None or access_ordinal is None:
        return None
    if block_addr < 0 or insn_addr < 0 or access_ordinal < 0:
        return None
    return (capture.function_addr, block_addr, insn_addr, access_ordinal)


def _refusal(
    capture: IRLogicalMemoryCaptureRecord8616,
    failure: IRLogicalMemoryFailureKind8616,
    detail: str,
) -> IRLogicalMemoryRefusal8616:
    """Build one deterministic refusal from its raw capture identity."""
    return IRLogicalMemoryRefusal8616(
        function_addr=capture.function_addr,
        block_addr=capture.block_addr,
        insn_addr=capture.insn_addr,
        access_ordinal=capture.access_ordinal,
        failure=failure,
        detail=detail,
    )


def _preflight_failure(
    function_addr: int,
    capture: IRLogicalMemoryCaptureRecord8616,
    duplicate_identities: frozenset[tuple[int, int, int, int]],
) -> tuple[IRLogicalMemoryFailureKind8616, str] | None:
    """Validate capture-owned identity, mode, width, and segmented address."""
    if capture.function_addr != function_addr:
        return (
            IRLogicalMemoryFailureKind8616.INVALID_ADDRESS,
            "capture function does not match resolver function",
        )
    if capture.block_addr is None or capture.block_addr < 0:
        return (
            IRLogicalMemoryFailureKind8616.MISSING_BLOCK_ADDR,
            "capture has no valid block address",
        )
    if capture.insn_addr is None or capture.insn_addr < 0:
        return (
            IRLogicalMemoryFailureKind8616.MISSING_INSN_ADDR,
            "capture has no valid instruction address",
        )
    if capture.access_ordinal is None or capture.access_ordinal < 0:
        return (
            IRLogicalMemoryFailureKind8616.INVALID_ADDRESS,
            "capture has no valid per-instruction access ordinal",
        )
    if _capture_identity(capture) in duplicate_identities:
        return (
            IRLogicalMemoryFailureKind8616.DUPLICATE_CAPTURE_KEY,
            "multiple captures share one durable access key",
        )
    if capture.kind not in {IRMemoryAccessKind8616.READ, IRMemoryAccessKind8616.WRITE}:
        return (
            IRLogicalMemoryFailureKind8616.UNSUPPORTED_MODE,
            "only typed READ and WRITE captures have execution slices",
        )
    if capture.address_bits not in {16, 32}:
        return (
            IRLogicalMemoryFailureKind8616.MISSING_ADDRESS_WIDTH,
            "capture address width is not exactly 16 or 32 bits",
        )
    if not isinstance(capture.address, IRAddress):
        return (
            IRLogicalMemoryFailureKind8616.INVALID_ADDRESS,
            "capture has no typed segmented address",
        )
    if capture.address.space not in _MEMORY_SPACES or capture.address.size <= 0:
        return (
            IRLogicalMemoryFailureKind8616.INVALID_ADDRESS,
            "capture address lacks a supported segment or positive width",
        )
    return None


def _assign_candidates(
    candidates: tuple[tuple[LogicalMemoryExecutionCandidate8616, ...], ...],
) -> tuple[tuple[LogicalMemoryExecutionCandidate8616, ...], ...]:
    """Find at most two ordered, non-overlapping site assignments."""
    assignments: list[tuple[LogicalMemoryExecutionCandidate8616, ...]] = []

    def visit(
        capture_index: int,
        previous_end: int,
        selected: tuple[LogicalMemoryExecutionCandidate8616, ...],
    ) -> None:
        """Enumerate enough complete assignments to prove uniqueness or ambiguity."""
        if len(assignments) >= 2:
            return
        if capture_index == len(candidates):
            assignments.append(selected)
            return
        for candidate in candidates[capture_index]:
            if candidate.start_position > previous_end:
                visit(capture_index + 1, candidate.end_position, (*selected, candidate))

    visit(0, -1, ())
    return tuple(assignments)


def _access_from_candidate(
    function_addr: int,
    capture: IRLogicalMemoryCaptureRecord8616,
    candidate: LogicalMemoryExecutionCandidate8616,
) -> IRLogicalMemoryAccess8616 | IRLogicalMemoryRefusal8616:
    """Materialize one complete candidate, refusing internal inconsistency."""
    block_addr = capture.block_addr
    insn_addr = capture.insn_addr
    access_ordinal = capture.access_ordinal
    address_bits = capture.address_bits
    assert block_addr is not None
    assert insn_addr is not None
    assert access_ordinal is not None
    assert address_bits is not None
    access = IRLogicalMemoryAccess8616(
        key=IRLogicalMemoryAccessKey8616(
            function_addr=function_addr,
            block_addr=block_addr,
            insn_addr=insn_addr,
            access_ordinal=access_ordinal,
        ),
        kind=capture.kind,
        address=candidate.address,
        address_bits=address_bits,
        execution_slices=candidate.slices,
    )
    if access.complete:
        return access
    return _refusal(
        capture,
        IRLogicalMemoryFailureKind8616.BYTE_COVERAGE_CONFLICT,
        "resolved execution slices do not satisfy the logical access contract",
    )


def _resolve_site(
    function_addr: int,
    block: IRBlock,
    insn_addr: int,
    captures: tuple[IRLogicalMemoryCaptureRecord8616, ...],
) -> tuple[tuple[IRLogicalMemoryAccess8616, ...], tuple[IRLogicalMemoryRefusal8616, ...]]:
    """Resolve one instruction's captures atomically in ordinal order."""
    sites = raw_logical_memory_sites_8616(block, insn_addr)
    ordered = tuple(sorted(captures, key=lambda capture: capture.access_ordinal or 0))
    candidate_sets = tuple(
        logical_memory_execution_candidates_8616(capture, sites) for capture in ordered
    )
    assignments = _assign_candidates(candidate_sets)
    if len(assignments) > 1:
        return (), tuple(
            _refusal(
                capture,
                IRLogicalMemoryFailureKind8616.AMBIGUOUS_EXECUTION_SLICES,
                "multiple ordered execution-slice assignments satisfy the capture site",
            )
            for capture in ordered
        )
    if not assignments:
        refusals = tuple(
            _refusal(
                capture,
                *(
                    (
                        IRLogicalMemoryFailureKind8616.AMBIGUOUS_EXECUTION_SLICES,
                        "candidate slices overlap another captured operand at this instruction",
                    )
                    if candidate_set
                    else logical_memory_candidate_failure_8616(capture, sites)
                ),
            )
            for capture, candidate_set in zip(ordered, candidate_sets, strict=True)
        )
        return (), refusals
    accesses: list[IRLogicalMemoryAccess8616] = []
    refusals_list: list[IRLogicalMemoryRefusal8616] = []
    for capture, candidate in zip(ordered, assignments[0], strict=True):
        outcome = _access_from_candidate(function_addr, capture, candidate)
        if isinstance(outcome, IRLogicalMemoryAccess8616):
            accesses.append(outcome)
        else:
            refusals_list.append(outcome)
    return tuple(accesses), tuple(refusals_list)


def resolve_logical_memory_accesses_8616(
    function_addr: int,
    blocks: tuple[IRBlock, ...],
    captures: tuple[IRLogicalMemoryCaptureRecord8616, ...],
) -> IRLogicalMemoryArtifact8616:
    """Resolve each captured operand to one exact wide/byte IR site or refusal.

    Correlation is limited to durable function, block, instruction, typed access
    kind, and per-instruction ordinal evidence. Uncaptured memory operations are
    never published merely because they are adjacent to a captured operation.
    """
    ordered_captures = tuple(sorted(captures, key=_capture_sort_key))
    identities = tuple(
        identity
        for capture in ordered_captures
        if (identity := _capture_identity(capture)) is not None
    )
    identity_counts = Counter(identities)
    duplicate_identities = frozenset(
        identity for identity, count in identity_counts.items() if count > 1
    )
    blocks_by_addr: dict[int, list[IRBlock]] = {}
    for block in blocks:
        blocks_by_addr.setdefault(block.addr, []).append(block)
    accesses: list[IRLogicalMemoryAccess8616] = []
    refusals: list[IRLogicalMemoryRefusal8616] = []
    valid_by_site: dict[tuple[int, int], list[IRLogicalMemoryCaptureRecord8616]] = {}
    for capture in ordered_captures:
        preflight = _preflight_failure(function_addr, capture, duplicate_identities)
        if preflight is not None:
            refusals.append(_refusal(capture, *preflight))
            continue
        assert capture.block_addr is not None
        assert capture.insn_addr is not None
        valid_by_site.setdefault((capture.block_addr, capture.insn_addr), []).append(capture)

    for (block_addr, insn_addr), site_captures in sorted(valid_by_site.items()):
        matching_blocks = tuple(blocks_by_addr.get(block_addr, ()))
        if len(matching_blocks) != 1:
            failure = (
                IRLogicalMemoryFailureKind8616.MISSING_EXECUTION_SLICES
                if not matching_blocks
                else IRLogicalMemoryFailureKind8616.AMBIGUOUS_EXECUTION_SLICES
            )
            detail = (
                "capture block is absent from the imported function IR"
                if not matching_blocks
                else "multiple imported blocks share the capture block address"
            )
            refusals.extend(_refusal(capture, failure, detail) for capture in site_captures)
            continue
        site_accesses, site_refusals = _resolve_site(
            function_addr,
            matching_blocks[0],
            insn_addr,
            tuple(site_captures),
        )
        accesses.extend(site_accesses)
        refusals.extend(site_refusals)

    accesses.sort(
        key=lambda access: (
            access.key.block_addr,
            access.key.insn_addr,
            access.key.access_ordinal,
            access.kind.value,
        )
    )
    refusals.sort(
        key=lambda refusal: (
            _optional_int_key(refusal.block_addr),
            _optional_int_key(refusal.insn_addr),
            _optional_int_key(refusal.access_ordinal),
            refusal.failure.value,
            refusal.detail,
        )
    )
    fact_count = len(captures)
    artifact = IRLogicalMemoryArtifact8616(
        function_addr=function_addr,
        accesses=tuple(accesses),
        refusals=tuple(refusals),
        stats=IRLogicalMemoryStats8616(
            raw_fact_count=fact_count,
            normalized_fact_count=fact_count,
            classified_fact_count=fact_count,
            materialized_count=len(accesses),
            failure_count=len(refusals),
        ),
    )
    if not artifact.closed:
        raise ValueError("logical-memory resolution accounting did not close")
    return artifact


__all__ = ["resolve_logical_memory_accesses_8616"]
