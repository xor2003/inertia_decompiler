"""Close a bounded binary caller corpus rooted at one proved entry.

Layer: Frontend instruction inventory.
Responsibility: traverse mapped direct-call targets from an independently
proved entry head across closed ``ExactFunctionRangeBoundary8616`` surfaces,
then publish one ``DecodedDirectCallsiteIndex8616`` for the whole corpus.
This owner never invents entries, never follows indirect or unresolved
control flow, and never consults optional function catalogs: every root is
caller-supplied evidence (an authenticated MZ header entry or another
proven head) and every discovered root is a decoded direct-call target
inside the mapped image. Missing boundaries, foreign projects and
exhausted budgets refuse with typed results instead of guessing.
Caller-supplied root iterables are consumed under an explicit
``max_root_inputs`` draw cap: an unbounded or duplicate-flooded
generator refuses ``BUDGET_ROOT_INPUTS`` rather than expanding without
limit, and an over-budget decoded census refuses
``BUDGET_INSTRUCTIONS`` without materializing a truncated corpus.

Caller-edge evidence exists before callee closure: a discovered direct-call
target whose mapped boundary cannot close (for example a callee whose near
return awaits the transported caller premise) becomes a typed pending
obligation — ``PARTIAL_CALLER_EVIDENCE`` with the target listed in
``pending_targets`` — instead of destroying the already-decoded caller
census. The partial corpus is never ``ready`` and its index covers only
closed caller surfaces; consumers must treat the obligations as unresolved
until their own proofs close them. Roots supplied by the caller are trusted
differently: an explicit root that cannot close still refuses the whole
corpus with ``BOUNDARY_MISSING``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from .frontend_direct_callsite_index import (
    DecodedCallerCensus8616,
    DecodedDirectCallsiteIndex8616,
    DecodedFarCallTarget8616,
    DirectCallTargetResolver8616,
    _boundary_instruction_address_8616,
    build_decoded_direct_callsite_index_8616,
)
from .frontend_function_boundary import mapped_entry_function_boundary_8616

__all__ = [
    "InvocationInventory8616",
    "InvocationInventoryBudget8616",
    "InvocationInventoryStats8616",
    "InvocationInventoryStatus8616",
    "build_invocation_inventory_8616",
]


class InvocationInventoryStatus8616(StrEnum):
    """Typed availability of one entry-rooted decoded caller corpus."""

    READY = "ready"
    #: The traversal completed and every closed caller surface contributed
    #: its decoded census to the index, but one or more discovered call
    #: targets could not close a mapped boundary — they remain typed
    #: obligations in ``pending_targets``. The index is caller-edge
    #: evidence only, never a claim that the corpus is closed.
    PARTIAL_CALLER_EVIDENCE = "partial_caller_evidence"
    SURFACE_UNAVAILABLE = "surface_unavailable"
    ENTRY_UNMAPPED = "entry_unmapped"
    BOUNDARY_MISSING = "boundary_missing"
    BUDGET_BOUNDARIES = "budget_boundaries"
    BUDGET_INSTRUCTIONS = "budget_instructions"
    BUDGET_ROOT_INPUTS = "budget_root_inputs"


@dataclass(frozen=True, slots=True)
class InvocationInventoryBudget8616:
    """Shared work limits; exhaustion supplies no corpus.

    ``max_boundaries`` bounds distinct closed caller surfaces and
    ``max_instructions`` bounds the decoded instruction census summed
    across them. ``max_root_inputs`` bounds items drawn from the
    caller-supplied root iterable — duplicates included — because
    covered roots do not consume the boundary budget and an unbounded
    iterable must refuse instead of hanging. All three must be positive
    so a zero budget can never look like a successful empty traversal.
    """

    max_boundaries: int = 64
    max_instructions: int = 65536
    max_root_inputs: int = 4096

    def __post_init__(self) -> None:
        """Require positive typed limits."""
        if type(self.max_boundaries) is not int or self.max_boundaries < 1:
            raise ValueError("invocation inventory requires a positive boundary budget")
        if type(self.max_instructions) is not int or self.max_instructions < 1:
            raise ValueError("invocation inventory requires a positive instruction budget")
        if type(self.max_root_inputs) is not int or self.max_root_inputs < 1:
            raise ValueError("invocation inventory requires a positive root-input budget")


@dataclass(frozen=True, slots=True)
class InvocationInventoryStats8616:
    """Closed traversal accounting: each examined head lands in one bucket.

    ``raw_fact_count`` counts every distinct head candidate examined —
    supplied roots plus each in-image decoded direct-call target the first
    time it is seen. ``normalized_fact_count`` resolves each candidate to
    exactly one outcome: a materialized boundary, a refused boundary, a
    deferred pending obligation, or coverage by an earlier boundary's
    decoded census. ``failure_count`` counts heads whose mapped-boundary
    closure refused; ``pending_count`` counts discovered targets deferred
    as obligations. A traversal that stops early leaves candidates
    unnormalized, so ``closed`` stays false on every non-READY result that
    still had queued work.
    """

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    covered_count: int
    pending_count: int

    @property
    def closed(self) -> bool:
        """Return whether every examined candidate has an accounted outcome."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count
            == self.materialized_count
            + self.failure_count
            + self.covered_count
            + self.pending_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count + self.pending_count
            and min(
                self.raw_fact_count,
                self.normalized_fact_count,
                self.classified_fact_count,
                self.materialized_count,
                self.failure_count,
                self.covered_count,
                self.pending_count,
            )
            >= 0
        )


@dataclass(frozen=True, slots=True)
class InvocationInventory8616:
    """One typed corpus result; a complete traversal may emit a partial index.

    ``boundary_heads`` preserves the deterministic traversal order of the
    closed surfaces; ``callsite_index`` is the decoded direct-call index
    over their combined instruction census — present for ``READY`` and for
    ``PARTIAL_CALLER_EVIDENCE``, where it covers only the closed caller
    surfaces. ``pending_targets`` names each discovered direct-call target
    whose boundary could not close: typed obligations a consumer must keep
    visible, never silently drop. ``refusal_addr`` names the head whose
    closure or budget check refused. ``stats`` stays closed whenever every
    examined candidate was resolved; an early refusal with queued work left
    reports honestly open accounting.
    """

    status: InvocationInventoryStatus8616
    entry: int
    boundary_heads: tuple[int, ...]
    callsite_index: DecodedDirectCallsiteIndex8616 | None
    stats: InvocationInventoryStats8616
    instruction_count: int
    out_of_image_target_count: int
    refusal_addr: int | None
    pending_targets: tuple[int, ...] = ()

    @property
    def ready(self) -> bool:
        """Return whether the corpus is closed; partial evidence never is."""
        return bool(
            self.status is InvocationInventoryStatus8616.READY
            and self.caller_evidence_ready
        )

    @property
    def caller_evidence_ready(self) -> bool:
        """Admit closed caller evidence only with reconciled target obligations."""
        if self.callsite_index is None or not self.stats.closed or self.stats.failure_count:
            return False
        if (
            self.stats.materialized_count != len(self.boundary_heads)
            or self.stats.pending_count != len(self.pending_targets)
            or len(set(self.pending_targets)) != len(self.pending_targets)
        ):
            return False
        if self.status is InvocationInventoryStatus8616.READY:
            return not self.pending_targets
        if self.status is InvocationInventoryStatus8616.PARTIAL_CALLER_EVIDENCE:
            return bool(self.pending_targets)
        return False


class _MappedImage8616(Protocol):
    """Third-party loaded-object bounds, inclusive at the upper endpoint."""

    min_addr: int
    max_addr: int


class _MappedLoader8616(Protocol):
    """Third-party object lookup for one independently proved address."""

    def find_object_containing(self, address: int) -> object | None:
        """Return the loaded image owning this coordinate."""
        ...


class _MappedProject8616(Protocol):
    """Minimal loader boundary; boundary closure stays with its owner."""

    loader: _MappedLoader8616


class _BoundaryDisassembly8616(Protocol):
    """Third-party decoded instruction sequence for one reachable block."""

    insns: Sequence[object]


class _BoundaryBlock8616(Protocol):
    """Third-party block projection consumed only at the frontend boundary."""

    addr: int
    capstone: _BoundaryDisassembly8616


@dataclass(slots=True)
class _Traversal8616:
    """Mutable traversal ledger for one bounded census.

    ``explicit_roots`` distinguishes caller-supplied heads (whose failed
    closure refuses the corpus) from traversal-discovered direct-call
    targets (whose failed closure becomes a pending obligation in
    ``pending_targets``).
    """

    queue: list[int]
    covered: set[int]
    seen: set[int]
    decoded_ranges: list[DecodedCallerCensus8616]
    explicit_roots: frozenset[int] = frozenset()
    boundary_heads: list[int] = field(default_factory=list)
    covered_count: int = 0
    failure_count: int = 0
    instruction_count: int = 0
    out_of_image_targets: set[int] = field(default_factory=set)
    pending_targets: list[int] = field(default_factory=list)


def _refused_inventory_8616(
    entry: int,
    status: InvocationInventoryStatus8616,
    *,
    stats: InvocationInventoryStats8616 | None = None,
    boundary_heads: tuple[int, ...] = (),
    instruction_count: int = 0,
    out_of_image_target_count: int = 0,
    refusal_addr: int | None = None,
    pending_targets: tuple[int, ...] = (),
) -> InvocationInventory8616:
    """Publish one typed non-result with the evidence collected so far."""
    return InvocationInventory8616(
        status=status,
        entry=entry,
        boundary_heads=boundary_heads,
        callsite_index=None,
        stats=(
            InvocationInventoryStats8616(0, 0, 0, 0, 0, 0, 0)
            if stats is None
            else stats
        ),
        instruction_count=instruction_count,
        out_of_image_target_count=out_of_image_target_count,
        refusal_addr=refusal_addr,
        pending_targets=pending_targets,
    )


def _mapped_bounds_8616(
    project: object, entry: int
) -> tuple[int, int] | InvocationInventoryStatus8616:
    """Return the mapped image bounds for ``entry`` or a typed refusal."""
    try:
        loader = cast(_MappedProject8616, project).loader
        mapped = cast(_MappedImage8616 | None, loader.find_object_containing(entry))
    except (AttributeError, TypeError):
        return InvocationInventoryStatus8616.SURFACE_UNAVAILABLE
    if mapped is None:
        return InvocationInventoryStatus8616.ENTRY_UNMAPPED
    lower, upper = mapped.min_addr, mapped.max_addr
    if type(lower) is not int or type(upper) is not int or not lower <= entry <= upper:
        return InvocationInventoryStatus8616.ENTRY_UNMAPPED
    return lower, upper


@dataclass(frozen=True, slots=True)
class _RootConsumption8616:
    """Bounded root-input consumption: one deduplicated queue or a refusal.

    ``queue`` preserves first-seen order with ``entry`` leading.
    ``distinct_count`` counts every distinct candidate examined —
    accepted roots plus an overflowing drawn item — so a refused result
    can still report how much evidence the input carried. A drawn item
    beyond ``max_root_inputs`` lands in ``overflow_root`` instead of the
    queue; the corpus is refused, never silently truncated.
    """

    queue: tuple[int, ...]
    distinct_count: int
    overflow_root: int | None


def _traversal_roots_8616(
    entry: int,
    extra_entries: Iterable[int],
    max_root_inputs: int,
) -> _RootConsumption8616:
    """Order the validated root set deterministically, entry first.

    The iterable is drawn lazily under the ``max_root_inputs`` cap on
    drawn items — not accepted roots — so a duplicate flood or unbounded
    generator still refuses on its ``max_root_inputs + 1``-th item.
    Malformed items remain a caller contract error and fail loudly
    before the cap is consulted.
    """
    queue: list[int] = [entry]
    queued: set[int] = {entry}
    for drawn, head in enumerate(extra_entries, start=1):
        if type(head) is not int or head < 0:
            raise TypeError("invocation inventory roots must be nonnegative integers")
        if drawn > max_root_inputs:
            return _RootConsumption8616(
                queue=tuple(queue),
                distinct_count=len(queued | {head}),
                overflow_root=head,
            )
        if head not in queued:
            queued.add(head)
            queue.append(head)
    return _RootConsumption8616(
        queue=tuple(queue),
        distinct_count=len(queued),
        overflow_root=None,
    )


def _scan_call_targets_8616(
    traversal: _Traversal8616,
    instructions: tuple[object, ...],
    lower: int,
    upper: int,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> None:
    """Fold one boundary's decoded direct-call targets into the worklist.

    An in-image target already covered by a decoded census is normalized
    as covered evidence; one already seen is deduplicated; a new one
    becomes a queued root. Out-of-image targets are counted evidence, not
    caller candidates — they can never close a mapped boundary.
    """
    for instruction in instructions:
        resolved = direct_target_resolver(instruction)
        target = (
            resolved.target_addr
            if isinstance(resolved, DecodedFarCallTarget8616)
            else resolved
        )
        if type(target) is not int:
            continue
        if not lower <= target <= upper:
            traversal.out_of_image_targets.add(target)
            continue
        if target in traversal.seen:
            continue
        traversal.seen.add(target)
        if target in traversal.covered:
            traversal.covered_count += 1
            continue
        traversal.queue.append(target)


def _bounded_instruction_census_8616(
    blocks: tuple[_BoundaryBlock8616, ...],
    remaining: int,
) -> tuple[object, ...] | None:
    """Collect one boundary's decoded census within the budget left.

    Blocks are visited in ascending address order and each block's
    disassembly is enumerated incrementally, so an oversized census draws at
    most ``remaining + 1`` instructions before refusing. A block's third-party
    decoder may already have materialized its instruction list; this bounds
    our additional census, not that decoder's work. No truncated corpus can
    pass as complete.
    ``None`` reports exhaustion; an empty boundary inside budget still
    returns an empty census.
    """
    instructions: list[object] = []
    for block in sorted(blocks, key=lambda item: item.addr):
        for instruction in block.capstone.insns:
            if len(instructions) >= remaining:
                return None
            instructions.append(instruction)
    return tuple(instructions)


def _traverse_inventory_8616(
    project: object,
    traversal: _Traversal8616,
    lower: int,
    upper: int,
    budget: InvocationInventoryBudget8616,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> tuple[InvocationInventoryStatus8616, int] | None:
    """Close every queued head, deferring discovered targets that cannot.

    A discovered direct-call target whose mapped boundary returns ``None``
    is a pending obligation — the caller's decoded edge is already
    authenticated evidence, and the callee may need a transported premise
    before its surface can close. The target is recorded in
    ``pending_targets`` and traversal continues; closed and pending heads
    share ``max_boundaries``, checked before another closure attempt, so an
    unclosable-target flood refuses without additional decoding. Caller-supplied
    roots are trusted evidence and still refuse ``BOUNDARY_MISSING`` when
    they cannot close, as does any malformed boundary object regardless of
    provenance.
    """
    cursor = 0
    while cursor < len(traversal.queue):
        head = traversal.queue[cursor]
        cursor += 1
        if head in traversal.covered:
            traversal.covered_count += 1
            continue
        if len(traversal.boundary_heads) + len(traversal.pending_targets) >= budget.max_boundaries:
            return InvocationInventoryStatus8616.BUDGET_BOUNDARIES, head
        boundary = mapped_entry_function_boundary_8616(project, head)
        if boundary is None and head not in traversal.explicit_roots:
            traversal.pending_targets.append(head)
            continue
        if (
            boundary is None
            or boundary.project is not project
            or boundary.addr != head
        ):
            traversal.failure_count += 1
            return InvocationInventoryStatus8616.BOUNDARY_MISSING, head
        blocks = tuple(cast(_BoundaryBlock8616, block) for block in boundary.blocks)
        instructions = _bounded_instruction_census_8616(
            blocks, budget.max_instructions - traversal.instruction_count
        )
        if instructions is None:
            return InvocationInventoryStatus8616.BUDGET_INSTRUCTIONS, head
        traversal.instruction_count += len(instructions)
        traversal.decoded_ranges.append(DecodedCallerCensus8616(
            boundary.addr, boundary.decode_start, boundary.decode_end, instructions
        ))
        traversal.boundary_heads.append(boundary.addr)
        traversal.covered |= boundary.reachable_instruction_addrs
        _scan_call_targets_8616(traversal, instructions, lower, upper, direct_target_resolver)
    return None


def build_invocation_inventory_8616(
    project: object,
    entry: int,
    *,
    extra_entries: Iterable[int] = (),
    budget: InvocationInventoryBudget8616 | None = None,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> InvocationInventory8616:
    """Decode every closed boundary reachable by mapped direct calls.

    Traversal roots are ``entry`` plus the caller-supplied
    ``extra_entries`` in first-seen order. Each closed boundary's decoded
    instructions are scanned once for direct-call targets; an in-image
    target not already covered by a decoded census becomes a new root, so
    header-derived startup participates independently of any optional
    catalog. Resolved targets outside the entry's mapped object are
    counted as out-of-image evidence and never traversed. An explicit
    root that fails mapped-boundary closure refuses the whole corpus —
    ``BOUNDARY_MISSING`` — rather than silently dropping the caller.
    A discovered target whose boundary cannot close (``None``) becomes a
    pending obligation instead: the traversal completes, emits the index
    over the closed caller surfaces, and reports
    ``PARTIAL_CALLER_EVIDENCE`` — never ``READY`` — with the unresolved
    heads in ``pending_targets``. A malformed boundary object (foreign
    project or wrong head) still refuses ``BOUNDARY_MISSING``.
    Drawing more than ``budget.max_root_inputs`` items from
    ``extra_entries`` refuses ``BUDGET_ROOT_INPUTS`` with the overflowing
    item as evidence; a corpus is never published from truncated input.
    """
    if budget is None:
        budget = InvocationInventoryBudget8616()
    if not isinstance(budget, InvocationInventoryBudget8616):
        raise TypeError("invocation inventory requires a typed budget")
    if not callable(direct_target_resolver):
        raise TypeError("invocation inventory requires a call target resolver")
    if type(entry) is not int or entry < 0:
        return _refused_inventory_8616(0, InvocationInventoryStatus8616.ENTRY_UNMAPPED)
    bounds = _mapped_bounds_8616(project, entry)
    if isinstance(bounds, InvocationInventoryStatus8616):
        return _refused_inventory_8616(entry, bounds, refusal_addr=entry)
    lower, upper = bounds
    roots = _traversal_roots_8616(entry, extra_entries, budget.max_root_inputs)
    if roots.overflow_root is not None:
        return _refused_inventory_8616(
            entry,
            InvocationInventoryStatus8616.BUDGET_ROOT_INPUTS,
            stats=InvocationInventoryStats8616(
                raw_fact_count=roots.distinct_count,
                normalized_fact_count=0,
                classified_fact_count=0,
                materialized_count=0,
                failure_count=0,
                covered_count=0,
                pending_count=0,
            ),
            refusal_addr=roots.overflow_root,
        )
    traversal = _Traversal8616(
        queue=list(roots.queue),
        covered=set(),
        seen=set(roots.queue),
        decoded_ranges=[],
        explicit_roots=frozenset(roots.queue),
    )
    refusal = _traverse_inventory_8616(
        project, traversal, lower, upper, budget, direct_target_resolver
    )
    # A pending head later reached by another boundary's decoded census is
    # covered evidence, not an obligation — classify it with the covered
    # count so stats and ``pending_targets`` report the same outcome.
    pending = tuple(
        head for head in traversal.pending_targets if head not in traversal.covered
    )
    late_covered = len(traversal.pending_targets) - len(pending)
    stats = InvocationInventoryStats8616(
        raw_fact_count=len(traversal.seen),
        normalized_fact_count=(
            len(traversal.boundary_heads)
            + traversal.failure_count
            + traversal.covered_count
            + len(traversal.pending_targets)
        ),
        classified_fact_count=(
            len(traversal.boundary_heads)
            + traversal.failure_count
            + len(pending)
        ),
        materialized_count=len(traversal.boundary_heads),
        failure_count=traversal.failure_count,
        covered_count=traversal.covered_count + late_covered,
        pending_count=len(pending),
    )
    if refusal is not None:
        status, refusal_addr = refusal
        return _refused_inventory_8616(
            entry,
            status,
            stats=stats,
            boundary_heads=tuple(traversal.boundary_heads),
            instruction_count=traversal.instruction_count,
            out_of_image_target_count=len(traversal.out_of_image_targets),
            refusal_addr=refusal_addr,
            pending_targets=pending,
        )
    index = build_decoded_direct_callsite_index_8616(
        tuple(traversal.decoded_ranges),
        direct_target_resolver=direct_target_resolver,
        instruction_address_resolver=_boundary_instruction_address_8616,
    )
    return InvocationInventory8616(
        status=(
            InvocationInventoryStatus8616.PARTIAL_CALLER_EVIDENCE
            if pending
            else InvocationInventoryStatus8616.READY
        ),
        entry=entry,
        boundary_heads=tuple(traversal.boundary_heads),
        callsite_index=index,
        stats=stats,
        instruction_count=traversal.instruction_count,
        out_of_image_target_count=len(traversal.out_of_image_targets),
        refusal_addr=None,
        pending_targets=pending,
    )
