"""Retain conditional near-CALL frame evidence from a refused inventory.

Layer: Frontend instruction inventory.
Responsibility: when the bounded entry-rooted caller inventory cannot close
the whole corpus — a budget refusal such as ``BUDGET_BOUNDARIES`` — but its
ledger already recorded closed caller surfaces, re-close exactly those
recorded heads and retain one closed ``DecodedDirectCallsiteIndex8616``
over only their decoded censuses, bound to the authenticated MZ source and
mapped-image digests. This is a LOCAL, conditional authority: a retained
row proves "if this exact near-CALL executes, this callee entry top slot
holds its return word" — never boot-to-caller reachability, never
segment/register preservation along a call chain, and never universal
invocation authority.

The evidence is deliberately NOT a ``Real16InvocationSource8616``: that
contract owns project-wide parent-edge search and boot authority. This
record is installed under ``_inertia_local_call_frame_evidence_8616`` and
only the conditional frame-premise consumer may consult it; pending callee
markers and complete invocation-chain requirements stay with their
existing owners. The collector decodes only surfaces the refused inventory
already proved closed — no new discovery and no budget increase — and
refuses to retain rows for callers outside the proved closed census.
Authentication failures, changed source bytes, or changed mapped native
bytes revoke the evidence rather than serving stale rows.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast

from .frontend_direct_callsite_index import (
    DecodedCallerCensus8616,
    DecodedDirectCallsiteIndex8616,
    DirectCallTargetResolver8616,
    _boundary_instruction_address_8616,
    build_decoded_direct_callsite_index_8616,
)
from .frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    mapped_entry_function_boundary_8616,
)
from .frontend_invocation_inventory import (
    InvocationInventory8616,
    InvocationInventoryBudget8616,
    InvocationInventoryStatus8616,
)
from .mz_invocation_source import MzInvocationSource8616

__all__ = [
    "LocalCallEvidenceStats8616",
    "LocalCallFrameEvidence8616",
    "collect_local_call_frame_evidence_8616",
    "install_local_call_frame_evidence_8616",
    "local_call_frame_evidence_8616",
    "local_call_frame_evidence_epoch_matches_8616",
]

# Inventory verdicts that carry a decoded corpus of their own; those install
# the project-wide source instead of local evidence.
_GLOBAL_INSTALL_STATUSES_8616: frozenset[InvocationInventoryStatus8616] = frozenset(
    {
        InvocationInventoryStatus8616.READY,
        InvocationInventoryStatus8616.PARTIAL_CALLER_EVIDENCE,
    }
)


@dataclass(frozen=True, slots=True)
class LocalCallEvidenceStats8616:
    """Closed evidence-loop accounting for one local census collection.

    ``raw_fact_count`` counts the refused inventory's closed heads;
    ``normalized_fact_count`` counts heads actually re-examined before any
    budget stop; ``classified_fact_count`` counts heads resolved to a
    materialized census or a failure; ``materialized_count`` counts
    censuses retained in the index; ``failure_count`` counts heads whose
    re-closure or census bound refused. An early budget stop leaves
    unexamined heads unnormalized, so ``closed`` reports the accounting
    honestly instead of claiming a complete re-census.
    """

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether every recorded head reached an accounted outcome."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
            and min(
                self.raw_fact_count,
                self.normalized_fact_count,
                self.classified_fact_count,
                self.materialized_count,
                self.failure_count,
            )
            >= 0
        )


@dataclass(frozen=True, slots=True)
class LocalCallFrameEvidence8616:
    """Source-authenticated conditional near-CALL frame evidence.

    Retained on the project under
    ``_inertia_local_call_frame_evidence_8616`` by the intake collector when
    the bounded caller inventory refuses but its ledger recorded closed
    caller surfaces. Fields:

    - ``project``, ``architecture`` — the exact authenticated decoding
      context; moving the record requires a new authenticated collection;
    - ``source_sha256``, ``load_segment``, ``entry_linear`` — the
      authenticated MZ projection identity the census was collected under;
    - ``image_base``, ``image_size``, ``image_sha256`` — the mapped-image
      span and digest authenticated at intake; the accessor re-reads and
      re-digests that span on every demand so mutated bytes revoke;
    - ``inventory_status`` — the refused inventory verdict, never
      ``READY`` or ``PARTIAL_CALLER_EVIDENCE``;
    - ``boundary_heads`` — exactly the caller surfaces re-closed into the
      index; the only callers whose rows this evidence may prove;
    - ``callsite_index`` — the closed decoded index over those surfaces;
      its rows are the identical objects a derived premise retains;
    - ``pending_targets`` — the refused inventory's unresolved discovered
      targets: typed obligations kept visible, never closure evidence;
    - ``stats`` — the collection's evidence-loop accounting.
    """

    project: object = field(repr=False, compare=False)
    architecture: object = field(repr=False, compare=False)
    source_sha256: str
    load_segment: int
    entry_linear: int
    image_base: int
    image_size: int
    image_sha256: str
    inventory_status: InvocationInventoryStatus8616
    boundary_heads: tuple[int, ...]
    callsite_index: DecodedDirectCallsiteIndex8616
    pending_targets: tuple[int, ...]
    stats: LocalCallEvidenceStats8616


class _LocalCallEvidenceHolder8616(Protocol):
    """Project slot carrying the optional local frame-evidence surface."""

    _inertia_local_call_frame_evidence_8616: LocalCallFrameEvidence8616 | None


class _MappedLoaderMemory8616(Protocol):
    """Third-party loader memory used for mapped-byte reauthentication."""

    def load(self, addr: int, size: int) -> object:
        """Return the mapped bytes for one linear range."""
        ...


class _MappedProject8616(Protocol):
    """Minimal loader boundary consumed by evidence reauthentication."""

    loader: _MappedLoaderSurface8616
    arch: object
    entry: int


class _MappedMainObject8616(Protocol):
    """Authenticated DOS loader paragraph used to project native bytes."""

    mz_load_segment: int


class _MappedLoaderSurface8616(Protocol):
    """Third-party loader surface exposing mapped memory."""

    memory: _MappedLoaderMemory8616
    main_object: _MappedMainObject8616


class _RetainedStaticIntake8616(Protocol):
    """Cross-layer deferred-intake record authored by the CLI layer."""

    source: object


def _bounded_boundary_census_8616(
    blocks: tuple[object, ...],
    remaining: int,
) -> tuple[object, ...] | None:
    """Collect one re-closed boundary's decoded census within the budget left.

    Blocks are visited in ascending address order and each block's
    disassembly is enumerated incrementally, mirroring the inventory
    census owner: at most ``remaining`` instructions are drawn before
    ``None`` reports exhaustion. A block's third-party decoder may already
    have materialized its instruction list; this bounds our additional
    census, not that decoder's work.
    """
    instructions: list[object] = []
    for block in sorted(blocks, key=lambda item: cast(_CensusBlock8616, item).addr):
        for instruction in cast(_CensusBlock8616, block).capstone.insns:
            if len(instructions) >= remaining:
                return None
            instructions.append(instruction)
    return tuple(instructions)


class _CensusDisassembly8616(Protocol):
    """Third-party decoded instruction sequence for one reachable block."""

    insns: Sequence[object]


class _CensusBlock8616(Protocol):
    """Third-party block projection consumed only at the frontend boundary."""

    addr: int
    capstone: _CensusDisassembly8616


def _census_instruction_addresses_8616(
    instructions: tuple[object, ...],
) -> frozenset[int]:
    """Return the decoded address set of one census instruction stream."""
    addresses: set[int] = set()
    for instruction in instructions:
        address = _boundary_instruction_address_8616(instruction)
        if type(address) is not int:
            raise ValueError("decoded boundary instruction has no address")
        addresses.add(address)
    return frozenset(addresses)


@dataclass(frozen=True, slots=True)
class _Recensus8616:
    """Outcome of re-closing the refused inventory's recorded heads.

    ``censuses`` and ``heads`` cover exactly the surfaces that re-closed
    identically under budget; ``normalized`` counts heads examined and
    ``failures`` counts heads whose re-closure or census bound refused.
    """

    censuses: tuple[DecodedCallerCensus8616, ...]
    heads: tuple[int, ...]
    normalized: int
    failures: int


def _reclosed_censuses_8616(
    project: object,
    heads: tuple[int, ...],
    budget: InvocationInventoryBudget8616,
) -> _Recensus8616:
    """Re-close each recorded head and census it within the shared budget.

    A head that fails the identical mapped-boundary closure is a recorded
    failure, never silent evidence; a census that would exceed the
    instruction budget ends the collection — unexamined heads stay
    unnormalized rather than truncated into false completeness. A census
    whose decoded addresses diverge from the boundary's own reachable set
    is a contract error and fails loudly.
    """
    censuses: list[DecodedCallerCensus8616] = []
    kept_heads: list[int] = []
    instruction_count = 0
    normalized = 0
    failures = 0
    for head in heads:
        normalized += 1
        boundary = mapped_entry_function_boundary_8616(project, head)
        if (
            type(boundary) is not ExactFunctionRangeBoundary8616
            or boundary.project is not project
            or boundary.addr != head
        ):
            failures += 1
            continue
        instructions = _bounded_boundary_census_8616(
            boundary.blocks, budget.max_instructions - instruction_count
        )
        if instructions is None:
            failures += 1
            break
        if _census_instruction_addresses_8616(instructions) != frozenset(
            boundary.reachable_instruction_addrs
        ):
            raise ValueError("re-closed boundary census does not match")
        instruction_count += len(instructions)
        censuses.append(
            DecodedCallerCensus8616(
                boundary.addr,
                boundary.decode_start,
                boundary.decode_end,
                instructions,
            )
        )
        kept_heads.append(head)
    return _Recensus8616(tuple(censuses), tuple(kept_heads), normalized, failures)


def collect_local_call_frame_evidence_8616(
    project: object,
    *,
    projection: MzInvocationSource8616,
    inventory: InvocationInventory8616,
    budget: InvocationInventoryBudget8616 | None = None,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> LocalCallFrameEvidence8616 | None:
    """Re-close a refused inventory's closed caller heads into a local index.

    Runs only after the intake has authenticated ``projection``'s source
    bytes against the project's mapped image. Only heads the refused
    traversal already closed are re-examined — discovered targets, pending
    obligations, and every other address are never visited, so no new
    discovery happens and the unchanged budget values bound the re-census.
    A head that cannot re-close identically, a census that would exceed
    the instruction budget, or a ledger whose head list is malformed ends
    that head's (or the whole collection's) evidence — recorded in
    ``stats``, never silently dropped. ``None`` when no closed caller
    surface survives, so empty evidence can never masquerade as a census.
    """
    if (
        type(inventory) is not InvocationInventory8616
        or type(projection) is not MzInvocationSource8616
    ):
        return None
    already_global = inventory.status in _GLOBAL_INSTALL_STATUSES_8616
    if (
        not projection.complete
        or already_global
        or inventory.callsite_index is not None
        or inventory.entry != projection.entry_linear
    ):
        return None
    if budget is None:
        budget = InvocationInventoryBudget8616()
    heads = inventory.boundary_heads
    if (
        not heads
        or len(heads) > budget.max_boundaries
        or len(set(heads)) != len(heads)
        or any(type(head) is not int or head < 0 for head in heads)
    ):
        return None
    if not callable(direct_target_resolver):
        raise TypeError("local call evidence requires a call target resolver")
    recensus = _reclosed_censuses_8616(project, heads, budget)
    if not recensus.censuses:
        return None
    index = build_decoded_direct_callsite_index_8616(
        recensus.censuses,
        direct_target_resolver=direct_target_resolver,
        instruction_address_resolver=_boundary_instruction_address_8616,
    )
    return LocalCallFrameEvidence8616(
        project=project,
        architecture=cast(_MappedProject8616, project).arch,
        source_sha256=hashlib.sha256(projection.source).hexdigest(),
        load_segment=projection.load_segment,
        entry_linear=projection.entry_linear,
        image_base=projection.module_base,
        image_size=len(projection.module),
        image_sha256=hashlib.sha256(projection.module).hexdigest(),
        inventory_status=inventory.status,
        boundary_heads=recensus.heads,
        callsite_index=index,
        pending_targets=inventory.pending_targets,
        stats=LocalCallEvidenceStats8616(
            raw_fact_count=len(heads),
            normalized_fact_count=recensus.normalized,
            classified_fact_count=len(recensus.censuses) + recensus.failures,
            materialized_count=len(recensus.censuses),
            failure_count=recensus.failures,
        ),
    )


def install_local_call_frame_evidence_8616(
    project: object,
    evidence: LocalCallFrameEvidence8616 | None,
) -> None:
    """Install or clear the project's local frame-evidence surface.

    Only the exact typed record is accepted, and only when its retained
    index is closed, its census set is identical to ``boundary_heads``,
    and every retained row binds the identical instruction tuple of the
    census its ``caller_start`` claims — a forged row can never borrow a
    proved caller's coordinates. ``None`` clears the slot so a failed
    collection never leaks a stale authority into later demands.
    """
    if evidence is not None:
        if type(evidence) is not LocalCallFrameEvidence8616:
            raise TypeError("local call frame evidence must be a typed record")
        index = evidence.callsite_index
        if (
            type(index) is not DecodedDirectCallsiteIndex8616
            or not index.stats.closed
        ):
            raise TypeError("local call frame evidence requires a closed index")
        heads = frozenset(evidence.boundary_heads)
        census_instructions = {
            census.entry_addr: census.instructions
            for census in index.caller_censuses
        }
        if not heads or frozenset(census_instructions) != heads:
            raise ValueError("local evidence census does not cover its heads")
        if evidence.inventory_status in _GLOBAL_INSTALL_STATUSES_8616:
            raise ValueError("local evidence cannot claim a closed corpus")
        for rows in (
            *index._entries_by_normalized_target.values(),
            *index._entries_by_exact_far_target.values(),
        ):
            for row in rows:
                instructions = census_instructions.get(row.caller_start)
                if instructions is None or row.instructions is not instructions:
                    raise ValueError("local evidence row has foreign census")
    cast(
        _LocalCallEvidenceHolder8616, project
    )._inertia_local_call_frame_evidence_8616 = evidence


def _project_still_authentic_8616(
    project: object,
    evidence: LocalCallFrameEvidence8616,
) -> bool:
    """Reject transferred evidence or a changed decoding/loading context.

    Matching bytes alone do not establish the original loader projection or
    instruction-decoding mode. Recollection authenticates any new context;
    this accessor cannot turn an old receipt into transport authority.
    """
    if project is not evidence.project:
        return False
    surface = cast(_MappedProject8616, project)
    try:
        return bool(
            surface.arch is evidence.architecture
            and surface.entry == evidence.entry_linear
            and surface.loader.main_object.mz_load_segment == evidence.load_segment
        )
    except AttributeError:
        return False


def _mapped_image_still_authentic_8616(
    project: object,
    evidence: LocalCallFrameEvidence8616,
) -> bool:
    """Reauthenticate the retained census against current native bytes.

    The mapped span recorded at collection is re-read and re-digested;
    a retained deferred-intake request must also still carry the source
    bytes the collector authenticated. Any divergence — mutated mapped
    bytes, a replaced or malformed request, a missing loader surface —
    revokes the evidence rather than serving stale rows.
    """
    bounds_sane = (
        type(evidence.image_base) is int
        and evidence.image_base >= 0
        and type(evidence.image_size) is int
        and evidence.image_size > 0
    )
    digests_sane = (
        type(evidence.image_sha256) is str
        and type(evidence.source_sha256) is str
    )
    if not bounds_sane or not digests_sane or not _project_still_authentic_8616(project, evidence):
        return False
    try:
        memory = cast(_MappedProject8616, project).loader.memory
        image = memory.load(evidence.image_base, evidence.image_size)
    except (AttributeError, TypeError):
        return False
    if not isinstance(image, (bytes, bytearray)):
        return False
    if hashlib.sha256(bytes(image)).hexdigest() != evidence.image_sha256:
        return False
    # A present request must still authenticate the same source, while an
    # absent one leaves the image digest authoritative.
    # Dynamic boundary on the third-party angr project — a plain attribute populated by the CLI layer.
    request = getattr(project, "_inertia_mz_static_invocation_request_8616", None)
    if request is not None:
        try:
            retained_source = cast(_RetainedStaticIntake8616, request).source
        except AttributeError:
            retained_source = None
        if (
            type(retained_source) is not bytes
            or hashlib.sha256(retained_source).hexdigest()
            != evidence.source_sha256
        ):
            return False
    return True


def local_call_frame_evidence_8616(
    project: object,
) -> LocalCallFrameEvidence8616 | None:
    """Return retained local frame evidence only while its bytes authenticate.

    The slot is populated solely by the intake collector on a refused
    inventory; a forged or mistyped slot raises, while changed native
    bytes, a changed retained source, or a lost loader surface clear the
    slot and report ``None`` — stale evidence is never served.
    """
    surface = cast(_LocalCallEvidenceHolder8616, project)
    try:
        evidence = surface._inertia_local_call_frame_evidence_8616
    except AttributeError:
        return None
    if evidence is None:
        return None
    if type(evidence) is not LocalCallFrameEvidence8616:
        raise TypeError("local call frame evidence must be a typed record")
    if not _mapped_image_still_authentic_8616(project, evidence):
        surface._inertia_local_call_frame_evidence_8616 = None
        return None
    return evidence


def local_call_frame_evidence_epoch_matches_8616(
    retained: LocalCallFrameEvidence8616,
    collected: LocalCallFrameEvidence8616,
) -> bool:
    """Return whether a recollection carries the retained census epoch.

    A refused-inventory demand re-collects the closed-caller census on
    every demand because retained project proof evidence can change what
    is collected; when the fresh record is value-identical in every
    compared field — source and image digests, loader context, refused
    verdict, closed boundary heads, the closed decoded index, pending
    obligations and collection stats — the recollection produced the same
    census epoch and the retained object may stay installed so derived
    boot/index/row identities survive across demands. Retained rows embed
    third-party decoded instruction objects, so equality is structural
    over the decoded census; a collection that cannot reproduce an equal
    record is conservatively a different epoch and never interns.

    ``project`` and ``architecture`` are context fields excluded from
    dataclass equality, so the predicate authenticates them explicitly:
    records minted under a different project object or a different
    decoding architecture never share an epoch even when every compared
    field matches.
    """
    return bool(
        type(retained) is LocalCallFrameEvidence8616
        and type(collected) is LocalCallFrameEvidence8616
        and retained.project is collected.project
        and retained.architecture is collected.architecture
        and retained == collected
    )
