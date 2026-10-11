"""Index decoded direct callsites once for repeated target queries.

Layer: Frontend instruction inventory.
Responsibility: map already-decoded direct call targets to exact caller and
instruction coordinates without classifying return use or recovering semantics.
Dynamic boundary: decoded instructions are third-party Capstone objects and are
interpreted only through injected target/address resolvers.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast

from .frontend_caller_entry_identity import CallerEntryIdentity8616, caller_target_identity_8616
from .frontend_function_boundary import ExactFunctionRangeBoundary8616

__all__ = [
    "DecodedCallerCensus8616",
    "DecodedDirectCallsite8616",
    "DecodedDirectCallsiteIndex8616",
    "DecodedDirectCallsiteIndexStats8616",
    "DecodedFarCallTarget8616",
    "RetainedDecodedCallsiteIndex8616",
    "build_boundary_direct_callsite_index_8616",
    "build_decoded_direct_callsite_index_8616",
    "decoded_callsite_index_for_boundary_8616",
    "registered_decoded_callsite_index_8616",
    "retain_decoded_callsite_index_8616",
]

type DirectCallTargetResolver8616 = Callable[[object], int | DecodedFarCallTarget8616 | None]
type InstructionAddressResolver8616 = Callable[[object], int | None]


class _BoundaryInstruction8616(Protocol):
    """Third-party Capstone instruction identity retained by a boundary."""

    address: object


class _NativeCallsiteInstruction8616(Protocol):
    """Exact encoding exposed by a third-party decoded instruction."""

    address: object
    size: object
    bytes: bytes


class _BoundaryDisassembly8616(Protocol):
    """Third-party decoded instruction sequence for one reachable block."""

    insns: Sequence[object]


class _BoundaryBlock8616(Protocol):
    """Third-party block projection consumed only at the frontend boundary."""

    addr: int
    capstone: _BoundaryDisassembly8616


def _boundary_instruction_address_8616(instruction: object) -> int | None:
    """Read an exact address without treating malformed decoded data as proof."""
    address = cast(_BoundaryInstruction8616, instruction).address
    return address if type(address) is int else None


def build_boundary_direct_callsite_index_8616(
    boundary: ExactFunctionRangeBoundary8616,
    *,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> DecodedDirectCallsiteIndex8616:
    """Index the exact reachable decoded census, without optional catalogs.

    This is a boundary-scoped inventory, not proof of every caller in a program.
    It deliberately does not disassemble a contiguous range containing possible
    embedded data or unreachable instructions. The supplied target resolver
    owns decoded near/far target interpretation, as in the general index API.
    Malformed retained boundaries are contract errors and fail loudly.
    """
    blocks = tuple(cast(_BoundaryBlock8616, block) for block in boundary.blocks)
    block_addresses = tuple(block.addr for block in blocks)
    if (len(set(block_addresses)) != len(blocks)
            or frozenset(block_addresses) != boundary.block_addrs_set):
        raise ValueError("decoded boundary block census does not match")
    instructions = tuple(
        instruction
        for block in sorted(blocks, key=lambda item: item.addr)
        for instruction in block.capstone.insns
    )
    addresses = tuple(_boundary_instruction_address_8616(instruction) for instruction in instructions)
    if (not addresses or None in addresses or len(set(addresses)) != len(addresses)
            or frozenset(addresses) != boundary.reachable_instruction_addrs):
        raise ValueError("decoded boundary instruction census does not match")
    index = build_decoded_direct_callsite_index_8616(
        (DecodedCallerCensus8616(boundary.addr, boundary.decode_start, boundary.decode_end, instructions),),
        direct_target_resolver=direct_target_resolver,
        instruction_address_resolver=_boundary_instruction_address_8616,
    )
    retain_decoded_callsite_index_8616(boundary.project, boundary, index)
    return index


@dataclass(frozen=True, slots=True)
class DecodedFarCallTarget8616:
    """Exact 20-bit control-flow target of one immediate far call."""

    target_addr: int

    def __post_init__(self) -> None:
        """Reject targets outside the real-mode physical code-address domain."""
        if not 0 <= self.target_addr <= 0xFFFFF:
            raise ValueError("far call target must be a 20-bit address")


@dataclass(frozen=True, slots=True)
class DecodedCallerCensus8616:
    """Retain decoding bounds independently of a callable entry identity.

    This contract does not assert entry equivalence or a NOP prefix. Multiple
    entries may own overlapping decoding bounds without collapsing their rows.
    """

    entry_addr: int
    decode_start: int
    decode_end: int
    instructions: tuple[object, ...]

    def __post_init__(self) -> None:
        """Reject an entry outside its declared decoding interval."""
        if not 0 <= self.decode_start <= self.entry_addr < self.decode_end:
            raise ValueError("caller census entry lies outside decoding bounds")


@dataclass(frozen=True, slots=True)
class DecodedDirectCallsite8616:
    """Retain one exact direct call coordinate in a decoded caller range."""

    caller_start: int
    instructions: tuple[object, ...]
    instruction_index: int
    callsite_addr: int
    target_addr: int
    entry_identity: CallerEntryIdentity8616 | None = None
    is_far: bool = False

    def encoded_near_coordinates(self) -> tuple[int, int] | None:
        """Decode continuation and raw E8 target independently of lookup aliases.

        These are candidate linear coordinates, not proof of a selector
        domain. Only an exact unprefixed word CALL binds this contract;
        downstream invocation proofs still authenticate loaded bytes and CS.
        ``target_addr`` may carry a normalized lookup identity and must not
        replace the encoded destination when selecting a census surface.
        """
        if (self.is_far or type(self.instruction_index) is not int
                or not 0 <= self.instruction_index < len(self.instructions)):
            return None
        instruction = cast(_NativeCallsiteInstruction8616,
                           self.instructions[self.instruction_index])
        try:
            address = instruction.address
            size = instruction.size
            encoding = bytes(instruction.bytes)
        except (AttributeError, TypeError):
            return None
        if (type(address) is not int or address != self.callsite_addr
                or type(size) is not int or size != 3):
            return None
        if len(encoding) != 3 or encoding[0] != 0xE8:
            return None
        next_addr = address + size
        displacement = int.from_bytes(encoding[1:3], "little", signed=True)
        return next_addr, next_addr + displacement


    def bound_near_coordinates(
        self, boundary: ExactFunctionRangeBoundary8616,
    ) -> tuple[int, int] | None:
        """Bind retained CALL bytes to the caller's exact decoded census.

        Index membership is only lookup evidence: a self-consistent forged
        index must not replace the native instruction the parent proof ran.
        Parent-domain replay separately authenticates this census to source.
        """
        coordinates = self.encoded_near_coordinates()
        if (coordinates is None or self.caller_start != boundary.addr
                or self.callsite_addr not in boundary.reachable_instruction_addrs):
            return None
        try:
            matches = tuple(
                instruction
                for block in boundary.blocks
                for instruction in cast(_BoundaryBlock8616, block).capstone.insns
                if _boundary_instruction_address_8616(instruction) == self.callsite_addr
            )
            if len(matches) != 1:
                return None
            actual = cast(_NativeCallsiteInstruction8616, matches[0])
            retained = cast(_NativeCallsiteInstruction8616,
                            self.instructions[self.instruction_index])
            if (type(actual.size) is not int or actual.size != 3
                    or bytes(actual.bytes) != bytes(retained.bytes)):
                return None
        except (AttributeError, TypeError):
            return None
        return coordinates


@dataclass(frozen=True, slots=True)
class DecodedDirectCallsiteIndexStats8616:
    """Closed accounting for direct-call candidates indexed from one corpus."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether every direct-call candidate became an entry or refusal."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
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
class DecodedDirectCallsiteIndex8616:
    """Provide deterministic normalized-target lookup over one decoded corpus."""

    _entries_by_normalized_target: dict[int, tuple[DecodedDirectCallsite8616, ...]]
    stats: DecodedDirectCallsiteIndexStats8616
    entry_identities: tuple[CallerEntryIdentity8616, ...] = ()
    _entries_by_exact_far_target: dict[int, tuple[DecodedDirectCallsite8616, ...]] = field(
        default_factory=dict
    )
    caller_censuses: tuple[DecodedCallerCensus8616, ...] = ()

    def target_identity(self, target_addr: int) -> int:
        """Use the same proven identity for lookup and recursive-cycle checks."""
        far_target = _exact_far_target_identity_8616(target_addr, self.entry_identities)
        if far_target in self._entries_by_exact_far_target:
            return far_target
        near_target: int = caller_target_identity_8616(target_addr, self.entry_identities)
        return near_target

    def for_target(self, target_addr: int) -> tuple[DecodedDirectCallsite8616, ...]:
        """Join near aliases and exact far targets without far low-word collisions."""
        near_target = caller_target_identity_8616(target_addr, self.entry_identities)
        near_entries = self._entries_by_normalized_target.get(near_target, ())
        far_target = _exact_far_target_identity_8616(target_addr, self.entry_identities)
        far_entries = self._entries_by_exact_far_target.get(far_target, ())
        if far_entries:
            near_entries = tuple(item for item in near_entries if item.target_addr == far_target)
        return tuple(sorted((*near_entries, *far_entries), key=lambda item: item.callsite_addr))


def _exact_far_target_identity_8616(
    target_addr: int,
    identities: tuple[CallerEntryIdentity8616, ...],
) -> int:
    """Normalize only a proven full-address NOP prefix, never a low word."""
    candidates = {
        identity.entry_addr for identity in identities
        if identity.decode_start <= target_addr <= identity.entry_addr
    }
    if len(candidates) > 1:
        raise ValueError(f"conflicting far caller entry aliases for {target_addr:#x}")
    return next(iter(candidates), target_addr)


def build_decoded_direct_callsite_index_8616(
    decoded_ranges: Mapping[tuple[int, int], tuple[object, ...]] | tuple[DecodedCallerCensus8616, ...],
    *,
    direct_target_resolver: DirectCallTargetResolver8616,
    instruction_address_resolver: InstructionAddressResolver8616,
    entry_identities: Mapping[tuple[int, int], CallerEntryIdentity8616] | None = None,
) -> DecodedDirectCallsiteIndex8616:
    """Scan decoded instructions once and return a closed direct-call index."""
    mutable_entries: dict[int, list[DecodedDirectCallsite8616]] = {}
    mutable_far_entries: dict[int, list[DecodedDirectCallsite8616]] = {}
    raw_fact_count = 0
    failure_count = 0
    identities = {} if entry_identities is None else entry_identities
    explicit_censuses = decoded_ranges if isinstance(decoded_ranges, tuple) else ()
    if explicit_censuses and entry_identities is not None:
        raise ValueError("explicit caller censuses cannot assert NOP entry identities")
    if entry_identities is not None and set(identities) != set(decoded_ranges):
        raise ValueError("caller entry identities do not cover the decoded ranges")
    ordered_identities = tuple(identities[key] for key in sorted(identities))
    rows = (
        tuple(((census.decode_start, census.decode_end), census.instructions, census.entry_addr)
              for census in explicit_censuses)
        if isinstance(decoded_ranges, tuple)
        else tuple((bounds, instructions, bounds[0]) for bounds, instructions in sorted(decoded_ranges.items()))
    )
    for caller_range, instructions, entry_addr in rows:
        identity = identities.get(caller_range)
        caller_start = entry_addr if identity is None else identity.entry_addr
        if identity is not None and (identity.decode_start, identity.decode_end) != caller_range:
            raise ValueError(f"caller entry identity disagrees with decode range {caller_range!r}")
        for instruction_index, instruction in enumerate(instructions):
            target = direct_target_resolver(instruction)
            target_addr: int | None
            if isinstance(target, DecodedFarCallTarget8616):
                is_far = True
                target_addr = target.target_addr
            else:
                is_far = False
                target_addr = target
            if not isinstance(target_addr, int):
                continue
            raw_fact_count += 1
            callsite_addr = instruction_address_resolver(instruction)
            if not isinstance(callsite_addr, int):
                failure_count += 1
                continue
            normalized_target = (
                _exact_far_target_identity_8616(target_addr, ordered_identities)
                if is_far
                else caller_target_identity_8616(target_addr, ordered_identities)
            )
            entry = DecodedDirectCallsite8616(
                caller_start=caller_start,
                instructions=instructions,
                instruction_index=instruction_index,
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                entry_identity=identity,
                is_far=is_far,
            )
            destination = mutable_far_entries if is_far else mutable_entries
            destination.setdefault(normalized_target, []).append(entry)
    entries = {
        target_addr: tuple(target_entries)
        for target_addr, target_entries in sorted(mutable_entries.items())
    }
    far_entries = {
        target_addr: tuple(target_entries)
        for target_addr, target_entries in sorted(mutable_far_entries.items())
    }
    materialized_count = sum(len(items) for items in (*entries.values(), *far_entries.values()))
    stats = DecodedDirectCallsiteIndexStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=raw_fact_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
    if not stats.closed:
        raise ValueError("decoded direct-call index accounting did not close")
    return DecodedDirectCallsiteIndex8616(entries, stats, ordered_identities, far_entries, explicit_censuses)


@dataclass(frozen=True, slots=True)
class _CallsiteFact8616:
    """Freeze one resolved call independently of its admission window."""

    lookup_target: int
    caller: int
    instruction_index: int
    callsite: int
    target: int
    far: bool
    identity: CallerEntryIdentity8616 | None
    instructions: tuple[tuple[int, int, bytes], ...]


@dataclass(frozen=True, slots=True)
class _DecodedCensusSnapshot8616:
    """Immutable native census; decoding bounds remain on the boundary."""

    head: int
    blocks: frozenset[int]
    instructions: frozenset[int]
    edges: tuple[tuple[int, int], ...]
    encodings: tuple[tuple[int, tuple[tuple[int, int, bytes], ...]], ...]


@dataclass(frozen=True, slots=True)
class _DecodedIndexSnapshot8616:
    """Immutable resolved index facts, excluding census admission bounds."""

    stats: DecodedDirectCallsiteIndexStats8616
    identities: tuple[CallerEntryIdentity8616, ...]
    near: tuple[_CallsiteFact8616, ...]
    far: tuple[_CallsiteFact8616, ...]
    censuses: tuple[tuple[int, tuple[tuple[int, int, bytes], ...]], ...]


def _instruction_snapshot_8616(instructions: Sequence[object]) -> tuple[tuple[int, int, bytes], ...] | None:
    """Copy third-party native instruction bytes, or retain legacy absence."""
    rows: list[tuple[int, int, bytes]] = []
    for instruction in instructions:
        native = cast(_NativeCallsiteInstruction8616, instruction)
        try:
            address, size, encoding = native.address, native.size, bytes(native.bytes)
        except (AttributeError, TypeError):
            return None
        if type(address) is not int or type(size) is not int or size <= 0 or len(encoding) != size:
            raise ValueError("malformed decoded instruction snapshot")
        rows.append((address, size, encoding))
    return tuple(rows)


def _census_snapshot_8616(boundary: ExactFunctionRangeBoundary8616) -> _DecodedCensusSnapshot8616 | None:
    """Authenticate census consistency and window containment without decoding."""
    if not boundary.blocks:
        return None
    rows: list[tuple[int, tuple[tuple[int, int, bytes], ...]]] = []
    addresses: list[int] = []
    for block in sorted((cast(_BoundaryBlock8616, item) for item in boundary.blocks), key=lambda item: item.addr):
        instructions = _instruction_snapshot_8616(block.capstone.insns)
        if instructions is None:
            return None
        if any(not boundary.decode_start <= addr < addr + size <= boundary.decode_end for addr, size, _ in instructions):
            raise ValueError("decoded instructions escape admission window")
        addresses.extend(addr for addr, _, _ in instructions)
        rows.append((block.addr, instructions))
    block_addresses = tuple(addr for addr, _ in rows)
    if (not boundary.decode_start <= boundary.addr < boundary.decode_end
            or len(set(block_addresses)) != len(block_addresses)
            or frozenset(block_addresses) != boundary.block_addrs_set
            or len(set(addresses)) != len(addresses)
            or frozenset(addresses) != boundary.reachable_instruction_addrs):
        raise ValueError("conflicting decoded callsite census for caller")
    return _DecodedCensusSnapshot8616(boundary.addr, boundary.block_addrs_set,
                                    boundary.reachable_instruction_addrs, boundary.successor_edges, tuple(rows))


type _InstructionSnapshotCache8616 = dict[int, tuple[Sequence[object], tuple[tuple[int, int, bytes], ...] | None]]


def _shared_instruction_snapshot_8616(
    instructions: Sequence[object], cache: _InstructionSnapshotCache8616,
) -> tuple[tuple[int, int, bytes], ...] | None:
    """Copy each pinned instruction sequence once within one snapshot operation."""
    key = id(instructions)
    if key not in cache:
        cache[key] = (instructions, _instruction_snapshot_8616(instructions))
    return cache[key][1]


def _callsite_snapshot_8616(
    entries: dict[int, tuple[DecodedDirectCallsite8616, ...]], cache: _InstructionSnapshotCache8616,
) -> tuple[_CallsiteFact8616, ...] | None:
    """Freeze lookup keys and call interpretation, not only instruction bytes."""
    rows: list[_CallsiteFact8616] = []
    for target, calls in sorted(entries.items()):
        for call in calls:
            instructions = _shared_instruction_snapshot_8616(call.instructions, cache)
            if instructions is None:
                return None
            rows.append(_CallsiteFact8616(target, call.caller_start, call.instruction_index,
                                         call.callsite_addr, call.target_addr, call.is_far,
                                         call.entry_identity, instructions))
    return tuple(rows)


def _index_snapshot_8616(index: DecodedDirectCallsiteIndex8616) -> _DecodedIndexSnapshot8616 | None:
    """Freeze every retained call fact while keeping window provenance separate."""
    cache: _InstructionSnapshotCache8616 = {}
    near = _callsite_snapshot_8616(index._entries_by_normalized_target, cache)
    far = _callsite_snapshot_8616(index._entries_by_exact_far_target, cache)
    if near is None or far is None:
        return None
    censuses: list[tuple[int, tuple[tuple[int, int, bytes], ...]]] = []
    for census in index.caller_censuses:
        instructions = _shared_instruction_snapshot_8616(census.instructions, cache)
        if instructions is None:
            return None
        if any(not census.decode_start <= addr < addr + size <= census.decode_end for addr, size, _ in instructions):
            raise ValueError("indexed instructions escape admission window")
        censuses.append((census.entry_addr, instructions))
    return _DecodedIndexSnapshot8616(index.stats, index.entry_identities, near, far, tuple(censuses))


@dataclass(frozen=True, slots=True)
class RetainedDecodedCallsiteIndex8616:
    """One closed decoded index retained against its exact caller census."""

    caller_addr: int
    boundary: ExactFunctionRangeBoundary8616
    index: DecodedDirectCallsiteIndex8616
    census_snapshot: _DecodedCensusSnapshot8616 | None = field(default=None, repr=False)
    index_snapshot: _DecodedIndexSnapshot8616 | None = field(default=None, repr=False)


def _require_same_retained_census_8616(
    existing: RetainedDecodedCallsiteIndex8616,
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616 | None = None,
) -> None:
    """Reuse exact immutable facts without widening their retained provenance."""
    incoming = _census_snapshot_8616(boundary)
    current = _census_snapshot_8616(existing.boundary)
    legacy_window_changed = incoming is None and existing.boundary != boundary
    if (existing.boundary.project is not boundary.project
            or existing.caller_addr != boundary.addr
            or current != existing.census_snapshot or incoming != existing.census_snapshot
            or legacy_window_changed):
        raise ValueError("conflicting decoded callsite census for caller")
    current_index = _index_snapshot_8616(existing.index)
    if current_index != existing.index_snapshot:
        raise ValueError("conflicting retained decoded callsite index facts")
    if index is not None:
        incoming_index = _index_snapshot_8616(index)
        if (incoming_index != existing.index_snapshot
                or (incoming_index is None and index != existing.index)):
            raise ValueError("conflicting decoded callsite index facts")


class _DecodedIndexRegistrySurface8616(Protocol):
    """Project-owned decoded-callsite index retention extension."""

    _inertia_decoded_callsite_indexes_8616: dict[int, RetainedDecodedCallsiteIndex8616]


def _existing_index_registry_8616(
    project: object,
) -> dict[int, RetainedDecodedCallsiteIndex8616] | None:
    """Return the retained index map without creating it."""
    surface = cast(_DecodedIndexRegistrySurface8616, project)
    try:
        registry = surface._inertia_decoded_callsite_indexes_8616
    except AttributeError:
        return None
    if not isinstance(registry, dict):
        raise TypeError("decoded callsite index registry must be a dict")
    return registry


def registered_decoded_callsite_index_8616(
    project: object,
    caller_addr: int,
) -> RetainedDecodedCallsiteIndex8616 | None:
    """Return the retained index record for one caller without decoding."""
    registry = _existing_index_registry_8616(project)
    record = None if registry is None else registry.get(caller_addr)
    if record is None:
        return None
    if type(record) is not RetainedDecodedCallsiteIndex8616 or (
        record.caller_addr != caller_addr
    ):
        raise TypeError("retained decoded callsite record has a foreign type")
    return record


def retain_decoded_callsite_index_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616,
) -> RetainedDecodedCallsiteIndex8616:
    """Retain one closed index against its exact decoded caller census.

    Native census snapshots identify decoded facts independently of admission
    bounds. Re-retaining the same facts keeps the first boundary provenance;
    changed bytes, edges or call facts fail loudly. Without native encodings,
    legacy records remain limited to an identical boundary.
    """
    if not isinstance(boundary, ExactFunctionRangeBoundary8616):
        raise ValueError("decoded callsite retention requires an exact boundary census")
    if boundary.project is not project:
        raise ValueError("decoded callsite boundary belongs to another project")
    if type(boundary.addr) is not int or boundary.addr < 0:
        raise ValueError("decoded callsite boundary has an invalid entry")
    if not isinstance(index, DecodedDirectCallsiteIndex8616) or not index.stats.closed:
        raise ValueError("decoded callsite index must have closed accounting")
    surface = cast(_DecodedIndexRegistrySurface8616, project)
    registry = _existing_index_registry_8616(project)
    if registry is None:
        registry = {}
        surface._inertia_decoded_callsite_indexes_8616 = registry
    existing = registry.get(boundary.addr)
    if existing is not None:
        _require_same_retained_census_8616(existing, boundary, index)
        return existing
    record = RetainedDecodedCallsiteIndex8616(boundary.addr, boundary, index,
                                            _census_snapshot_8616(boundary), _index_snapshot_8616(index))
    registry[boundary.addr] = record
    return record


def decoded_callsite_index_for_boundary_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> RetainedDecodedCallsiteIndex8616:
    """Return the retained index for one exact census, decoding at most once.

    A retained record for the identical census is reused verbatim — no
    re-decode. A missing record decodes through the boundary builder, which
    retains against the same census key.
    """
    if not isinstance(boundary, ExactFunctionRangeBoundary8616):
        raise ValueError("decoded callsite index requires an exact boundary census")
    if boundary.project is not project:
        raise ValueError("decoded callsite boundary belongs to another project")
    existing = registered_decoded_callsite_index_8616(project, boundary.addr)
    if existing is not None:
        _require_same_retained_census_8616(existing, boundary)
        return existing
    build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=direct_target_resolver
    )
    record = registered_decoded_callsite_index_8616(project, boundary.addr)
    if record is None:
        raise ValueError("decoded callsite index retention did not hold")
    _require_same_retained_census_8616(record, boundary)
    return record
