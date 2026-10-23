"""Detach a bounded prefix census candidate without minting reuse authority.

Layer: IR.
Responsibility: freeze explicitly normalized census data, retain exact owner
identities, and refuse incomplete capture. Canonical admission remains core-owned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic

from .core import IRBlock, IRFunctionArtifact, IRInstr
from .real16_path_memory8616 import PathMemory8616, PathMemorySnapshot8616, snapshot_path_memory_8616


class PrefixCaptureOrigin8616(StrEnum):
    """Untrusted normalized provenance claims; none constitutes an admission seal."""

    CURRENT_CANONICAL = "current_canonical"
    FAILED = "failed"
    PARTIAL = "partial"
    CACHED = "cached"
    TRANSPORTED = "transported"


class PrefixCaptureFailure8616(StrEnum):
    """Typed reasons no detached payload was produced."""

    ORIGIN = "origin"
    FACTS = "facts"
    ROWS = "rows"
    MEMORY = "memory"
    STATE = "state"
    WORK = "work"
    DEADLINE = "deadline"


class _Refused(Exception):
    """Carry an explicit capture failure without swallowing unrelated defects."""

    def __init__(self, failure: PrefixCaptureFailure8616) -> None:
        self.failure = failure
        super().__init__(failure.value)


@dataclass(slots=True)
class PrefixCaptureBudget8616:
    """Capture allowance to be debited from the existing ambient traversal."""

    max_work_units: int
    deadline: float
    work_units: int = 0

    def charge(self, units: int = 1) -> None:
        """Refuse before consuming work beyond the existing allowance."""
        if not monotonic() < self.deadline:
            raise _Refused(PrefixCaptureFailure8616.DEADLINE)
        if units < 0 or self.work_units + units > self.max_work_units:
            raise _Refused(PrefixCaptureFailure8616.WORK)
        self.work_units += units

    def sorting(self, size: int) -> None:
        """Prepay comparisons and tuple construction for a bounded scalar sort."""
        self.charge(size * (size.bit_length() + 2))


@dataclass(frozen=True, slots=True)
class PrefixCaptureBinding8616:
    """Exact current input/admission claims, retained solely as opaque identities."""

    project: object
    source: object
    boot: object
    boot_recompute: object
    artifact: IRFunctionArtifact
    boundary: object
    admission: object
    traversal: object
    producer: object
    derivation: object
    services: tuple[object, ...]
    call_proofs: tuple[object, ...]
    entry_call_proofs: tuple[object, ...]
    initial_memory: object | None = None
    environment: object | None = None


@dataclass(slots=True)
class PrefixCaptureState8616:
    """Core-normalized mutable scalar state immediately before the CALL transfer."""

    registers: dict[str, int]
    memory: PathMemory8616
    direction: bool | None
    tmps: dict[int, int] = field(default_factory=dict)
    dirty: set[str] = field(default_factory=set)
    instruction_entry: dict[str, int] = field(default_factory=dict)
    current_addr: int | None = None


@dataclass(frozen=True, slots=True)
class PrefixCapturedState8616:
    """Detached scalar continuation data; direction alone is not tracker authority."""

    registers: tuple[tuple[str, int], ...]
    memory: PathMemorySnapshot8616
    direction: bool | None
    tmps: tuple[tuple[int, int], ...]
    dirty: tuple[str, ...]
    instruction_entry: tuple[tuple[str, int], ...]
    current_addr: int | None


@dataclass(frozen=True, slots=True)
class PrefixCaptureRow8616:
    """One census key's exact IR and current native block/instruction owners."""

    artifact: IRFunctionArtifact
    block: IRBlock
    index: int
    row: IRInstr
    native_block: IRBlock
    native_row: IRInstr


@dataclass(slots=True)
class PrefixCaptureInput8616:
    """Explicit core projection; successful provenance is still an untrusted claim."""

    binding: PrefixCaptureBinding8616
    origin: PrefixCaptureOrigin8616
    seed: PrefixCaptureState8616
    call_state: PrefixCaptureState8616
    call_row: PrefixCaptureRow8616
    raw_facts: set[tuple[int, int]]
    normalized_facts: set[tuple[int, int]]
    classified_facts: set[tuple[int, int]]
    materialized_facts: set[tuple[int, int]]
    counts: tuple[int, int, int, int, int]
    rows: tuple[PrefixCaptureRow8616, ...]
    manifest: set[tuple[int, int]]
    machine_bytes: dict[int, bytes]


@dataclass(frozen=True, slots=True)
class PrefixTranscriptData8616:
    """Ephemeral detached data, never an authenticated successful-census receipt."""

    binding: PrefixCaptureBinding8616
    seed: PrefixCapturedState8616
    call_state: PrefixCapturedState8616
    call_row: PrefixCaptureRow8616
    raw_facts: frozenset[tuple[int, int]]
    normalized_facts: frozenset[tuple[int, int]]
    classified_facts: frozenset[tuple[int, int]]
    materialized_facts: frozenset[tuple[int, int]]
    counts: tuple[int, int, int, int, int]
    rows: tuple[PrefixCaptureRow8616, ...]
    manifest: tuple[tuple[int, int], ...]
    machine_bytes: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True, slots=True)
class PrefixCaptureResult8616:
    """DATA_ONLY capture outcome; no completion or reuse verdict is exposed."""

    payload: PrefixTranscriptData8616 | None
    failure: PrefixCaptureFailure8616 | None
    work_units: int

    @property
    def authorizes_reuse(self) -> bool:
        """Always refuse authority, including for forged CURRENT provenance claims."""
        return False


def _memory(source: PathMemory8616, budget: PrefixCaptureBudget8616) -> PathMemorySnapshot8616:
    """Consume the existing snapshot owner after bounded overlay validation."""
    budget.charge()
    if source.tainted:
        raise _Refused(PrefixCaptureFailure8616.MEMORY)
    for address, value in source.known.items():
        budget.charge()
        if type(address) is not int or type(value) is not int or not 0 <= value <= 255:
            raise _Refused(PrefixCaptureFailure8616.MEMORY)
        if address < 0 or address in source.unknown:
            raise _Refused(PrefixCaptureFailure8616.MEMORY)
    for address in source.unknown:
        budget.charge()
        if type(address) is not int or address < 0:
            raise _Refused(PrefixCaptureFailure8616.MEMORY)
    budget.sorting(len(source.known) + len(source.unknown))
    return snapshot_path_memory_8616(source)


def _state(source: PrefixCaptureState8616, budget: PrefixCaptureBudget8616) -> PrefixCapturedState8616:
    """Validate and detach registers, continuation scalars and touched-byte overlay."""
    memory = _memory(source.memory, budget)
    if source.direction is not None and type(source.direction) is not bool:
        raise _Refused(PrefixCaptureFailure8616.STATE)
    if source.current_addr is not None and type(source.current_addr) is not int:
        raise _Refused(PrefixCaptureFailure8616.STATE)
    for entries in (source.registers, source.instruction_entry):
        for name, value in entries.items():
            budget.charge()
            if type(name) is not str or type(value) is not int:
                raise _Refused(PrefixCaptureFailure8616.STATE)
        budget.sorting(len(entries))
    for tmp, value in source.tmps.items():
        budget.charge()
        if type(tmp) is not int or type(value) is not int:
            raise _Refused(PrefixCaptureFailure8616.STATE)
    for name in source.dirty:
        budget.charge()
        if type(name) is not str:
            raise _Refused(PrefixCaptureFailure8616.STATE)
    budget.sorting(len(source.tmps) + len(source.dirty))
    return PrefixCapturedState8616(tuple(sorted(source.registers.items())), memory, source.direction,
        tuple(sorted(source.tmps.items())), tuple(sorted(source.dirty)),
        tuple(sorted(source.instruction_entry.items())), source.current_addr)


def _rows(source: PrefixCaptureInput8616, budget: PrefixCaptureBudget8616) -> set[tuple[int, int]]:
    """Bind exact row positions without deep equality or nested artifact hashing."""
    if type(source.rows) is not tuple:
        raise _Refused(PrefixCaptureFailure8616.ROWS)
    owners: dict[int, dict[int, IRBlock]] = {}
    keys: set[tuple[int, int]] = set()
    selected = False
    for ref in source.rows:
        budget.charge()
        if id(ref.artifact) not in owners:
            blocks: dict[int, IRBlock] = {}
            for block in ref.artifact.blocks:
                budget.charge()
                blocks[id(block)] = block
            owners[id(ref.artifact)] = blocks
        if id(ref.block) not in owners[id(ref.artifact)] or type(ref.index) is not int:
            raise _Refused(PrefixCaptureFailure8616.ROWS)
        if not 0 <= ref.index < len(ref.block.instrs) or not 0 <= ref.index < len(ref.native_block.instrs):
            raise _Refused(PrefixCaptureFailure8616.ROWS)
        if ref.block.instrs[ref.index] is not ref.row or ref.native_block.instrs[ref.index] is not ref.native_row:
            raise _Refused(PrefixCaptureFailure8616.ROWS)
        key = (ref.block.addr, ref.index)
        if key in keys:
            raise _Refused(PrefixCaptureFailure8616.ROWS)
        keys.add(key)
        selected |= ref is source.call_row
    if not selected or source.call_row.row.op != "CALL" or source.call_row.artifact is not source.binding.artifact:
        raise _Refused(PrefixCaptureFailure8616.ROWS)
    return keys


def _facts(source: PrefixCaptureInput8616, keys: set[tuple[int, int]],
           budget: PrefixCaptureBudget8616) -> frozenset[tuple[int, int]]:
    """Preserve exact four stage sets and reject partial or inconsistent counts."""
    stages = (source.raw_facts, source.normalized_facts, source.classified_facts, source.materialized_facts)
    if type(source.counts) is not tuple or len(source.counts) != 5:
        raise _Refused(PrefixCaptureFailure8616.FACTS)
    if any(type(count) is not int for count in source.counts):
        raise _Refused(PrefixCaptureFailure8616.FACTS)
    for index, facts in enumerate(stages):
        for key in facts:
            budget.charge()
            if key not in keys:
                raise _Refused(PrefixCaptureFailure8616.FACTS)
        if len(facts) != len(keys) or len(facts) != source.counts[index]:
            raise _Refused(PrefixCaptureFailure8616.FACTS)
    if not keys or source.counts[4] != 0:
        raise _Refused(PrefixCaptureFailure8616.FACTS)
    # All four identities were checked independently against the exact row
    # census. Share one detached immutable set instead of copying it four times.
    budget.charge(len(keys))
    return frozenset(keys)


def capture_prefix_transcript_8616(source: PrefixCaptureInput8616, *,
                                  budget: PrefixCaptureBudget8616) -> PrefixCaptureResult8616:
    """Capture detached data only; core must separately seal CURRENT provenance."""
    start = budget.work_units
    try:
        budget.charge()
        if source.origin is not PrefixCaptureOrigin8616.CURRENT_CANONICAL:
            raise _Refused(PrefixCaptureFailure8616.ORIGIN)
        keys = _rows(source, budget)
        facts = _facts(source, keys, budget)
        seed, state = _state(source.seed, budget), _state(source.call_state, budget)
        for address, size in source.manifest:
            budget.charge()
            if type(address) is not int or type(size) is not int or size <= 0:
                raise _Refused(PrefixCaptureFailure8616.ROWS)
        for address, data in source.machine_bytes.items():
            budget.charge()
            if type(address) is not int or type(data) is not bytes:
                raise _Refused(PrefixCaptureFailure8616.ROWS)
        budget.sorting(len(source.manifest) + len(source.machine_bytes))
        payload = PrefixTranscriptData8616(source.binding, seed, state, source.call_row,
            facts, facts, facts, facts, source.counts, source.rows,
            tuple(sorted(source.manifest)), tuple(sorted(source.machine_bytes.items())))
        budget.charge(0)
    except _Refused as refused:
        return PrefixCaptureResult8616(None, refused.failure, budget.work_units - start)
    return PrefixCaptureResult8616(payload, None, budget.work_units - start)
