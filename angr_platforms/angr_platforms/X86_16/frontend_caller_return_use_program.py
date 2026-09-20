"""Decode one caller-range corpus for repeated return-use queries.

Layer: Frontend instruction inventory.
Responsibility: retain exact decoded caller ranges and their direct-call index
inside one explicit request scope. Return-use classification remains owned by
Semantics/callsite summary.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from .frontend_caller_entry_identity import CallerEntryIdentity8616, prove_caller_entry_identity_8616
from .frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_decoded_direct_callsite_index_8616,
)

type DirectCallTargetResolver8616 = Callable[[object], int | None]
type InstructionAddressResolver8616 = Callable[[object], int | None]


class CallerReturnUseProgramStatus8616(StrEnum):
    """Typed availability of one decoded caller-range corpus."""

    READY = "ready"
    DECODER_UNAVAILABLE = "decoder_unavailable"


class _MemoryBoundary8616(Protocol):
    """Third-party loader memory surface used by Frontend decoding."""

    def load(self, addr: int, size: int) -> object:
        """Return exact bytes for one linear caller range."""
        ...


class _DisassemblerBoundary8616(Protocol):
    """Third-party Capstone surface used by Frontend decoding."""

    detail: bool

    def disasm(self, data: bytes, addr: int) -> Iterable[object]:
        """Decode one exact byte range at its linear address."""
        ...


class _ArchBoundary8616(Protocol):
    """Third-party architecture fields used by Frontend decoding."""

    capstone: _DisassemblerBoundary8616


class _LoaderBoundary8616(Protocol):
    """Third-party loader fields used by Frontend decoding."""

    memory: _MemoryBoundary8616


class _ProjectBoundary8616(Protocol):
    """Third-party project fields used by Frontend decoding."""

    arch: _ArchBoundary8616
    loader: _LoaderBoundary8616


@dataclass(frozen=True, slots=True)
class CallerReturnUseProgramStats8616:
    """Closed range-level accounting for one decoded caller corpus."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether every requested range became evidence or refusal."""
        return bool(
            self.raw_fact_count >= self.normalized_fact_count
            >= self.classified_fact_count
            >= self.materialized_count
            >= 0
            and self.raw_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class CallerReturnUseProgramEvidence8616:
    """One request-owned decoded range corpus and direct-call index."""

    source_project: object = field(repr=False, compare=False)
    function_ranges: tuple[tuple[int, int], ...]
    callsites: DecodedDirectCallsiteIndex8616
    status: CallerReturnUseProgramStatus8616
    stats: CallerReturnUseProgramStats8616

    @property
    def range_census_complete(self) -> bool:
        """Require every distinct caller range before interpreting absent uses."""
        return (
            self.status is CallerReturnUseProgramStatus8616.READY
            and self.stats.closed
            and self.stats.materialized_count == self.stats.normalized_fact_count
        )

    @property
    def complete(self) -> bool:
        """Return whether range and callsite accounting are coherent."""
        return bool(
            self.stats.closed
            and self.callsites.stats.closed
            and self.function_ranges == tuple(sorted(set(self.function_ranges)))
        )

    def matches(
        self,
        project: object,
        function_ranges: Sequence[tuple[int, int]],
    ) -> bool:
        """Match the explicit request owner and exact normalized range census."""
        return bool(
            self.complete
            and project is self.source_project
            and self.function_ranges == tuple(sorted(set(function_ranges)))
        )


_ACTIVE_CALLER_RETURN_PROGRAM_8616: ContextVar[
    CallerReturnUseProgramEvidence8616 | None
] = ContextVar("active_caller_return_program_8616", default=None)


def _empty_callsite_index_8616(
    direct_target_resolver: DirectCallTargetResolver8616,
    instruction_address_resolver: InstructionAddressResolver8616,
) -> DecodedDirectCallsiteIndex8616:
    """Build a closed empty index through the authoritative Frontend owner."""
    return build_decoded_direct_callsite_index_8616(
        {},
        direct_target_resolver=direct_target_resolver,
        instruction_address_resolver=instruction_address_resolver,
    )


def build_caller_return_use_program_evidence_8616(
    project: object,
    function_ranges: Sequence[tuple[int, int]],
    *,
    direct_target_resolver: DirectCallTargetResolver8616,
    instruction_address_resolver: InstructionAddressResolver8616,
) -> CallerReturnUseProgramEvidence8616:
    """Decode exact ranges once and publish a closed direct-call index."""
    normalized_ranges = tuple(sorted(set(function_ranges)))
    raw_fact_count = len(function_ranges)
    try:
        project_boundary = cast(_ProjectBoundary8616, project)
        disassembler = project_boundary.arch.capstone
        memory = project_boundary.loader.memory
    except AttributeError:
        return CallerReturnUseProgramEvidence8616(
            project,
            normalized_ranges,
            _empty_callsite_index_8616(
                direct_target_resolver,
                instruction_address_resolver,
            ),
            CallerReturnUseProgramStatus8616.DECODER_UNAVAILABLE,
            CallerReturnUseProgramStats8616(
                raw_fact_count,
                len(normalized_ranges),
                0,
                0,
                raw_fact_count,
            ),
        )
    with suppress(AttributeError, TypeError, ValueError):
        disassembler.detail = True

    decoded_ranges: dict[tuple[int, int], tuple[object, ...]] = {}
    identities: dict[tuple[int, int], CallerEntryIdentity8616] = {}
    classified_fact_count = 0
    for start, end in normalized_ranges:
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            continue
        classified_fact_count += 1
        try:
            loaded = memory.load(start, end - start)
            data = bytes(cast(bytes | bytearray | memoryview, loaded))
            identity = prove_caller_entry_identity_8616(start, end, data)
            if identity is None:
                continue
            decoded_ranges[(start, end)] = tuple(disassembler.disasm(data, start))
            identities[(start, end)] = identity
        except (AttributeError, KeyError, OSError, TypeError, ValueError):
            continue
    callsites = build_decoded_direct_callsite_index_8616(
        decoded_ranges,
        entry_identities=identities,
        direct_target_resolver=direct_target_resolver,
        instruction_address_resolver=instruction_address_resolver,
    )
    materialized_count = len(decoded_ranges)
    evidence = CallerReturnUseProgramEvidence8616(
        project,
        normalized_ranges,
        callsites,
        CallerReturnUseProgramStatus8616.READY,
        CallerReturnUseProgramStats8616(
            raw_fact_count,
            len(normalized_ranges),
            classified_fact_count,
            materialized_count,
            raw_fact_count - materialized_count,
        ),
    )
    if not evidence.complete:
        raise ValueError("caller return-use program accounting did not close")
    return evidence


@contextmanager
def use_caller_return_use_program_evidence_8616(
    evidence: CallerReturnUseProgramEvidence8616,
) -> Iterator[None]:
    """Expose one immutable decoded corpus only inside its request scope."""
    if not evidence.complete:
        raise ValueError("caller return-use request received open program evidence")
    token = _ACTIVE_CALLER_RETURN_PROGRAM_8616.set(evidence)
    try:
        yield
    finally:
        _ACTIVE_CALLER_RETURN_PROGRAM_8616.reset(token)


def current_caller_return_use_program_evidence_8616(
    project: object,
    function_ranges: Sequence[tuple[int, int]],
) -> CallerReturnUseProgramEvidence8616 | None:
    """Return matching request evidence without creating a persistent cache."""
    evidence = _ACTIVE_CALLER_RETURN_PROGRAM_8616.get()
    if evidence is None or not evidence.matches(project, function_ranges):
        return None
    return evidence


__all__ = [
    "CallerReturnUseProgramEvidence8616",
    "CallerReturnUseProgramStats8616",
    "CallerReturnUseProgramStatus8616",
    "build_caller_return_use_program_evidence_8616",
    "current_caller_return_use_program_evidence_8616",
    "use_caller_return_use_program_evidence_8616",
]
