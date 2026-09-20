"""Index decoded direct callsites once for repeated target queries.

Layer: Frontend instruction inventory.
Responsibility: map already-decoded direct call targets to exact caller and
instruction coordinates without classifying return use or recovering semantics.
Dynamic boundary: decoded instructions are third-party Capstone objects and are
interpreted only through injected target/address resolvers.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .frontend_caller_entry_identity import CallerEntryIdentity8616, caller_target_identity_8616

__all__ = [
    "DecodedDirectCallsite8616",
    "DecodedDirectCallsiteIndex8616",
    "DecodedDirectCallsiteIndexStats8616",
    "build_decoded_direct_callsite_index_8616",
]

type DirectCallTargetResolver8616 = Callable[[object], int | None]
type InstructionAddressResolver8616 = Callable[[object], int | None]


@dataclass(frozen=True, slots=True)
class DecodedDirectCallsite8616:
    """Retain one exact direct call coordinate in a decoded caller range."""

    caller_start: int
    instructions: tuple[object, ...]
    instruction_index: int
    callsite_addr: int
    target_addr: int
    entry_identity: CallerEntryIdentity8616 | None = None


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

    def target_identity(self, target_addr: int) -> int:
        """Use the same proven identity for lookup and recursive-cycle checks."""
        return caller_target_identity_8616(target_addr, self.entry_identities)

    def for_target(self, target_addr: int) -> tuple[DecodedDirectCallsite8616, ...]:
        """Return exact callsites for the existing 16-bit target identity rule."""
        target = self.target_identity(target_addr)
        return self._entries_by_normalized_target.get(target, ())


def build_decoded_direct_callsite_index_8616(
    decoded_ranges: Mapping[tuple[int, int], tuple[object, ...]],
    *,
    direct_target_resolver: DirectCallTargetResolver8616,
    instruction_address_resolver: InstructionAddressResolver8616,
    entry_identities: Mapping[tuple[int, int], CallerEntryIdentity8616] | None = None,
) -> DecodedDirectCallsiteIndex8616:
    """Scan decoded instructions once and return a closed direct-call index."""
    mutable_entries: dict[int, list[DecodedDirectCallsite8616]] = {}
    raw_fact_count = 0
    failure_count = 0
    identities = {} if entry_identities is None else entry_identities
    if entry_identities is not None and set(identities) != set(decoded_ranges):
        raise ValueError("caller entry identities do not cover the decoded ranges")
    ordered_identities = tuple(identities[key] for key in sorted(identities))
    for caller_range, instructions in sorted(decoded_ranges.items()):
        identity = identities.get(caller_range)
        caller_start = caller_range[0] if identity is None else identity.entry_addr
        if identity is not None and (identity.decode_start, identity.decode_end) != caller_range:
            raise ValueError(f"caller entry identity disagrees with decode range {caller_range!r}")
        for instruction_index, instruction in enumerate(instructions):
            target_addr = direct_target_resolver(instruction)
            if not isinstance(target_addr, int):
                continue
            raw_fact_count += 1
            callsite_addr = instruction_address_resolver(instruction)
            if not isinstance(callsite_addr, int):
                failure_count += 1
                continue
            normalized_target = caller_target_identity_8616(target_addr, ordered_identities)
            mutable_entries.setdefault(normalized_target, []).append(
                DecodedDirectCallsite8616(
                    caller_start=caller_start,
                    instructions=instructions,
                    instruction_index=instruction_index,
                    callsite_addr=callsite_addr,
                    target_addr=target_addr,
                    entry_identity=identity,
                )
            )
    entries = {
        target_addr: tuple(target_entries)
        for target_addr, target_entries in sorted(mutable_entries.items())
    }
    materialized_count = sum(len(target_entries) for target_entries in entries.values())
    stats = DecodedDirectCallsiteIndexStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=raw_fact_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
    if not stats.closed:
        raise ValueError("decoded direct-call index accounting did not close")
    return DecodedDirectCallsiteIndex8616(entries, stats, ordered_identities)
