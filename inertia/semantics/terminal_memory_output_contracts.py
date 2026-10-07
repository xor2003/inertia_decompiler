"""Typed contracts for direct segmented storage reaching function returns.

Layer: Semantics.
Responsibility: own immutable identities, verdicts, failures, and closed evidence
accounting for terminal direct-memory output proofs. This module does not inspect
CFGs, infer aliases, choose C types, mutate prototypes, or render C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import AddressStatus, IRAddress, MemSpace

type MemoryOutputKey8616 = tuple[MemSpace, int, int]


class TerminalMemoryOutputDisposition8616(StrEnum):
    """Path-complete classification of one direct segmented storage range."""

    CONDITIONAL = "conditional"
    MUST_WRITE = "must_write"


class TerminalMemoryOutputFailure8616(StrEnum):
    """Stable reasons direct memory output evidence cannot close."""

    ALIAS_CONFLICT = "alias_conflict"
    CFG_INCOMPLETE = "cfg_incomplete"
    ENTRY_BLOCK_MISSING = "entry_block_missing"
    TERMINAL_NOT_RETURN = "terminal_not_return"


@dataclass(frozen=True, slots=True)
class TerminalMemoryStoreSite8616:
    """One exact typed STORE contributing to a direct storage candidate."""

    block_addr: int
    instr_index: int
    instr_addr: int


@dataclass(frozen=True, slots=True)
class TerminalMemoryOutputFact8616:
    """All exact stores and terminal disposition for one segmented range."""

    address: IRAddress
    disposition: TerminalMemoryOutputDisposition8616
    store_sites: tuple[TerminalMemoryStoreSite8616, ...]
    terminal_block_addrs: tuple[int, ...]
    definitely_written_terminal_block_addrs: tuple[int, ...]

    @property
    def key(self) -> MemoryOutputKey8616:
        """Return the byte-accurate segmented range identity."""
        return (self.address.space, self.address.offset, self.address.size)

    @property
    def complete(self) -> bool:
        """Return whether the fact retains exact stores and terminal coverage."""
        definite = self.definitely_written_terminal_block_addrs
        terminals = self.terminal_block_addrs
        disposition_matches = (
            definite == terminals
            if self.disposition is TerminalMemoryOutputDisposition8616.MUST_WRITE
            else definite != terminals
        )
        return bool(
            self.address.space in {MemSpace.DS, MemSpace.ES}
            and not self.address.base
            and self.address.size > 0
            and self.address.status is AddressStatus.STABLE
            and self.store_sites
            and terminals
            and tuple(sorted(set(terminals))) == terminals
            and tuple(sorted(set(definite))) == definite
            and set(definite) <= set(terminals)
            and disposition_matches
        )


@dataclass(frozen=True, slots=True)
class TerminalMemoryOutputStats8616:
    """Closed evidence accounting for direct memory-output candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every direct candidate has one retained outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class TerminalMemoryOutputEvidence8616:
    """Direct-storage facts or one atomic path/alias refusal."""

    function_addr: int
    facts: tuple[TerminalMemoryOutputFact8616, ...]
    failure: TerminalMemoryOutputFailure8616 | None
    stats: TerminalMemoryOutputStats8616

    @property
    def complete(self) -> bool:
        """Return whether all bounded direct candidates were classified."""
        return (
            self.failure is None
            and self.stats.complete
            and all(fact.complete for fact in self.facts)
        )

    @property
    def must_write_facts(self) -> tuple[TerminalMemoryOutputFact8616, ...]:
        """Return exact ranges definitely written on every return path."""
        return tuple(
            fact
            for fact in self.facts
            if fact.disposition is TerminalMemoryOutputDisposition8616.MUST_WRITE
        )


__all__ = [
    "MemoryOutputKey8616",
    "TerminalMemoryOutputDisposition8616",
    "TerminalMemoryOutputEvidence8616",
    "TerminalMemoryOutputFact8616",
    "TerminalMemoryOutputFailure8616",
    "TerminalMemoryOutputStats8616",
    "TerminalMemoryStoreSite8616",
]
