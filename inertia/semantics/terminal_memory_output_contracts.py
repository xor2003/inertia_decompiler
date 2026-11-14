# cython: language_level=3, infer_types=True
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
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import AddressStatus, IRAddress, MemSpace
import dataclasses
import operator

MemoryOutputKey8616 = typing.TypeAliasType("MemoryOutputKey8616", tuple[MemSpace, int, int])


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


@dataclasses.dataclass(frozen=True, )
class TerminalMemoryStoreSite8616:
    """One exact typed STORE contributing to a direct storage candidate."""

    block_addr: cython.longlong
    instr_index: cython.longlong
    instr_addr: cython.longlong


@dataclasses.dataclass(frozen=True, )
class TerminalMemoryOutputFact8616:
    """All exact stores and terminal disposition for one segmented range."""

    address: IRAddress
    disposition: TerminalMemoryOutputDisposition8616
    store_sites: object
    terminal_block_addrs: object
    definitely_written_terminal_block_addrs: object

    @property
    def key(self) -> MemoryOutputKey8616:
        """Return the byte-accurate segmented range identity."""
        return (self.address.space, self.address.offset, self.address.size)

    @property
    def complete(self) -> cython.bint:
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
            and operator.eq(tuple(sorted(tuple(set(terminals)))), terminals)
            and operator.eq(tuple(sorted(tuple(set(definite)))), definite)
            and set(definite) <= set(terminals)
            and disposition_matches
        )


@dataclasses.dataclass(frozen=True, )
class TerminalMemoryOutputStats8616:
    """Closed evidence accounting for direct memory-output candidates."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every direct candidate has one retained outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclasses.dataclass(frozen=True, )
class TerminalMemoryOutputEvidence8616:
    """Direct-storage facts or one atomic path/alias refusal."""

    function_addr: cython.longlong
    facts: object
    failure: TerminalMemoryOutputFailure8616 | None
    stats: TerminalMemoryOutputStats8616

    @property
    def complete(self) -> cython.bint:
        """Return whether all bounded direct candidates were classified."""
        return (
            self.failure is None
            and self.stats.complete
            and all(fact.complete for fact in iter(self.facts))
        )

    @property
    def must_write_facts(self) -> tuple[TerminalMemoryOutputFact8616, ...]:
        """Return exact ranges definitely written on every return path."""
        return tuple(
            fact
            for fact in iter(self.facts)
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
