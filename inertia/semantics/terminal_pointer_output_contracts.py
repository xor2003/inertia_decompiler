# cython: language_level=3, infer_types=True
"""Typed contracts for pointer-relative storage reaching function returns.

Layer: Semantics.
Responsibility: own immutable identities, verdicts, failures, and closed evidence
accounting for terminal pointer-relative output proofs. This module does not
inspect CFGs, infer aliases, choose C types, mutate prototypes, or render C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin
import dataclasses
import operator

PointerOutputKey8616 = typing.TypeAliasType("PointerOutputKey8616", tuple[MemSpace, str, int, int, int])


class TerminalPointerOutputDisposition8616(StrEnum):
    """Path-complete classification of one pointer-relative storage range."""

    CONDITIONAL = "conditional"
    MUST_WRITE = "must_write"


class TerminalPointerOutputFailure8616(StrEnum):
    """Stable reasons pointer-relative output evidence cannot close."""

    ALIAS_CONFLICT = "alias_conflict"
    CFG_INCOMPLETE = "cfg_incomplete"
    ENTRY_BLOCK_MISSING = "entry_block_missing"
    TERMINAL_NOT_RETURN = "terminal_not_return"


@dataclasses.dataclass(frozen=True, )
class TerminalPointerStoreSite8616:
    """One exact typed STORE contributing to a pointer-relative candidate."""

    block_addr: cython.longlong
    instr_index: cython.longlong
    instr_addr: cython.longlong


@dataclasses.dataclass(frozen=True, )
class TerminalPointerOutputFact8616:
    """All exact stores and terminal disposition for one versioned pointer range."""

    address: IRAddress
    base_value: IRValue
    disposition: TerminalPointerOutputDisposition8616
    store_sites: object
    terminal_block_addrs: object
    definitely_written_terminal_block_addrs: object

    @property
    def conditional_store_blocks(self) -> tuple[cython.longlong, ...]:
        """Return conservative coexecution evidence, unnecessary for must-writes.

        Equal terminal sets do not identify which incoming paths wrote memory.
        Equal store-block sets do prove that the lanes execute together on
        normally returning paths through these complete SSA basic blocks.
        Distinct sets require further path evidence before combining outputs.
        """
        if self.disposition is TerminalPointerOutputDisposition8616.MUST_WRITE:
            return ()
        return tuple(sorted({site.block_addr for site in iter(self.store_sites)}))

    @property
    def segment(self) -> MemSpace:
        """Return the exact segmented memory space of this output."""
        return self.address.space

    @property
    def base_register(self) -> object:
        """Return the exact register carried by the pointer address."""
        name = self.base_value.name
        return name if isinstance(name, str) and name else None

    @property
    def base_version(self) -> int | None:
        """Return the exact SSA version carried by the pointer address."""
        version = self.base_value.version
        return version if isinstance(version, int) and not isinstance(version, bool) else None

    @property
    def relative_offset(self) -> cython.longlong:
        """Return the signed byte offset relative to the versioned pointer."""
        return int(self.address.offset)

    @property
    def width(self) -> cython.longlong:
        """Return the exact STORE width in bytes."""
        return int(self.address.size)

    @property
    def key(self) -> PointerOutputKey8616 | None:
        """Return the byte-accurate pointer range identity when versioned."""
        if self.base_value.name is None or self.base_value.version is None:
            return None
        return (
            self.address.space,
            self.base_value.name,
            self.base_value.version,
            self.address.offset,
            self.address.size,
        )

    @property
    def complete(self) -> cython.bint:
        """Return whether pointer identity, stores, and terminal coverage agree."""
        definite = self.definitely_written_terminal_block_addrs
        terminals = self.terminal_block_addrs
        disposition_matches = (
            definite == terminals
            if self.disposition is TerminalPointerOutputDisposition8616.MUST_WRITE
            else definite != terminals
        )
        return bool(
            self.address.space in {MemSpace.DS, MemSpace.ES}
            and self.address.status is AddressStatus.STABLE
            and self.address.segment_origin is SegmentOrigin.PROVEN
            and self.address.size > 0
            and len(self.address.base) == len(self.address.base_values) == 1
            and operator.eq(self.address.base, (self.base_value.name,))
            and operator.eq(self.address.base_values, (self.base_value,))
            and self.base_value.space is MemSpace.REG
            and self.base_value.name is not None
            and self.base_value.version is not None
            and self.store_sites
            and terminals
            and operator.eq(tuple(sorted(tuple(set(terminals)))), terminals)
            and operator.eq(tuple(sorted(tuple(set(definite)))), definite)
            and set(definite) <= set(terminals)
            and disposition_matches
        )


@dataclasses.dataclass(frozen=True, )
class TerminalPointerOutputStats8616:
    """Closed evidence accounting for pointer-relative output candidates."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every pointer candidate has one retained outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclasses.dataclass(frozen=True, )
class TerminalPointerOutputEvidence8616:
    """Pointer-relative facts or one atomic path/alias refusal."""

    function_addr: cython.longlong
    facts: object
    failure: TerminalPointerOutputFailure8616 | None
    stats: TerminalPointerOutputStats8616

    @property
    def complete(self) -> cython.bint:
        """Return whether all bounded pointer candidates were classified."""
        return (
            self.failure is None
            and self.stats.complete
            and operator.eq(len(self.facts), self.stats.materialized_count)
            and all(fact.complete for fact in iter(self.facts))
        )

    @property
    def must_write_facts(self) -> tuple[TerminalPointerOutputFact8616, ...]:
        """Return exact pointer ranges definitely written on every return path."""
        return tuple(
            fact
            for fact in iter(self.facts)
            if fact.disposition is TerminalPointerOutputDisposition8616.MUST_WRITE
        )


__all__ = [
    "PointerOutputKey8616",
    "TerminalPointerOutputDisposition8616",
    "TerminalPointerOutputEvidence8616",
    "TerminalPointerOutputFact8616",
    "TerminalPointerOutputFailure8616",
    "TerminalPointerOutputStats8616",
    "TerminalPointerStoreSite8616",
]
