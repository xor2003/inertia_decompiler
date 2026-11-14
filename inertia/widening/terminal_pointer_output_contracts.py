# cython: language_level=3, infer_types=True
"""Typed Widening contracts for terminal pointer-parameter output views.

Layer: Widening.
Responsibility: retain byte-accurate contiguous output views after Alias proves
their pointer-parameter owner. This module does not inspect CFGs, recover
storage identity, infer pointee types, bind callers, mutate prototypes, or
render C. Gaps and distinct path coverage remain separate evidence.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.terminal_pointer_output_contracts import (
    TerminalPointerAliasEvidence8616,
    TerminalPointerAliasFact8616,
)
from inertia.ir.core import IRAddress, MemSpace
from inertia.semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
)
import dataclasses
import operator


class TerminalPointerOutputViewFailure8616(StrEnum):
    """Stable reasons pointer-output Widening cannot close."""

    ALIAS_EVIDENCE_REFUSED = "alias_evidence_refused"
    OUTPUT_INCOMPLETE = "output_incomplete"
    DUPLICATE_OUTPUT = "duplicate_output"
    OVERLAPPING_PATH_CONFLICT = "overlapping_path_conflict"


@dataclasses.dataclass(frozen=True, )
class TerminalPointerOutputViewFact8616:
    """One contiguous segmented range owned by one pointer parameter."""

    parameter_storage: IRAddress
    segment: MemSpace
    relative_offset: cython.longlong
    width: cython.longlong
    disposition: TerminalPointerOutputDisposition8616
    terminal_block_addrs: object
    definitely_written_terminal_block_addrs: object
    alias_outputs: object

    @property
    def end_offset(self) -> cython.longlong:
        """Return the exclusive relative byte end of this view."""
        return self.relative_offset + self.width

    @property
    def complete(self) -> cython.bint:
        """Return whether all lanes form one exact gap-free output view."""
        end: object
        start: object
        if self.width <= 0 or not self.alias_outputs:
            return False
        conditional_blocks = {
            fact.terminal_output.conditional_store_blocks for fact in iter(self.alias_outputs)
        }
        if len(conditional_blocks) != 1:
            return False
        intervals = sorted(
            (
                fact.terminal_output.relative_offset,
                fact.terminal_output.relative_offset + fact.terminal_output.width,
            )
            for fact in iter(self.alias_outputs)
        )
        covered_end = intervals[0][1]
        if operator.ne(intervals[0][0], self.relative_offset):
            return False
        for start, end in intervals[1:]:
            if start > covered_end:
                return False
            covered_end = max(covered_end, end)
        return bool(
            operator.eq(covered_end, self.end_offset)
            and self.segment in {MemSpace.DS, MemSpace.ES}
            and all(
                fact.complete
                and operator.eq(fact.parameter_storage, self.parameter_storage)
                and fact.terminal_output.segment is self.segment
                and fact.terminal_output.disposition is self.disposition
                and operator.eq(fact.terminal_output.terminal_block_addrs, self.terminal_block_addrs)
                and operator.eq(fact.terminal_output.definitely_written_terminal_block_addrs, self.definitely_written_terminal_block_addrs)
                for fact in iter(self.alias_outputs)
            )
        )


@dataclasses.dataclass(frozen=True, )
class TerminalPointerOutputViewStats8616:
    """Closed accounting for pointer-output range Widening."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every normalized view has one retained outcome."""
        return bool(
            self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclasses.dataclass(frozen=True, )
class TerminalPointerOutputViewEvidence8616:
    """All widened pointer outputs or one atomic typed refusal."""

    function_addr: cython.longlong
    facts: object
    failure: TerminalPointerOutputViewFailure8616 | None
    stats: TerminalPointerOutputViewStats8616
    source: TerminalPointerAliasEvidence8616

    @property
    def complete(self) -> cython.bint:
        """Return whether source identity and every Widening outcome close."""
        retained = tuple(
            alias_output
            for fact in iter(self.facts)
            for alias_output in iter(fact.alias_outputs)
        )
        return bool(
            self.source.complete
            and operator.eq(self.function_addr, self.source.function_addr)
            and self.failure is None
            and self.stats.complete
            and operator.eq(self.stats.raw_fact_count, len(self.source.facts))
            and operator.eq(self.stats.materialized_count, len(self.facts))
            and operator.eq(len(retained), len(self.source.facts))
            and all(alias_output in retained for alias_output in iter(self.source.facts))
            and all(fact.complete for fact in iter(self.facts))
        )


__all__ = [
    "TerminalPointerOutputViewEvidence8616",
    "TerminalPointerOutputViewFact8616",
    "TerminalPointerOutputViewFailure8616",
    "TerminalPointerOutputViewStats8616",
]
