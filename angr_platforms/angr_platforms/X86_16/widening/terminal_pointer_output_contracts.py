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

from dataclasses import dataclass
from enum import StrEnum

from ..alias.terminal_pointer_output_contracts import (
    TerminalPointerAliasEvidence8616,
    TerminalPointerAliasFact8616,
)
from ..ir import IRAddress, MemSpace
from ..semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
)


class TerminalPointerOutputViewFailure8616(StrEnum):
    """Stable reasons pointer-output Widening cannot close."""

    ALIAS_EVIDENCE_REFUSED = "alias_evidence_refused"
    OUTPUT_INCOMPLETE = "output_incomplete"
    DUPLICATE_OUTPUT = "duplicate_output"
    OVERLAPPING_PATH_CONFLICT = "overlapping_path_conflict"


@dataclass(frozen=True, slots=True)
class TerminalPointerOutputViewFact8616:
    """One contiguous segmented range owned by one pointer parameter."""

    parameter_storage: IRAddress
    segment: MemSpace
    relative_offset: int
    width: int
    disposition: TerminalPointerOutputDisposition8616
    terminal_block_addrs: tuple[int, ...]
    definitely_written_terminal_block_addrs: tuple[int, ...]
    alias_outputs: tuple[TerminalPointerAliasFact8616, ...]

    @property
    def end_offset(self) -> int:
        """Return the exclusive relative byte end of this view."""
        return self.relative_offset + self.width

    @property
    def complete(self) -> bool:
        """Return whether all lanes form one exact gap-free output view."""
        if self.width <= 0 or not self.alias_outputs:
            return False
        conditional_blocks = {
            fact.terminal_output.conditional_store_blocks for fact in self.alias_outputs
        }
        if len(conditional_blocks) != 1:
            return False
        intervals = sorted(
            (
                fact.terminal_output.relative_offset,
                fact.terminal_output.relative_offset + fact.terminal_output.width,
            )
            for fact in self.alias_outputs
        )
        covered_end = intervals[0][1]
        if intervals[0][0] != self.relative_offset:
            return False
        for start, end in intervals[1:]:
            if start > covered_end:
                return False
            covered_end = max(covered_end, end)
        return bool(
            covered_end == self.end_offset
            and self.segment in {MemSpace.DS, MemSpace.ES}
            and all(
                fact.complete
                and fact.parameter_storage == self.parameter_storage
                and fact.terminal_output.segment is self.segment
                and fact.terminal_output.disposition is self.disposition
                and fact.terminal_output.terminal_block_addrs
                == self.terminal_block_addrs
                and fact.terminal_output.definitely_written_terminal_block_addrs
                == self.definitely_written_terminal_block_addrs
                for fact in self.alias_outputs
            )
        )


@dataclass(frozen=True, slots=True)
class TerminalPointerOutputViewStats8616:
    """Closed accounting for pointer-output range Widening."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every normalized view has one retained outcome."""
        return bool(
            self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class TerminalPointerOutputViewEvidence8616:
    """All widened pointer outputs or one atomic typed refusal."""

    function_addr: int
    facts: tuple[TerminalPointerOutputViewFact8616, ...]
    failure: TerminalPointerOutputViewFailure8616 | None
    stats: TerminalPointerOutputViewStats8616
    source: TerminalPointerAliasEvidence8616

    @property
    def complete(self) -> bool:
        """Return whether source identity and every Widening outcome close."""
        retained = tuple(
            alias_output
            for fact in self.facts
            for alias_output in fact.alias_outputs
        )
        return bool(
            self.source.complete
            and self.function_addr == self.source.function_addr
            and self.failure is None
            and self.stats.complete
            and self.stats.raw_fact_count == len(self.source.facts)
            and self.stats.materialized_count == len(self.facts)
            and len(retained) == len(self.source.facts)
            and all(alias_output in retained for alias_output in self.source.facts)
            and all(fact.complete for fact in self.facts)
        )


__all__ = [
    "TerminalPointerOutputViewEvidence8616",
    "TerminalPointerOutputViewFact8616",
    "TerminalPointerOutputViewFailure8616",
    "TerminalPointerOutputViewStats8616",
]
