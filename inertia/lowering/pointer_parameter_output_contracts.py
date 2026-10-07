"""Typed Types/Lowering contracts for pointer-parameter output bindings.

Layer: Types/Lowering.
Responsibility: bind each Widening-proven pointer output view to one exact
logical callee input. These contracts do not project caller targets, infer
pointee types, mutate prototypes, or render C. Caller projection requires a
separate exact reaching-argument-definition proof.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.terminal_pointer_output_contracts import TerminalPointerAliasEvidence8616
from inertia.ir.core import AddressStatus, IRAddress, MemSpace
from inertia.ir.function_ssa_registry import FunctionSSAArtifactFailure8616
from inertia.semantics.terminal_pointer_output_contracts import TerminalPointerOutputEvidence8616
from inertia.widening.terminal_pointer_output_contracts import (
    TerminalPointerOutputViewEvidence8616,
    TerminalPointerOutputViewFact8616,
)


class PointerParameterOutputFailure8616(StrEnum):
    """Stable reasons pointer-output Lowering cannot close."""

    FUNCTION_UNAVAILABLE = "function_unavailable"
    CALLEE_SSA_UNAVAILABLE = "callee_ssa_unavailable"
    SEMANTICS_REFUSED = "semantics_refused"
    ALIAS_REFUSED = "alias_refused"
    WIDENING_REFUSED = "widening_refused"
    ARGUMENT_WIDTHS_REFUSED = "argument_widths_refused"
    PARAMETER_STORAGE_UNMATCHED = "parameter_storage_unmatched"
    PARAMETER_STORAGE_CONFLICT = "parameter_storage_conflict"


@dataclass(frozen=True, slots=True)
class PointerParameterOutputContract8616:
    """One output view bound to one exact logical pointer input."""

    logical_index: int
    argument_storage: IRAddress
    output_view: TerminalPointerOutputViewFact8616

    @property
    def complete(self) -> bool:
        """Return whether the logical input and Alias owner agree exactly."""
        parameter = self.output_view.parameter_storage
        return bool(
            self.logical_index >= 0
            and self.output_view.complete
            and self.argument_storage.space is MemSpace.SS
            and self.argument_storage.base == ("bp",)
            and self.argument_storage.status is AddressStatus.STABLE
            and self.argument_storage.offset == parameter.offset
            and self.argument_storage.size == parameter.size
        )


@dataclass(frozen=True, slots=True)
class PointerParameterOutputStats8616:
    """Closed accounting for pointer-output Types/Lowering materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every Widening view became one retained contract."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class PointerParameterOutputEvidence8616:
    """Published logical input bindings or one atomic typed refusal."""

    function_addr: int
    facts: tuple[PointerParameterOutputContract8616, ...]
    failure: PointerParameterOutputFailure8616 | None
    stats: PointerParameterOutputStats8616
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None
    terminal: TerminalPointerOutputEvidence8616 | None = None
    aliases: TerminalPointerAliasEvidence8616 | None = None
    views: TerminalPointerOutputViewEvidence8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether all upstream and materialized evidence closes."""
        views = self.views
        return bool(
            self.failure is None
            and self.ssa_failure is None
            and self.terminal is not None
            and self.terminal.complete
            and self.aliases is not None
            and self.aliases.complete
            and views is not None
            and views.complete
            and self.stats.complete
            and len(self.facts) == len(views.facts) == self.stats.materialized_count
            and all(fact.complete for fact in self.facts)
            and tuple(fact.output_view for fact in self.facts) == views.facts
        )


__all__ = [
    "PointerParameterOutputContract8616",
    "PointerParameterOutputEvidence8616",
    "PointerParameterOutputFailure8616",
    "PointerParameterOutputStats8616",
]
