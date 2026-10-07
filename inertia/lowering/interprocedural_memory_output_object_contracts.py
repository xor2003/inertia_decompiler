"""Typed contracts for Alias-owned function memory-output objects.

Layer: Types/Lowering.
Responsibility: retain one canonical Alias owner, its exact caller projections,
typed refusals, and closed evidence counters. Collection and grouping live in
``interprocedural_memory_output_objects``; this module performs no CFG, Alias,
type, codegen, rewrite, or rendering work.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.terminal_memory_outputs import TerminalMemoryAliasFact8616
from inertia.semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
)

from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
)
from .interprocedural_storage_live_out_contracts import (
    MemoryLiveOutUseDisposition8616,
    MemoryLiveOutUseFact8616,
)
from .pointer_parameter_memory_output_contracts import (
    PointerParameterMemoryOutputObject8616,
)


class MemoryOutputObjectJoinVerdict8616(StrEnum):
    """Typed outcome of joining caller views under Alias owners."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"
    CONFLICT = "conflict"


class MemoryOutputObjectFailure8616(StrEnum):
    """Stable reasons a function memory-output object cannot close."""

    INCOMPLETE_EFFECT = "incomplete_effect"
    DUPLICATE_EFFECT = "duplicate_effect"
    MISSING_TRIAL = "missing_trial"
    EXTRA_TRIAL = "extra_trial"
    TRIAL_CONFLICT = "trial_conflict"
    SIGNEDNESS_CONFLICT = "signedness_conflict"
    VALUE_CLASS_CONFLICT = "value_class_conflict"
    OWNER_CONFLICT = "owner_conflict"
    OWNER_OVERLAP = "owner_overlap"
    POINTER_OUTPUT_REFUSED = "pointer_output_refused"


@dataclass(frozen=True, slots=True)
class MemoryOutputObjectStats8616:
    """Closed evidence accounting for function memory-output views."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every raw effect became one retained view."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class MemoryOutputViewBinding8616:
    """One caller-specific projection of an Alias-owned memory output."""

    caller_addr: int
    callee_addr: int
    callsite_addr: int
    effect: MemoryLiveOutUseFact8616
    trial: StorageTrial8616 | None

    @property
    def complete(self) -> bool:
        """Return whether effect and optional value trial agree exactly."""
        needs_trial = bool(
            self.effect.disposition is MemoryLiveOutUseDisposition8616.USED
            and self.effect.terminal_output.disposition
            is TerminalMemoryOutputDisposition8616.MUST_WRITE
        )
        trial = self.trial
        trial_matches = bool(
            trial is not None
            and trial.is_complete
            and trial.role is StorageTrialRole8616.LIVE_OUT
            and trial.callee_addr == self.callee_addr
            and trial.caller_addr == self.caller_addr
            and trial.callsite_addr == self.callsite_addr
            and trial.storage == self.effect.storage
        )
        return bool(
            self.caller_addr >= 0
            and self.callee_addr >= 0
            and self.callsite_addr >= 0
            and self.effect.complete
            and (trial_matches if needs_trial else trial is None)
        )


@dataclass(frozen=True, slots=True)
class MemoryOutputObjectContract8616:
    """One canonical Alias owner and all exact caller view bindings."""

    alias_output: TerminalMemoryAliasFact8616
    storage: StorageIdentity8616
    views: tuple[MemoryOutputViewBinding8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether owner identity and every projected view agree."""
        owner_address = self.alias_output.terminal_output.address
        view_keys = tuple(
            (
                view.callee_addr,
                view.caller_addr,
                view.callsite_addr,
                view.effect.storage.key,
            )
            for view in self.views
        )
        return bool(
            self.alias_output.complete
            and self.alias_output.is_owner
            and self.storage.kind is StorageIdentityKind8616.MEMORY
            and self.storage.is_exact
            and self.storage.address == owner_address
            and self.views
            and len(set(view_keys)) == len(view_keys)
            and all(
                view.complete and view.effect.alias_output == self.alias_output
                for view in self.views
            )
        )


@dataclass(frozen=True, slots=True)
class MemoryOutputObjectJoinEvidence8616:
    """All function memory-output objects or one atomic typed refusal."""

    verdict: MemoryOutputObjectJoinVerdict8616
    objects: tuple[MemoryOutputObjectContract8616, ...]
    failure: MemoryOutputObjectFailure8616 | None
    stats: MemoryOutputObjectStats8616
    pointer_objects: tuple[PointerParameterMemoryOutputObject8616, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether every effect has one coherent object projection."""
        return bool(
            self.verdict is MemoryOutputObjectJoinVerdict8616.PROVEN
            and self.failure is None
            and self.stats.complete
            and (
                sum(len(item.views) for item in self.objects)
                + sum(len(item.views) for item in self.pointer_objects)
            )
            == self.stats.materialized_count
            and all(item.complete for item in self.objects)
            and all(item.complete for item in self.pointer_objects)
        )

    @property
    def storage_failure(self) -> StorageTrialFailureKind8616 | None:
        """Map the detailed owner failure to the function solver contract."""
        if self.failure is None:
            return None
        if self.failure is MemoryOutputObjectFailure8616.SIGNEDNESS_CONFLICT:
            return StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT
        if self.failure is MemoryOutputObjectFailure8616.VALUE_CLASS_CONFLICT:
            return StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT
        if self.verdict is MemoryOutputObjectJoinVerdict8616.CONFLICT:
            return StorageTrialFailureKind8616.STORAGE_CONFLICT
        return StorageTrialFailureKind8616.INCOMPLETE_TRIAL


__all__ = [
    "MemoryOutputObjectContract8616",
    "MemoryOutputObjectFailure8616",
    "MemoryOutputObjectJoinEvidence8616",
    "MemoryOutputObjectJoinVerdict8616",
    "MemoryOutputObjectStats8616",
    "MemoryOutputViewBinding8616",
]
