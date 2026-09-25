"""Validate Alias-owned memory outputs at the publication transaction.

Layer: Types/Lowering.
Responsibility: prove that every accepted function memory-output object retains
exactly the caller effects and LIVE_OUT trials published in the same immutable
function contract. This module validates owned contracts only; it does not
collect storage, infer aliases or types, mutate prototypes, or render C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .interprocedural_memory_output_object_contracts import (
    MemoryOutputViewBinding8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageBinding8616,
    FunctionStorageContract8616,
)
from .pointer_parameter_memory_output_contracts import (
    PointerParameterMemoryOutputObject8616,
    PointerParameterMemoryOutputView8616,
)


class MemoryOutputTransactionVerdict8616(StrEnum):
    """Typed result of validating one function memory-output transaction."""

    PROVEN = "proven"
    CONFLICT = "conflict"


class MemoryOutputTransactionFailure8616(StrEnum):
    """Stable reasons an accepted memory-output transaction is incoherent."""

    CALLSITE_CONFLICT = "callsite_conflict"
    CALLSITE_MISSING = "callsite_missing"
    DUPLICATE_OWNER = "duplicate_owner"
    DUPLICATE_VIEW = "duplicate_view"
    OBJECT_INCOMPLETE = "object_incomplete"
    EFFECT_MISSING = "effect_missing"
    EFFECT_CONFLICT = "effect_conflict"
    TRIAL_MISMATCH = "trial_mismatch"
    ORPHAN_EFFECT = "orphan_effect"
    ORPHAN_TRIAL = "orphan_trial"


@dataclass(frozen=True, slots=True)
class MemoryOutputTransactionStats8616:
    """Closed evidence accounting for one publication validation."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every retained fact passed transaction validation."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class MemoryOutputTransactionEvidence8616:
    """Complete publication proof or one typed atomic refusal."""

    verdict: MemoryOutputTransactionVerdict8616
    failure: MemoryOutputTransactionFailure8616 | None
    stats: MemoryOutputTransactionStats8616

    @property
    def complete(self) -> bool:
        """Return whether the complete memory-output transaction is coherent."""
        return bool(
            self.verdict is MemoryOutputTransactionVerdict8616.PROVEN
            and self.failure is None
            and self.stats.complete
        )


def _raw_fact_count_8616(contract: FunctionStorageContract8616) -> int:
    """Count every callsite, object, view, effect, and trial being validated."""
    return (
        len(contract.callsites)
        + len(contract.memory_outputs)
        + len(contract.pointer_memory_outputs)
        + sum(len(item.views) for item in contract.memory_outputs)
        + sum(len(item.views) for item in contract.pointer_memory_outputs)
        + sum(
            len(callsite.memory_effects)
            + len(callsite.pointer_effects)
            + len(callsite.live_outs)
            for callsite in contract.callsites
        )
    )


def _refused_8616(
    failure: MemoryOutputTransactionFailure8616,
    raw_count: int,
) -> MemoryOutputTransactionEvidence8616:
    """Build one typed refusal without accepting any transaction fact."""
    return MemoryOutputTransactionEvidence8616(
        MemoryOutputTransactionVerdict8616.CONFLICT,
        failure,
        MemoryOutputTransactionStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=raw_count,
            failure_count=1,
        ),
    )


@dataclass(slots=True)
class _TransactionScan8616:
    """Mutable consumed-identity state for one transaction validation."""

    callsites: dict[tuple[int, int], CallsiteStorageBinding8616]
    function_addr: int
    raw_count: int
    consumed_effects: set[tuple[int, int, int]] = field(default_factory=set)
    consumed_pointer_effects: set[tuple[int, int, int]] = field(default_factory=set)
    consumed_trials: set[tuple[int, int, int]] = field(default_factory=set)
    view_keys: set[tuple[object, ...]] = field(default_factory=set)
    pointer_source_keys: set[tuple[object, ...]] = field(default_factory=set)

    def check_object_view(
        self,
        view: MemoryOutputViewBinding8616,
    ) -> MemoryOutputTransactionEvidence8616 | None:
        """Consume one memory-object view or return a typed refusal."""
        callsite_key = (view.caller_addr, view.callsite_addr)
        callsite = self.callsites.get(callsite_key)
        if callsite is None:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.CALLSITE_MISSING,
                self.raw_count,
            )
        view_key = (*callsite_key, *view.effect.storage.key)
        if view_key in self.view_keys:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.DUPLICATE_VIEW,
                self.raw_count,
            )
        self.view_keys.add(view_key)
        effect_indices = tuple(
            index
            for index, effect in enumerate(callsite.memory_effects)
            if effect == view.effect
        )
        if not effect_indices:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.EFFECT_MISSING,
                self.raw_count,
            )
        if len(effect_indices) != 1:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.EFFECT_CONFLICT,
                self.raw_count,
            )
        self.consumed_effects.add((*callsite_key, effect_indices[0]))
        if view.trial is not None:
            trial_indices = tuple(
                index
                for index, trial in enumerate(callsite.live_outs)
                if trial == view.trial
            )
            if len(trial_indices) != 1:
                return _refused_8616(
                    MemoryOutputTransactionFailure8616.TRIAL_MISMATCH,
                    self.raw_count,
                )
            self.consumed_trials.add((*callsite_key, trial_indices[0]))
        if not view.complete:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.OBJECT_INCOMPLETE,
                self.raw_count,
            )
        return None

    def check_pointer_object(
        self,
        pointer_object: PointerParameterMemoryOutputObject8616,
    ) -> MemoryOutputTransactionEvidence8616 | None:
        """Consume one pointer-output object and its views or refuse."""
        source = pointer_object.source
        source_view = source.output_view
        source_key = (
            source.logical_index,
            source.argument_storage.offset,
            source.argument_storage.size,
            source_view.segment.value,
            source_view.relative_offset,
            source_view.width,
        )
        if source_key in self.pointer_source_keys:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.DUPLICATE_OWNER,
                self.raw_count,
            )
        self.pointer_source_keys.add(source_key)
        for pointer_view in pointer_object.views:
            refusal = self._check_pointer_view(pointer_view)
            if refusal is not None:
                return refusal
        if not pointer_object.complete:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.OBJECT_INCOMPLETE,
                self.raw_count,
            )
        return None

    def _check_pointer_view(
        self,
        pointer_view: PointerParameterMemoryOutputView8616,
    ) -> MemoryOutputTransactionEvidence8616 | None:
        """Consume one pointer-output view or return a typed refusal."""
        callsite_key = (pointer_view.caller_addr, pointer_view.callsite_addr)
        callsite = self.callsites.get(callsite_key)
        if callsite is None or pointer_view.callee_addr != self.function_addr:
            return _refused_8616(
                (
                    MemoryOutputTransactionFailure8616.CALLSITE_MISSING
                    if callsite is None
                    else MemoryOutputTransactionFailure8616.CALLSITE_CONFLICT
                ),
                self.raw_count,
            )
        view_key = (*callsite_key, "pointer", pointer_view.effect.logical_index)
        if view_key in self.view_keys:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.DUPLICATE_VIEW,
                self.raw_count,
            )
        self.view_keys.add(view_key)
        effect_indices = tuple(
            index
            for index, effect in enumerate(callsite.pointer_effects)
            if effect == pointer_view.effect
        )
        if not effect_indices:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.EFFECT_MISSING,
                self.raw_count,
            )
        if len(effect_indices) != 1:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.EFFECT_CONFLICT,
                self.raw_count,
            )
        self.consumed_pointer_effects.add((*callsite_key, effect_indices[0]))
        if not pointer_view.complete:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.OBJECT_INCOMPLETE,
                self.raw_count,
            )
        return None

    def check_orphans(self) -> MemoryOutputTransactionEvidence8616 | None:
        """Require every callsite effect and trial to be consumed."""
        for callsite_key, callsite in self.callsites.items():
            if any(
                (*callsite_key, index) not in self.consumed_effects
                for index in range(len(callsite.memory_effects))
            ):
                return _refused_8616(
                    MemoryOutputTransactionFailure8616.ORPHAN_EFFECT,
                    self.raw_count,
                )
            if any(
                (*callsite_key, index) not in self.consumed_trials
                for index in range(len(callsite.live_outs))
            ):
                return _refused_8616(
                    MemoryOutputTransactionFailure8616.ORPHAN_TRIAL,
                    self.raw_count,
                )
            if any(
                (*callsite_key, index) not in self.consumed_pointer_effects
                for index in range(len(callsite.pointer_effects))
            ):
                return _refused_8616(
                    MemoryOutputTransactionFailure8616.ORPHAN_EFFECT,
                    self.raw_count,
                )
        return None


def validate_memory_output_transaction_8616(
    contract: FunctionStorageContract8616,
) -> MemoryOutputTransactionEvidence8616:
    """Prove that object views and callsite facts form one exact transaction."""
    raw_count = _raw_fact_count_8616(contract)
    callsites = {
        (callsite.caller_addr, callsite.callsite_addr): callsite
        for callsite in contract.callsites
    }
    if len(callsites) != len(contract.callsites):
        return _refused_8616(
            MemoryOutputTransactionFailure8616.CALLSITE_CONFLICT,
            raw_count,
        )

    owner_keys = tuple(item.storage.key for item in contract.memory_outputs)
    if len(set(owner_keys)) != len(owner_keys):
        return _refused_8616(
            MemoryOutputTransactionFailure8616.DUPLICATE_OWNER,
            raw_count,
        )

    scan = _TransactionScan8616(callsites, contract.function_addr, raw_count)
    for memory_object in contract.memory_outputs:
        for view in memory_object.views:
            refusal = scan.check_object_view(view)
            if refusal is not None:
                return refusal
        if not memory_object.complete:
            return _refused_8616(
                MemoryOutputTransactionFailure8616.OBJECT_INCOMPLETE,
                raw_count,
            )

    for pointer_object in contract.pointer_memory_outputs:
        refusal = scan.check_pointer_object(pointer_object)
        if refusal is not None:
            return refusal

    orphan_refusal = scan.check_orphans()
    if orphan_refusal is not None:
        return orphan_refusal

    return MemoryOutputTransactionEvidence8616(
        MemoryOutputTransactionVerdict8616.PROVEN,
        None,
        MemoryOutputTransactionStats8616(
            raw_count,
            raw_count,
            raw_count,
            raw_count,
        ),
    )


__all__ = [
    "MemoryOutputTransactionEvidence8616",
    "MemoryOutputTransactionFailure8616",
    "MemoryOutputTransactionStats8616",
    "MemoryOutputTransactionVerdict8616",
    "validate_memory_output_transaction_8616",
]
