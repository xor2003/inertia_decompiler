"""Join caller memory views into Alias-owned function output objects.

Layer: Types/Lowering.
Responsibility: validate each proof-bearing caller memory effect against its
exact LIVE_OUT trial, then group those views under one canonical Alias owner.
Function return slots, CFG traversal, Alias discovery, C types, and rendering
remain outside this module. A memory object is not a scalar function return;
its callsite views stay explicit in the accepted function contract.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..alias.storage_fact_join import (
    SegmentedAccessRelation8616,
    segmented_access_relation_8616,
)
from ..alias.terminal_memory_outputs import TerminalMemoryAliasFact8616
from ..semantics.terminal_memory_output_contracts import (
    TerminalMemoryOutputDisposition8616,
)
from .interprocedural_memory_output_object_contracts import (
    MemoryOutputObjectContract8616,
    MemoryOutputObjectFailure8616,
    MemoryOutputObjectJoinEvidence8616,
    MemoryOutputObjectJoinVerdict8616,
    MemoryOutputObjectStats8616,
    MemoryOutputViewBinding8616,
)
from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrial8616,
)
from .interprocedural_storage_live_out_contracts import (
    MemoryLiveOutUseDisposition8616,
    MemoryLiveOutUseFact8616,
)
from .pointer_parameter_memory_outputs import (
    join_pointer_parameter_memory_outputs_8616,
)


def _refused_8616(
    failure: MemoryOutputObjectFailure8616,
    raw_count: int,
    normalized_count: int,
) -> MemoryOutputObjectJoinEvidence8616:
    """Build one atomic refusal without publishing partial objects."""
    conflict = failure in {
        MemoryOutputObjectFailure8616.DUPLICATE_EFFECT,
        MemoryOutputObjectFailure8616.TRIAL_CONFLICT,
        MemoryOutputObjectFailure8616.SIGNEDNESS_CONFLICT,
        MemoryOutputObjectFailure8616.VALUE_CLASS_CONFLICT,
        MemoryOutputObjectFailure8616.OWNER_CONFLICT,
        MemoryOutputObjectFailure8616.OWNER_OVERLAP,
    }
    return MemoryOutputObjectJoinEvidence8616(
        (
            MemoryOutputObjectJoinVerdict8616.CONFLICT
            if conflict
            else MemoryOutputObjectJoinVerdict8616.UNKNOWN_REFUSE
        ),
        (),
        failure,
        MemoryOutputObjectStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
    )


def _owner_storage_8616(alias_output: TerminalMemoryAliasFact8616) -> StorageIdentity8616:
    """Project one Alias owner to the function-contract storage identity."""
    address = alias_output.terminal_output.address
    return StorageIdentity8616(StorageIdentityKind8616.MEMORY, address.size, address)


def _storage_order_8616(storage: StorageIdentity8616) -> tuple[str, int, int]:
    """Return a primitive deterministic key for exact segmented memory."""
    address = storage.address
    if address is None:
        return ("", -1, storage.width)
    return (address.space.value, address.offset, address.size)


def _view_order_8616(view: MemoryOutputViewBinding8616) -> tuple[object, ...]:
    """Return deterministic callsite and projected-storage order."""
    return (
        view.callsite_addr,
        view.caller_addr,
        *_storage_order_8616(view.effect.storage),
    )


_GroupedOwnerViews8616 = dict[
    tuple[str, int, int],
    tuple[TerminalMemoryAliasFact8616, StorageIdentity8616, list[MemoryOutputViewBinding8616]],
]


def _effect_trial_8616(
    effect: MemoryLiveOutUseFact8616,
    candidates: list[StorageTrial8616],
    raw_count: int,
    normalized_count: int,
) -> StorageTrial8616 | MemoryOutputObjectJoinEvidence8616 | None:
    """Bind at most one matching live-out trial to one memory effect."""
    needs_trial = bool(
        effect.disposition is MemoryLiveOutUseDisposition8616.USED
        and effect.terminal_output.disposition
        is TerminalMemoryOutputDisposition8616.MUST_WRITE
    )
    if needs_trial and not candidates:
        return _refused_8616(
            MemoryOutputObjectFailure8616.MISSING_TRIAL,
            raw_count,
            normalized_count,
        )
    if len(candidates) > 1:
        return _refused_8616(
            MemoryOutputObjectFailure8616.TRIAL_CONFLICT,
            raw_count,
            normalized_count,
        )
    if candidates and not needs_trial:
        return _refused_8616(
            MemoryOutputObjectFailure8616.EXTRA_TRIAL,
            raw_count,
            normalized_count,
        )
    return candidates[0] if candidates else None


def _record_owner_view_8616(
    callsite: CallsiteStorageTrials8616,
    effect: MemoryLiveOutUseFact8616,
    trial: StorageTrial8616 | None,
    grouped: _GroupedOwnerViews8616,
    raw_count: int,
    normalized_count: int,
) -> MemoryOutputObjectJoinEvidence8616 | None:
    """Attach one complete view to its canonical Alias owner group."""
    view = MemoryOutputViewBinding8616(
        callsite.caller_addr,
        callsite.callee_addr,
        callsite.callsite_addr,
        effect,
        trial,
    )
    if not view.complete:
        return _refused_8616(
            MemoryOutputObjectFailure8616.TRIAL_CONFLICT,
            raw_count,
            normalized_count,
        )
    owner = effect.alias_output
    owner_storage = _owner_storage_8616(owner)
    owner_key = _storage_order_8616(owner_storage)
    previous = grouped.get(owner_key)
    if previous is None:
        grouped[owner_key] = (owner, owner_storage, [view])
    elif previous[0] != owner or previous[1] != owner_storage:
        return _refused_8616(
            MemoryOutputObjectFailure8616.OWNER_CONFLICT,
            raw_count,
            normalized_count,
        )
    else:
        previous[2].append(view)
    return None


def _group_callsite_effects_8616(
    callsite: CallsiteStorageTrials8616,
    grouped: _GroupedOwnerViews8616,
    raw_count: int,
    normalized_count: int,
) -> int | MemoryOutputObjectJoinEvidence8616:
    """Fold one callsite's effects under their canonical Alias owners."""
    trials_by_storage: dict[tuple[object, ...], list[StorageTrial8616]] = {}
    for live_out_trial in callsite.live_outs:
        trials_by_storage.setdefault(live_out_trial.storage.key, []).append(live_out_trial)
    seen_effects: set[tuple[object, ...]] = set()
    consumed_trials: set[int] = set()
    effects = sorted(callsite.memory_effects, key=lambda item: _storage_order_8616(item.storage))
    for effect in effects:
        if not effect.complete:
            return _refused_8616(
                MemoryOutputObjectFailure8616.INCOMPLETE_EFFECT,
                raw_count,
                normalized_count,
            )
        normalized_count += 1
        if effect.storage.key in seen_effects:
            return _refused_8616(
                MemoryOutputObjectFailure8616.DUPLICATE_EFFECT,
                raw_count,
                normalized_count,
            )
        seen_effects.add(effect.storage.key)
        candidates = trials_by_storage.get(effect.storage.key, [])
        trial_gate = _effect_trial_8616(effect, candidates, raw_count, normalized_count)
        if isinstance(trial_gate, MemoryOutputObjectJoinEvidence8616):
            return trial_gate
        trial = trial_gate
        if trial is not None:
            consumed_trials.add(id(trial))
        owner_refusal = _record_owner_view_8616(
            callsite, effect, trial, grouped, raw_count, normalized_count
        )
        if owner_refusal is not None:
            return owner_refusal
    if any(id(item) not in consumed_trials for item in callsite.live_outs):
        return _refused_8616(
            MemoryOutputObjectFailure8616.EXTRA_TRIAL,
            raw_count,
            normalized_count,
        )
    return normalized_count


def _owner_trial_consistency_8616(
    grouped: _GroupedOwnerViews8616,
    raw_count: int,
    normalized_count: int,
) -> MemoryOutputObjectJoinEvidence8616 | None:
    """Require uniform signedness and value class per owner trial group."""
    for _owner, _storage, views in grouped.values():
        by_storage: dict[tuple[object, ...], list[StorageTrial8616]] = {}
        for view in views:
            if view.trial is not None:
                by_storage.setdefault(view.trial.storage.key, []).append(view.trial)
        for trials in by_storage.values():
            if len({trial.signedness for trial in trials}) != 1:
                return _refused_8616(
                    MemoryOutputObjectFailure8616.SIGNEDNESS_CONFLICT,
                    raw_count,
                    normalized_count,
                )
            if len({trial.value_class for trial in trials}) != 1:
                return _refused_8616(
                    MemoryOutputObjectFailure8616.VALUE_CLASS_CONFLICT,
                    raw_count,
                    normalized_count,
                )
    return None


def _owner_disjointness_8616(
    owners: tuple[TerminalMemoryAliasFact8616, ...],
    raw_count: int,
    normalized_count: int,
) -> MemoryOutputObjectJoinEvidence8616 | None:
    """Require every pair of Alias owners to be disjoint or exact."""
    for index, left in enumerate(owners):
        for right in owners[index + 1 :]:
            relation = segmented_access_relation_8616(
                left.terminal_output.address,
                right.terminal_output.address,
            )
            if relation not in {
                SegmentedAccessRelation8616.DISJOINT,
                SegmentedAccessRelation8616.EXACT,
            }:
                return _refused_8616(
                    MemoryOutputObjectFailure8616.OWNER_OVERLAP,
                    raw_count,
                    normalized_count,
                )
    return None


def join_memory_output_object_contracts_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
) -> MemoryOutputObjectJoinEvidence8616:
    """Join complete caller memory effects under canonical Alias owners."""
    pointer_join = join_pointer_parameter_memory_outputs_8616(callsites)
    direct_count = sum(len(callsite.memory_effects) for callsite in callsites)
    raw_count = direct_count + pointer_join.stats.raw_fact_count
    normalized_count = pointer_join.stats.normalized_fact_count
    if not pointer_join.complete:
        return _refused_8616(
            MemoryOutputObjectFailure8616.POINTER_OUTPUT_REFUSED,
            raw_count,
            normalized_count,
        )
    grouped: _GroupedOwnerViews8616 = {}
    for callsite in sorted(callsites, key=lambda item: (item.callsite_addr, item.caller_addr)):
        grouped_result = _group_callsite_effects_8616(
            callsite, grouped, raw_count, normalized_count
        )
        if isinstance(grouped_result, MemoryOutputObjectJoinEvidence8616):
            return grouped_result
        normalized_count = grouped_result

    owners = tuple(item[0] for _key, item in sorted(grouped.items()))
    consistency = _owner_trial_consistency_8616(grouped, raw_count, normalized_count)
    if consistency is not None:
        return consistency
    overlap = _owner_disjointness_8616(owners, raw_count, normalized_count)
    if overlap is not None:
        return overlap

    objects = tuple(
        MemoryOutputObjectContract8616(owner, storage, tuple(sorted(views, key=_view_order_8616)))
        for _key, (owner, storage, views) in sorted(grouped.items())
    )
    return MemoryOutputObjectJoinEvidence8616(
        MemoryOutputObjectJoinVerdict8616.PROVEN,
        objects,
        None,
        MemoryOutputObjectStats8616(
            raw_count,
            raw_count,
            raw_count,
            raw_count,
        ),
        pointer_join.objects,
    )


__all__ = [
    "MemoryOutputObjectContract8616",
    "MemoryOutputObjectFailure8616",
    "MemoryOutputObjectJoinEvidence8616",
    "MemoryOutputObjectJoinVerdict8616",
    "MemoryOutputObjectStats8616",
    "MemoryOutputViewBinding8616",
    "join_memory_output_object_contracts_8616",
]
