"""Join exact interprocedural storage slots across a complete caller census.

Layer: Types/Lowering.
Responsibility: normalize proof-bearing input and scalar-return trials into
deterministic function-level storage slots whose shapes agree at every relevant
callsite. Memory live-outs remain callsite views and are joined separately under
Alias owners. This module does not collect trials, infer storage, mutate
codegen, or synthesize missing uses.
Consumes alias, widening, and typed facts. Storage-trial facts remain the
authoritative proof payload.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace

from .interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    StorageSlotContract8616,
    StorageTrial8616,
    StorageTrialFailureKind8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
)

__all__ = ["join_storage_slot_contracts_8616", "ordered_storage_trials_8616"]

_SlotJoinResult8616 = tuple[
    tuple[StorageSlotContract8616, ...] | None,
    StorageTrialFailureKind8616 | None,
]
_StoragePiecesKey8616 = tuple[tuple[object, ...], ...]


def _joined_signedness_8616(
    values: set[StorageTrialSignedness8616],
) -> StorageTrialSignedness8616 | None:
    """Join sign-insensitive observations with one informative class."""
    if not values or StorageTrialSignedness8616.UNKNOWN in values:
        return None
    if StorageTrialSignedness8616.NOT_APPLICABLE in values:
        return (
            StorageTrialSignedness8616.NOT_APPLICABLE
            if values == {StorageTrialSignedness8616.NOT_APPLICABLE}
            else None
        )
    informative = values - {StorageTrialSignedness8616.SIGN_INSENSITIVE}
    if len(informative) > 1:
        return None
    return (
        next(iter(informative))
        if informative
        else StorageTrialSignedness8616.SIGN_INSENSITIVE
    )


def ordered_storage_trials_8616(
    callsite: CallsiteStorageTrials8616,
    role: StorageTrialRole8616,
) -> tuple[StorageTrial8616, ...]:
    """Return one role's trials in deterministic logical-piece order."""
    trials = callsite.arguments
    if role is StorageTrialRole8616.LIVE_OUT:
        trials = callsite.live_outs
    elif role is StorageTrialRole8616.RETURN:
        trials = callsite.returns
    return tuple(sorted(trials, key=lambda item: (item.logical_index, item.piece_index)))


def _trial_groups_8616(
    trials: tuple[StorageTrial8616, ...],
) -> tuple[tuple[StorageTrial8616, ...], ...] | None:
    """Group contiguous logical slots and reject missing or duplicate pieces."""
    if not trials:
        return ()
    grouped: dict[int, list[StorageTrial8616]] = {}
    for trial in trials:
        grouped.setdefault(trial.logical_index, []).append(trial)
    if tuple(sorted(grouped)) != tuple(range(len(grouped))):
        return None
    result: list[tuple[StorageTrial8616, ...]] = []
    for logical_index in sorted(grouped):
        pieces = tuple(sorted(grouped[logical_index], key=lambda item: item.piece_index))
        if (
            not pieces
            or any(item.piece_count != len(pieces) for item in pieces)
            or tuple(item.piece_index for item in pieces) != tuple(range(len(pieces)))
        ):
            return None
        result.append(pieces)
    return tuple(result)


def _slot_from_pieces_8616(
    role: StorageTrialRole8616,
    pieces: tuple[StorageTrial8616, ...],
) -> tuple[StorageSlotContract8616 | None, StorageTrialFailureKind8616 | None]:
    """Build one slot only when all physical pieces agree on typed meaning."""
    if role is not StorageTrialRole8616.INPUT and len(pieces) > 1:
        provenances = {item.provenance for item in pieces}
        if len(provenances) != 1 or None in provenances:
            return None, StorageTrialFailureKind8616.SPLIT_PROVENANCE_CONFLICT
    signedness = _joined_signedness_8616({item.signedness for item in pieces})
    if signedness is None:
        return None, StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT
    value_classes = {item.value_class for item in pieces}
    if len(value_classes) != 1:
        return None, StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT
    return (
        StorageSlotContract8616(
            role=role,
            logical_index=pieces[0].logical_index,
            pieces=tuple(item.storage for item in pieces),
            signedness=signedness,
            value_class=pieces[0].value_class,
        ),
        None,
    )


def _site_slots_8616(
    callsite: CallsiteStorageTrials8616,
    role: StorageTrialRole8616,
) -> _SlotJoinResult8616:
    """Normalize one callsite's complete trial groups into exact slots."""
    trials = ordered_storage_trials_8616(callsite, role)
    if any(trial.role is not role for trial in trials):
        return None, StorageTrialFailureKind8616.INCOMPLETE_TRIAL
    groups = _trial_groups_8616(trials)
    if groups is None:
        return None, StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT
    slots: list[StorageSlotContract8616] = []
    for pieces in groups:
        slot, failure = _slot_from_pieces_8616(role, pieces)
        if slot is None:
            return None, failure
        slots.append(slot)
    return tuple(slots), None


def _pieces_key_8616(slot: StorageSlotContract8616) -> _StoragePiecesKey8616:
    """Return one exact physical-storage key independent of local slot order."""
    return tuple(piece.key for piece in slot.pieces)


def _join_one_site_8616(
    joined: list[StorageSlotContract8616],
    current: tuple[StorageSlotContract8616, ...],
) -> StorageTrialFailureKind8616 | None:
    """Merge one callsite's slots into the joined shape or return the conflict."""
    if len(current) != len(joined):
        return StorageTrialFailureKind8616.ARGUMENT_ORDER_CONFLICT
    for index, (left, right) in enumerate(zip(joined, current, strict=True)):
        if _pieces_key_8616(left) != _pieces_key_8616(right):
            return StorageTrialFailureKind8616.STORAGE_CONFLICT
        signedness = _joined_signedness_8616(
            {left.signedness, right.signedness}
        )
        if signedness is None:
            return StorageTrialFailureKind8616.SIGNEDNESS_CONFLICT
        if left.value_class is not right.value_class:
            return StorageTrialFailureKind8616.VALUE_CLASS_CONFLICT
        joined[index] = replace(left, signedness=signedness)
    return None


def _uniform_slot_contracts_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
    role: StorageTrialRole8616,
) -> _SlotJoinResult8616:
    """Require one identical input or scalar-return shape across callsites."""
    relevant = callsites
    if role is StorageTrialRole8616.RETURN:
        relevant = tuple(
            callsite
            for callsite in callsites
            if ordered_storage_trials_8616(callsite, role)
        )
    if not relevant:
        return (), None
    site_contracts: list[tuple[StorageSlotContract8616, ...]] = []
    for callsite in relevant:
        slots, failure = _site_slots_8616(callsite, role)
        if slots is None:
            return None, failure
        site_contracts.append(slots)
    joined = list(site_contracts[0])
    for current in site_contracts[1:]:
        failure = _join_one_site_8616(joined, current)
        if failure is not None:
            return None, failure
    return tuple(joined), None


def join_storage_slot_contracts_8616(
    callsites: tuple[CallsiteStorageTrials8616, ...],
    role: StorageTrialRole8616,
) -> _SlotJoinResult8616:
    """Join one input/return role's exact slots over a complete census."""
    if role is StorageTrialRole8616.LIVE_OUT:
        return None, StorageTrialFailureKind8616.INCOMPLETE_TRIAL
    return _uniform_slot_contracts_8616(callsites, role)
