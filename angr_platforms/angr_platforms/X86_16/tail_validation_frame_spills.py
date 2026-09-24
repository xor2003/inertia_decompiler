"""Validate removal of exact callee-saved frame-spill fingerprints.

Layer: Tail Validation.
Responsibility: consume closed Types/Lowering frame-prune evidence and accept
only the corresponding removed ``SS:SP`` segmented-write locations.
Forbidden: semantic recovery, frame inference, or AST cleanup in validation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from .lowering.callee_saved_frame import (
    CalleeSavedFrameCarrierKind8616,
    CalleeSavedFrameInstructionRole8616,
    CalleeSavedFramePruneFact8616,
    CalleeSavedFramePruneRecord8616,
)

_SS_SP_SEGMENTED_WRITE_RE_8616 = re.compile(
    r"deref:Add\(Mul\(reg:ss,const:16\),reg:sp(?:,const:(?P<displacement>-?[0-9]+))?\)"
)


def _fingerprints_8616(value: object) -> tuple[object, ...]:
    """Normalize one owned validation fingerprint sequence."""
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    return ()


def _changed_delta_fields_8616(delta: Mapping[str, object]) -> frozenset[str]:
    """Return validation fields that contain an added or removed fingerprint."""
    return frozenset(
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _fingerprints_8616(field_delta.get("added"))
            or _fingerprints_8616(field_delta.get("removed"))
        )
    )


def _ss_sp_displacement_8616(token: object) -> int | None:
    """Decode one canonical Tail Validation ``SS:SP`` location fingerprint."""
    if not isinstance(token, str):
        return None
    match = _SS_SP_SEGMENTED_WRITE_RE_8616.fullmatch(token)
    if match is None:
        return None
    displacement = match.group("displacement")
    return int(displacement) if displacement is not None else 0


def _push_facts_proven_8616(facts: tuple[CalleeSavedFramePruneFact8616, ...]) -> bool:
    """Require one complete PUSH-fact census with typed store coordinates."""
    return bool(
        facts
        and all(
            fact.instruction_role is CalleeSavedFrameInstructionRole8616.PUSH for fact in facts
        )
        and all(fact.instruction_addr == fact.push_addr for fact in facts)
        and all(fact.stack_displacement is not None for fact in facts)
        and all(
            fact.access_width is not None and fact.access_width > 0 for fact in facts
        )
    )


def callee_saved_frame_prune_delta_8616(
    record: CalleeSavedFramePruneRecord8616 | None,
    validation: Mapping[str, object],
) -> bool:
    """Accept only removed segmented writes proven by a closed frame census."""
    if record is None or not record.closes_evidence:
        return False
    if _fingerprints_8616(validation.get("semantic_failures")):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping) or _changed_delta_fields_8616(delta) != {"segmented_writes"}:
        return False
    segmented_delta = delta.get("segmented_writes")
    if not isinstance(segmented_delta, Mapping) or _fingerprints_8616(segmented_delta.get("added")):
        return False
    removed = _fingerprints_8616(segmented_delta.get("removed"))
    facts = record.frame_stack_store_evidence
    if not removed or not _push_facts_proven_8616(facts):
        return False
    actual = tuple(_ss_sp_displacement_8616(token) for token in removed)
    if None in actual or len(actual) != len(set(actual)) or len(actual) != len(facts):
        return False
    exact_displacements = frozenset(
        fact.stack_displacement
        for fact in facts
        if fact.carrier_kind is CalleeSavedFrameCarrierKind8616.SEGMENTED_STACK_WRITE
    )
    normalized_store_count = sum(
        fact.carrier_kind is CalleeSavedFrameCarrierKind8616.STACK_SLOT_WRITE
        for fact in facts
    )
    actual_displacements = frozenset(actual)
    return bool(
        exact_displacements <= actual_displacements
        and len(actual_displacements - exact_displacements) == normalized_store_count
    )


__all__ = ["callee_saved_frame_prune_delta_8616"]
