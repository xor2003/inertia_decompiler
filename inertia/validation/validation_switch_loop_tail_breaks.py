"""Validate exact switch-to-loop-tail goto collapse.

Layer: Tail validation.
Responsibility: consume only control-flow deltas whose integer goto targets are
proved by the typed Structuring switch-loop tail result.

This validator composes with other evidence validators. It removes only the
proved ``goto:<address>`` observations from a validation delta and leaves every
unrelated condition, call, return, write, or control-flow change untouched.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from enum import StrEnum

from inertia.structuring.switch_loop_tail_breaks import (
    SwitchLoopTailBreakDecision8616,
    SwitchLoopTailBreakResult8616,
)


class SwitchLoopTailBreakValidationStatus8616(StrEnum):
    """Typed outcome for one attempted validation-delta consumption."""

    ACCEPTED = "accepted"
    REFUSED_NO_RESULT = "refused_no_result"
    REFUSED_UNCLOSED_EVIDENCE = "refused_unclosed_evidence"
    REFUSED_MALFORMED_DELTA = "refused_malformed_delta"
    REFUSED_MISSING_TARGET = "refused_missing_target"


@dataclass(frozen=True, slots=True)
class SwitchLoopTailBreakValidationResult8616:
    """Consumed goto fingerprints and remaining validation state."""

    status: SwitchLoopTailBreakValidationStatus8616
    consumed_gotos: tuple[str, ...] = ()
    residual_changed: bool = True

    @property
    def accepted(self) -> bool:
        """Return whether exact Structuring evidence consumed a delta."""
        return self.status is SwitchLoopTailBreakValidationStatus8616.ACCEPTED


def _boundary_tuple_8616(value: object) -> tuple[object, ...]:
    """Normalize one validation boundary without iterating text or mappings."""
    if isinstance(value, (tuple, list, set, frozenset)):
        return tuple(value)
    return ()


def _evidence_is_closed_8616(result: SwitchLoopTailBreakResult8616) -> bool:
    """Return whether every classified collapse has one durable materialization."""
    stats = result.stats
    materialized_decisions = sum(
        decision is SwitchLoopTailBreakDecision8616.MATERIALIZED
        for decision in result.decisions
    )
    targets = tuple(item.target for item in result.materializations)
    return (
        stats.classified_fact_count > 0
        and stats.classified_fact_count == stats.materialized_count
        and stats.materialized_count == result.removed_label_count
        and stats.materialized_count == len(result.materializations)
        and stats.materialized_count == materialized_decisions
        and result.replaced_goto_count
        == sum(item.replaced_goto_count for item in result.materializations)
        and all(item.replaced_goto_count > 0 for item in result.materializations)
        and len(set(targets)) == len(targets)
    )


def _delta_still_changed_8616(delta: Mapping[str, object]) -> bool:
    """Return whether any observable field retains an added or removed value."""
    for field_delta in delta.values():
        if not isinstance(field_delta, Mapping):
            continue
        if _boundary_tuple_8616(field_delta.get("added", ())):
            return True
        if _boundary_tuple_8616(field_delta.get("removed", ())):
            return True
    return False


def consume_switch_loop_tail_break_validation_delta_8616(
    result: SwitchLoopTailBreakResult8616 | None,
    validation: MutableMapping[str, object],
) -> SwitchLoopTailBreakValidationResult8616:
    """Consume only goto removals proved by a closed Structuring result."""
    if result is None:
        return SwitchLoopTailBreakValidationResult8616(
            SwitchLoopTailBreakValidationStatus8616.REFUSED_NO_RESULT
        )
    if not _evidence_is_closed_8616(result):
        return SwitchLoopTailBreakValidationResult8616(
            SwitchLoopTailBreakValidationStatus8616.REFUSED_UNCLOSED_EVIDENCE
        )
    delta = validation.get("delta")
    precision = validation.get("precision_improvements")
    if not isinstance(delta, MutableMapping) or not isinstance(precision, MutableMapping):
        return SwitchLoopTailBreakValidationResult8616(
            SwitchLoopTailBreakValidationStatus8616.REFUSED_MALFORMED_DELTA
        )
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, MutableMapping):
        return SwitchLoopTailBreakValidationResult8616(
            SwitchLoopTailBreakValidationStatus8616.REFUSED_MALFORMED_DELTA
        )
    removed = _boundary_tuple_8616(control_delta.get("removed", ()))
    expected = frozenset(f"goto:{item.target}" for item in result.materializations)
    removed_strings = frozenset(item for item in removed if isinstance(item, str))
    if not expected or not expected <= removed_strings:
        return SwitchLoopTailBreakValidationResult8616(
            SwitchLoopTailBreakValidationStatus8616.REFUSED_MISSING_TARGET
        )

    consumed = tuple(item for item in removed if isinstance(item, str) and item in expected)
    control_delta["removed"] = tuple(item for item in removed if item not in expected)
    precision["switch_loop_tail_breaks"] = {
        "removed": consumed,
        "targets": tuple(item.target for item in result.materializations),
        "replaced_goto_count": result.replaced_goto_count,
    }
    residual_changed = _delta_still_changed_8616(delta)
    validation["changed"] = residual_changed
    validation["status"] = "changed" if residual_changed else "stable"
    return SwitchLoopTailBreakValidationResult8616(
        SwitchLoopTailBreakValidationStatus8616.ACCEPTED,
        consumed_gotos=consumed,
        residual_changed=residual_changed,
    )
