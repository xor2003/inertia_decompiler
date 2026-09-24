"""Validate one exact identical-return guard collapse delta.

Layer: Tail validation.
Responsibility: consume only the condition and control-flow observations
removed by a closed typed Structuring identical-return result.

This compatibility boundary checks field ownership and cardinality in the
existing fingerprint delta. It does not parse condition text or infer return
semantics from fingerprints; Structuring must already have proved purity and
return-expression identity.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from enum import StrEnum

from .structuring.identical_return_guards import (
    IdenticalReturnGuardCollapseResult8616,
    IdenticalReturnGuardShape8616,
)
from .tail_validation_selector_returns import (
    parse_selector_return_fingerprint_8616,
)


class IdenticalReturnGuardValidationStatus8616(StrEnum):
    """Typed outcome for one attempted validation-delta consumption."""

    ACCEPTED = "accepted"
    REFUSED_NO_RESULT = "refused_no_result"
    REFUSED_UNCLOSED_EVIDENCE = "refused_unclosed_evidence"
    REFUSED_MALFORMED_DELTA = "refused_malformed_delta"
    REFUSED_UNEXPECTED_EFFECT = "refused_unexpected_effect"


@dataclass(frozen=True, slots=True)
class IdenticalReturnGuardValidationResult8616:
    """Validation outcome, consumed observations, and residual-delta state."""

    status: IdenticalReturnGuardValidationStatus8616
    consumed_condition_count: int = 0
    consumed_control_effect_count: int = 0
    consumed_selector_return_count: int = 0
    residual_changed: bool = False

    @property
    def accepted(self) -> bool:
        """Return whether this owner's exact typed observations were consumed."""
        return self.status is IdenticalReturnGuardValidationStatus8616.ACCEPTED


def _tokens_8616(field_delta: object, direction: str) -> tuple[object, ...] | None:
    """Read one established tail-validation delta channel."""
    if not isinstance(field_delta, Mapping):
        return None
    value = field_delta.get(direction, ())
    return tuple(value) if isinstance(value, (tuple, list, set, frozenset)) else None


def _evidence_is_closed_8616(result: IdenticalReturnGuardCollapseResult8616) -> bool:
    """Require one fully classified identical-return collapse."""
    stats = result.stats
    return bool(
        stats.complete
        and result.collapsed_guard_count == 1
        and stats.materialized_count == 1
        and len(result.materializations) == 1
        and result.materializations[0].shape
        in {
            IdenticalReturnGuardShape8616.ELSE_RETURN,
            IdenticalReturnGuardShape8616.FALLTHROUGH_RETURN,
        }
        and len(result.refusals) == stats.failure_count
    )


def _delta_channels_8616(
    delta: MutableMapping[str, object],
) -> dict[str, tuple[tuple[object, ...], tuple[object, ...]]] | IdenticalReturnGuardValidationResult8616:
    """Return per-field added/removed channels or a malformed-delta refusal."""
    channels: dict[str, tuple[tuple[object, ...], tuple[object, ...]]] = {}
    for field_name, field_delta in delta.items():
        added = _tokens_8616(field_delta, "added")
        removed = _tokens_8616(field_delta, "removed")
        if added is None or removed is None:
            return IdenticalReturnGuardValidationResult8616(
                IdenticalReturnGuardValidationStatus8616.REFUSED_MALFORMED_DELTA
            )
        if added or removed:
            channels[str(field_name)] = (added, removed)
    return channels


def _consume_removed_guard_effects_8616(
    shape: IdenticalReturnGuardShape8616,
    condition_removed: tuple[object, ...],
    control_removed: tuple[object, ...],
) -> tuple[tuple[object, ...], tuple[object, ...], int, int] | IdenticalReturnGuardValidationResult8616:
    """Match the one collapsed guard against removed condition/control effects."""
    matched_conditions = tuple(
        condition
        for condition in condition_removed
        if f"if:{condition}" in control_removed
    )
    if len(matched_conditions) != 1:
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )
    consumed_condition = matched_conditions[0]
    consumed_control = f"if:{consumed_condition}"
    remaining_conditions = tuple(
        condition for condition in condition_removed if condition != consumed_condition
    )
    remaining_control = tuple(
        effect for effect in control_removed if effect != consumed_control
    )
    consumed_control_count = 1
    if (
        shape is IdenticalReturnGuardShape8616.ELSE_RETURN
        and "if:else" in remaining_control
    ):
        remaining_control = tuple(effect for effect in remaining_control if effect != "if:else")
        consumed_control_count += 1

    matching_selectors = tuple(
        effect
        for effect in remaining_control
        if (
            isinstance(effect, str)
            and (selector := parse_selector_return_fingerprint_8616(effect))
            is not None
            and selector.arms_identical
            and consumed_condition in selector.condition_candidates
        )
    )
    consumed_selector_return_count = 0
    if len(matching_selectors) == 1:
        consumed_selector = matching_selectors[0]
        remaining_control = tuple(
            effect for effect in remaining_control if effect != consumed_selector
        )
        consumed_control_count += 1
        consumed_selector_return_count = 1
    return (
        remaining_conditions,
        remaining_control,
        consumed_control_count,
        consumed_selector_return_count,
    )


def _apply_residual_guard_delta_8616(
    validation: MutableMapping[str, object],
    delta: MutableMapping[str, object],
    condition_added: tuple[object, ...],
    remaining_conditions: tuple[object, ...],
    control_added: tuple[object, ...],
    remaining_control: tuple[object, ...],
) -> bool | IdenticalReturnGuardValidationResult8616:
    """Write the balanced residual delta or refuse an unbalanced one."""
    residual_changed = bool(
        condition_added
        or remaining_conditions
        or control_added
        or remaining_control
    )
    if residual_changed and not all(
        (condition_added, remaining_conditions, control_added, remaining_control)
    ):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )

    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(condition_delta, MutableMapping) or not isinstance(
        control_delta, MutableMapping
    ):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_MALFORMED_DELTA
        )
    condition_delta["removed"] = remaining_conditions
    control_delta["removed"] = remaining_control
    if not residual_changed:
        validation["changed"] = False
        validation["status"] = "stable"
        validation["summary_text"] = "no observable whole-tail changes"
        validation.pop("delta", None)
    return residual_changed


def consume_identical_return_guard_validation_delta_8616(
    result: IdenticalReturnGuardCollapseResult8616 | None,
    validation: MutableMapping[str, object],
) -> IdenticalReturnGuardValidationResult8616:
    """Consume one proved guard collapse and preserve a balanced residual delta."""
    if result is None:
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_NO_RESULT
        )
    if not _evidence_is_closed_8616(result):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNCLOSED_EVIDENCE
        )
    delta = validation.get("delta")
    if not isinstance(delta, MutableMapping):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_MALFORMED_DELTA
        )
    channels = _delta_channels_8616(delta)
    if isinstance(channels, IdenticalReturnGuardValidationResult8616):
        return channels
    if set(channels) - {"conditions", "control_flow_effects"}:
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )
    condition_added, condition_removed = channels.get("conditions", ((), ()))
    control_added, control_removed = channels.get("control_flow_effects", ((), ()))
    if any(
        not isinstance(item, str)
        for item in condition_added + condition_removed + control_added + control_removed
    ):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )
    if validation.get("semantic_failures", ()):
        return IdenticalReturnGuardValidationResult8616(
            IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
        )

    consumed = _consume_removed_guard_effects_8616(
        result.materializations[0].shape,
        condition_removed,
        control_removed,
    )
    if isinstance(consumed, IdenticalReturnGuardValidationResult8616):
        return consumed
    (
        remaining_conditions,
        remaining_control,
        consumed_control_count,
        consumed_selector_return_count,
    ) = consumed

    residual = _apply_residual_guard_delta_8616(
        validation,
        delta,
        condition_added,
        remaining_conditions,
        control_added,
        remaining_control,
    )
    if isinstance(residual, IdenticalReturnGuardValidationResult8616):
        return residual
    residual_changed = residual
    return IdenticalReturnGuardValidationResult8616(
        IdenticalReturnGuardValidationStatus8616.ACCEPTED,
        consumed_condition_count=1,
        consumed_control_effect_count=consumed_control_count,
        consumed_selector_return_count=consumed_selector_return_count,
        residual_changed=residual_changed,
    )
