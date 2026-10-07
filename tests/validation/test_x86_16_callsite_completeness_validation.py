from __future__ import annotations

from types import SimpleNamespace

import inertia.structuring.decompiler_structuring_stage as stage

from inertia.validation.callsite_completeness import (
    CallsiteCompletenessDeltaReason8616,
    CallsiteCompletenessDeltaVerdict8616,
    classify_callsite_completeness_delta_8616,
)
from inertia.validation.tail_validation import X86_16TailValidationSummary


def _summary(*helper_calls: str) -> X86_16TailValidationSummary:
    """Exercise the immutable production summary at the validation boundary."""
    return X86_16TailValidationSummary(
        helper_calls=helper_calls,
        register_writes=(),
        stack_writes=(),
        global_writes=(),
        segmented_writes=(),
        returns=(),
        conditions=(),
        control_flow_effects=(),
    )


def _missing_callsite_delta(*removed: str) -> dict[str, object]:
    return {
        "changed": True,
        "status": "changed",
        "delta": {
            "helper_calls": {"added": (), "removed": removed},
            "conditions": {"added": (), "removed": ()},
        },
    }


def test_callsite_completeness_accepts_all_removed_deficits() -> None:
    validation = _missing_callsite_delta("missing-callsite:addr:0x11e6")

    result = classify_callsite_completeness_delta_8616(
        _summary("addr:0x11e6", "missing-callsite:addr:0x11e6"),
        _summary("addr:0x11e6"),
        validation,
    )

    assert result.verdict is CallsiteCompletenessDeltaVerdict8616.COMPLETE_IMPROVEMENT
    assert result.reason is CallsiteCompletenessDeltaReason8616.COMPLETE
    assert result.accepted is True
    assert result.as_dict()["materialized_count"] == 1


def test_callsite_completeness_refuses_remaining_deficit() -> None:
    validation = _missing_callsite_delta("missing-callsite:addr:0x11e6")

    result = classify_callsite_completeness_delta_8616(
        _summary("missing-callsite:addr:0x11e6", "missing-callsite:addr:0x11e8"),
        _summary("missing-callsite:addr:0x11e8"),
        validation,
    )

    assert result.verdict is CallsiteCompletenessDeltaVerdict8616.UNKNOWN_REFUSE
    assert result.reason is CallsiteCompletenessDeltaReason8616.REMAINING_DEFICIT
    assert result.accepted is False


def test_callsite_completeness_refuses_other_observable_delta() -> None:
    validation = _missing_callsite_delta("missing-callsite:addr:0x11e6")
    delta = validation["delta"]
    assert isinstance(delta, dict)
    delta["returns"] = {"added": ("const:1",), "removed": ()}

    result = classify_callsite_completeness_delta_8616(
        _summary("missing-callsite:addr:0x11e6"),
        _summary(),
        validation,
    )

    assert result.verdict is CallsiteCompletenessDeltaVerdict8616.UNKNOWN_REFUSE
    assert result.reason is CallsiteCompletenessDeltaReason8616.OTHER_OBSERVABLE_DELTA


def test_callsite_completeness_reports_removed_deficit_mismatch() -> None:
    validation = _missing_callsite_delta("missing-callsite:addr:0x11e6")

    result = classify_callsite_completeness_delta_8616(
        _summary("missing-callsite:addr:0x11e6", "missing-callsite:addr:0x11e8"),
        _summary(),
        validation,
    )

    assert result.verdict is CallsiteCompletenessDeltaVerdict8616.UNKNOWN_REFUSE
    assert result.reason is CallsiteCompletenessDeltaReason8616.REMOVED_DEFICIT_MISMATCH


def test_structuring_consumes_typed_callsite_completeness_improvement() -> None:
    validation = _missing_callsite_delta("missing-callsite:addr:0x11e6")
    codegen = SimpleNamespace()

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        SimpleNamespace(),
        codegen,
        validation,
        spec_name="final",
        before_summary=_summary("addr:0x11e6", "missing-callsite:addr:0x11e6"),
        after_summary=_summary("addr:0x11e6"),
    )

    assert accepted is True
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_callsite_completeness_delta_8616.accepted is True
