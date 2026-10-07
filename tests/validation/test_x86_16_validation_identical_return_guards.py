from __future__ import annotations

from inertia.structuring.identical_return_guards import (
    IdenticalReturnGuardCollapseResult8616,
    IdenticalReturnGuardCollapseStats8616,
    IdenticalReturnGuardMaterialization8616,
    IdenticalReturnGuardShape8616,
)
from inertia.validation.tail_validation_selector_returns import (
    SelectorReturnFingerprint8616,
    encode_selector_return_fingerprint_8616,
)
from inertia.validation.validation_identical_return_guards import (
    IdenticalReturnGuardValidationStatus8616,
    consume_identical_return_guard_validation_delta_8616,
)


def _closed_result(
    shape: IdenticalReturnGuardShape8616 = IdenticalReturnGuardShape8616.ELSE_RETURN,
) -> IdenticalReturnGuardCollapseResult8616:
    return IdenticalReturnGuardCollapseResult8616(
        collapsed_guard_count=1,
        stats=IdenticalReturnGuardCollapseStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        ),
        materializations=(IdenticalReturnGuardMaterialization8616(0, shape),),
    )


def _validation_delta() -> dict[str, object]:
    fields = (
        "conditions",
        "control_flow_effects",
        "global_writes",
        "helper_calls",
        "register_writes",
        "returns",
        "segmented_writes",
        "stack_writes",
    )
    delta = {name: {"added": (), "removed": ()} for name in fields}
    delta["conditions"]["removed"] = ("condition-fingerprint",)
    delta["control_flow_effects"]["removed"] = (
        "if:condition-fingerprint",
        "if:else",
    )
    return {
        "changed": True,
        "status": "changed",
        "delta": delta,
        "semantic_failures": (),
    }


def test_identical_return_guard_validation_consumes_exact_delta() -> None:
    validation = _validation_delta()

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.accepted
    assert result.consumed_condition_count == 1
    assert result.consumed_control_effect_count == 2
    assert result.residual_changed is False
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation


def test_identical_return_guard_validation_consumes_matching_selector_return() -> None:
    validation = _validation_delta()
    selector = encode_selector_return_fingerprint_8616(
        SelectorReturnFingerprint8616(
            condition="inverse-condition-fingerprint",
            inverse_condition="condition-fingerprint",
            true_returns=("const:0",),
            false_returns=("const:0",),
        )
    )
    validation["delta"]["control_flow_effects"]["removed"] += (selector,)

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.accepted
    assert result.consumed_control_effect_count == 3
    assert result.consumed_selector_return_count == 1
    assert result.residual_changed is False
    assert validation["changed"] is False
    assert "delta" not in validation


def test_identical_return_guard_validation_refuses_unequal_selector_returns() -> None:
    validation = _validation_delta()
    selector = encode_selector_return_fingerprint_8616(
        SelectorReturnFingerprint8616(
            condition="condition-fingerprint",
            true_returns=("const:0",),
            false_returns=("const:1",),
        )
    )
    validation["delta"]["control_flow_effects"]["removed"] += (selector,)

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.status is (
        IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
    )
    assert validation["changed"] is True
    assert "delta" in validation


def test_identical_return_guard_validation_consumes_minimal_else_delta() -> None:
    validation = _validation_delta()
    validation["delta"]["control_flow_effects"]["removed"] = (
        "if:condition-fingerprint",
    )

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.accepted
    assert result.consumed_condition_count == 1
    assert result.consumed_control_effect_count == 1
    assert result.residual_changed is False
    assert validation["changed"] is False
    assert "delta" not in validation


def test_identical_return_guard_validation_refuses_write_delta() -> None:
    validation = _validation_delta()
    validation["delta"]["stack_writes"]["removed"] = ("stack-write",)

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.status is (
        IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
    )
    assert validation["changed"] is True
    assert "delta" in validation


def test_identical_return_guard_validation_refuses_unbounded_control_delta() -> None:
    validation = _validation_delta()
    validation["delta"]["control_flow_effects"]["removed"] = (
        "if:condition-fingerprint",
        "first-control-fingerprint",
        "second-control-fingerprint",
        "third-control-fingerprint",
    )

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.status is (
        IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
    )
    assert validation["changed"] is True
    assert "delta" in validation


def test_identical_return_guard_validation_consumes_fallthrough_shape() -> None:
    validation = _validation_delta()
    validation["delta"]["control_flow_effects"]["removed"] = (
        "if:condition-fingerprint",
    )

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(IdenticalReturnGuardShape8616.FALLTHROUGH_RETURN),
        validation,
    )

    assert result.accepted
    assert result.consumed_condition_count == 1
    assert result.consumed_control_effect_count == 1
    assert result.residual_changed is False
    assert validation["changed"] is False


def test_identical_return_guard_validation_preserves_balanced_condition_residual() -> None:
    validation = _validation_delta()
    delta = validation["delta"]
    delta["conditions"]["added"] = ("guard-a", "guard-b")
    delta["conditions"]["removed"] = (
        "condition-fingerprint",
        "decoded-a",
        "decoded-b",
    )
    delta["control_flow_effects"]["added"] = (
        "ifbreak:guard-a",
        "ifbreak:guard-b",
    )
    delta["control_flow_effects"]["removed"] = (
        "if:condition-fingerprint",
        "ifbreak:decoded-a",
        "ifbreak:decoded-b",
    )

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.accepted
    assert result.residual_changed is True
    assert validation["changed"] is True
    assert delta["conditions"]["removed"] == ("decoded-a", "decoded-b")
    assert delta["control_flow_effects"]["removed"] == (
        "ifbreak:decoded-a",
        "ifbreak:decoded-b",
    )


def test_identical_return_guard_validation_refuses_ambiguous_owned_condition() -> None:
    validation = _validation_delta()
    delta = validation["delta"]
    delta["conditions"]["added"] = ("guard-a",)
    delta["conditions"]["removed"] = ("condition-a", "condition-b")
    delta["control_flow_effects"]["added"] = ("ifbreak:guard-a",)
    delta["control_flow_effects"]["removed"] = (
        "if:condition-a",
        "if:condition-b",
    )

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.status is (
        IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
    )
    assert validation["changed"] is True
    assert delta["conditions"]["removed"] == ("condition-a", "condition-b")
