"""Regress liveness gating for consumed call-argument setup definitions."""

from __future__ import annotations

from inertia.lowering.call_argument_carrier_liveness import (
    CallArgumentSetupLivenessVerdict8616,
    call_argument_setup_is_proven_dead_8616,
    classify_call_argument_setup_liveness_8616,
)


def test_setup_definition_live_later_is_not_deletable() -> None:
    """A later structured consumer must keep the setup definition alive."""
    identity = ("reg", 0, 2, "v19")

    evidence = classify_call_argument_setup_liveness_8616(
        identity,
        frozenset({identity, ("reg", 2, 2, "v20")}),
    )

    assert evidence.closes_evidence is True
    assert evidence.verdict is CallArgumentSetupLivenessVerdict8616.LIVE_LATER


def test_setup_definition_without_later_consumer_is_proven_dead() -> None:
    """An exact identity absent from the suffix may be consumed."""
    evidence = classify_call_argument_setup_liveness_8616(
        ("stack", -8, 2, "local_8"),
        frozenset({("stack", -6, 2, "local_6")}),
    )

    assert evidence.closes_evidence is True
    assert evidence.verdict is CallArgumentSetupLivenessVerdict8616.PROVEN_DEAD
    assert call_argument_setup_is_proven_dead_8616(
        ("stack", -8, 2, "local_8"),
        frozenset({("stack", -6, 2, "local_6")}),
    ) is True


def test_setup_definition_without_identity_refuses_deletion() -> None:
    """Missing identity evidence must preserve the candidate assignment."""
    evidence = classify_call_argument_setup_liveness_8616(None, frozenset())

    assert evidence.closes_evidence is False
    assert evidence.verdict is CallArgumentSetupLivenessVerdict8616.UNKNOWN_REFUSE
    assert call_argument_setup_is_proven_dead_8616(None, frozenset()) is False
