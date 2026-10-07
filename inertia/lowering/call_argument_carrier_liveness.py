"""Classify virtual carrier definitions retained by materialized call arguments.

Layer: Types/Lowering.
Responsibility: compare exact structured virtual identities on consumed-PUSH
assignments with the arguments of the owning materialized call.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This contract prevents PUSH cleanup from deleting a carrier definition while
the structured call still reads that carrier. It does not infer argument
values, repair calls, or decide whether any unrelated stack effect is dead.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.semantics.expression_analysis import describe_virtual_value_identity_8616

__all__ = (
    "CallArgumentCarrierLivenessEvidence8616",
    "CallArgumentCarrierLivenessVerdict8616",
    "CallArgumentMaterializationEvidence8616",
    "CallArgumentMaterializationVerdict8616",
    "CallArgumentSetupLivenessEvidence8616",
    "CallArgumentSetupLivenessVerdict8616",
    "call_argument_requires_typed_rematerialization_8616",
    "call_argument_setup_is_proven_dead_8616",
    "classify_call_argument_carrier_liveness_8616",
    "classify_call_argument_materialization_8616",
    "classify_call_argument_setup_liveness_8616",
)


class CallArgumentCarrierLivenessVerdict8616(StrEnum):
    """Typed ownership verdict for one virtual assignment lvalue."""

    LIVE_ARGUMENT_DEFINITION = "live_argument_definition"
    NOT_ARGUMENT_DEFINITION = "not_argument_definition"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallArgumentMaterializationVerdict8616(StrEnum):
    """Typed status of one structured call-argument expression."""

    SELF_CONTAINED = "self_contained"
    UNRESOLVED_VIRTUAL_CARRIER = "unresolved_virtual_carrier"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallArgumentSetupLivenessVerdict8616(StrEnum):
    """Typed deletion verdict for one consumed call-setup definition."""

    PROVEN_DEAD = "proven_dead"
    LIVE_LATER = "live_later"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class CallArgumentCarrierLivenessEvidence8616:
    """Closed evidence loop for one virtual carrier liveness decision."""

    verdict: CallArgumentCarrierLivenessVerdict8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closes_evidence(self) -> bool:
        """Return whether the input produced one applicable typed verdict."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class CallArgumentMaterializationEvidence8616:
    """Closed evidence loop for one existing call-argument expression."""

    verdict: CallArgumentMaterializationVerdict8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closes_evidence(self) -> bool:
        """Return whether the argument produced one applicable typed verdict."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class CallArgumentSetupLivenessEvidence8616:
    """Closed evidence loop for one consumed setup-definition decision."""

    verdict: CallArgumentSetupLivenessVerdict8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closes_evidence(self) -> bool:
        """Return whether the identity facts produced one typed verdict."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


def classify_call_argument_carrier_liveness_8616(
    assignment_lhs: object,
    materialized_arguments: tuple[object, ...],
) -> CallArgumentCarrierLivenessEvidence8616:
    """Classify whether an exact virtual lvalue remains live in call arguments."""
    lhs_identity = describe_virtual_value_identity_8616(assignment_lhs)
    if lhs_identity is None or not materialized_arguments:
        return CallArgumentCarrierLivenessEvidence8616(
            verdict=CallArgumentCarrierLivenessVerdict8616.UNKNOWN_REFUSE,
            raw_fact_count=1,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )

    argument_identities = frozenset(
        identity
        for argument in materialized_arguments
        for node in _iter_c_nodes_deep_8616(argument)
        if (identity := describe_virtual_value_identity_8616(node)) is not None
    )
    verdict = (
        CallArgumentCarrierLivenessVerdict8616.LIVE_ARGUMENT_DEFINITION
        if lhs_identity in argument_identities
        else CallArgumentCarrierLivenessVerdict8616.NOT_ARGUMENT_DEFINITION
    )
    return CallArgumentCarrierLivenessEvidence8616(
        verdict=verdict,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def classify_call_argument_materialization_8616(
    argument: object,
) -> CallArgumentMaterializationEvidence8616:
    """Classify whether an existing argument still contains a virtual carrier."""
    nodes = tuple(_iter_c_nodes_deep_8616(argument))
    if not nodes:
        return CallArgumentMaterializationEvidence8616(
            verdict=CallArgumentMaterializationVerdict8616.UNKNOWN_REFUSE,
            raw_fact_count=1,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )
    has_virtual_carrier = any(
        describe_virtual_value_identity_8616(node) is not None for node in nodes
    )
    return CallArgumentMaterializationEvidence8616(
        verdict=(
            CallArgumentMaterializationVerdict8616.UNRESOLVED_VIRTUAL_CARRIER
            if has_virtual_carrier
            else CallArgumentMaterializationVerdict8616.SELF_CONTAINED
        ),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def classify_call_argument_setup_liveness_8616(
    assignment_identity: tuple[object, ...] | None,
    later_identities: frozenset[tuple[object, ...]],
) -> CallArgumentSetupLivenessEvidence8616:
    """Classify whether a consumed setup definition is referenced later."""
    if assignment_identity is None:
        return CallArgumentSetupLivenessEvidence8616(
            verdict=CallArgumentSetupLivenessVerdict8616.UNKNOWN_REFUSE,
            raw_fact_count=1,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )
    return CallArgumentSetupLivenessEvidence8616(
        verdict=(
            CallArgumentSetupLivenessVerdict8616.LIVE_LATER
            if assignment_identity in later_identities
            else CallArgumentSetupLivenessVerdict8616.PROVEN_DEAD
        ),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def call_argument_setup_is_proven_dead_8616(
    assignment_identity: tuple[object, ...] | None,
    later_identities: frozenset[tuple[object, ...]],
) -> bool:
    """Return whether closed Lowering evidence permits setup deletion."""
    evidence = classify_call_argument_setup_liveness_8616(
        assignment_identity,
        later_identities,
    )
    return bool(
        evidence.closes_evidence
        and evidence.verdict is CallArgumentSetupLivenessVerdict8616.PROVEN_DEAD
    )


def call_argument_requires_typed_rematerialization_8616(argument: object) -> bool:
    """Return whether closed Lowering evidence rejects an existing argument."""
    evidence = classify_call_argument_materialization_8616(argument)
    return bool(
        evidence.closes_evidence
        and evidence.verdict
        is CallArgumentMaterializationVerdict8616.UNRESOLVED_VIRTUAL_CARRIER
    )
