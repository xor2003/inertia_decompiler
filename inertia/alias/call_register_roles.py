"""Canonical Alias decision for CALL register preservation.

Layer: Alias.
Responsibility: own the consumer decision that turns semantics-evidenced
call register roles into a preservation verdict for one register view. Only
the may-clobber role can prove preservation; input, caller-dead and result
roles never masquerade as preservation, and unsupported views refuse instead
of truncating a wider register into a narrower domain.
Owns canonical register-domain and slice identities plus the consumer
decision. Do not perform semantic recovery, lowering, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.semantics.call_register_role_contracts import (
    CallRegisterRoleCoverage8616,
    CallRegisterRoleKind8616,
    CallRegisterRolesFact8616,
)

from .domains import (
    DomainKey,
    View,
    register_domain_for_name,
    register_view_for_name,
)

__all__ = (
    "CallRegisterPreservationDecision8616",
    "CallRegisterPreservationVerdict8616",
    "call_role_preserves_register_8616",
    "decide_call_register_preservation_8616",
)


class CallRegisterPreservationVerdict8616(StrEnum):
    """Typed outcome of the Alias call-preservation decision."""

    PRESERVED = "preserved"
    SPOILED = "spoiled"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class CallRegisterPreservationDecision8616:
    """One preservation verdict for a register view across an exact CALL.

    Decided verdicts partition the queried view into preserved and spoiled
    bits. A refused verdict retains the unresolved mask and leaves the
    positive masks empty; its underlying role fact retains any decided bits.
    Counters close on the single view decision, with no positive
    classification for a refused view.
    """

    register: str
    domain: DomainKey | None
    view: View | None
    verdict: CallRegisterPreservationVerdict8616
    preserved_bits: int
    spoiled_bits: int
    undecided_bits: int
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def preserves(self) -> bool:
        """Return whether the full view is proven unwritten by the call."""
        return self.verdict is CallRegisterPreservationVerdict8616.PRESERVED


def _refused_decision_8616(
    register: str,
    domain: DomainKey | None,
    view: View | None,
    *,
    undecided_bits: int,
) -> CallRegisterPreservationDecision8616:
    """Return one closed refusal for an unsupported or undecided view."""
    return CallRegisterPreservationDecision8616(
        register,
        domain,
        view,
        CallRegisterPreservationVerdict8616.UNKNOWN_REFUSE,
        0,
        0,
        undecided_bits,
        1,
        1,
        0,
        0,
        1,
    )


def decide_call_register_preservation_8616(
    fact: CallRegisterRolesFact8616,
    register: str,
) -> CallRegisterPreservationDecision8616:
    """Decide whether one exact CALL preserves every bit of ``register``.

    Preservation requires complete may-clobber evidence over the canonical
    domain view: any spoiled or undecided bit inside the view refuses the
    proof. Caller-dead, input and result roles are never consulted here.
    """
    normalized = register.lower() if isinstance(register, str) else ""
    view = register_view_for_name(normalized)
    domain = register_domain_for_name(normalized)
    if view is None or domain is None:
        return _refused_decision_8616(normalized, domain, view, undecided_bits=0)
    view_mask = ((1 << view.bit_width) - 1) << view.bit_offset
    evidence = fact.role(CallRegisterRoleKind8616.MAY_CLOBBER)
    if evidence.coverage is CallRegisterRoleCoverage8616.UNKNOWN_REFUSE:
        return _refused_decision_8616(
            normalized, domain, view, undecided_bits=view_mask,
        )
    entry = evidence.domain_bits(domain.name)
    if entry is None:
        return _refused_decision_8616(
            normalized, domain, view, undecided_bits=view_mask,
        )
    spoiled = view_mask & entry.role_bits
    undecided = view_mask & ~entry.known_bits
    if undecided:
        return _refused_decision_8616(
            normalized, domain, view, undecided_bits=undecided,
        )
    verdict = (
        CallRegisterPreservationVerdict8616.SPOILED
        if spoiled
        else CallRegisterPreservationVerdict8616.PRESERVED
    )
    return CallRegisterPreservationDecision8616(
        normalized,
        domain,
        view,
        verdict,
        view_mask & ~spoiled,
        spoiled,
        0,
        1,
        1,
        1,
        1,
        0,
    )


def call_role_preserves_register_8616(
    fact: CallRegisterRolesFact8616,
    register: str,
) -> bool:
    """Return whether the call's may-clobber evidence preserves ``register``."""
    return decide_call_register_preservation_8616(fact, register).preserves
