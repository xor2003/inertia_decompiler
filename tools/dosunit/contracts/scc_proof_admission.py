"""Layer: dosunit proof admission.

Responsibility: conservatively aggregate SCC member verdicts without promoting
conditional, absent or unrecognized evidence to unconditional proof.
"""

from __future__ import annotations

from collections.abc import Iterable

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus


def admit_scc_statuses(statuses: Iterable[ProofStatus | None]) -> ProofStatus:
    """Require every nonempty component member to be unconditionally proved.

    A counterexample dominates missing evidence. Every other incomplete status
    refuses, including CONDITIONAL; matching members cannot discharge premises.
    """
    members = tuple(statuses)
    if ProofStatus.COUNTEREXAMPLE in members:
        return ProofStatus.COUNTEREXAMPLE
    if members and all(status is ProofStatus.PROVED for status in members):
        return ProofStatus.PROVED
    return ProofStatus.UNKNOWN


def scc_status_counters(statuses: Iterable[ProofStatus | None]) -> FactCounters:
    """Account for every materialized SCC verdict, including failed admissions."""
    members = tuple(statuses)
    count = len(members)
    return FactCounters(
        raw_fact_count=count,
        normalized_fact_count=count,
        classified_fact_count=count,
        materialized_count=count,
        failure_count=sum(status is not ProofStatus.PROVED for status in members),
    )
