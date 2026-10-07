"""Encode retained program callsite summaries for clean workers.

Layer: Traits/summaries/confidence.
Responsibility: losslessly serialize and validate already-derived caller and
callsite coordinates plus their typed summary. No summaries are inferred here.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .callsite_summary_codec import (
    callsite_summary_from_record_8616,
    callsite_summary_record_8616,
)
from .callsite_summary_program import (
    ProgramCallsiteSummaryEvidence8616,
    ProgramCallsiteSummaryFact8616,
)

__all__ = [
    "program_callsite_summary_evidence_from_record_8616",
    "program_callsite_summary_evidence_record_8616",
]


def program_callsite_summary_evidence_record_8616(
    evidence: ProgramCallsiteSummaryEvidence8616,
) -> dict[str, object]:
    """Encode one validated artifact deterministically."""
    evidence.validate()
    return {
        "facts": [
            {
                "caller_addr": fact.caller_addr,
                "callsite_addr": fact.callsite_addr,
                "summary": (
                    None
                    if fact.summary is None
                    else callsite_summary_record_8616(fact.summary)
                ),
            }
            for fact in evidence.facts
        ],
        "raw_fact_count": evidence.raw_fact_count,
        "normalized_fact_count": evidence.normalized_fact_count,
        "classified_fact_count": evidence.classified_fact_count,
        "materialized_count": evidence.materialized_count,
        "failure_count": evidence.failure_count,
    }


def _nonnegative_int_8616(value: object, label: str) -> int:
    """Decode one exact nonnegative integer or reject malformed JSON."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def program_callsite_summary_evidence_from_record_8616(
    value: object,
) -> ProgramCallsiteSummaryEvidence8616:
    """Decode and validate one lossless program summary artifact."""
    if not isinstance(value, dict) or set(value) != {
        "facts",
        "raw_fact_count",
        "normalized_fact_count",
        "classified_fact_count",
        "materialized_count",
        "failure_count",
    }:
        raise ValueError("program callsite summary record has incompatible fields")
    raw_facts = value["facts"]
    if not isinstance(raw_facts, list):
        raise ValueError("program callsite summary facts must be an array")
    facts: list[ProgramCallsiteSummaryFact8616] = []
    for raw_fact in raw_facts:
        if not isinstance(raw_fact, dict) or set(raw_fact) != {
            "caller_addr",
            "callsite_addr",
            "summary",
        }:
            raise ValueError("program callsite summary fact has incompatible fields")
        raw_caller = raw_fact["caller_addr"]
        caller_addr = (
            None
            if raw_caller is None
            else _nonnegative_int_8616(raw_caller, "program callsite caller address")
        )
        raw_summary = raw_fact["summary"]
        facts.append(
            ProgramCallsiteSummaryFact8616(
                caller_addr=caller_addr,
                callsite_addr=_nonnegative_int_8616(
                    raw_fact["callsite_addr"],
                    "program callsite address",
                ),
                summary=(
                    None
                    if raw_summary is None
                    else callsite_summary_from_record_8616(raw_summary)
                ),
            )
        )
    evidence = ProgramCallsiteSummaryEvidence8616(
        facts=tuple(facts),
        raw_fact_count=_nonnegative_int_8616(value["raw_fact_count"], "raw count"),
        normalized_fact_count=_nonnegative_int_8616(
            value["normalized_fact_count"],
            "normalized count",
        ),
        classified_fact_count=_nonnegative_int_8616(
            value["classified_fact_count"],
            "classified count",
        ),
        materialized_count=_nonnegative_int_8616(
            value["materialized_count"],
            "materialized count",
        ),
        failure_count=_nonnegative_int_8616(value["failure_count"], "failure count"),
    )
    evidence.validate()
    return evidence
