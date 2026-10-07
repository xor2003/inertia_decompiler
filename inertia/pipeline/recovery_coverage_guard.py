"""Enforce exact frontend recovery-coverage evidence.

Layer: Pipeline governance.
Responsibility: reject a recovered function when exact frontend instruction
identity proves that CFG ownership omitted instructions.
Owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from inertia.cli.recovery_instruction_coverage import (
    ExactInstructionCoverageEvidence8616,
    ExactInstructionCoverageVerdict8616,
)

from .errors import PipelineHardError

__all__ = ["assert_exact_instruction_coverage_8616"]


def assert_exact_instruction_coverage_8616(evidence: ExactInstructionCoverageEvidence8616) -> None:
    """Raise when exact frontend evidence proves incomplete CFG ownership."""
    if evidence.verdict is ExactInstructionCoverageVerdict8616.UNAVAILABLE:
        return
    counts_are_closed = (
        evidence.raw_fact_count > 0
        and evidence.raw_fact_count == evidence.normalized_fact_count
        and evidence.normalized_fact_count == evidence.classified_fact_count
        and evidence.classified_fact_count
        == evidence.materialized_count + evidence.excluded_unreachable_count + evidence.failure_count
        and evidence.failure_count == len(evidence.missing_instruction_addrs)
    )
    if not counts_are_closed:
        raise PipelineHardError(
            "exact instruction recovery coverage has an inconsistent evidence census",
            layer="recovery:exact_instruction_coverage",
            function_addr=evidence.function_addr,
            details=evidence.to_dict(),
        )
    if evidence.complete:
        return
    raise PipelineHardError(
        "function recovery omitted exact instructions from CFG ownership",
        layer="recovery:exact_instruction_coverage",
        function_addr=evidence.function_addr,
        details=evidence.to_dict(),
    )
