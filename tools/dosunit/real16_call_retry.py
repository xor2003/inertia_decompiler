"""Whole-function fallback evidence for the public real16 comparator.

Layer: dosunit binary proof orchestration.
Responsibility: consume complete inlined call proofs under the same immutable
binary contract as ordinary function evidence; preserve dependency identities
and every refusal in the public report.

Additive diagnostics: each deadline-gated
stage admission decision is additionally recorded under
``backend["retry_budget"][stage]`` as a typed ``RetryStageDecision``
document. Scheduling, gates, deadline arithmetic, timeout arguments and
verdict rows are unchanged from production.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from tools.dosunit.binary_environment import active_ordered_io
from tools.dosunit.cutpoint_state_relations import CutpointStateRelation
from tools.dosunit.proof_contracts import (
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ProofStatus,
    proof_status_from_legacy,
)
from tools.dosunit.real16_call_composition import compare_real16_with_calls
from tools.dosunit.real16_call_contracts import Real16CallLimits
from tools.dosunit.real16_loop_calls import compare_real16_loop_calls
from tools.dosunit.real16_proof_evidence import _group_parts, _mapped_candidate_keys
from tools.dosunit.real16_region_proof import compare_real16_regions
from tools.dosunit.real16_retry_diagnostics import RetryStageDecision, record_stage_decision
from tools.dosunit.register_affine_relations import RegisterAffineRelation

if TYPE_CHECKING:
    from tools.dosunit.ordered_io_environment import OrderedIoContract


@dataclass(frozen=True)
class FunctionRetryEvidence:
    """One complete function obligation plus call and region diagnostics."""

    evidence: ObligationEvidence
    backend: dict[str, Any]


def retry_whole_function(
    obligation: Obligation,
    oracle_entry: dict[str, Any],
    contract: ContractIdentity,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    mapping: dict[str, Any] | None,
    *,
    timeout_ms: int,
    limits: Real16CallLimits,
    io_model: OrderedIoContract | None = None,
) -> FunctionRetryEvidence | None:
    """Attempt checked call composition and closed paired-region induction.

    Callees are composed from their complete fresh binary-derived state effects,
    rather than assuming matching targets imply equal post-call states.

    ``io_model`` binds the declared ordered-I/O environment contract; when
    absent the ambient caller-installed contract (``installed_ordered_io``)
    applies so unowned intermediaries inherit the identical typed model.
    Any consumed premise keeps the row CONDITIONAL — never unconditional
    PROVED.

    Every deadline-gated stage decision (loop induction, paired regions) is
    also recorded under ``result["retry_budget"]`` as additive typed
    metadata; the gates, deadlines and verdict fields are unchanged.
    """
    io_model = io_model if io_model is not None else active_ordered_io()
    function_id = str(oracle_entry.get("id") or obligation.id.key)
    parts = _group_parts(oracle).get(function_id, [])
    has_calls = any(part.get("source", {}).get("jumpkind") == "Ijk_Call" for part in parts)
    keys = _mapped_candidate_keys(obligation.id.key, oracle_entry, mapping)
    groups = _group_parts(candidate)
    candidates = {str(groups[key][0]["function"]["id"]) for key in keys if key in groups}
    if len(candidates) != 1:
        return None
    deadline = time.monotonic() + timeout_ms / 1000
    candidate_id = next(iter(candidates))
    result: dict[str, Any] = compare_real16_with_calls(
        oracle, candidate, function_id, candidate_function=candidate_id,
        timeout_ms=timeout_ms, limits=limits, io_model=io_model,
    ) if has_calls else {"status": "refused", "reason": "paired_regions_required"}
    status = proof_status_from_legacy(result.get("status")) or ProofStatus.UNKNOWN
    assumptions = tuple(str(item) for item in result.get("assumptions") or ())
    if result.get("skipped_layout_outputs"):
        assumptions = (*assumptions, "layout_outputs_unproved")
    method = "ssa_z3_complete_call_inlining"
    reason = str(result.get("reason") or "direct_call_composition")
    counters = FactCounters(1, 1, 1, 1, int(status is not ProofStatus.PROVED))
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    loop_decision = RetryStageDecision.decide(
        required=has_calls and status is ProofStatus.UNKNOWN,
        remaining_ms=remaining_ms,
    )
    record_stage_decision(result, "loop_induction", loop_decision)
    if loop_decision.attempted:
        induction = compare_real16_loop_calls(
            oracle, candidate, function_id, candidate_function=candidate_id,
            timeout_ms=remaining_ms, limits=limits,
        )
        result["loop_induction"] = {
            "status": induction.status.value, "reason": induction.reason.value,
            "detail": induction.detail, "dependencies": list(induction.dependencies),
            "counters": asdict(induction.counters),
            "transitions": [{"delta": row.delta, "status": row.status.value,
                             "reason": row.reason.value, "diagnostics": row.diagnostics}
                            for row in induction.transitions],
        }
        if induction.status is ProofStatus.PROVED:
            status, reason, method = induction.status, induction.reason.value, "ssa_z3_closed_call_loop_induction"
            assumptions = ()
            counters = induction.counters
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    region_decision = RetryStageDecision.decide(
        required=status is ProofStatus.UNKNOWN,
        remaining_ms=remaining_ms,
    )
    record_stage_decision(result, "paired_regions", region_decision)
    if region_decision.attempted:
        regions = compare_real16_regions(
            oracle, candidate, function_id, candidate_function=candidate_id,
            timeout_ms=remaining_ms, limits=limits,
        )
        result["paired_regions"] = asdict(regions)
        counters = regions.counters
        reason = regions.reason.value
        if regions.status is ProofStatus.PROVED:
            status = regions.status
            method = "ssa_z3_paired_region_induction"
            if not regions.relation.is_identity:
                method = "ssa_z3_affine_region_induction" if isinstance(regions.relation, RegisterAffineRelation) else "ssa_z3_register_region_induction"
            if isinstance(regions.relation, CutpointStateRelation) and not regions.relation.is_identity:
                method = "ssa_z3_memory_region_induction"
            assumptions = ()
    row = ObligationEvidence(
        id=obligation.id, contract=contract, status=status,
        reason=reason, method=method, assumptions=assumptions, counters=counters,
    )
    return FunctionRetryEvidence(row, result)
