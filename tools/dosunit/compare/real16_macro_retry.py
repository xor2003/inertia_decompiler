"""Whole-function retry owner: real16 chain plus macro-step induction.

Layer: dosunit binary proof orchestration .
Responsibility: run the unmodified production ``retry_whole_function`` chain
(direct-call inlining, closed call-loop induction, paired-region induction)
first, and only when that chain leaves the obligation UNKNOWN with remaining
total deadline, attempt the bounded unequal-step macro proof
``compare_real16_macro`` once. Every prior attempt stays in the returned
backend dict; a scoped macro counterexample is admitted only as UNKNOWN via
``proof_scope``/``admit_scope_status`` and is never relabeled a real
counterexample. A macro result is promoted into the obligation row only when
its scoped status admits as PROVED — failed, conditional or unfinished
relations keep the UNKNOWN row.

Additive diagnostics: each deadline-gated
macro admission decision is additionally recorded under
``backend["retry_budget"]["macro_steps"]`` as a typed ``RetryStageDecision``
document — including the first shared-deadline early return that previously
left no attempt evidence. A required retry stopped by the shared deadline
reports budget exhaustion while preserving earlier stage evidence. Scheduling,
gates, deadline arithmetic and timeout arguments remain unchanged.
"""

from __future__ import annotations

import time
from dataclasses import asdict, replace
from typing import Any, Final

from tools.dosunit.compare.macro_step_contracts import MacroStepLimits, MacroStepProof
from tools.dosunit.compare.real16_call_contracts import Real16CallLimits
from tools.dosunit.compare.real16_call_retry import FunctionRetryEvidence, retry_whole_function
from tools.dosunit.compare.real16_macro_proof import compare_real16_macro
from tools.dosunit.compare.real16_proof_evidence import _group_parts, _mapped_candidate_keys
from tools.dosunit.compare.real16_retry_diagnostics import RetryStageDecision, record_stage_decision
from tools.dosunit.contracts.proof_contracts import (
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ProofStatus,
)
from tools.dosunit.contracts.proof_scope import admit_scope_status

MACRO_STEP_METHOD: Final[str] = "ssa_z3_macro_step_induction"


def admit_macro_status(proof: MacroStepProof) -> ProofStatus:
    """Admit one scoped macro verdict as whole-function evidence status.

    The macro step proof discharges every frontier transition from the entry
    macro-cut under CUTPOINT_SIMULATION scope, including solver-proved complete
    and disjoint coverage on both sides. A PROVED result is therefore a real
    entry-to-terminal simulation and may discharge the requested-function
    obligation. A scoped COUNTEREXAMPLE stays UNKNOWN: a SAT cutpoint state
    refutes the proposed relation but need not be reachable in either
    executable.
    """
    return admit_scope_status(proof.status, proof.proof_scope)


def _sole_candidate_id(
    obligation_key: str, oracle_entry: dict[str, Any],
    candidate: dict[str, Any], mapping: dict[str, Any] | None,
) -> str | None:
    """Resolve the single mapped candidate function id, exactly as the chain."""
    keys = _mapped_candidate_keys(obligation_key, oracle_entry, mapping)
    groups = _group_parts(candidate)
    candidates = {str(groups[key][0]["function"]["id"]) for key in keys if key in groups}
    return next(iter(candidates)) if len(candidates) == 1 else None


def _macro_backend(proof: MacroStepProof, admitted: ProofStatus) -> dict[str, Any]:
    """Serialize the macro attempt with raw status, declared scope and admission."""
    return {
        "status": proof.status.value,
        "reason": proof.reason.value,
        "direction": proof.direction.value if proof.direction is not None else None,
        "proof_scope": proof.proof_scope.value,
        "admitted_status": admitted.value,
        "search_status": proof.search_status.value if proof.search_status is not None else None,
        "search_refusal": proof.search_refusal.value if proof.search_refusal is not None else None,
        "detail": proof.detail,
        "counters": asdict(proof.counters),
        "attempts": [asdict(attempt) for attempt in proof.attempts],
        "transitions": [asdict(row) for row in proof.transitions],
        "graph_evidence": proof.graph_evidence,
    }


def retry_whole_function_with_macro(
    obligation: Obligation,
    oracle_entry: dict[str, Any],
    contract: ContractIdentity,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    mapping: dict[str, Any] | None,
    *,
    timeout_ms: int,
    limits: Real16CallLimits,
    macro_limits: MacroStepLimits | None = None,
) -> FunctionRetryEvidence | None:
    """Production whole-function retry chain plus one bounded macro attempt.

    The macro stage is reached only when every existing retry leaves UNKNOWN
    and the shared total deadline still has budget. On a scoped-admitted PROVED
    macro result the obligation row is replaced with macro evidence under the
    ``ssa_z3_macro_step_induction`` method; otherwise the production row stands
    with the macro attempt recorded under ``macro_steps`` in the backend dict.

    Every reached macro admission gate — both deadline reads and the
    candidate-resolution gate — is recorded under
    ``backend["retry_budget"]["macro_steps"]`` as additive typed metadata.
    """
    if timeout_ms <= 0:
        row = ObligationEvidence(
            id=obligation.id, contract=contract, status=ProofStatus.UNKNOWN,
            reason="compose_budget_exceeded", dependencies=obligation.dependencies,
            counters=FactCounters(1, 1, 1, 1, 1),
        )
        return FunctionRetryEvidence(row, {"status": "refused", "reason": "compose_budget_exceeded"})
    deadline = time.monotonic() + max(timeout_ms, 0) / 1000.0
    retry = retry_whole_function(
        obligation, oracle_entry, contract, oracle, candidate, mapping,
        timeout_ms=timeout_ms, limits=limits,
    )
    if retry is None or retry.evidence.status is not ProofStatus.UNKNOWN:
        return retry
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    candidate_id = _sole_candidate_id(obligation.id.key, oracle_entry, candidate, mapping)
    macro_decision = RetryStageDecision.decide(
        required=candidate_id is not None,
        remaining_ms=remaining_ms,
    )
    if not macro_decision.attempted:
        record_stage_decision(retry.backend, "macro_steps", macro_decision)
        if macro_decision.required and not macro_decision.budget_open:
            return FunctionRetryEvidence(
                replace(retry.evidence, reason="compose_budget_exceeded"), retry.backend,
            )
        return retry
    function_id = str(oracle_entry.get("id") or obligation.id.key)
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    macro_decision = RetryStageDecision.decide(required=True, remaining_ms=remaining_ms)
    if not macro_decision.attempted:
        row = replace(retry.evidence, reason="compose_budget_exceeded",
                      counters=FactCounters(1, 1, 1, 1, 1))
        backend = {**retry.backend, "macro_steps": {
            "status": ProofStatus.UNKNOWN.value, "reason": "compose_budget_exceeded", "attempted": False,
        }}
        record_stage_decision(backend, "macro_steps", macro_decision)
        return FunctionRetryEvidence(row, backend)
    macro = compare_real16_macro(
        oracle, candidate, function_id, candidate_function=candidate_id,
        limits=limits, macro_limits=macro_limits, timeout_ms=remaining_ms,
    )
    admitted = admit_macro_status(macro)
    backend = dict(retry.backend)
    backend["macro_steps"] = _macro_backend(macro, admitted)
    record_stage_decision(backend, "macro_steps", macro_decision)
    if admitted is ProofStatus.PROVED:
        row = replace(
            retry.evidence, status=ProofStatus.PROVED,
            reason=macro.reason.value, method=MACRO_STEP_METHOD,
            assumptions=(), counters=macro.counters,
        )
    else:
        row = replace(retry.evidence, reason=macro.reason.value, counters=macro.counters)
    return FunctionRetryEvidence(row, backend)
