"""Complete flat32 transition checks with separately discharged invariants.

Layer: dosunit flat32 induction proof.
Responsibility: check every paired transition under the artifact driver model,
retain raw cutpoint countermodels, enforce the shared deadline and prevent
failed invariant obligations from becoming complete-function equivalence.
"""
from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from tools.dosunit.compare.memory_invariant_obligations import MemoryInvariantProof
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.contracts.proof_scope import ProofScope, admit_scope_status


def comparison_deadline(timeout_ms: int, total_deadline: float | None = None) -> float:
    """Share an outer deadline without giving nested comparisons extra time."""
    natural = time.monotonic() + max(timeout_ms, 1) / 1000
    return natural if total_deadline is None else min(natural, total_deadline)


def compare_attempt(
    ossa: dict[str, Any], cssa: dict[str, Any], deadline: float,
    adapter: Any, catalog: Any, verdict: Any,  # noqa: ANN401
    invariant_proofs: tuple[MemoryInvariantProof, ...] = (),
    *, candidate_normalization: Mapping[int, int] | None = None,
) -> tuple[Any, dict[str, Any], list[dict[str, Any]]]:
    """Check every transition without promoting internal SAT to binary mismatch.

    An explicit constant map labels every checked row and aggregate success
    conditional. Callers must retain the exact premise in the final report
    and protect control tokens before requesting normalized induction.
    """
    timeout_ms = int((deadline - time.monotonic()) * 1000)
    if timeout_ms <= 0:
        rows = [verdict.refusal(f"sb_{index}", f"oracle:sb_{index}", verdict.Reason.ABORTED)
                for index in range(len(ossa["functions"]))]
        return verdict.Status.REFUSED, {"status": "refused", "reason": "compose_deadline_exceeded"}, rows
    if candidate_normalization:
        # Premises belong to this attempt, not to the reusable native SSA.
        # A later literal invariant check must see the original coordinates.
        cssa = {**cssa, "functions": [
            {**function, "_constant_normalization": dict(candidate_normalization),
             "_constant_normalization_reasons": dict.fromkeys(candidate_normalization, "global_reloc")}
            for function in cssa["functions"]
        ]}
    compared = adapter.S.compare_ssa_documents(
        oracle=ossa,
        candidate=cssa,
        mapping_document=catalog.mapping("oracle", "candidate", [f"sb_{index}" for index in range(len(ossa["functions"]))]),
        timeout_ms=timeout_ms,
        max_solver_assignments=4096,
        max_solver_inputs=64,
        max_solver_memory_stores=256,
        skip_binary_equal=False,
        allow_aliased_call_targets=False,
        enable_callee_lemmas=False,
        enable_region_equality=False,
        enable_connectivity=False,
    )
    expected = {f"sb_{index}": f"oracle:sb_{index}" for index in range(len(ossa["functions"]))}
    verdicts = verdict.checked_results(expected, compared, relocation=candidate_normalization)
    # SAT at an arbitrary internal cutpoint refutes this simulation relation;
    # it does not establish a reachable whole-function counterexample.
    accepted = {ProofStatus.PROVED}
    if candidate_normalization:
        accepted.add(ProofStatus.CONDITIONAL)
    status = (verdict.Status.CONDITIONAL if candidate_normalization else verdict.Status.PASSED) if verdicts and all(
        admit_scope_status(proof_status_from_legacy(row.get("status")) or ProofStatus.UNKNOWN,
                           ProofScope.CUTPOINT_SIMULATION) in accepted for row in verdicts
    ) else verdict.Status.REFUSED
    if any(proof.status is not ProofStatus.PROVED for proof in invariant_proofs):
        status = verdict.Status.REFUSED
    if time.monotonic() >= deadline:
        status = verdict.Status.REFUSED
        compared["deadline_exceeded"] = True
    return status, compared, verdicts
