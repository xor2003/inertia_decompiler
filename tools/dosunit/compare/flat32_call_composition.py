"""Layer: validation call composition.

Responsibility: bounded flat-i386 direct-call composition over real VEX IR.

Every admitted call is proved, not assumed: the call block's own 32-bit
return-address push and ``esp`` update compose like any other block, the
complete acyclic callee body is inlined through its composed register/memory
final state, and the substituted return target must be proved equal to the
recorded fallthrough by Z3 before the caller continuation is walked.
Admitted acyclic tail transfers (unconditional terminal jumps to separately
declared foreign entries) are composed the same way minus the return-address
push: the destination's complete summary is substituted over the live state
and its ``eip`` is discharged by the enclosing call's return-target proof or
observed as the root summary's terminal state.  Indirect, recursive,
unmapped, conditional-exit, looped or unprovable calls refuse.  Summary
documents keep the ``inputs``/``outputs``/``assignments``
shape produced by ``flat32_region.summarize`` so both flat32 drivers can
consume them, and ``compare_functions_with_calls`` mirrors
``flat32_region.compare_region`` verdict semantics.

The public boundary is ``summarize_with_calls`` /
``compare_functions_with_calls`` plus the ``CallCompositionLimits`` /
``CallCompositionRefusal`` contracts.  Lifting lives in
``flat32_call_lowering``, path and call execution in
``flat32_call_execution``, shared contracts in ``flat32_call_contracts``.

Every comparison runs under one absolute ``time.monotonic`` deadline
derived from ``timeout_ms`` (optionally tightened by ``total_deadline``):
both sides' lifting, composition, substitution and return proofs draw
from it, nested solver calls are clamped to the remaining budget, and
expiry refuses with ``compose_budget_exceeded`` instead of publishing.

Lifting and lowering consume explicit native i386 architecture state.
Callers do not need to install mutable flat32 adapter globals.
"""

from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    PRESERVED_OUTPUTS,
    BlockLiftRetry,
    CallCompositionLimits,
    CallCompositionRefusal,
    CallProofSide,
    ReturnTargetProofFailure,
    _check_compose_deadline,
    _ComposeSession,
    _normalize_function_map,
    _register_widths,
    _resolve_total_deadline,
    _term_nodes,
)
from tools.dosunit.compare.flat32_call_execution import _compose_root
from tools.dosunit.compare.flat32_environment_coverage import environment_parts
from tools.dosunit.compare.flat32_region_attempts import comparison_deadline
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy

if TYPE_CHECKING:
    import angr

__all__ = [
    "PRESERVED_OUTPUTS",
    "BlockLiftRetry",
    "CallCompositionLimits",
    "CallCompositionRefusal",
    "CallProofSide",
    "ReturnTargetProofFailure",
    "compare_functions_with_calls",
    "summarize_with_calls",
]


def summarize_with_calls(
    project: angr.Project,
    *,
    entry: int,
    functions: Mapping[int, int],
    outputs: tuple[str, ...],
    limits: CallCompositionLimits | None = None,
    labels: Mapping[int, str] | None = None,
    entry_domain: Flat32ProofDomain | None = None,
    total_deadline: float | None = None,
) -> dict[str, Any]:
    """Compose one complete flat32 function, inlining proved direct calls.

    ``functions`` maps each known function entry linear address to its complete
    byte size; a call is admitted only when its constant target is a declared
    entry and the callee's own reachable blocks stay inside its declared range.
    Labels are evidence metadata only; call targets resolve by address.

    Caller-selected ``outputs`` choose which return values are observed, but
    the ABI-preserved registers in ``PRESERVED_OUTPUTS`` (ebx, ebp, esi, edi,
    esp) plus ``eip``, ``memory`` and ``io`` are always observed, so a callee
    that silently clobbers a preserved register cannot pass under a narrow
    output selection.

    ``entry_domain`` is an optional caller-declared premise bounding the
    top-level entry ``esp`` input.  It is attached to root-frame return
    proofs and echoed into the document as ``input_constraints`` plus the
    unproved ``entry_domain_assumptions`` payload, so a summary produced
    under the premise is never unlabelled. Generic nested summaries do not
    inherit a root interval. A return-proof refusal can trigger one root-bound
    retry: callee inputs are composed from actual caller state before walking,
    so nested proofs refer to root inputs rather than a shifted frame. This
    retry reuses lifted blocks and shares all work/deadline limits.
    ``root_bound_retry`` identifies this mode in the summary. Block/call/tail
    work counters include the failed first attempt; proof records and the
    return-target proof count describe only the successful complete attempt.

    ``limits.retry_max_blocks_per_function`` is a separate, strictly opt-in
    bound: a function closure whose lift worklist demonstrably reaches
    ``max_blocks_per_function`` may continue the same pending queue once up
    to the retry cap.  Engaged continuations are published as
    ``block_lift_retries`` — typed records naming the entry, both caps and
    the closure's actual lifted count.  A closure that completes under the
    original cap records nothing, and a continuation that still exhausts
    keeps the ``block_limit`` refusal.

    Returns a ``flat32_region.summarize``-shaped document (``inputs``,
    ``outputs``, ``assignments``) plus composition counters and the proved
    ``call_sites``.  Admitted tail transfers are published separately as the
    ``tail_transfers`` count and the ``tail_sites`` dependency records
    (``site``/``block``/``target``/``depth``/``callee``); a tail transfer is
    not a call, so it never appears in ``call_sites`` and carries no
    return-target proof of its own.  Raises :class:`CallCompositionRefusal`
    for any incomplete or unsupported evidence; it never returns a partial
    summary. Native i386 architecture is supplied explicitly by the shared
    lowering owner; no adapter installation boundary is required.

    ``total_deadline`` is an optional absolute ``time.monotonic()`` deadline
    shared into the session's ``compose_stats``: lifting, block composition,
    callee-summary substitution and every callee return-target proof check
    it at their work boundaries, and each return proof's solver timeout is
    clamped to the remaining budget.  ``limits.max_total_seconds`` applies
    the same way when set; the effective bound is their minimum.  Expiry
    refuses with ``compose_budget_exceeded`` — an exhausted budget never
    publishes a summary.
    """
    if entry_domain is not None and not isinstance(entry_domain, Flat32ProofDomain):
        raise CallCompositionRefusal("invalid_entry_domain")
    limits = limits or CallCompositionLimits()
    deadline = _resolve_total_deadline(limits, total_deadline)
    reg_widths = _register_widths()
    function_map = _normalize_function_map(functions)
    if entry not in function_map:
        raise CallCompositionRefusal("entry_not_in_functions")
    compose_stats: dict[str, Any] = {}
    if deadline is not None:
        compose_stats["deadline"] = deadline
    session = _ComposeSession(
        project=project,
        functions=function_map,
        labels={address: str(name) for address, name in (labels or {}).items()},
        limits=limits,
        reg_widths=reg_widths,
        entry_domain=entry_domain,
        compose_stats=compose_stats,
    )
    final_state = _compose_root(session, entry)
    _check_compose_deadline(session.compose_stats)
    observed = tuple(dict.fromkeys((*outputs, *PRESERVED_OUTPUTS, "eip", "memory", "io")))
    if any(name not in final_state for name in observed):
        raise CallCompositionRefusal("observable_state_missing")
    terms = {name: final_state[name] for name in observed}
    if _term_nodes(terms, limits.max_term_nodes) > limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    materialized: dict[str, dict[str, Any]] = {}
    for name, term in terms.items():
        _check_compose_deadline(session.compose_stats)
        materialized[name] = S._materialize_json_term(
            term, assignments=assignments, memo=memo, term_cache=term_cache
        )
    document = {
        "inputs": S._term_input_items(list(materialized.values()), assignments),
        "outputs": materialized,
        "assignments": assignments,
        "blocks_composed": session.compositions,
        "blocks_lifted": session.blocks_lifted,
        "inlined_calls": session.inlined_calls,
        "return_targets_proved": session.return_targets_proved,
        "call_sites": session.call_sites,
        "tail_transfers": session.tail_transfers,
        "tail_sites": session.tail_sites,
        "block_lift_retries": [
            retry.to_document() for retry in session.block_lift_retries
        ],
        "root_bound_retry": session.root_bound_inputs,
        "environment_parts": environment_parts({
            address: block for blocks in session.blocks.values() for address, block in blocks.items()
        }),
    }
    if entry_domain is not None:
        document["input_constraints"] = entry_domain.constraints()
        document["entry_domain_assumptions"] = entry_domain.assumption_document()
    _check_compose_deadline(session.compose_stats)
    return document


def _summarize_side(
    side: CallProofSide,
    project: angr.Project,
    *,
    entry: int,
    functions: Mapping[int, int],
    outputs: tuple[str, ...],
    limits: CallCompositionLimits,
    labels: Mapping[int, str] | None,
    entry_domain: Flat32ProofDomain | None,
    total_deadline: float | None,
) -> dict[str, Any]:
    """Compose one compare side; retained proof evidence records which side refused.

    ``total_deadline`` is the single absolute deadline shared by both sides
    and the final solver; each side's session re-checks it at every work
    boundary and clamps nested solver budgets to the remaining time.
    """
    try:
        return summarize_with_calls(
            project,
            entry=entry,
            functions=functions,
            outputs=outputs,
            limits=limits,
            labels=labels,
            entry_domain=entry_domain,
            total_deadline=total_deadline,
        )
    except CallCompositionRefusal as error:
        if error.evidence is None:
            raise
        raise CallCompositionRefusal(
            str(error), evidence=replace(error.evidence, side=side)
        ) from error


def _has_lazy_flags(summary: dict[str, Any], limit: int) -> bool:
    """Treat SAT with an uninterpreted x86 flag helper as inconclusive."""
    helpers = S.X86_LAZY_FLAG_SUMMARY_OPS
    assignments = {
        item["id"]: item
        for item in summary.get("assignments", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    pending = [summary.get("outputs", {}), summary.get("assignments", [])]
    seen = 0
    while pending and seen <= limit:
        item = pending.pop()
        if isinstance(item, dict):
            seen += 1
            if item.get("op") in helpers and S._x86_lazy_flag_summary_is_uninterpreted(item, assignments):
                return True
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return bool(pending)


def _normalization_assumptions(normalization: Mapping[int, int]) -> dict[str, Any]:
    """Describe a caller-supplied constant map as an explicit unproved assumption."""
    return {
        "kind": "caller_supplied_constant_relocation",
        "proved": False,
        "provenance": "caller_supplied_map",
        "constant_map": {hex(candidate): hex(oracle) for candidate, oracle in normalization.items()},
        "scope": (
            "each listed candidate constant is assumed to denote the corresponding oracle "
            "constant (relocated code addresses); the map is caller-supplied evidence, not a "
            "proved relation, and no semantic pointer equivalence is inferred from labels"
        ),
    }


def _normalization_map(candidate_normalization: Mapping[int, int] | None) -> dict[int, int]:
    """Normalize a caller-supplied relocation map to plain integer keys."""
    if not candidate_normalization:
        return {}
    return {int(key): int(value) for key, value in candidate_normalization.items()}


def _stamp_normalization(candidate_summary: dict[str, Any], normalization: Mapping[int, int]) -> None:
    """Attach the relocation map to the candidate document for constant folding."""
    if not normalization:
        return
    candidate_summary["_constant_normalization"] = normalization
    candidate_summary["_constant_normalization_reasons"] = dict.fromkeys(
        normalization, "global_reloc"
    )


def _domain_labelled_refusal(
    reason: str, entry_domain: Flat32ProofDomain | None
) -> dict[str, Any]:
    """Build a refused report that still labels any declared entry premise."""
    report: dict[str, Any] = {"status": "refused", "reason": reason}
    if entry_domain is not None:
        report["input_constraints"] = entry_domain.constraints()
        report["entry_domain_assumptions"] = entry_domain.assumption_document()
    return report


def _mask_lazy_flag_counterexample(
    comparison: dict[str, Any],
    oracle_summary: dict[str, Any],
    candidate_summary: dict[str, Any],
    term_limit: int,
) -> None:
    """Downgrade a counterexample verdict when a lazy x86 flag helper is modeled."""
    if proof_status_from_legacy(comparison.get("status")) is ProofStatus.COUNTEREXAMPLE and (
        _has_lazy_flags(oracle_summary, term_limit)
        or _has_lazy_flags(candidate_summary, term_limit)
    ):
        comparison["status"] = "refused"
        comparison["reason"] = "uninterpreted_x86_flags"


def _record_caller_premises(
    comparison: dict[str, Any],
    *,
    normalization: Mapping[int, int],
    entry_domain: Flat32ProofDomain | None,
) -> None:
    """Label a verdict with every caller-supplied premise it ran under.

    Each declared premise is serialized next to its payload regardless of
    outcome so consumers never receive an unlabelled assumed summary.  A
    backend ``passed`` is published as ``conditional`` whose ``reason`` names
    each unproved premise and whose ``assumptions`` carries the payloads —
    the single payload directly, or all payloads keyed by reason when more
    than one premise was declared.
    """
    premises: dict[str, dict[str, Any]] = {}
    if normalization:
        premises["unproved_constant_normalization"] = _normalization_assumptions(normalization)
        comparison["normalization_assumptions"] = premises["unproved_constant_normalization"]
    if entry_domain is not None:
        premises["unproved_entry_esp_domain"] = entry_domain.assumption_document()
        comparison["entry_domain_assumptions"] = premises["unproved_entry_esp_domain"]
        comparison["input_constraints"] = entry_domain.constraints()
    if premises and proof_status_from_legacy(comparison.get("status")) is ProofStatus.PROVED:
        comparison.update(
            status="conditional",
            reason="+".join(premises),
            assumptions=(
                next(iter(premises.values())) if len(premises) == 1 else dict(premises)
            ),
        )


def _shared_compare_deadline(timeout_ms: int, total_deadline: float | None) -> float:
    """Resolve the single absolute compare deadline, refusing unusable bounds.

    ``timeout_ms`` supplies the natural budget from ``time.monotonic()``; an
    explicit ``total_deadline`` can only tighten it.  ``NaN``/``±inf`` inputs
    refuse with ``invalid_total_deadline`` — a ``NaN`` comparison never
    holds, so it would silently disable the bound — and an already-expired
    deadline refuses with ``compose_budget_exceeded`` before any work runs.
    """
    if timeout_ms <= 0:
        raise CallCompositionRefusal("compose_budget_exceeded")
    if total_deadline is not None and not math.isfinite(total_deadline):
        raise CallCompositionRefusal("invalid_total_deadline")
    deadline = comparison_deadline(timeout_ms, total_deadline)
    if not math.isfinite(deadline):
        raise CallCompositionRefusal("invalid_total_deadline")
    if time.monotonic() >= deadline:
        raise CallCompositionRefusal("compose_budget_exceeded")
    return deadline


def compare_functions_with_calls(
    oracle: angr.Project,
    candidate: angr.Project,
    *,
    oracle_entry: int,
    candidate_entry: int,
    oracle_functions: Mapping[int, int],
    candidate_functions: Mapping[int, int],
    outputs: tuple[str, ...],
    timeout_ms: int,
    limits: CallCompositionLimits | None = None,
    oracle_labels: Mapping[int, str] | None = None,
    candidate_labels: Mapping[int, str] | None = None,
    candidate_normalization: Mapping[int, int] | None = None,
    entry_domain: Flat32ProofDomain | None = None,
    total_deadline: float | None = None,
) -> dict[str, Any]:
    """Compare two complete flat32 functions, inlining proved direct calls.

    Each side is lifted from its own project over its own declared byte ranges
    and composed independently, so a strict verdict is a real equality proof:
    ``passed`` needs no paired-call assumptions and a changed callee changes
    the caller's composed semantics directly.

    ``candidate_normalization`` is an explicit, unproved candidate-constant to
    oracle-constant map applied to the candidate document (as in
    ``bc5 flat32_region``).  Because the map is assumed rather than proved, a
    backend ``passed`` under normalization is published as ``conditional``
    with the map recorded in ``assumptions``; it is never unconditional.
    Without a map, relocated return-slot writes legitimately fail strict
    memory equality.

    ``entry_domain`` is an optional caller-declared premise bounding the
    shared top-level entry ``esp`` input of both sides.  It is applied to
    root-frame return proofs and to the final whole-function comparison, and
    like normalization it is assumed, not proved: a backend ``passed`` under
    a declared domain publishes ``conditional`` with
    ``unproved_entry_esp_domain`` and the exact interval serialized.  When
    both premises are declared the ``reason`` names each unproved premise and
    ``assumptions`` carries both payloads keyed by their reason. Generic nested
    summaries cannot inherit that interval. The bounded contextual retry first
    substitutes each callee's inputs into root coordinates, so those nested
    proofs can use the root premise without applying it to a shifted frame.

    Status strings match ``flat32_verdict.Status`` values;
    refusals keep their typed reason.  A refusal caused by a failed callee
    return-target proof additionally publishes ``return_proof_failure``:
    the typed solver status, the failing callsite/target/fallthrough, the
    compare side and the bounded SSA solver report (with countermodel inputs
    for ``counterexample`` failures, and the applied ``input_constraints``
    when the proof ran under the declared domain).

    The report publishes per-side ``oracle_tail_transfers`` /
    ``candidate_tail_transfers`` counts and a ``tail_sites`` map keyed by
    side, parallel to ``call_sites``: admitted unconditional tail transfers
    to separately declared foreign entries, each recorded with its
    site/block/target/depth/label evidence.  A tail transfer pushes no
    return address, so it is never counted among ``inlined_calls``.

    ``block_lift_retries`` is a per-side map of the typed
    ``BlockLiftRetry`` documents for each closure that engaged the opt-in
    ``retry_max_blocks_per_function`` continuation: entry, the original
    and retry caps, and the actual lifted block count.  Refused
    comparisons keep the minimal refused-report shape and do not publish
    it.

    The whole comparison shares one absolute deadline: ``timeout_ms`` bounds
    the total wall-clock budget (an optional ``total_deadline`` absolute
    ``time.monotonic()`` value can only tighten it, as in
    ``flat32_cfg_regions``/``flat32_macro_proof``).  Both sides' lifting,
    composition, substitution and callee return proofs draw from the same
    deadline, each return proof is clamped to ``min(ret_check_timeout_ms,
    remaining)``, and the final solver call receives only the remaining
    milliseconds.  Expiry at any boundary reports a refused
    ``compose_budget_exceeded`` verdict; a verdict is never published after
    the deadline, even if a solver run finished just past it.
    """
    limits = limits or CallCompositionLimits()
    normalization = _normalization_map(candidate_normalization)
    if entry_domain is not None and not isinstance(entry_domain, Flat32ProofDomain):
        return _domain_labelled_refusal("invalid_entry_domain", None)
    try:
        deadline = _shared_compare_deadline(timeout_ms, total_deadline)
        oracle_summary = _summarize_side(
            CallProofSide.ORACLE,
            oracle,
            entry=oracle_entry,
            functions=oracle_functions,
            outputs=outputs,
            limits=limits,
            labels=oracle_labels,
            entry_domain=entry_domain,
            total_deadline=deadline,
        )
        if time.monotonic() >= deadline:
            raise CallCompositionRefusal("compose_budget_exceeded")
        candidate_summary = _summarize_side(
            CallProofSide.CANDIDATE,
            candidate,
            entry=candidate_entry,
            functions=candidate_functions,
            outputs=outputs,
            limits=limits,
            labels=candidate_labels,
            entry_domain=entry_domain,
            total_deadline=deadline,
        )
        _stamp_normalization(candidate_summary, normalization)
        gate = S._ssa_solver_gate(
            oracle_summary,
            candidate_summary,
            max_solver_assignments=limits.max_term_nodes,
            max_solver_inputs=limits.max_solver_inputs,
            max_solver_memory_stores=limits.max_memory_stores,
        )
        if gate is not None:
            raise CallCompositionRefusal(str(gate["reason"]))
    except CallCompositionRefusal as error:
        report = _domain_labelled_refusal(str(error), entry_domain)
        if error.evidence is not None:
            report["return_proof_failure"] = error.evidence.to_document()
        return report
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if remaining_ms <= 0:
        return _domain_labelled_refusal("compose_budget_exceeded", entry_domain)
    comparison = S._compare_functions(
        oracle_summary,
        candidate_summary,
        timeout_ms=min(timeout_ms, remaining_ms),
        input_constraints=(
            entry_domain.constraints() if entry_domain is not None else None
        ),
    )
    if time.monotonic() >= deadline:
        return _domain_labelled_refusal("compose_budget_exceeded", entry_domain)
    if comparison.get("skipped_layout_outputs"):
        return _domain_labelled_refusal("observable_output_skipped", entry_domain)
    _mask_lazy_flag_counterexample(
        comparison, oracle_summary, candidate_summary, limits.max_term_nodes
    )
    _record_caller_premises(
        comparison, normalization=normalization, entry_domain=entry_domain
    )
    if time.monotonic() >= deadline:
        return _domain_labelled_refusal("compose_budget_exceeded", entry_domain)
    return {
        **comparison,
        "oracle_blocks_composed": oracle_summary["blocks_composed"],
        "candidate_blocks_composed": candidate_summary["blocks_composed"],
        "oracle_inlined_calls": oracle_summary["inlined_calls"],
        "candidate_inlined_calls": candidate_summary["inlined_calls"],
        "return_targets_proved": (
            oracle_summary["return_targets_proved"] + candidate_summary["return_targets_proved"]
        ),
        "environment_coverage": {
            "oracle": oracle_summary["environment_parts"],
            "candidate": candidate_summary["environment_parts"],
        },
        "call_sites": {
            "oracle": oracle_summary["call_sites"],
            "candidate": candidate_summary["call_sites"],
        },
        "oracle_tail_transfers": oracle_summary["tail_transfers"],
        "candidate_tail_transfers": candidate_summary["tail_transfers"],
        "tail_sites": {
            "oracle": oracle_summary["tail_sites"],
            "candidate": candidate_summary["tail_sites"],
        },
        "block_lift_retries": {
            "oracle": oracle_summary["block_lift_retries"],
            "candidate": candidate_summary["block_lift_retries"],
        },
    }
