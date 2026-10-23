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

import json
import math
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from tools.dosunit.architectures.flat32 import X87_REGISTER_NAMES
from tools.dosunit.architectures.flat32_entry_inputs import bind_direction_input
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_abi_observation import (
    Flat32AbiObservation,
    apply_completed_observation,
    observation_outputs,
    record_abi_observation,
)
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
from tools.dosunit.compare.flat32_external_binding import bind_project_imports, import_slot_correspondence
from tools.dosunit.compare.flat32_external_call import Flat32ExternalCall
from tools.dosunit.compare.flat32_memory_preservation import simplify_preserved_root_reads
from tools.dosunit.compare.flat32_region_attempts import comparison_deadline
from tools.dosunit.contracts.flat32_buffer_domain import (
    Flat32EntryMemoryBinding,
    Flat32EntryMemoryRange,
    Flat32StackDisjointBuffer,
)
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.contracts.proof_scope import ProofScope
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.obligation_codec import encode_bound_predicates

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
    external_contracts: tuple[Flat32ExternalCall, ...] = (),
    root_buffer_domains: tuple[tuple[Flat32StackDisjointBuffer, int], ...] = (),
    root_memory_bindings: tuple[Flat32EntryMemoryBinding, ...] = (),
) -> dict[str, Any]:
    """Compose one complete flat32 function, inlining proved direct calls.

    ``functions`` maps each known function entry linear address to its complete
    byte size; a call is admitted only when its constant target is a declared
    entry and the callee's own reachable blocks stay inside its declared range.
    Labels are evidence metadata only; call targets resolve by address.

    ``external_contracts`` explicitly opts into returning PE-import effects.
    Each declaration must bind a real loaded import. Exact CALL/JMP-IAT forms
    require a live-target preservation proof against root-entry memory before
    effects apply. Initial loader binding and the external ABI/effects remain
    declared premises, retained in ``external_sites``. All nested execution
    uses root inputs in this mode, without generic callee-summary caching.

    Caller-selected ``outputs`` choose which return values are observed, but
    the ABI-preserved registers in ``PRESERVED_OUTPUTS`` (ebx, ebp, esi, edi,
    esp) plus ``eip``, ``memory`` and ``io`` are always observed, so a callee
    that silently clobbers a preserved register cannot pass under a narrow
    output selection.

    ``abi_observation`` optionally projects only completed root outputs under
    a caller-declared scalar return and private-stack lifetime premise. All
    executed memory accesses, intermediate state and return checks remain
    unchanged. Any projected success is conditional with its exact byte
    exclusions published; absence preserves strict comparison.

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

    ``root_buffer_domains`` carries explicit root argument-buffer/frame
    disjointness predicates into auxiliary return proofs. This mode binds all
    nested execution to root inputs from the start, without reusable generic
    callee summaries. Predicates remain in the final document's obligations;
    complete comparisons publish the caller's ABI premise and per-call
    ``return_buffer_proofs``. No store is removed from memory observations.

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
        root_buffer_domains=root_buffer_domains,
        root_memory_bindings=root_memory_bindings,
        compose_stats=compose_stats,
        external_bindings=bind_project_imports(project, external_contracts),
    )
    buffer_obligations = [item.obligation(depth) for item, depth in root_buffer_domains]
    memory_obligations = [item.domain.obligation() for item in root_memory_bindings]
    final_state = _compose_root(session, entry)
    _check_compose_deadline(session.compose_stats)
    observed = tuple(dict.fromkeys(
        (*outputs, *PRESERVED_OUTPUTS, "eip", "memory", "io", *X87_REGISTER_NAMES)))
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
        materialized[name] = materialize_term(
            term, assignments=assignments, memo=memo, term_cache=term_cache
        )
    document = {
        "inputs": input_items(
            list(materialized.values()) + [
                obligation.get("predicate")
                for obligation in [*session.x87_obligations, *buffer_obligations, *memory_obligations]
            ],
            assignments,
        ),
        "outputs": materialized,
        "assignments": assignments,
        "blocks_composed": session.compositions,
        "blocks_lifted": session.blocks_lifted,
        "inlined_calls": session.inlined_calls,
        "repeat_sites": [
            {"entry": hex(block.address), "summary": block.part["summary"]}
            for blocks in session.blocks.values() for block in blocks.values()
            if isinstance(block.part.get("summary"), dict) and block.part["summary"].get("kind") == "repeat_string"
        ],
        "x87_sites": [
            {"entry": hex(block.address), "summary": block.part["summary"]}
            for blocks in session.blocks.values() for block in blocks.values()
            if isinstance(block.part.get("summary"), dict) and block.part["summary"].get("premises")
        ],
        "obligations": [dict(obligation) for obligation in [*session.x87_obligations, *buffer_obligations, *memory_obligations]],
        "return_buffer_proofs": session.return_buffer_proofs,
        "root_buffer_domains": buffer_obligations,
        "root_memory_domains": memory_obligations,
        "return_targets_proved": session.return_targets_proved,
        "call_sites": session.call_sites,
        "constant_branch_proofs": session.constant_branch_proofs,
        "unreachable_exception_proofs": session.unreachable_exception_proofs,
        "tail_transfers": session.tail_transfers,
        "tail_sites": session.tail_sites,
        "block_lift_retries": [
            retry.to_document() for retry in session.block_lift_retries
        ],
        "root_bound_retry": session.root_bound_inputs and not session.external_bindings and not root_buffer_domains
        and not root_memory_bindings,
        "root_bound_external_calls": bool(session.external_bindings),
        "external_sites": session.external_sites,
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
    external_contracts: tuple[Flat32ExternalCall, ...] = (),
    root_buffer_domains: tuple[tuple[Flat32StackDisjointBuffer, int], ...] = (),
    root_memory_bindings: tuple[Flat32EntryMemoryBinding, ...] = (),
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
            external_contracts=external_contracts,
            root_buffer_domains=root_buffer_domains,
            root_memory_bindings=root_memory_bindings,
        )
    except CallCompositionRefusal as error:
        if error.evidence is None and error.location is None:
            raise
        raise CallCompositionRefusal(
            str(error),
            evidence=replace(error.evidence, side=side) if error.evidence is not None else None,
            location=replace(error.location, side=side, root_entry=entry) if error.location is not None else None,
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
            "constant (relocated code or data addresses); the map is caller-supplied evidence, not a "
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


def _composition_refusal_report(
    error: CallCompositionRefusal, entry_domain: Flat32ProofDomain | None,
) -> dict[str, Any]:
    """Retain domain premises, return-proof failures and exact stopping sites."""
    report = _domain_labelled_refusal(str(error), entry_domain)
    if error.evidence is not None:
        report["return_proof_failure"] = error.evidence.to_document()
    if error.location is not None:
        report["refusal_location"] = error.location.to_document()
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


def _block_x87_premises(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect each distinct declared x87 premise record from a composed body.

    Dedup uses the whole serialized record — two sites or policies sharing a
    ``kind`` but different effects/predicates must never overwrite each other.
    """
    premises: dict[str, dict[str, Any]] = {}
    for site in summary.get("x87_sites", ()):
        for premise in site.get("summary", {}).get("premises", ()):
            premises.setdefault(json.dumps(premise, sort_keys=True), premise)
    return list(premises.values())


def _bound_x87_obligations(*summaries: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect bound per-site obligation records, keeping typed predicates."""
    bound: list[dict[str, Any]] = []
    for side, summary in zip(("oracle", "candidate"), summaries, strict=True):
        for obligation in summary.get("obligations", ()) or ():
            if isinstance(obligation, dict) and obligation.get("kind") == "x87_pending_check":
                bound.append({"side": side, **obligation})
    return bound


def _record_x87_premises(
    comparison: dict[str, Any],
    oracle_summary: dict[str, Any], candidate_summary: dict[str, Any],
) -> None:
    """Publish all declared policies and bound checking-instruction premises.

    The shared SSA solver enforces these predicates and verifies the domain
    is nonempty before producing a proof or countermodel. Do not re-evaluate
    them with a second, partial interpreter: SSA shift widths and signed
    comparisons must have the same meaning in validation and publication.
    """
    records = [*_block_x87_premises(oracle_summary), *_block_x87_premises(candidate_summary)]
    obligations = _bound_x87_obligations(oracle_summary, candidate_summary)
    if not records and not obligations:
        return
    assumption = {
        "kind": "declared_x87_premises",
        "premises": records,
        "obligations": obligations,
    }
    comparison["x87_assumptions"] = assumption
    if comparison.get("status") == "passed":
        comparison.update(status="conditional", reason="declared_x87_premises", assumptions=assumption)
    elif comparison.get("status") == "conditional":
        existing = comparison.get("assumptions")
        if isinstance(existing, dict):
            comparison["assumptions"] = {**existing, "declared_x87_premises": assumption}
        else:
            comparison["assumptions"] = {"prior": existing, "declared_x87_premises": assumption}


def _discovered_indirect_cell_obligations(*summaries: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect seeded indirect-call cell premises, tagged with their side."""
    bound: list[dict[str, Any]] = []
    for side, summary in zip(("oracle", "candidate"), summaries, strict=True):
        for obligation in summary.get("obligations", ()) or ():
            if (
                isinstance(obligation, dict)
                and obligation.get("provenance") == "discovered_indirect_target_bytes"
            ):
                bound.append({"side": side, **obligation})
    return bound


def _record_indirect_cell_premises(
    comparison: dict[str, Any],
    oracle_summary: dict[str, Any], candidate_summary: dict[str, Any],
) -> None:
    """Publish image-derived entry-memory cell premises as disclosed assumptions.

    A deferred indirect call whose selector preserved a literal global read
    retried composition under an explicit root-entry premise naming the image
    bytes at that cell.  The premise is unproved: every verdict reached under
    it is ``conditional`` and the record carries side/address/value/site so a
    corrupted cell stays a mismatch instead of a silent pass.
    """
    obligations = _discovered_indirect_cell_obligations(oracle_summary, candidate_summary)
    if not obligations:
        return
    assumption = {
        "kind": "discovered_indirect_target_bytes",
        "obligations": obligations,
        "scope": (
            "canonical root entry memory only; image-derived disclosed premise, "
            "not an immutability claim"
        ),
    }
    comparison["indirect_cell_assumptions"] = assumption
    if comparison.get("status") == "passed":
        comparison.update(
            status="conditional",
            reason="discovered_indirect_target_bytes",
            assumptions=assumption,
        )
    elif comparison.get("status") == "conditional":
        existing = comparison.get("assumptions")
        if isinstance(existing, dict):
            comparison["assumptions"] = {
                **existing, "discovered_indirect_target_bytes": assumption}
        else:
            comparison["assumptions"] = {
                "prior": existing, "discovered_indirect_target_bytes": assumption}


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
    deadline: float = comparison_deadline(timeout_ms, total_deadline)
    if not math.isfinite(deadline):
        raise CallCompositionRefusal("invalid_total_deadline")
    if time.monotonic() >= deadline:
        raise CallCompositionRefusal("compose_budget_exceeded")
    return deadline


def _record_external_premises(
    comparison: dict[str, Any], contracts: tuple[Flat32ExternalCall, ...],
    oracle_summary: dict[str, Any], candidate_summary: dict[str, Any],
) -> None:
    """Publish premises only for used external summaries, preserving native witnesses."""
    if contracts and (oracle_summary["external_sites"] or candidate_summary["external_sites"]):
        external_premise = {
            "kind": "declared_external_call_contracts",
            "contracts": [contract.declared_fields() for contract in contracts],
            "oracle_sites": oracle_summary["external_sites"],
            "candidate_sites": candidate_summary["external_sites"],
        }
        comparison["external_call_assumptions"] = external_premise
        if comparison.get("status") == "passed":
            comparison.update(status="conditional", reason="declared_external_call_contracts", assumptions=external_premise)
        elif comparison.get("status") == "conditional":
            comparison["assumptions"] = {"prior": comparison.get("assumptions"), "external_calls": external_premise}
        elif proof_status_from_legacy(comparison.get("status")) is ProofStatus.COUNTEREXAMPLE:
            # An arbitrary external-memory countermodel is not a concrete OS failure.
            comparison.update(status="refused", reason="opaque_external_call_countermodel")


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
    abi_observation: Flat32AbiObservation | None = None,
    external_contracts: tuple[Flat32ExternalCall, ...] = (),
) -> dict[str, Any]:
    """Compare two complete flat32 functions, inlining proved direct calls.

    Each side is lifted from its own project over its own declared byte ranges
    and composed independently, so a strict verdict is a real equality proof:
    ``passed`` needs no paired-call assumptions and a changed callee changes
    the caller's composed semantics directly.

    ``external_contracts`` is an opt-in shared declaration for returning PE
    imports. Each image independently binds its actual IAT slots and proves
    live-target preservation. Success is conditional and publishes both sets
    of sites plus the full contract. Opaque-effect countermodels are refused
    as inconclusive, never reported as witnessed operating-system failures.

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

    Completed summaries carry ``ProofScope.COMPLETE_FUNCTION`` even when
    neither root contains a call. Every entry-to-return path has been
    composed; their result is not a cutpoint-only induction obligation.

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
    outputs = observation_outputs(outputs, abi_observation)
    root_buffer_domains = tuple((item, abi_observation.private_stack_bytes)
        for item in abi_observation.stack_disjoint_buffers) if abi_observation is not None else ()
    normalization = _normalization_map(candidate_normalization)
    if entry_domain is not None and not isinstance(entry_domain, Flat32ProofDomain):
        return _domain_labelled_refusal("invalid_entry_domain", None)
    try:
        import_slots = import_slot_correspondence(oracle, candidate, external_contracts)
        _merge_import_slots(normalization, import_slots)
        memory_ranges = abi_observation.entry_memory_ranges if abi_observation is not None else ()
        oracle_bindings = _entry_memory_bindings(memory_ranges, {})
        candidate_bindings = _entry_memory_bindings(memory_ranges, normalization)
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
            external_contracts=external_contracts,
            root_buffer_domains=root_buffer_domains,
            root_memory_bindings=oracle_bindings,
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
            external_contracts=external_contracts,
            root_buffer_domains=root_buffer_domains,
            root_memory_bindings=candidate_bindings,
        )
        oracle_summary, candidate_summary, abi_premise = apply_completed_observation(
            oracle_summary, candidate_summary, abi_observation,
        )
        oracle_summary = bind_direction_input(
            oracle_summary, architecture_name=oracle.arch.name, compose_stats={"deadline": deadline},
        )
        candidate_summary = bind_direction_input(
            candidate_summary, architecture_name=candidate.arch.name, compose_stats={"deadline": deadline},
        )
        _stamp_normalization(candidate_summary, normalization)
        oracle_summary = simplify_preserved_root_reads(
            oracle_summary,
            normalize=lambda value, width: value,
            check_budget=lambda: _check_compose_deadline({"deadline": deadline}),
        )
        candidate_summary = simplify_preserved_root_reads(
            candidate_summary,
            normalize=lambda value, width: S._normalized_constant_value(
                value, width=width, document=candidate_summary),
            check_budget=lambda: _check_compose_deadline({"deadline": deadline}),
        )
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
        return _composition_refusal_report(error, entry_domain)
    except S.LowerFailure as error:
        return _domain_labelled_refusal(error.reason, entry_domain)
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
    comparison["import_slot_correspondence"] = {
        "source": "loaded_pe_import_metadata_exact_dll_export_identity",
        "slots": {hex(candidate): hex(oracle) for candidate, oracle in import_slots.items()},
        "live_pointer_equality_proved": False,
    }
    _record_x87_premises(comparison, oracle_summary, candidate_summary)
    _record_indirect_cell_premises(comparison, oracle_summary, candidate_summary)
    record_abi_observation(comparison, abi_premise)
    _record_external_premises(comparison, external_contracts, oracle_summary, candidate_summary)
    if time.monotonic() >= deadline:
        return _domain_labelled_refusal("compose_budget_exceeded", entry_domain)
    encoded: dict[str, Any] = encode_bound_predicates({
        **comparison,
        "proof_scope": ProofScope.COMPLETE_FUNCTION,
        "root_read_preservation": {"oracle": oracle_summary.get("root_read_preservation", []),
                                   "candidate": candidate_summary.get("root_read_preservation", [])},
        "return_buffer_proofs": {"oracle": oracle_summary["return_buffer_proofs"],
                                 "candidate": candidate_summary["return_buffer_proofs"]},
        "architectural_input_bindings": {
            "oracle": oracle_summary.get("architectural_input_bindings", {}),
            "candidate": candidate_summary.get("architectural_input_bindings", {}),
        },
        "oracle_blocks_composed": oracle_summary["blocks_composed"],
        "candidate_blocks_composed": candidate_summary["blocks_composed"],
        "oracle_inlined_calls": oracle_summary["inlined_calls"],
        "candidate_inlined_calls": candidate_summary["inlined_calls"],
        "oracle_repeat_summaries": len(oracle_summary["repeat_sites"]),
        "candidate_repeat_summaries": len(candidate_summary["repeat_sites"]),
        "repeat_sites": {"oracle": oracle_summary["repeat_sites"], "candidate": candidate_summary["repeat_sites"]},
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
        "unreachable_exception_proofs": {
            "oracle": oracle_summary["unreachable_exception_proofs"],
            "candidate": candidate_summary["unreachable_exception_proofs"],
        },
        "constant_branch_proofs": {
            "oracle": oracle_summary["constant_branch_proofs"],
            "candidate": candidate_summary["constant_branch_proofs"],
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
    })
    return encoded


def _entry_memory_bindings(
    ranges: tuple[Flat32EntryMemoryRange, ...], normalization: dict[int, int],
) -> tuple[Flat32EntryMemoryBinding, ...]:
    """Bind singleton root bytes to an unambiguous side-local coordinate."""
    bindings = []
    for item in ranges:
        if item.minimum != item.maximum:
            continue
        candidates = [address for address, original in normalization.items() if original == item.address]
        if len(candidates) > 1:
            raise CallCompositionRefusal("ambiguous_entry_memory_binding")
        address = candidates[0] if candidates else item.address
        bindings.append(Flat32EntryMemoryBinding(item, address))
    return tuple(bindings)


def _merge_import_slots(normalization: dict[int, int], slots: dict[int, int]) -> None:
    """Extend relocation only when declared and metadata-derived identities agree."""
    for candidate, oracle in slots.items():
        if candidate in normalization and normalization[candidate] != oracle:
            raise CallCompositionRefusal("conflicting_import_slot_correspondence")
        normalization[candidate] = oracle
