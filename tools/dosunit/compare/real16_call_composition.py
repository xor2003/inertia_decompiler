"""Layer: tools/dosunit real-mode comparator helpers.

Responsibility: public entry point for bounded real16 call
composition.  ``compare_real16_with_calls`` composes non-recursive
acyclic direct calls and solver-admitted bounded finite indirect calls on
both sides using actual SSA terms (see
``real16_call_execution``), materializes the final full-state summaries, and
compares them through ``_compare_functions``.  Any incomplete evidence —
unresolved call targets, missing blocks, recursion, loops, unsupported
control flow or external effects, unproved return targets/CS, or exhausted
budgets — yields ``refused`` rather than a partial comparison.  Documents
must be fresh full-state lowerings (``output_regs`` covering
``INTERNAL_STATE_REGS``) so full-width return ``control_ip`` terms are observable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import (
    Real16CallLimits,
    Real16CallRefusal,
    materialize_function,
)
from tools.dosunit.compare.real16_call_evidence import dependencies_for, group_lookup
from tools.dosunit.compare.real16_call_execution import summarize
from tools.dosunit.contracts.ordered_io_environment import ORDERED_IO_PREMISE_NAME
from tools.dosunit.contracts.proof_contracts import Architecture, ProofStatus, proof_status_from_legacy
from tools.dosunit.contracts.real16_entry_domain import code_entry_domain

if TYPE_CHECKING:
    from tools.dosunit.contracts.ordered_io_environment import OrderedIoContract


def _refusal_result(function: str, exc: Real16CallRefusal) -> dict[str, Any]:
    """Legacy-style refused result preserving the typed refusal reason."""
    return {
        "status": "refused",
        "reason": exc.reason,
        "function": function,
        "detail": exc.detail,
        "calls": {
            "inlined_calls": 0,
            "return_targets_proved": 0,
            "indirect_call_sites": 0,
            "indirect_targets_proved": 0,
        },
        "dependencies": [],
    }


def compare_real16_with_calls(
    oracle_doc: dict[str, Any],
    candidate_doc: dict[str, Any],
    function: str,
    *,
    candidate_function: str | None = None,
    timeout_ms: int = 30_000,
    limits: Real16CallLimits | None = None,
    io_model: OrderedIoContract | None = None,
) -> dict[str, Any]:
    """Compose direct calls on both sides and compare full-state summaries.

    Returns a legacy-style result: ``status``/``reason`` plus composition
    counters and dependency identities (whole-body SHA and semantic identity
    of the entry function and every transitively reached callee).
    ``candidate_function`` selects a differently-keyed candidate entry.

    ``io_model`` binds the declared ordered-I/O environment contract to both
    sides' admission and composition.  When bound, every consumed result is
    conditional on the recorded premise — the ordered event relation is an
    explicit assumption, never an unconditional proof — and incompatible or
    uncovered effects still refuse.
    """
    if io_model is not None:
        io_model.validate_for(Architecture.REAL16)
    effective_limits = limits or Real16CallLimits()
    deadline_ms = max(timeout_ms, 1)
    try:
        oracle_state, oracle_session = summarize(
            oracle_doc, function, limits=effective_limits, timeout_ms=deadline_ms,
            io_model=io_model,
        )
        candidate_state, candidate_session = summarize(
            candidate_doc,
            candidate_function or function,
            limits=effective_limits,
            timeout_ms=deadline_ms,
            io_model=io_model,
        )
    except Real16CallRefusal as exc:
        return _refusal_result(function, exc)
    except S.LowerFailure as exc:
        return {
            "status": "refused",
            "reason": "compose_budget_exceeded",
            "function": function,
            "detail": {"failure": str(exc)},
            "calls": {
                "inlined_calls": 0,
                "return_targets_proved": 0,
                "indirect_call_sites": 0,
                "indirect_targets_proved": 0,
            },
            "dependencies": [],
        }
    oracle_summary = materialize_function(f"oracle:{function}", oracle_state)
    candidate_summary = materialize_function(f"candidate:{function}", candidate_state)
    _, oracle_ctx = group_lookup(oracle_doc, function, io_model=io_model)
    _, candidate_ctx = group_lookup(
        candidate_doc, candidate_function or function, io_model=io_model
    )
    oracle_domain = code_entry_domain(oracle_ctx.entry_linear)
    candidate_domain = code_entry_domain(candidate_ctx.entry_linear)
    if oracle_domain is None or candidate_domain is None:
        return _refusal_result(function, Real16CallRefusal("code_entry_domain_unmapped"))
    minimum = max(oracle_domain.minimum_cs, candidate_domain.minimum_cs)
    maximum = min(oracle_domain.maximum_cs, candidate_domain.maximum_cs)
    if minimum > maximum:
        return _refusal_result(function, Real16CallRefusal("code_entry_relation_empty"))
    constraints = [{"name": "cs", "kind": "unsigned_range", "min": minimum, "max": maximum}]
    gate = S._ssa_solver_gate(
        oracle_summary, candidate_summary,
        max_solver_assignments=effective_limits.max_solver_assignments,
        max_solver_inputs=effective_limits.max_solver_inputs,
        max_solver_memory_stores=effective_limits.max_solver_memory_stores,
    )
    result: dict[str, Any] = gate if gate is not None else S._compare_functions(
        oracle_summary, candidate_summary, timeout_ms=deadline_ms, input_constraints=constraints,
    )
    result["function"] = function
    result["entry_domain"] = {"cs_min": minimum, "cs_max": maximum,
                              "control_width": 32, "code_offset_width": 16}
    result["calls"] = {
        "inlined_calls": oracle_session.inlined_calls + candidate_session.inlined_calls,
        "return_targets_proved": (
            oracle_session.return_targets_proved + candidate_session.return_targets_proved
        ),
        "cs_preserved_proved": (
            oracle_session.cs_preserved_proved + candidate_session.cs_preserved_proved
        ),
        "indirect_call_sites": (
            oracle_session.indirect_call_sites + candidate_session.indirect_call_sites
        ),
        "indirect_targets_proved": (
            oracle_session.indirect_targets_proved + candidate_session.indirect_targets_proved
        ),
        "compositions": (
            oracle_session.stats.get("compositions", 0)
            + candidate_session.stats.get("compositions", 0)
        ),
    }
    try:
        result["dependencies"] = [
            {
                "side": "oracle",
                **dependencies_for(
                    oracle_doc,
                    function,
                    extra_contexts=oracle_session.resolved_contexts,
                    extra_callee_ids=frozenset(oracle_session.resolved_contexts),
                    io_model=io_model,
                ),
            },
            {
                "side": "candidate",
                **dependencies_for(
                    candidate_doc,
                    candidate_function or function,
                    extra_contexts=candidate_session.resolved_contexts,
                    extra_callee_ids=frozenset(candidate_session.resolved_contexts),
                    io_model=io_model,
                ),
            },
        ]
    except Real16CallRefusal as exc:
        return _refusal_result(function, exc)
    if io_model is not None:
        # The ordered event relation is a declared premise, never proved
        # against the real device: a verdict that consumed it is conditional
        # even when every compared output matched.
        result["environment"] = {
            "premise": io_model.premise_document(),
            "relation_identity": io_model.identity_digest(),
        }
        status = proof_status_from_legacy(result.get("status"))
        if status is ProofStatus.PROVED:
            result["status"] = "conditional"
            result["reason"] = "ordered_io_environment_premise"
            status = ProofStatus.CONDITIONAL
        if status is ProofStatus.CONDITIONAL:
            result["assumptions"] = [
                *result.get("assumptions", []), ORDERED_IO_PREMISE_NAME
            ]
    return result
