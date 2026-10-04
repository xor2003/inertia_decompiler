"""Staged real16 macro-path row composition and masked discharge helpers.

Layer: dosunit relational macro-step proof.
Responsibility: compose concatenated frontier paths through the production
``compose_region`` transition, extract join guards from the real control
term, build masked full-state rows and discharge one paired transition with
masked-state and per-side endpoint consistency checks. All solver results
stay cutpoint-scoped; refusals are typed through ``MacroStepRefusal``.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit import region_path_terms as T
from tools.dosunit import straightline_ssa as S
from tools.dosunit.macro_step_contracts import (
    MacroEndpointKind,
    MacroObligation,
    MacroStepReason,
    MacroStepRefusal,
    MacroTransitionProof,
)
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.proof_scope import ProofScope, admit_scope_status
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    initial_state,
    materialize_function,
    prove_terms_equal,
    term_nodes,
)
from tools.dosunit.real16_region_transitions import compose_region

_CONTROL_DROP = frozenset({"ip", "control_ip"})


def compose_concat(
    session: ComposeSession, contexts: dict[str, FunctionCtx], ctx: FunctionCtx,
    paths: tuple[Any, ...], limit: int, *,
    incoming: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], T.Term]:
    """Compose one concatenated frontier path and its exact select guard.

    Each inter-region join guard is read from the real composed control term;
    ``compose_region`` re-pins the physical head at every region entry exactly
    as it does for the production rows, preserving per-member progress,
    call boundaries and cutpoint-domain checks.
    """
    state = initial_state() if incoming is None else dict(incoming)
    guard = T.guard_true()
    first = True
    for path in paths:
        for region in path.regions:
            if not first:
                join = T.path_guard_term(state["control_ip"], region.members[0])
                if join is None:
                    raise MacroStepRefusal(
                        MacroStepReason.MACRO_GUARD_UNRESOLVED,
                        {"head": region.members[0]},
                    )
                guard = T.guard_and(guard, join)
            first = False
            state = compose_region(session, contexts, ctx, region, incoming=state)
            if term_nodes(state, limit) > limit:
                raise MacroStepRefusal(
                    MacroStepReason.MACRO_TERM_LIMIT, {"counter": "term_nodes"},
                )
    last = paths[-1]
    if last.end_kind is MacroEndpointKind.CONTINUING:
        end_guard = T.path_guard_term(state["control_ip"], last.end_head)
        if end_guard is None:
            raise MacroStepRefusal(
                MacroStepReason.MACRO_GUARD_UNRESOLVED, {"end": last.end_head},
            )
        guard = T.guard_and(guard, end_guard)
    return state, guard


def _endpoint_ok(
    state: dict[str, dict[str, Any]], end_head: int, guard: T.Term,
) -> T.Term:
    """Per-side ``guard -> (control == paired head and ip == trunc control)``."""
    projection = {"op": "trunc", "width": 16, "args": [state["control_ip"]]}
    return T.endpoint_consistency_term(
        state["control_ip"], end_head, guard,
        extra_predicates=(T.guard_eq(state["ip"], projection),),
    )


def _masked_outputs(
    state: dict[str, dict[str, Any]], guard: T.Term, end_kind: MacroEndpointKind,
) -> dict[str, T.Term]:
    """Mask the complete observable state; returns keep physical control."""
    if end_kind is MacroEndpointKind.RETURN:
        return T.masked_state(state, guard)
    return T.masked_state(state, guard, drop_names=_CONTROL_DROP)


def _compare_masked(
    index: int, left_out: dict[str, T.Term], right_out: dict[str, T.Term],
    sessions: tuple[ComposeSession, ComposeSession], limits: Real16CallLimits,
    constraints: list[dict[str, Any]], timeout_ms: int,
) -> tuple[ProofStatus, dict[str, Any]]:
    """Materialize both masked states and discharge the solver comparison."""
    left_summary = materialize_function(f"oracle:mp_{index}", left_out)
    right_summary = materialize_function(f"candidate:mp_{index}", right_out)
    gate = S._ssa_solver_gate(
        left_summary, right_summary, max_solver_assignments=limits.max_solver_assignments,
        max_solver_inputs=limits.max_solver_inputs,
        max_solver_memory_stores=limits.max_solver_memory_stores,
    )
    compared: dict[str, Any] = gate if gate is not None else S._compare_functions(
        left_summary, right_summary,
        timeout_ms=sessions[0].remaining_ms(timeout_ms), input_constraints=constraints,
    )
    status = proof_status_from_legacy(compared.get("status")) or ProofStatus.UNKNOWN
    status = admit_scope_status(status, ProofScope.CUTPOINT_SIMULATION)
    if status is not ProofStatus.PROVED or compared.get("skipped_layout_outputs"):
        status = ProofStatus.UNKNOWN
    return status, compared


def discharge_pair(
    index: int, oracle_paths: tuple[Any, ...], candidate_paths: tuple[Any, ...],
    oracle_state: dict[str, dict[str, Any]], oracle_guard: T.Term,
    candidate_state: dict[str, dict[str, Any]], candidate_guard: T.Term,
    sessions: tuple[ComposeSession, ComposeSession], limits: Real16CallLimits,
    constraints: list[dict[str, Any]], timeout_ms: int,
) -> tuple[MacroTransitionProof, int, int]:
    """Masked full-state equality plus per-side endpoint consistency."""
    end_kind = oracle_paths[-1].end_kind
    facts = failures = 0
    obligations = [MacroObligation.PATH_GUARD_EQUALITY, MacroObligation.MASKED_STATE_EQUALITY]
    diagnostics: dict[str, object] = {"guard_status": ProofStatus.PROVED.value}
    left_out = _masked_outputs(oracle_state, oracle_guard, end_kind)
    right_out = _masked_outputs(candidate_state, candidate_guard, end_kind)
    status, compared = _compare_masked(
        index, left_out, right_out, sessions, limits, constraints, timeout_ms,
    )
    diagnostics["state_compare"] = compared
    facts += 1
    if status is not ProofStatus.PROVED:
        failures += 1
    if end_kind is MacroEndpointKind.CONTINUING:
        oracle_ok = _endpoint_ok(oracle_state, oracle_paths[-1].end_head, oracle_guard)
        candidate_ok = _endpoint_ok(
            candidate_state, candidate_paths[-1].end_head, candidate_guard,
        )
        for side, ok_term in (("oracle", oracle_ok), ("candidate", candidate_ok)):
            endpoint_status = prove_terms_equal(
                ok_term, T.guard_true(), sessions[0].remaining_ms(timeout_ms),
                input_constraints=constraints,
            )
            diagnostics[f"{side}_endpoint"] = endpoint_status.value
            facts += 1
            if endpoint_status is not ProofStatus.PROVED:
                failures += 1
                status = ProofStatus.UNKNOWN
        obligations.append(MacroObligation.ENDPOINT_CONSISTENCY)
    oracle_members = tuple(
        member for path in oracle_paths for region in path.regions for member in region.members
    )
    candidate_members = tuple(
        member for path in candidate_paths for region in path.regions for member in region.members
    )
    obligations.append(MacroObligation.POSITIVE_PROGRESS)
    row = MacroTransitionProof(
        index, oracle_members, candidate_members, len(oracle_paths), len(candidate_paths),
        end_kind, 0, status, ProofStatus.PROVED, tuple(obligations), diagnostics,
    )
    return row, facts, failures
