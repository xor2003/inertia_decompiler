"""Real16 bounded macro-step proof over actual MZ lowering.

Layer: dosunit relational macro-step proof.
Responsibility: consume the production real16 region machinery, expand
finite frontier paths at the paired entry macro-cut, and discharge each
proposed unequal-step transition with the same composed-state, Z3 guard and
masked full-state checks the row proof already owns. Region composition uses
``compose_region`` unchanged; the staged layer threads its incoming state
across a concatenated path and extracts each join guard from the real
control term. Every refusal is typed; nothing here weakens the production
contracts, and no proposal is treated as proof.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit import macro_step_pairing as pairing
from tools.dosunit import real16_macro_rows as rows
from tools.dosunit import region_path_terms as T
from tools.dosunit import straightline_ssa as S
from tools.dosunit.macro_step_contracts import (
    MacroCoverageProof,
    MacroDirection,
    MacroProofReason,
    MacroStepAttempt,
    MacroStepLimits,
    MacroStepProof,
    MacroStepReason,
    MacroStepRefusal,
    MacroTransitionProof,
)
from tools.dosunit.paired_region_graph import RegionGraphRefusal
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.proof_scope import ProofScope
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
    prove_terms_equal,
)
from tools.dosunit.real16_call_evidence import (
    check_lowering_refusals,
    dependencies_for,
    group_lookup,
    reachable_call_ids,
)
from tools.dosunit.real16_loop_invariants import loop_entry_domain
from tools.dosunit.real16_region_transitions import region_nodes

_REASON_PROVED = MacroProofReason.PROVED
_REASON_UNPROVED = MacroProofReason.UNPROVED


def _common_domain(left: FunctionCtx, right: FunctionCtx) -> tuple[int, int]:
    """Require a nonempty selector interval admitted by both physical entries."""
    original, rebuilt = loop_entry_domain(left), loop_entry_domain(right)
    minimum = max(original.minimum_cs, rebuilt.minimum_cs)
    maximum = min(original.maximum_cs, rebuilt.maximum_cs)
    if minimum > maximum:
        raise Real16CallRefusal("code_entry_relation_empty")
    return minimum, maximum


def _coverage(
    side: str, guards: list[T.Term], sessions: tuple[ComposeSession, ComposeSession],
    constraints: list[dict[str, Any]], timeout_ms: int,
) -> tuple[MacroCoverageProof, int, int]:
    """Solver-discharge complete disjoint coverage of one side's cut states."""
    facts = failures = 0
    covered = T.guard_false()
    for guard in guards:
        covered = T.guard_or(covered, guard)
    completeness = prove_terms_equal(
        covered, T.guard_true(), sessions[0].remaining_ms(timeout_ms),
        input_constraints=constraints,
    )
    facts += 1
    disjoint_pairs = disjoint_failures = 0
    for left_index, left_guard in enumerate(guards):
        for right_guard in guards[left_index + 1:]:
            disjoint = prove_terms_equal(
                T.guard_and(left_guard, right_guard), T.guard_false(),
                sessions[0].remaining_ms(timeout_ms), input_constraints=constraints,
            )
            disjoint_pairs += 1
            facts += 1
            if disjoint is not ProofStatus.PROVED:
                disjoint_failures += 1
                failures += 1
    if completeness is not ProofStatus.PROVED:
        failures += 1
    proof = MacroCoverageProof(
        side, completeness, disjoint_pairs, disjoint_failures,
        {"guards": len(guards)},
    )
    return proof, facts, failures


def _pair_fast_path(
    path_index: int, pairing_candidate: Any, oracle_is_fast: bool,  # noqa: ANN401
    contexts: tuple[dict[str, FunctionCtx], dict[str, FunctionCtx]],
    functions: tuple[FunctionCtx, FunctionCtx],
    sessions: tuple[ComposeSession, ComposeSession],
    fast_session: ComposeSession, slow_session: ComposeSession,
    limits: Real16CallLimits, constraints: list[dict[str, Any]],
    timeout_ms: int, macro_limits: MacroStepLimits, resolved: int,
) -> tuple[MacroTransitionProof | None, T.Term | None, T.Term | None, T.Term, int, int]:
    """Compose the fast path, then discharge the first guard-equal slow concat.

    Returns the transition row, the oracle-side and candidate-side guard
    terms, the fast path's own guard term, plus solver fact/failure counts.
    A ``None`` row means no slow concat proved guard-equal; the caller
    decides whether the fast path is provably infeasible or a typed refusal.
    """
    facts = failures = 0
    fast_state, fast_guard = rows.compose_concat(
        fast_session, contexts[0], functions[0], (pairing_candidate.fast_path,),
        macro_limits.max_term_nodes,
    )
    for slow_concat in pairing_candidate.slow_concats:
        if resolved + 1 > macro_limits.max_transitions:
            raise MacroStepRefusal(MacroStepReason.MACRO_TRANSITION_LIMIT)
        slow_state, slow_guard = rows.compose_concat(
            slow_session, contexts[1], functions[1], slow_concat,
            macro_limits.max_term_nodes,
        )
        equal = prove_terms_equal(
            fast_guard, slow_guard, fast_session.remaining_ms(timeout_ms),
            input_constraints=constraints,
        )
        facts += 1
        if equal is not ProofStatus.PROVED:
            continue
        if oracle_is_fast:
            oracle_paths, candidate_paths = (pairing_candidate.fast_path,), slow_concat
            oracle_state, oracle_guard = fast_state, fast_guard
            candidate_state, candidate_guard = slow_state, slow_guard
        else:
            oracle_paths, candidate_paths = slow_concat, (pairing_candidate.fast_path,)
            oracle_state, oracle_guard = slow_state, slow_guard
            candidate_state, candidate_guard = fast_state, fast_guard
        row, row_facts, row_failures = rows.discharge_pair(
            path_index, oracle_paths, candidate_paths,
            oracle_state, oracle_guard, candidate_state, candidate_guard,
            sessions=sessions, limits=limits, constraints=constraints,
            timeout_ms=timeout_ms,
        )
        return row, oracle_guard, candidate_guard, fast_guard, facts + row_facts, failures + row_failures
    return None, None, None, fast_guard, facts, failures


def _attempt_proposal(
    proposal: Any, left_contexts: dict[str, FunctionCtx], left: FunctionCtx,  # noqa: ANN401
    right_contexts: dict[str, FunctionCtx], right: FunctionCtx,
    sessions: tuple[ComposeSession, ComposeSession], limits: Real16CallLimits,
    constraints: list[dict[str, Any]], timeout_ms: int, macro_limits: MacroStepLimits,
) -> MacroStepAttempt:
    """Resolve one directional proposal into discharged or refused rows."""
    oracle_is_fast = proposal.direction is MacroDirection.CANDIDATE_SLOWER
    contexts = (left_contexts, right_contexts) if oracle_is_fast else (right_contexts, left_contexts)
    functions = (left, right) if oracle_is_fast else (right, left)
    fast_session, slow_session = sessions if oracle_is_fast else (sessions[1], sessions[0])
    rows: list[MacroTransitionProof] = []
    facts = failures = 0
    oracle_guards: list[T.Term] = []
    candidate_guards: list[T.Term] = []
    resolved = 0
    try:
        for path_index, pairing_candidate in enumerate(proposal.pairings):
            row, o_guard, c_guard, fast_guard, row_facts, row_failures = _pair_fast_path(
                path_index, pairing_candidate, oracle_is_fast, contexts, functions,
                sessions, fast_session, slow_session, limits, constraints,
                timeout_ms, macro_limits, resolved,
            )
            facts += row_facts
            failures += row_failures
            if row is not None:
                rows.append(row)
                assert o_guard is not None and c_guard is not None
                oracle_guards.append(o_guard)
                candidate_guards.append(c_guard)
                resolved += 1
                continue
            facts += 1
            infeasible = prove_terms_equal(
                fast_guard, T.guard_false(), fast_session.remaining_ms(timeout_ms),
                input_constraints=constraints,
            )
            if infeasible is ProofStatus.PROVED:
                continue  # Provably infeasible frontier path: recorded, never paired.
            failures += 1
            raise MacroStepRefusal(
                MacroStepReason.MACRO_PATH_UNPAIRED if infeasible is not ProofStatus.UNKNOWN
                else MacroStepReason.MACRO_GUARD_UNRESOLVED,
                {"path": path_index},
            )
    except MacroStepRefusal as error:
        counters = FactCounters(facts, facts, facts, facts, failures + 1)
        return MacroStepAttempt(
            proposal.direction, ProofStatus.UNKNOWN, tuple(rows), (), counters,
            error.reason, str(error.detail),
        )
    coverage: list[MacroCoverageProof] = []
    for side, guards in (("oracle", oracle_guards), ("candidate", candidate_guards)):
        proof, cover_facts, cover_failures = _coverage(
            side, guards, sessions, constraints, timeout_ms,
        )
        coverage.append(proof)
        facts += cover_facts
        failures += cover_failures
    status = ProofStatus.PROVED if rows and not failures else ProofStatus.UNKNOWN
    counters = FactCounters(facts, facts, facts, facts, failures)
    return MacroStepAttempt(
        proposal.direction, status, tuple(rows), tuple(coverage), counters, None, "",
    )


def compare_real16_macro(
    oracle: dict[str, Any], candidate: dict[str, Any], function: str, *,
    candidate_function: str | None = None, limits: Real16CallLimits | None = None,
    macro_limits: MacroStepLimits | None = None, timeout_ms: int = 30000,
) -> MacroStepProof:
    """Staged bounded unequal-step proof for actual real16 MZ functions.

    Runs the production admission and region-node formation, proposes entry-cut
    macro-step pairings, and discharges every transition under
    CUTPOINT_SIMULATION scope with retained failed attempts and closed fact
    counters. This is not a complete-function or initialized-image claim.
    """
    bound = limits or Real16CallLimits()
    macro_bound = macro_limits or MacroStepLimits()
    timeout_ms = max(timeout_ms, 1)
    attempts: list[MacroStepAttempt] = []
    search_status = None
    search_refusal = None
    try:
        left_contexts, left = group_lookup(oracle, function)
        right_contexts, right = group_lookup(candidate, candidate_function or function)
        check_lowering_refusals(oracle, reachable_call_ids(left_contexts, left) | {left.function_id})
        check_lowering_refusals(candidate, reachable_call_ids(right_contexts, right) | {right.function_id})
        domain = _common_domain(left, right)
        constraints = [{"name": "cs", "kind": "unsigned_range", "min": domain[0], "max": domain[1]}]
        sessions = (ComposeSession.with_deadline(bound, timeout_ms),
                    ComposeSession.with_deadline(bound, timeout_ms))
        search = pairing.propose_macro_steps(
            region_nodes(left, sessions[0]), region_nodes(right, sessions[1]),
            left.entry_linear, right.entry_linear, limits=macro_bound,
            deadline_seconds=sessions[0].remaining_ms(timeout_ms) / 1000.0,
        )
        search_status, search_refusal = search.status, search.refusal
        for proposal in search.proposals:
            attempts.append(_attempt_proposal(
                proposal, left_contexts, left, right_contexts, right,
                sessions, bound, constraints, timeout_ms, macro_bound,
            ))
            if attempts[-1].status is ProofStatus.PROVED:
                break
        dependencies = ({"side": "oracle", **dependencies_for(oracle, function)},
                        {"side": "candidate", **dependencies_for(candidate, candidate_function or function)})
    except MacroStepRefusal as error:
        return MacroStepProof(
            ProofStatus.UNKNOWN, error.reason, None, (),
            FactCounters(1, 1, 1, 1, 1), tuple(attempts), search_status, error.reason,
            ProofScope.CUTPOINT_SIMULATION, str(error.detail),
        )
    except RegionGraphRefusal as error:
        return MacroStepProof(
            ProofStatus.UNKNOWN, error.reason, None, (),
            FactCounters(1, 1, 1, 1, 1), tuple(attempts), search_status,
            MacroStepReason.MACRO_ADMISSION, ProofScope.CUTPOINT_SIMULATION,
            error.reason.value,
        )
    except (Real16CallRefusal, S.LowerFailure) as error:
        return MacroStepProof(
            ProofStatus.UNKNOWN, MacroStepReason.MACRO_ADMISSION, None, (),
            FactCounters(1, 1, 1, 1, 1), tuple(attempts), search_status,
            MacroStepReason.MACRO_ADMISSION, ProofScope.CUTPOINT_SIMULATION, str(error),
        )
    if not attempts:
        return MacroStepProof(
            ProofStatus.UNKNOWN, _REASON_UNPROVED, None, (),
            FactCounters(1, 1, 1, 1, 1), (), search_status, search_refusal,
            ProofScope.CUTPOINT_SIMULATION, "no_complete_proposal",
        )
    selected = attempts[-1]
    return MacroStepProof(
        selected.status,
        _REASON_PROVED if selected.status is ProofStatus.PROVED else _REASON_UNPROVED,
        selected.direction, selected.transitions, selected.counters, tuple(attempts),
        search_status, None if selected.status is ProofStatus.PROVED else selected.refusal,
        ProofScope.CUTPOINT_SIMULATION,
        graph_evidence={"dependencies": list(dependencies)},
    )
