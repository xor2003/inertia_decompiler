"""Discharge actual SSA effects against proposed finite recursive stack domains.

Layer: dosunit recursive invariant proof obligations (staging).
Responsibility: prove entry, PUSH/BODY preservation and POP closure independently
of recursive callee summaries. These facts cannot alone promote a component.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import z3

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import materialize_function
from tools.dosunit.recursive_proofs.stack.recursive_stack_address_comparisons import (
    AddressComparisonEvidence,
    AddressComparisonResult,
    discharge_address_comparisons,
    push_address_comparisons,
    refine_address_comparisons,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import (
    StackClause,
    StackClauseBatch,
    StackClauseEvidence,
    StackClauseKind,
    StackClauseReason,
    call_continuation_clause,
    check_continuation_argument,
    check_stack_clauses,
    required_stack_clauses,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import (
    StackObligation as StackObligation,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordDomain, StackWordLayout
from tools.dosunit.recursive_proofs.stack.recursive_stack_scalar_lemmas import (
    StackLemmaEvidence,
    StackLemmaReason,
    discharge_scalar_lemmas,
    push_scalar_candidates,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_store_coordinates import (
    StoreCoordinateEvidence,
    StoreCoordinateReason,
    StoreCoordinateResult,
    normalize_push_coordinates,
)
from tools.dosunit.register_state_relations import MachineState


class StackProofReason(StrEnum):
    """A discharged local obligation or an explicit refusal/countermodel class."""

    PROVED = "stack_obligation_discharged"
    COUNTERMODEL = "stack_cutpoint_countermodel"
    VACUOUS = "stack_domain_vacuous"
    UNKNOWN = "stack_solver_unknown"
    DEADLINE = "stack_deadline_exceeded"


@dataclass(frozen=True, slots=True)
class StackInvariantProof:
    """Local inductive evidence; no recursive function status is encoded here.

    ``expected_continuation`` retains the optional per-CALL binding the caller
    asked for: an admitted loaded continuation whose own CS-relative saved word
    must occupy the pushed slot. It survives refusals, so a rejected proof still
    reports exactly which per-call obligation was attempted.
    """

    obligation: StackObligation
    status: ProofStatus
    reason: StackProofReason
    counters: FactCounters
    elapsed_ms: int
    layout: StackWordLayout
    detail: str = ""
    countermodel: tuple[tuple[str, int], ...] = ()
    scalar_lemmas: tuple[StackLemmaEvidence, ...] = ()
    store_coordinates: tuple[StoreCoordinateEvidence, ...] = ()
    coordinate_reason: StoreCoordinateReason | None = None
    clauses: tuple[StackClauseEvidence, ...] = ()
    required_clauses: tuple[StackClauseKind, ...] = ()
    address_comparisons: AddressComparisonEvidence | None = None
    expected_continuation: int | None = None


def _state_exprs(state: MachineState, inputs: dict[str, tuple[z3.ExprRef, int]]) -> dict[str, z3.ExprRef]:
    """Encode existing full SSA effects at the established dynamic solver boundary."""
    document = materialize_function("stack:transition", state)
    assignments = {item["id"]: item for item in document["assignments"]}
    cache: dict[str, z3.ExprRef] = {}
    return {name: S._z3_term(term, document=document, inputs=inputs, z3=z3,
                            assignments=assignments, cache=cache, output_name=name)
            for name, term in document["outputs"].items()}


def _goals(domain: StackWordDomain, obligation: StackObligation, post: dict[str, z3.ExprRef],
           pointer: str, control: str, index: z3.BitVecRef,
           expected_continuation: int | None = None) -> z3.BoolRef:
    """Expose the conjunction of the same authoritative independent clauses."""
    return cast(z3.BoolRef, z3.And(*(clause.condition for clause in
                                   _goal_clauses(domain, obligation, post, pointer, control, index,
                                                 expected_continuation))))


def _goal_clauses(domain: StackWordDomain, obligation: StackObligation, post: dict[str, z3.ExprRef],
                  pointer: str, control: str, index: z3.BitVecRef,
                  expected_continuation: int | None = None) -> tuple[StackClause, ...]:
    """Require exact pointer/selector effects and every stack invariant conjunct."""
    rank, allocated = domain.rank, domain.allocated
    if obligation is StackObligation.PUSH:
        rank, allocated = domain.after_push()
    elif obligation is StackObligation.POP:
        rank = rank - 1
    memory, offset = post["memory"], post[pointer]
    if not isinstance(memory, z3.ArrayRef) or not isinstance(offset, z3.BitVecRef):
        raise ValueError("invalid stack memory/pointer sorts")
    continuing = z3.BoolVal(True)
    if obligation is StackObligation.POP:
        continuing = z3.Or(domain.allocated == domain.layout.capacity, domain.rank != 0)
    goals = [StackClause(StackClauseKind.POINTER, cast(z3.BoolRef, offset == domain.offset(rank))),
             StackClause(StackClauseKind.BOUNDS, z3.Implies(continuing, domain.bounds(rank, allocated))),
             StackClause(StackClauseKind.SLOT, z3.Implies(continuing, domain.slot_clause(memory, index, allocated))),
             StackClause(StackClauseKind.ROOT_FRAME, z3.Implies(continuing, domain.root_frame_clause(memory, allocated)))]
    if domain.stack_selector is not None:
        goals += [StackClause(StackClauseKind.STACK_SELECTOR, cast(z3.BoolRef, post["ss"] == domain.stack_selector)),
                  StackClause(StackClauseKind.CODE_SELECTOR, cast(z3.BoolRef, post["cs"] == domain.code_selector))]
    if obligation is StackObligation.POP:
        destinations = [post[control] == value for value in domain.layout.continuations]
        root_exit = z3.And(domain.rank == 0, domain.allocated != domain.layout.capacity,
                           post[control] == domain.physical_control(domain.caller_word))
        goals.append(StackClause(StackClauseKind.RETURN_TARGET, cast(z3.BoolRef, z3.Or(root_exit, z3.And(continuing, z3.Or(*destinations))))))
    if expected_continuation is not None:
        goals.append(call_continuation_clause(domain, memory, expected_continuation))
    return tuple(goals)


def prove_stack_step(
    state: MachineState, layout: StackWordLayout, obligation: StackObligation, *,
    timeout_ms: int = 30000, deadline: float | None = None,
    expected_continuation: int | None = None,
) -> StackInvariantProof:
    """Prove a local stack fact under a nonvacuous, explicit ghost invariant.

    Actual register/memory effects come from SSA. The proof never invents a
    callee post-state or grants dependency closure. Caller frame/selector and
    stack-domain premises must be included by the eventual component contract.
    A requested PUSH continuation proves its particular saved word; omission
    retains the generic global-membership contract. Original deadlines and the
    complete requested clause manifest survive every refusal.
    """
    started = time.monotonic()
    check_continuation_argument(obligation, layout, expected_continuation)
    deadline = min(deadline, started + timeout_ms / 1000) if deadline is not None else started + timeout_ms / 1000
    if deadline <= started:
        return _result(obligation, layout, StackProofReason.DEADLINE, 0, started,
                       expected_continuation=expected_continuation)
    domain, post, hypotheses, _, pointer, control, index = _encode_obligation(state, layout, obligation,
                                                                           expected_continuation)
    refusal, checks, detail = _check_nonvacuity(domain, hypotheses, deadline)
    if refusal is not None:
        return _result(obligation, layout, refusal, checks, started, detail,
                       expected_continuation=expected_continuation)
    solver = z3.Solver()
    solver.add(*hypotheses)
    scalar_lemmas: tuple[StackLemmaEvidence, ...] = ()
    coordinates: StoreCoordinateResult | None = None
    comparisons: AddressComparisonResult | None = None
    if obligation is StackObligation.PUSH:
        batch = discharge_scalar_lemmas(push_scalar_candidates(domain, index), solver, deadline=deadline)
        scalar_lemmas = batch.evidence
        checks += batch.checks
        if not batch.proved:
            refusal = StackProofReason.DEADLINE if batch.evidence[-1].reason is StackLemmaReason.DEADLINE else StackProofReason.UNKNOWN
            return _result(obligation, layout, refusal, checks, started,
                           batch.evidence[-1].detail, scalar_lemmas=scalar_lemmas,
                           expected_continuation=expected_continuation)
        memory = post["memory"]
        if not isinstance(memory, z3.ArrayRef):
            raise ValueError("invalid frame output memory sort")
        coordinates = normalize_push_coordinates(memory, domain, deadline=deadline)
        checks += coordinates.checks
        if coordinates.proved:
            # Every replacement is globally equal, so congruence retains the
            # entire native array, including arbitrary preceding body writes.
            post["memory"] = coordinates.memory
            comparisons = discharge_address_comparisons(push_address_comparisons(domain, index), deadline=deadline)
            checks += int(comparisons.evidence.attempted)
    goals = _goal_clauses(domain, obligation, post, pointer, control, index, expected_continuation)
    goals = tuple(StackClause(clause.kind, refine_address_comparisons(clause.condition, comparisons))
                  for clause in goals)
    clauses = check_stack_clauses(goals, solver, deadline=deadline)
    checks += clauses.checks
    if clauses.proved:
        return _result(obligation, layout, StackProofReason.PROVED, checks, started,
                       scalar_lemmas=scalar_lemmas, coordinates=coordinates, clauses=clauses, comparisons=comparisons,
                       expected_continuation=expected_continuation)
    failed = clauses.evidence[-1]
    values: tuple[tuple[str, int], ...] = ()
    reasons = {StackClauseReason.DEADLINE: StackProofReason.DEADLINE,
               StackClauseReason.UNKNOWN: StackProofReason.UNKNOWN,
               StackClauseReason.COUNTERMODEL: StackProofReason.COUNTERMODEL}
    if failed.reason is StackClauseReason.COUNTERMODEL:
        if clauses.model is None:
            raise ValueError("SAT stack clause must retain its native countermodel")
        values = _countermodel(clauses.model, domain, post, pointer, control)
    return _result(obligation, layout, reasons[failed.reason], checks, started, failed.detail,
                   countermodel=values, scalar_lemmas=scalar_lemmas, coordinates=coordinates, clauses=clauses, comparisons=comparisons,
                   expected_continuation=expected_continuation)


def _encode_obligation(state: MachineState, layout: StackWordLayout,
                       obligation: StackObligation,
                       expected_continuation: int | None = None) -> tuple[StackWordDomain, dict[str, z3.ExprRef],
                                                            tuple[z3.BoolRef, ...], z3.BoolRef, str, str, z3.BitVecRef]:
    """Encode the full-depth stack premise and actual SSA frame effects."""
    pointer, control = ("sp", "control_ip") if layout.segmented else ("esp", "eip")
    selected = {name: state[name] for name in ("memory", pointer, control, *(('ss', 'cs') if layout.segmented else ()))}
    document = materialize_function("stack:effect", selected)
    baseline: MachineState = {pointer: {"op": "input", "name": pointer, "width": layout.offset_bits},
                              "memory": {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}}
    if layout.segmented:
        baseline.update({name: {"op": "input", "name": name, "width": 16} for name in ("ss", "cs")})
    inputs = S._z3_inputs(materialize_function("stack:inputs", baseline), document, z3)
    ss = inputs["ss"][0] if layout.segmented else None
    cs = inputs["cs"][0] if layout.segmented else None
    if ss is not None and not isinstance(ss, z3.BitVecRef):
        raise ValueError("invalid stack selector sort")
    if cs is not None and not isinstance(cs, z3.BitVecRef):
        raise ValueError("invalid code selector sort")
    domain = StackWordDomain.create(layout, stack_selector=ss, code_selector=cs)
    memory = inputs["mem"][0]
    if not isinstance(memory, z3.ArrayRef):
        raise ValueError("invalid input memory sort")
    post = _state_exprs(selected, inputs)
    # Apply the explicit input-SP relation to effect expressions before array
    # reasoning. This is substitution of a declared hypothesis, not a guessed
    # stack relation or a narrower input domain; the premise remains below.
    pointer_relation = (inputs[pointer][0], domain.offset(domain.rank))
    post = {name: z3.simplify(z3.substitute(value, pointer_relation)) for name, value in post.items()}
    index = z3.BitVec("frame_arbitrary_proof_slot", layout.rank_bits)
    # The index is FREE, not a chosen/observed slot. UNSAT proves the output
    # clause for all indices and all ranks/frontiers. Only input instances are
    # assumed, so this is a stronger theorem than the quantified implication.
    hypotheses = [domain.local_invariant(memory, domain.rank, domain.allocated, index),
                  inputs[pointer][0] == domain.offset(domain.rank)]
    if obligation is StackObligation.INITIATION:
        hypotheses = [domain.bounds(domain.rank, domain.allocated), domain.rank == 0, domain.allocated == 0,
                      inputs[pointer][0] == domain.root_offset,
                      domain.word(memory, z3.BitVecVal(0, layout.rank_bits)) == domain.caller_word]
    else:
        hypotheses.append(domain.slot_clause(memory, domain.rank, domain.allocated))
    goal = _goals(domain, obligation, post, pointer, control, index, expected_continuation)
    return domain, post, tuple(hypotheses), goal, pointer, control, index


def _check_nonvacuity(domain: StackWordDomain, hypotheses: tuple[z3.BoolRef, ...],
                      deadline: float) -> tuple[StackProofReason | None, int, str]:
    """Establish existence independently of the unrestricted preservation check.

    A shallow witness proves only that at least one state satisfies the premise.
    A failed witness never classifies the full domain as empty: the unrestricted
    premises are then checked with only the original deadline's remainder.
    """
    substitutions = ((domain.rank, z3.BitVecVal(0, domain.layout.rank_bits)),
                     (domain.allocated, z3.BitVecVal(0, domain.layout.rank_bits + 1)))
    witness = z3.Solver()
    witness.add(*(z3.simplify(z3.substitute(clause, *substitutions)) for clause in hypotheses))
    checked = _check(witness, deadline)
    if checked is None:
        return StackProofReason.DEADLINE, 0, ""
    if checked == z3.sat:
        return None, 1, ""
    unrestricted = z3.Solver()
    unrestricted.add(*hypotheses)
    checked = _check(unrestricted, deadline)
    if checked is None:
        return StackProofReason.DEADLINE, 1, ""
    if checked == z3.sat:
        return None, 2, ""
    reason = StackProofReason.VACUOUS if checked == z3.unsat else StackProofReason.UNKNOWN
    return reason, 2, unrestricted.reason_unknown()


def _check(solver: z3.Solver, deadline: float) -> z3.CheckSatResult | None:
    """Check under only the remaining portion of the one original deadline."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        return None
    solver.set(timeout=remaining)
    return solver.check()


def _countermodel(model: z3.ModelRef, domain: StackWordDomain, post: dict[str, z3.ExprRef],
                  pointer: str, control: str) -> tuple[tuple[str, int], ...]:
    """Retain actual local values without labeling abstraction SAT as mismatch."""
    values = (("rank", domain.rank), ("allocated", domain.allocated), ("root_offset", domain.root_offset),
              ("actual_control", post[control]), ("caller_control", domain.physical_control(domain.caller_word)),
              ("actual_sp", post[pointer]))
    rows: list[tuple[str, int]] = []
    for name, value in values:
        evaluated = model.eval(value, model_completion=True)
        if not isinstance(evaluated, z3.BitVecNumRef):
            raise ValueError(f"stack countermodel value is not a concrete bitvector: {name}")
        rows.append((name, evaluated.as_long()))
    return tuple(rows)


def _result(obligation: StackObligation, layout: StackWordLayout, reason: StackProofReason, checks: int, started: float,
            detail: str = "", *, countermodel: tuple[tuple[str, int], ...] = (),
            scalar_lemmas: tuple[StackLemmaEvidence, ...] = (),
            coordinates: StoreCoordinateResult | None = None,
            clauses: StackClauseBatch | None = None,
            comparisons: AddressComparisonResult | None = None,
            expected_continuation: int | None = None) -> StackInvariantProof:
    """Retain actual checked obligations and a local countermodel without promotion."""
    proved = reason is StackProofReason.PROVED
    required = required_stack_clauses(layout, obligation, expected_continuation=expected_continuation)
    if clauses is not None and clauses.required != required:
        raise ValueError("encoded stack clauses differ from the authoritative required manifest")
    return StackInvariantProof(obligation, ProofStatus.PROVED if proved else ProofStatus.UNKNOWN, reason,
                               FactCounters(checks, checks, checks, checks, 0 if proved else 1),
                               int((time.monotonic() - started) * 1000), layout, detail, countermodel, scalar_lemmas,
                               () if coordinates is None else coordinates.evidence,
                               None if coordinates is None else coordinates.reason,
                               () if clauses is None else clauses.evidence,
                               required,
                               None if comparisons is None else comparisons.evidence, expected_continuation)
