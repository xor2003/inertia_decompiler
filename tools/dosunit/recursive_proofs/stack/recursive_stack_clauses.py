"""Layer: dosunit recursive proof staging.

Responsibility: own required frame-clause manifests and per-CALL saved-word
goals, then discharge every conjunct under one unchanged premise and shared
deadline, retaining exact attempted/completed evidence.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import z3

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordDomain, StackWordLayout


class StackObligation(StrEnum):
    """The exact inductive stack obligation checked against machine effects."""

    INITIATION = "stack_initiation"
    PUSH = "stack_push_preservation"
    BODY = "stack_body_preservation"
    POP = "stack_pop_closure"


class StackClauseKind(StrEnum):
    """Distinct required parts of a finite stack transition obligation."""

    POINTER = "stack_pointer"
    BOUNDS = "stack_bounds"
    SLOT = "stack_arbitrary_slot"
    ROOT_FRAME = "stack_root_frame"
    STACK_SELECTOR = "stack_selector"
    CODE_SELECTOR = "code_selector"
    RETURN_TARGET = "return_target"
    CALL_CONTINUATION = "call_continuation"


class StackClauseReason(StrEnum):
    """Typed native solver observation for one conjunct."""

    DISCHARGED = "stack_clause_discharged"
    COUNTERMODEL = "stack_clause_countermodel"
    UNKNOWN = "stack_clause_unknown"
    DEADLINE = "stack_clause_deadline"


def check_continuation_argument(obligation: StackObligation, layout: StackWordLayout,
                                 expected_continuation: int | None) -> None:
    """Reject out-of-scope, mistyped or unadmitted continuation API arguments."""
    if expected_continuation is None:
        return
    if obligation is not StackObligation.PUSH:
        raise ValueError("expected_continuation is defined only for PUSH obligations")
    if type(expected_continuation) is not int:
        raise TypeError("expected_continuation must be an int loaded continuation")
    if expected_continuation not in layout.continuations:
        raise ValueError("expected_continuation must be an admitted loaded continuation")


def required_stack_clauses(layout: StackWordLayout, obligation: StackObligation, *,
                          expected_continuation: int | None = None) -> tuple[StackClauseKind, ...]:
    """Own the fixed clause manifest shared by producers and their consumers.

    Required clauses survive even refusal before encoding or the first solver
    query. A generic PUSH has no per-call binding; a requested binding adds its
    exact word alongside every existing frame/selector/slot obligation.
    """
    check_continuation_argument(obligation, layout, expected_continuation)
    kinds = [StackClauseKind.POINTER, StackClauseKind.BOUNDS, StackClauseKind.SLOT, StackClauseKind.ROOT_FRAME]
    if layout.segmented:
        kinds += [StackClauseKind.STACK_SELECTOR, StackClauseKind.CODE_SELECTOR]
    if obligation is StackObligation.POP:
        kinds.append(StackClauseKind.RETURN_TARGET)
    if expected_continuation is not None:
        kinds.append(StackClauseKind.CALL_CONTINUATION)
    return tuple(kinds)


def call_continuation_clause(domain: StackWordDomain, memory: z3.ArrayRef,
                              expected_continuation: int) -> StackClause:
    """Require this CALL's CS-relative word in the actual post-PUSH slot.

    Addressing, saved-word conversion and finite stack wrap come from the
    authoritative domain. No other member of its continuation set substitutes
    for the particular continuation requested by the composing checker.
    """
    pushed, _allocated = domain.after_push()
    index = domain.layout.continuations.index(expected_continuation)
    saved = domain.continuation_words()[index]
    condition = cast(z3.BoolRef, domain.word(memory, pushed) == saved)
    return StackClause(StackClauseKind.CALL_CONTINUATION, condition)


@dataclass(frozen=True, slots=True)
class StackClause:
    """One mandatory conjunct of the original unrestricted proof goal."""

    kind: StackClauseKind
    condition: z3.BoolRef

    def __post_init__(self) -> None:
        """Require a native Boolean goal at the external Z3 type boundary."""
        if not isinstance(self.condition, z3.BoolRef):
            raise TypeError("stack clause must carry a native Boolean condition")


@dataclass(frozen=True, slots=True)
class StackClauseEvidence:
    """Actual query result; expired time does not count as an attempted check."""

    kind: StackClauseKind
    status: ProofStatus
    reason: StackClauseReason
    attempted: bool
    elapsed_ms: int
    detail: str = ""


@dataclass(frozen=True, slots=True)
class StackClauseBatch:
    """Exact conjunct manifest plus solver evidence and any actual SAT model."""

    required: tuple[StackClauseKind, ...]
    evidence: tuple[StackClauseEvidence, ...]
    model: z3.ModelRef | None = None

    @property
    def proved(self) -> bool:
        """Accept only one discharged observation for every required conjunct."""
        return (bool(self.required) and len(set(self.required)) == len(self.required)
                and tuple(row.kind for row in self.evidence) == self.required
                and all(row.status is ProofStatus.PROVED and row.attempted
                        and row.reason is StackClauseReason.DISCHARGED for row in self.evidence))

    @property
    def checks(self) -> int:
        """Count actual native solver calls, including SAT and UNKNOWN."""
        return sum(row.attempted for row in self.evidence)


def check_stack_clauses(clauses: tuple[StackClause, ...], solver: z3.Solver, *,
                        deadline: float) -> StackClauseBatch:
    """Check all conjuncts without narrowing premises or replenishing time.

    Every fresh query uses exactly the caller's premise and the remaining
    deadline. Earlier proofs are never assumed to hide a later countermodel.
    Independent solvers retain native preprocessing; incremental push/pop can
    disable those reductions and make even unchanged-memory POP queries slow.
    The caller's context is never mutated, including on external exceptions.
    """
    required = tuple(clause.kind for clause in clauses)
    if not required or len(set(required)) != len(required):
        raise ValueError("stack clauses must be nonempty with unique kinds")
    assertions = solver.assertions()
    hypotheses = tuple(assertions[index] for index in range(len(assertions)))
    rows: list[StackClauseEvidence] = []
    for clause in clauses:
        started = time.monotonic()
        remaining = int((deadline - started) * 1000)
        if remaining <= 0:
            rows.append(StackClauseEvidence(clause.kind, ProofStatus.UNKNOWN,
                                            StackClauseReason.DEADLINE, False, 0))
            return StackClauseBatch(required, tuple(rows))
        query = z3.Solver()
        query.set(timeout=remaining)
        query.add(*hypotheses, z3.Not(clause.condition))
        checked = query.check()
        elapsed = int((time.monotonic() - started) * 1000)
        if checked == z3.unsat:
            rows.append(StackClauseEvidence(clause.kind, ProofStatus.PROVED,
                                            StackClauseReason.DISCHARGED, True, elapsed))
        else:
            reason = StackClauseReason.COUNTERMODEL if checked == z3.sat else StackClauseReason.UNKNOWN
            detail = "" if checked == z3.sat else query.reason_unknown()
            rows.append(StackClauseEvidence(clause.kind, ProofStatus.UNKNOWN, reason, True, elapsed, detail))
            model = query.model() if checked == z3.sat else None
            return StackClauseBatch(required, tuple(rows), model)
    return StackClauseBatch(required, tuple(rows))
