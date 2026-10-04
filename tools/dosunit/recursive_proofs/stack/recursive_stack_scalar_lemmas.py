"""Discharge modular frame arithmetic before reasoning about memory arrays.

Layer: dosunit recursive invariant refinement (staging).
Responsibility: retain typed scalar candidates/checks and install only globally
proved implications in a caller's existing preservation solver. Every query
consumes the same original deadline; these facts never grant recursive equality.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import z3

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordDomain


class StackLemmaKind(StrEnum):
    """Independent algebraic facts needed by finite frame preservation."""

    FRONTIER = "stack_initialized_frontier"
    POINTER = "stack_pointer_advance"
    INDEX_SEPARATION = "stack_arbitrary_slot_separation"
    ROOT_SEPARATION = "stack_root_slot_separation"


class StackLemmaReason(StrEnum):
    """The exact outcome of one candidate, never an equality of programs."""

    DISCHARGED = "scalar_lemma_discharged"
    COUNTERMODEL = "scalar_lemma_countermodel"
    UNKNOWN = "scalar_lemma_solver_unknown"
    DEADLINE = "scalar_lemma_deadline_exceeded"


@dataclass(frozen=True, slots=True)
class StackScalarLemma:
    """One candidate implication at the external Z3-expression boundary."""

    kind: StackLemmaKind
    expression: z3.BoolRef


@dataclass(frozen=True, slots=True)
class StackLemmaEvidence:
    """One actual scalar solver observation or explicit unattempted refusal."""

    kind: StackLemmaKind
    status: ProofStatus
    reason: StackLemmaReason
    attempted: bool
    elapsed_ms: int
    detail: str = ""


@dataclass(frozen=True, slots=True)
class StackLemmaBatch:
    """Complete prefix of checked candidates under one original deadline."""

    evidence: tuple[StackLemmaEvidence, ...]
    required: tuple[StackLemmaKind, ...] = tuple(StackLemmaKind)

    @property
    def proved(self) -> bool:
        """Require a nonempty batch with every candidate actually discharged."""
        complete = bool(self.required) and len(set(self.required)) == len(self.required)
        complete = complete and tuple(row.kind for row in self.evidence) == self.required
        return complete and all(row.status is ProofStatus.PROVED and row.attempted
                                and row.reason is StackLemmaReason.DISCHARGED for row in self.evidence)

    @property
    def checks(self) -> int:
        """Count solver observations, excluding unattempted deadline refusals."""
        return sum(row.attempted for row in self.evidence)


def _separation(domain: StackWordDomain, index: z3.BitVecRef, pushed: z3.BitVecRef) -> z3.BoolRef:
    """Propose exact byte disjointness for distinct modular frame slots."""
    left, right = domain.offset(index), domain.offset(pushed)
    clauses = [domain.address(left, a) != domain.address(right, b)
               for a in range(domain.layout.frame_bytes) for b in range(domain.layout.frame_bytes)]
    return z3.Implies(index != pushed, z3.And(*clauses))


def push_scalar_candidates(domain: StackWordDomain, index: z3.BitVecRef) -> tuple[StackScalarLemma, ...]:
    """Propose complete arithmetic implications without assuming any are true."""
    pushed, _ = domain.after_push()
    pointer = domain.offset(domain.rank) - domain.layout.frame_bytes == domain.offset(pushed)
    return (
        StackScalarLemma(StackLemmaKind.FRONTIER, domain.push_frontier_lemma(index)),
        StackScalarLemma(StackLemmaKind.POINTER, cast(z3.BoolRef, pointer)),
        StackScalarLemma(StackLemmaKind.INDEX_SEPARATION, _separation(domain, index, pushed)),
        StackScalarLemma(StackLemmaKind.ROOT_SEPARATION,
                         _separation(domain, z3.BitVecVal(0, domain.layout.rank_bits), pushed)),
    )


def _check_candidate(candidate: StackScalarLemma, deadline: float) -> StackLemmaEvidence:
    """Prove the negated candidate unsatisfiable with only remaining time."""
    started = time.monotonic()
    remaining = int((deadline - started) * 1000)
    if remaining <= 0:
        return StackLemmaEvidence(candidate.kind, ProofStatus.UNKNOWN, StackLemmaReason.DEADLINE, False, 0)
    algebra = z3.SolverFor("QF_BV")
    algebra.set(timeout=remaining)
    algebra.add(z3.Not(candidate.expression))
    checked = algebra.check()
    elapsed = int((time.monotonic() - started) * 1000)
    if checked == z3.unsat:
        return StackLemmaEvidence(candidate.kind, ProofStatus.PROVED, StackLemmaReason.DISCHARGED, True, elapsed)
    if checked == z3.sat:
        return StackLemmaEvidence(candidate.kind, ProofStatus.UNKNOWN, StackLemmaReason.COUNTERMODEL, True, elapsed)
    return StackLemmaEvidence(candidate.kind, ProofStatus.UNKNOWN, StackLemmaReason.UNKNOWN, True, elapsed,
                              algebra.reason_unknown())


def discharge_scalar_lemmas(
    candidates: tuple[StackScalarLemma, ...], solver: z3.Solver, *, deadline: float,
) -> StackLemmaBatch:
    """Add only separately proved algebra; preserve any failed/unknown prefix.

    No caller premises are used to prove a candidate. Thus each added implication
    is valid throughout the complete preservation domain. A resource refusal or
    countermodel adds no assumption and prevents batch success.
    """
    if not candidates or len({row.kind for row in candidates}) != len(candidates):
        raise ValueError("scalar lemma candidates must be nonempty with unique kinds")
    evidence: list[StackLemmaEvidence] = []
    for candidate in candidates:
        checked = _check_candidate(candidate, deadline)
        evidence.append(checked)
        if checked.status is not ProofStatus.PROVED:
            break
        solver.add(candidate.expression)
    return StackLemmaBatch(tuple(evidence), tuple(row.kind for row in candidates))
