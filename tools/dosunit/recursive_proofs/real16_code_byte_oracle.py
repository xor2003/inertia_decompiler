"""Layer: dosunit physical code-byte projection proof (staging).

Responsibility: discharge nonvacuity and byte preservation of one actual memory
prefix. Producers must independently bind arrays, range and predicate to native
source and established domains; this local algebra cannot grant binary proof.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import z3

from tools.dosunit.proof_contracts import FactCounters, ProofStatus


class CodeByteReason(StrEnum):
    """The exact local preservation result, without interpreting SAT as a binary mismatch."""

    PRESERVED = "physical_byte_projection_preserved"
    COUNTERMODEL = "physical_byte_projection_countermodel"
    VACUOUS = "physical_byte_projection_empty_domain"
    SORT = "physical_byte_projection_wrong_sort"
    UNKNOWN = "physical_byte_projection_solver_unknown"
    DEADLINE = "physical_byte_projection_deadline_exhausted"


@dataclass(frozen=True, slots=True)
class CodeByteProjectionProof:
    """Two required local obligations; source and global fetch closure are absent."""

    status: ProofStatus
    reason: CodeByteReason
    counters: FactCounters
    model: str = ""
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Byte-array algebra grants neither source provenance nor program equivalence."""
        return False


@dataclass(frozen=True, slots=True)
class _ByteQuery:
    """Native solver outcome with the explicit original-budget stop state."""

    result: z3.CheckSatResult
    deadline_exhausted: bool = False
    model: str = ""
    detail: str = ""


def _query(condition: z3.BoolRef, deadline: float) -> _ByteQuery:
    """Never replenish the original budget for witness and preservation queries."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        return _ByteQuery(z3.unknown, deadline_exhausted=True)
    solver = z3.Solver()
    solver.set(timeout=remaining)
    solver.add(condition)
    result = solver.check()
    if time.monotonic() >= deadline:
        return _ByteQuery(z3.unknown, deadline_exhausted=True)
    model = str(solver.model()) if result == z3.sat else ""
    detail = solver.reason_unknown() if result == z3.unknown else ""
    if time.monotonic() >= deadline:
        return _ByteQuery(z3.unknown, deadline_exhausted=True, model=model, detail=detail)
    return _ByteQuery(result, model=model, detail=detail)


def prove_physical_byte_projection(before: z3.ArrayRef, after: z3.ArrayRef,
                                   index: z3.BitVecRef, premise: z3.BoolRef,
                                   *, deadline: float) -> CodeByteProjectionProof:
    """Prove every selected byte unchanged under a nonempty supplied predicate.

    A free32-bit index makes the implication universal. The producer supplies
    its independently verified fetched-range and input-domain predicate. Check
    that predicate has a witness before preservation, so a contradictory domain
    never proves equality. All memory outside the predicate remains present.
    """
    if type(deadline) not in {float, int} or not math.isfinite(deadline):
        raise ValueError("byte projection requires a finite absolute deadline")
    count = FactCounters(2, 2, 2, 0, 2)
    expected = z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8))
    if before.sort() != expected or after.sort() != expected or index.size() != 32:
        return CodeByteProjectionProof(ProofStatus.UNKNOWN, CodeByteReason.SORT, count)
    if time.monotonic() >= deadline:
        return CodeByteProjectionProof(ProofStatus.UNKNOWN, CodeByteReason.DEADLINE, count)
    witness = _query(premise, deadline)
    if witness.result != z3.sat:
        reason = CodeByteReason.VACUOUS if witness.result == z3.unsat else CodeByteReason.UNKNOWN
        if witness.deadline_exhausted:
            reason = CodeByteReason.DEADLINE
        return CodeByteProjectionProof(ProofStatus.UNKNOWN, reason, FactCounters(2, 2, 2, 1, 2), detail=witness.detail)
    difference = cast(z3.BoolRef, z3.And(premise, z3.Select(after, index) != z3.Select(before, index)))
    query = _query(difference, deadline)
    if query.result == z3.unsat:
        return CodeByteProjectionProof(ProofStatus.PROVED, CodeByteReason.PRESERVED, FactCounters(2, 2, 2, 2, 0))
    if query.result == z3.sat:
        return CodeByteProjectionProof(ProofStatus.COUNTEREXAMPLE, CodeByteReason.COUNTERMODEL,
                                       FactCounters(2, 2, 2, 2, 1), model=query.model)
    reason = CodeByteReason.DEADLINE if query.deadline_exhausted else CodeByteReason.UNKNOWN
    return CodeByteProjectionProof(ProofStatus.UNKNOWN, reason, FactCounters(2, 2, 2, 2, 1), detail=query.detail)
