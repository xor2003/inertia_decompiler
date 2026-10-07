"""Normalize frame-store coordinates only through discharged scalar equalities.

Layer: dosunit recursive memory refinement (staging).
Responsibility: inspect the external Z3 Store tail, prove each actual address
matches its proposed finite frame byte, and substitute equal terms by congruence.
All array stores and values remain present, including earlier body writes.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import z3

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordDomain


class StoreCoordinateReason(StrEnum):
    """Exact result of an address proposal or missing Store-tail evidence."""

    DISCHARGED = "store_byte_coordinate_discharged"
    UNAVAILABLE = "frame_store_tail_unavailable"
    COUNTERMODEL = "store_byte_coordinate_countermodel"
    UNKNOWN = "store_byte_coordinate_unknown"
    DEADLINE = "store_byte_coordinate_deadline"


@dataclass(frozen=True, slots=True)
class StoreByteCoordinate:
    """One actual Store address paired with a proposed frame byte coordinate."""

    byte: int
    original: z3.BitVecRef
    proposed: z3.BitVecRef


@dataclass(frozen=True, slots=True)
class StoreCoordinateEvidence:
    """Retain an actual solver observation for one proposed byte address."""

    byte: int
    status: ProofStatus
    reason: StoreCoordinateReason
    attempted: bool
    elapsed_ms: int
    detail: str = ""


@dataclass(frozen=True, slots=True)
class StoreCoordinateResult:
    """A complete address normalization or the unchanged original memory."""

    memory: z3.ArrayRef
    required_bytes: int
    evidence: tuple[StoreCoordinateEvidence, ...]
    reason: StoreCoordinateReason

    @property
    def proved(self) -> bool:
        """Require one discharged observation per actual frame byte."""
        return (self.reason is StoreCoordinateReason.DISCHARGED and self.required_bytes > 0
                and tuple(row.byte for row in self.evidence) == tuple(reversed(range(self.required_bytes)))
                and all(row.status is ProofStatus.PROVED and row.reason is StoreCoordinateReason.DISCHARGED
                        and row.attempted for row in self.evidence))

    @property
    def checks(self) -> int:
        """Count actual native queries, excluding missing/expired evidence."""
        return sum(row.attempted for row in self.evidence)


def _coordinates(memory: z3.ArrayRef, domain: StackWordDomain) -> tuple[StoreByteCoordinate, ...] | None:
    """Read native Store nodes without assembly/C text or guessed data values."""
    pushed, _ = domain.after_push()
    offset = domain.offset(pushed)
    current = memory
    rows: list[StoreByteCoordinate] = []
    for byte in reversed(range(domain.layout.frame_bytes)):
        if not z3.is_store(current):
            return None
        prior, address, value = current.arg(0), current.arg(1), current.arg(2)
        if not isinstance(prior, z3.ArrayRef) or not isinstance(address, z3.BitVecRef):
            raise TypeError("native Store must have an array and bitvector address")
        if not isinstance(value, z3.BitVecRef) or value.size() != 8:
            raise TypeError("native frame stores must contain byte-sized values")
        rows.append(StoreByteCoordinate(byte, address, domain.address(offset, byte)))
        current = prior
    return tuple(rows)


def _check(coordinate: StoreByteCoordinate, deadline: float) -> StoreCoordinateEvidence:
    """Discharge a substituted SSA address globally with only remaining time."""
    started = time.monotonic()
    remaining = int((deadline - started) * 1000)
    if remaining <= 0:
        return StoreCoordinateEvidence(coordinate.byte, ProofStatus.UNKNOWN,
                                       StoreCoordinateReason.DEADLINE, False, 0)
    solver = z3.Solver()
    solver.set(timeout=remaining)
    solver.add(coordinate.original != coordinate.proposed)
    checked = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    if checked == z3.unsat:
        return StoreCoordinateEvidence(coordinate.byte, ProofStatus.PROVED,
                                       StoreCoordinateReason.DISCHARGED, True, elapsed)
    if checked == z3.sat:
        return StoreCoordinateEvidence(coordinate.byte, ProofStatus.UNKNOWN,
                                       StoreCoordinateReason.COUNTERMODEL, True, elapsed)
    return StoreCoordinateEvidence(coordinate.byte, ProofStatus.UNKNOWN,
                                   StoreCoordinateReason.UNKNOWN, True, elapsed, solver.reason_unknown())


def normalize_push_coordinates(memory: z3.ArrayRef, domain: StackWordDomain, *,
                               deadline: float) -> StoreCoordinateResult:
    """Normalize a complete frame tail through independently proved equalities.

    Each proposed equality is checked without assuming the stack invariant.
    Substitution changes only equal address expressions; it preserves the entire
    array by congruence. Any unknown/missing byte returns the untouched memory.
    Values and earlier stores are preserved, so hidden stores remain observable.
    """
    coordinates = _coordinates(memory, domain)
    if coordinates is None:
        return StoreCoordinateResult(memory, domain.layout.frame_bytes, (), StoreCoordinateReason.UNAVAILABLE)
    evidence: list[StoreCoordinateEvidence] = []
    for row in coordinates:
        checked = _check(row, deadline)
        evidence.append(checked)
        if checked.status is not ProofStatus.PROVED:
            return StoreCoordinateResult(memory, domain.layout.frame_bytes, tuple(evidence), checked.reason)
    replacements = tuple((row.original, row.proposed) for row in coordinates)
    normalized = z3.substitute(memory, *replacements)
    return StoreCoordinateResult(cast(z3.ArrayRef, normalized), domain.layout.frame_bytes,
                                 tuple(evidence), StoreCoordinateReason.DISCHARGED)
