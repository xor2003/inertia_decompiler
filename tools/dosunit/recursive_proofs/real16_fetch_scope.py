"""Layer: dosunit native instruction-fetch geometry (staging).

Responsibility: prove a loader-linear decoded block's complete byte span fits
the active CS window and the normal first-MiB physical model, under a nonempty
native entry predicate. This is geometry only: source bytes, dispatch/control
correspondence, executable permissions, traps and asynchronous events require
independent evidence. Legacy VEX ``ip`` is not an architectural IP witness.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

import z3
from angr_platforms.X86_16 import control_coordinates
from angr_platforms.X86_16.control_coordinates import ControlAddressDomain

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import materialize_function
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain, entry_domain_model_hash
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs
from tools.dosunit.register_state_relations import MachineState

SEGMENT_EXTENT: int = 0x10000
PHYSICAL_EXTENT: int = 0x100000


class FetchScopeObligation(StrEnum):
    """Every required local fetch fact, even when a prerequisite fails."""

    NONVACUITY = "fetch_native_domain_nonempty"
    SEGMENT = "entire_fetch_span_within_cs_window"
    PHYSICAL = "entire_fetch_span_within_first_mib"


class FetchScopeReason(StrEnum):
    """Exact geometric closure or the retained unsupported boundary."""

    SCOPED = "native_fetch_geometry_scoped"
    COORDINATE = "fetch_coordinate_domain_unsupported"
    DOMAIN = "fetch_native_domain_vacuous"
    COUNTERMODEL = "fetch_span_scope_countermodel"
    UNKNOWN = "fetch_scope_solver_unknown"
    DEADLINE = "fetch_scope_original_deadline_exhausted"


@dataclass(frozen=True, slots=True)
class FetchScopeFact:
    """One geometric fact with its actual solver outcome and countermodel."""

    obligation: FetchScopeObligation
    status: ProofStatus
    native_result: z3.CheckSatResult | None = None
    deadline_exhausted: bool = False
    detail: str = ""
    model: str = ""


@dataclass(frozen=True, slots=True)
class Real16FetchScope:
    """Local geometry certificate; never a source or binary equivalence verdict."""

    status: ProofStatus
    reason: FetchScopeReason
    address: int
    size: int
    coordinate_domain: ControlAddressDomain
    model_hash: str
    facts: tuple[FetchScopeFact, ...]
    counters: FactCounters

    @property
    def complete(self) -> bool:
        """Require exact unique obligations, proved facts and coherent counters."""
        ids = tuple(row.obligation for row in self.facts)
        count = len(FetchScopeObligation)
        expected = FactCounters(count, count, count, count, 0)
        return (self.status is ProofStatus.PROVED and self.reason is FetchScopeReason.SCOPED
                and self.coordinate_domain is ControlAddressDomain.LOADER_LINEAR
                and len(ids) == len(set(ids)) and set(ids) == set(FetchScopeObligation)
                and all(row.status is ProofStatus.PROVED for row in self.facts)
                and self.counters == expected)

    @property
    def binary_equivalence_proved(self) -> bool:
        """Geometry cannot establish fetched bytes, control, faults or events."""
        return False


def fetch_scope_model_hash() -> str:
    """Seal geometry, native predicate and the authoritative coordinate contract."""
    digest = hashlib.sha256(entry_domain_model_hash().encode("ascii"))
    for path in (Path(__file__), Path(control_coordinates.__file__)):
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _query(obligation: FetchScopeObligation, predicate: z3.BoolRef, deadline: float, solver: z3.Solver,
           *, witness: bool = False) -> FetchScopeFact:
    """Check one fact on a shared native premise and the original absolute budget."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        return FetchScopeFact(obligation, ProofStatus.UNKNOWN, deadline_exhausted=True,
                              detail="original fetch-scope deadline exhausted")
    solver.push()
    try:
        solver.set(timeout=remaining)
        solver.add(predicate)
        result = solver.check()
        if time.monotonic() >= deadline:
            return FetchScopeFact(obligation, ProofStatus.UNKNOWN, z3.unknown, True,
                                  "original fetch-scope deadline exhausted")
        success = result == (z3.sat if witness else z3.unsat)
        if success:
            return FetchScopeFact(obligation, ProofStatus.PROVED, result)
        if result == z3.unknown:
            return FetchScopeFact(obligation, ProofStatus.UNKNOWN, result, detail=solver.reason_unknown())
        if witness:
            return FetchScopeFact(obligation, ProofStatus.UNKNOWN, result, detail="native fetch input domain is empty")
        model = str(solver.model())
        if time.monotonic() >= deadline:
            return FetchScopeFact(obligation, ProofStatus.UNKNOWN, z3.unknown, True,
                                  "original fetch-scope deadline exhausted")
        return FetchScopeFact(obligation, ProofStatus.COUNTEREXAMPLE, result,
                              detail="decoded fetch extent violates its declared scope", model=model)
    finally:
        solver.pop()


def _report(address: int, size: int, coordinates: ControlAddressDomain, model: str,
            rows: tuple[FetchScopeFact, ...], reason: FetchScopeReason) -> Real16FetchScope:
    """Retain all three rows; count produced solver facts separately from missing rows."""
    count = len(FetchScopeObligation)
    failed = sum(row.status is not ProofStatus.PROVED for row in rows)
    status = ProofStatus.PROVED if failed == 0 else ProofStatus.UNKNOWN
    if any(row.status is ProofStatus.COUNTEREXAMPLE for row in rows):
        status = ProofStatus.COUNTEREXAMPLE
    materialized = sum(row.native_result is not None for row in rows)
    return Real16FetchScope(status, reason, address, size, coordinates, model, rows,
                           FactCounters(count, count, count, materialized, failed))


def _scope_reason(rows: tuple[FetchScopeFact, ...]) -> FetchScopeReason:
    """Retain exhausted budgets and countermodels before ordinary non-results."""
    if any(row.deadline_exhausted for row in rows):
        return FetchScopeReason.DEADLINE
    if any(row.status is ProofStatus.COUNTEREXAMPLE for row in rows):
        return FetchScopeReason.COUNTERMODEL
    if any(row.status is not ProofStatus.PROVED for row in rows):
        return FetchScopeReason.UNKNOWN
    return FetchScopeReason.SCOPED


def check_real16_fetch_scope(address: int, size: int, entry: MachineState,
                             domain: Real16ScalarDomain | None, *, deadline: float,
                             coordinates: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
                             ) -> Real16FetchScope:
    """Check the entire decoded span without truncating or wrapping an invalid offset.

    Under loader-linear coordinates, the architectural offset is address minus
    CS*16. Prove that subtraction is nonnegative and its complete extent is at
    most 65536 BEFORE any word projection. Extents use64-bit unsigned arithmetic:
    an unsigned32 address plus unsigned32 size needs at most33bits, while the
    CS base plus segment size needs at most21bits. Neither can wrap at64bits.
    Neither proposal nor an empty input predicate
    is evidence that the native program reaches this fetch.
    """
    if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("fetch address requires an unsigned32 loaded coordinate")
    if type(size) is not int or not 0 < size <= 0xFFFFFFFF:
        raise ValueError("fetch span requires a positive unsigned32 decoded size")
    if type(deadline) not in {float, int} or not math.isfinite(deadline):
        raise ValueError("fetch scope requires a finite absolute deadline")
    model = fetch_scope_model_hash()
    if coordinates is not ControlAddressDomain.LOADER_LINEAR:
        rows = tuple(FetchScopeFact(item, ProofStatus.UNKNOWN, detail="requires loader-linear fetch coordinates")
                     for item in FetchScopeObligation)
        return _report(address, size, coordinates, model, rows, FetchScopeReason.COORDINATE)
    document = materialize_function("fetch-scope:entry", entry)
    inputs = S._z3_inputs(document, document, z3)
    state = _state_exprs(entry, inputs)
    cs = state["cs"]
    if not isinstance(cs, z3.BitVecRef) or cs.size() != 16:
        raise ValueError("fetch scope requires a native16 CS selector")
    premise = z3.BoolVal(True) if domain is None else domain.predicate(state)
    solver = z3.Solver()
    solver.add(premise)
    witness = _query(FetchScopeObligation.NONVACUITY, z3.BoolVal(True), deadline, solver, witness=True)
    if witness.status is not ProofStatus.PROVED:
        rows = (witness, *(FetchScopeFact(item, ProofStatus.UNKNOWN,
                              deadline_exhausted=witness.deadline_exhausted,
                              detail="nonempty native fetch input domain not established")
                           for item in (FetchScopeObligation.SEGMENT, FetchScopeObligation.PHYSICAL)))
        reason = FetchScopeReason.DOMAIN if witness.native_result == z3.unsat else FetchScopeReason.UNKNOWN
        if witness.deadline_exhausted:
            reason = FetchScopeReason.DEADLINE
        return _report(address, size, coordinates, model, rows, reason)
    base = cast(z3.BitVecRef, z3.ZeroExt(48, cs) << 4)
    limit = cast(z3.BitVecRef, base + SEGMENT_EXTENT)
    extent = address + size
    within_segment = cast(z3.BoolRef, z3.And(z3.UGE(z3.BitVecVal(address, 64), base),
                                           z3.ULE(z3.BitVecVal(extent, 64), limit)))
    segment = _query(FetchScopeObligation.SEGMENT,
                     cast(z3.BoolRef, z3.Not(within_segment)), deadline, solver)
    physical = _query(FetchScopeObligation.PHYSICAL,
                      z3.BoolVal(extent > PHYSICAL_EXTENT), deadline, solver)
    rows = (witness, segment, physical)
    return _report(address, size, coordinates, model, rows, _scope_reason(rows))
