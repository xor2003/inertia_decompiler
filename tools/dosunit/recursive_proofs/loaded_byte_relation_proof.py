"""Layer: dosunit initialized-memory proof (staging).

Responsibility: check global full-array byte-XOR algebra and exhaustive snapshot
binding, provide its explicit finite-store array constructor and derive loaded-byte
seed establishment by finite store induction.
This proves an initialization relation only, never native/program equivalence.
"""
from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import cast

import z3

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    ADDRESS_WIDTH,
    BYTE_WIDTH,
    ByteXorRelation,
    LoadedByteProposal,
    LoadedBytes,
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
    propose_loaded_byte_relation,
    snapshot_loaded_bytes,
)

LOADED_BYTE_MODEL_HASH: str = hashlib.sha256(
    f"loaded-byte-xor-seed-v1:a{ADDRESS_WIDTH}:b{BYTE_WIDTH}:z3-{z3.get_version_string()}".encode()
).hexdigest()
"""Version the algebra, memory widths and actual SMT backend for reuse."""


class ByteRelationObligation(StrEnum):
    """Every premise required for the initialized full-array relation theorem."""

    BINDING = "complete_loaded_snapshot_and_mask_binding"
    INVOLUTION = "global_array_involution"
    READ_FRAME = "global_masked_read_and_untouched_byte_frame"
    STORE_TRANSLATION = "global_arbitrary_store_translation"
    MASK_ERASURE = "global_overwrite_erasure_of_masked_background"
    INITIALIZATION = "complete_loaded_seed_establishment"


@dataclass(frozen=True, slots=True)
class ByteRelationFact:
    """One exact attempted theorem result, including unknown and countermodels."""

    obligation: ByteRelationObligation
    status: ProofStatus
    detail: str = ""
    model_hash: str = LOADED_BYTE_MODEL_HASH


@dataclass(frozen=True, slots=True)
class LoadedRelationProof:
    """Closed accounting for initialized bytes, without a binary verdict."""

    status: ProofStatus
    reason: LoadedRelationReason
    proposal: LoadedByteProposal
    facts: tuple[ByteRelationFact, ...]
    counters: FactCounters
    detail: str = ""
    model_hash: str = LOADED_BYTE_MODEL_HASH

    @property
    def binary_equivalence_proved(self) -> bool:
        """Native transitions, observers and physical scope remain separate work."""
        return False



def seed_loaded_array(snapshot: LoadedBytes, background: z3.ArrayRef,
                      limits: LoadedRelationLimits) -> z3.ArrayRef:
    """Construct literal loaded bytes over an otherwise unrestricted byte array.

    Revalidate the complete immutable snapshot before using any bytes. This is
    the actual finite-store seed used by the initialization theorem, rather
    than the relative XOR map. Use it at loader entry; mutable image data must
    not be reseeded at later cutpoints. It grants no reachability, preservation
    or binary verdict; consumers must establish their dynamic domain separately.
    """
    limits.check_time()
    expected_sort = z3.ArraySort(z3.BitVecSort(ADDRESS_WIDTH), z3.BitVecSort(BYTE_WIDTH))
    if background.sort() != expected_sort:
        raise LoadedRelationRefusal(LoadedRelationReason.DOMAIN, "seed requires a32/b8 background array")
    rebound = snapshot_loaded_bytes(snapshot.architecture, snapshot.chunks, limits=limits)
    if rebound != snapshot:
        raise LoadedRelationRefusal(LoadedRelationReason.MALFORMED, "seed snapshot identity changed")
    result = background
    for address, data in snapshot.chunks:
        for offset, value in enumerate(data):
            limits.check_time()
            result = cast(z3.ArrayRef, z3.Store(result, z3.BitVecVal(address + offset, ADDRESS_WIDTH),
                                               z3.BitVecVal(value, BYTE_WIDTH)))
    limits.check_time()
    return result


def apply_array_relation(relation: ByteXorRelation, memory: z3.ArrayRef,
                         limits: LoadedRelationLimits) -> z3.ArrayRef:
    """Build the exact map on an arbitrary full native byte array iteratively."""
    limits.check_time()
    expected = z3.ArraySort(z3.BitVecSort(ADDRESS_WIDTH), z3.BitVecSort(BYTE_WIDTH))
    if memory.sort() != expected:
        raise LoadedRelationRefusal(LoadedRelationReason.DOMAIN, "relation requires a32/b8 native memory array")
    if len(relation.masks) > limits.max_patches:
        raise LoadedRelationRefusal(LoadedRelationReason.LIMIT, "array relation exceeds caller patch budget")
    result = memory
    for patch in relation.masks:
        limits.check_time()
        address = z3.BitVecVal(patch.address, ADDRESS_WIDTH)
        byte = cast(z3.BitVecRef, z3.Select(memory, address))
        result = cast(z3.ArrayRef, z3.Store(result, address, byte ^ z3.BitVecVal(patch.mask, BYTE_WIDTH)))
    limits.check_time()
    return result


def mask_array(relation: ByteXorRelation, limits: LoadedRelationLimits) -> z3.ArrayRef:
    """Make the exact sparse mask array, with zero at every other byte."""
    result = cast(z3.ArrayRef, z3.K(z3.BitVecSort(ADDRESS_WIDTH), z3.BitVecVal(0, BYTE_WIDTH)))
    if len(relation.masks) > limits.max_patches:
        raise LoadedRelationRefusal(LoadedRelationReason.LIMIT, "mask array exceeds caller patch budget")
    for patch in relation.masks:
        limits.check_time()
        result = cast(z3.ArrayRef, z3.Store(result, z3.BitVecVal(patch.address, ADDRESS_WIDTH),
                                           z3.BitVecVal(patch.mask, BYTE_WIDTH)))
    limits.check_time()
    return result


@dataclass(slots=True)
class _ProofRun:
    """One unchanged deadline and complete retained obligation evidence."""

    proposal: LoadedByteProposal
    limits: LoadedRelationLimits
    facts: list[ByteRelationFact] = field(default_factory=list)

    def check(self, kind: ByteRelationObligation, equation: z3.BoolRef) -> bool:
        """Prove a global theorem by searching its unrestricted countermodel."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "algebra original deadline exhausted")
        solver = z3.Solver()
        solver.set(timeout=remaining)
        solver.add(z3.Not(equation))
        result = solver.check()
        self.limits.check_time()
        if result == z3.unsat:
            fact = ByteRelationFact(kind, ProofStatus.PROVED)
        elif result == z3.sat:
            fact = ByteRelationFact(kind, ProofStatus.COUNTEREXAMPLE, str(solver.model()))
        else:
            fact = ByteRelationFact(kind, ProofStatus.UNKNOWN, solver.reason_unknown())
        self.facts.append(fact)
        return fact.status is ProofStatus.PROVED

    def report(self, reason: LoadedRelationReason, detail: str = "") -> LoadedRelationProof:
        """Missing, duplicate or contradictory evidence never completes the report."""
        expected = set(ByteRelationObligation)
        kinds = tuple(fact.obligation for fact in self.facts)
        complete = len(kinds) == len(expected) and set(kinds) == expected
        failures = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failures += len(expected - set(kinds)) + len(kinds) - len(set(kinds))
        failures += len(set(kinds) - expected)
        proved = complete and failures == 0 and reason is LoadedRelationReason.DISCHARGED
        if not proved and reason is LoadedRelationReason.DISCHARGED:
            reason = LoadedRelationReason.UNKNOWN
        counters = FactCounters(len(expected), len(expected), len(expected), len(self.facts), failures)
        return LoadedRelationProof(ProofStatus.PROVED if proved else ProofStatus.UNKNOWN,
                                    reason, self.proposal, tuple(self.facts), counters, detail)


def _overwrite_masked(relation: ByteXorRelation, memory: z3.ArrayRef,
                       values: z3.ArrayRef, limits: LoadedRelationLimits) -> z3.ArrayRef:
    """Overwrite all masked coordinates with common arbitrary candidate bytes."""
    result = memory
    for patch in relation.masks:
        limits.check_time()
        address = z3.BitVecVal(patch.address, ADDRESS_WIDTH)
        result = cast(z3.ArrayRef, z3.Store(result, address, z3.Select(values, address)))
    return result


def _prove_algebra(run: _ProofRun) -> bool:
    """Discharge four independent global premises without seed restrictions."""
    relation, limits = run.proposal.relation, run.limits
    memory = z3.Array("loaded_relation_memory", z3.BitVecSort(ADDRESS_WIDTH), z3.BitVecSort(BYTE_WIDTH))
    values = z3.Array("loaded_relation_values", z3.BitVecSort(ADDRESS_WIDTH), z3.BitVecSort(BYTE_WIDTH))
    address = z3.BitVec("loaded_relation_address", ADDRESS_WIDTH)
    byte = z3.BitVec("loaded_relation_byte", BYTE_WIDTH)
    transformed = apply_array_relation(relation, memory, limits)
    masks = mask_array(relation, limits)
    # Construct each theorem only when its turn arrives, under the same budget.
    equations: tuple[tuple[ByteRelationObligation, Callable[[], z3.BoolRef]], ...] = (
        (ByteRelationObligation.INVOLUTION,
         lambda: cast(z3.BoolRef, apply_array_relation(relation, transformed, limits) == memory)),
        (ByteRelationObligation.READ_FRAME,
         lambda: cast(z3.BoolRef, z3.Select(transformed, address)
                      == (cast(z3.BitVecRef, z3.Select(memory, address))
                          ^ cast(z3.BitVecRef, z3.Select(masks, address))))),
        (ByteRelationObligation.STORE_TRANSLATION,
         lambda: cast(z3.BoolRef, apply_array_relation(relation, cast(z3.ArrayRef, z3.Store(memory, address, byte)), limits)
                      == z3.Store(transformed, address, byte ^ cast(z3.BitVecRef, z3.Select(masks, address))))),
        (ByteRelationObligation.MASK_ERASURE,
         lambda: cast(z3.BoolRef, _overwrite_masked(relation, transformed, values, limits)
                      == _overwrite_masked(relation, memory, values, limits))),
    )
    for kind, equation in equations:
        limits.check_time()
        if not run.check(kind, equation()):
            return False
    return True


def prove_loaded_byte_relation(proposal: LoadedByteProposal, *, timeout_ms: int = 10000,
                               limits: LoadedRelationLimits | None = None) -> LoadedRelationProof:
    """Prove ``R(seed(original,M)) == seed(candidate,M)`` for every background M.

    Exact same-domain snapshots bind all masks. Global store translation gives
    finite initialization induction from R(M); overwrite erasure removes its
    masked background because every mask coordinate is initialized. Read/frame
    and involution retain a bijection on the entire array. Native code-as-data
    transitions, caller patches, observers, faults and events are not proved.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("loaded relation proof timeout must be a nonnegative integer")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000.0
    if selected.deadline >= 0.0:
        deadline = min(deadline, selected.deadline)
    run = _ProofRun(proposal, replace(selected, deadline=deadline))
    try:
        expected = propose_loaded_byte_relation(proposal.original, proposal.candidate, limits=run.limits)
        if expected != proposal:
            run.facts.append(ByteRelationFact(ByteRelationObligation.BINDING, ProofStatus.UNKNOWN,
                                               "proposed masks are not the exact complete loaded-byte delta"))
            return run.report(LoadedRelationReason.MASK)
        run.facts.append(ByteRelationFact(ByteRelationObligation.BINDING, ProofStatus.PROVED))
        if not _prove_algebra(run):
            reason = LoadedRelationReason.COUNTERMODEL if any(
                fact.status is ProofStatus.COUNTEREXAMPLE for fact in run.facts) else LoadedRelationReason.UNKNOWN
            return run.report(reason)
        run.limits.check_time()
        run.facts.append(ByteRelationFact(ByteRelationObligation.INITIALIZATION, ProofStatus.PROVED,
                                           "exact finite seed induction consumes binding/store/frame/erasure theorems"))
        return run.report(LoadedRelationReason.DISCHARGED)
    except LoadedRelationRefusal as refusal:
        # The named surface cannot produce complete evidence; retain prior facts.
        run.facts.append(ByteRelationFact(ByteRelationObligation.INITIALIZATION, ProofStatus.UNKNOWN, refusal.detail))
        return run.report(refusal.reason, refusal.detail)
