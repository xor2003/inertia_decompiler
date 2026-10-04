"""Layer: dosunit fetched-code memory invariant.

Responsibility: establish literal fetched bytes in the actual loader seed and
consume complete universal store-prefix preservation. This is code stability
inside the admitted physical byte model; faults, events and equivalence remain
separate. Mutable image data is never reinitialized at later cutpoints.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

import z3

from tools.dosunit.proof_contracts import Architecture, FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import loaded_byte_relation_proof as seed_owner
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    LoadedTransitionReason,
    _consume_initialized,
    _TransitionRefusal,
    _TransitionRun,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof, seed_loaded_array
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import (
    Real16CodePrefixProof,
    code_prefix_model_hash,
)
from tools.dosunit.recursive_proofs.real16_fetched_code_intake import (
    PrefixIntakeReason,
    establish_prefix_intake,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import BoundDomainConsumption
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBindingReason,
    NativeBlockRequest,
    _BindingRun,
    _block_bytes,
    _NativeRefusal,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.register_state_relations import MachineState


class FetchedCodeReason(StrEnum):
    """Exact local establishment or refusal without program promotion."""

    PRESERVED = "loaded_fetched_code_invariant_established"
    SOURCE = "fetched_code_prefix_or_source_binding_refused"
    INITIALIZATION = "fetched_code_loaded_relation_refused"
    COUNTERMODEL = "fetched_code_seed_countermodel"
    UNKNOWN = "fetched_code_solver_unknown"
    MODEL = "fetched_code_semantic_model_changed"
    DEADLINE = "fetched_code_original_deadline_exhausted"
    RESOURCE = "fetched_code_resource_boundary"


class FetchedCodeObligation(StrEnum):
    """Complete required ledger, fixed before work starts."""

    PREFIX = "complete_current_prefix_receipt"
    SOURCE = "current_producer_source_domain_receipt"
    INITIALIZATION = "exact_loaded_snapshot_relation"
    LOAD = "immutable_executable_and_loaded_bytes"
    WITNESS = "absolute_loaded_seed_domain_nonempty"
    SEED = "every_fetched_byte_has_loaded_literal"
    PRESERVATION = "every_native_prefix_preserves_all_fetched_spans"
    AFTER = "prefix_model_still_current"
    MODEL = "invariant_model_still_current"


@dataclass(frozen=True, slots=True)
class FetchedCodeSpan:
    """One exact decoded interval and its actual initialized bytes."""

    address: int
    data: bytes


@dataclass(frozen=True, slots=True)
class FetchedCodeDomain:
    """Absolute code-byte predicate; other bytes remain live and unrestricted."""

    side: int
    file_hash: str
    snapshot_hash: str
    spans: tuple[FetchedCodeSpan, ...]

    def predicate(self, memory: z3.ArrayRef, limits: LoadedRelationLimits) -> z3.BoolRef:
        """Select literal code bytes without overwriting any runtime memory."""
        expected = z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8))
        if memory.sort() != expected:
            raise LoadedRelationRefusal(LoadedRelationReason.DOMAIN, "code invariant requires a32/b8 memory array")
        rows: list[z3.BoolRef] = []
        for span in self.spans:
            for offset, byte in enumerate(span.data):
                limits.check_time()
                rows.append(cast(z3.BoolRef, z3.Select(memory, span.address + offset) == byte))
        limits.check_time()
        if not rows:
            raise LoadedRelationRefusal(LoadedRelationReason.DOMAIN, "code invariant requires a nonempty fetched manifest")
        return cast(z3.BoolRef, z3.And(*rows))


@dataclass(frozen=True, slots=True)
class FetchedCodeKey:
    """One exact required occurrence, never inferred from an attempted fact."""

    obligation: FetchedCodeObligation
    side: int = -1
    address: int = -1


@dataclass(frozen=True, slots=True)
class FetchedCodeFact:
    """One attempted result with native outcome and exact refusal detail."""

    key: FetchedCodeKey
    status: ProofStatus
    detail: str = ""
    native_result: z3.CheckSatResult | None = None


@dataclass(frozen=True, slots=True)
class Real16FetchedCodeInvariant:
    """Loader initiation plus local preservation; dispatch is composed separately."""

    status: ProofStatus
    reason: FetchedCodeReason
    model_hash: str
    proposal_hash: str
    required: tuple[FetchedCodeKey, ...]
    facts: tuple[FetchedCodeFact, ...]
    domains: tuple[FetchedCodeDomain, ...]
    counters: FactCounters
    detail: str = ""
    consumption: BoundDomainConsumption | None = None

    @property
    def complete(self) -> bool:
        """Missing, duplicate, unknown and failed rows cannot close code memory."""
        ids = tuple(row.key for row in self.facts)
        count = len(self.required)
        return (self.status is ProofStatus.PROVED and self.reason is FetchedCodeReason.PRESERVED
                and len(set(self.required)) == count and len(ids) == count and set(ids) == set(self.required)
                and all(row.status is ProofStatus.PROVED for row in self.facts)
                and len(self.domains) == 2 and all(domain.spans for domain in self.domains)
                and self.consumption is not None and self.consumption.complete
                and self.counters == FactCounters(count, count, count, count, 0))

    @property
    def binary_equivalence_proved(self) -> bool:
        """Code initiation and preservation do not close faults, events or observers."""
        return False


def _model_hash(prefix_model: str) -> str:
    """Use an explicitly fresh leaf only inside this digest construction."""
    digest = hashlib.sha256(prefix_model.encode("ascii"))
    for path in (Path(__file__), Path(seed_owner.__file__)):
        digest.update(path.read_bytes())
    return digest.hexdigest()


def fetched_code_model_hash() -> str:
    """Read all code-preservation and seed dependencies at this boundary."""
    return _model_hash(code_prefix_model_hash())


def _requirements(requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]) -> tuple[FetchedCodeKey, ...]:
    """Freeze both seeds and every prefix before a solver or source can refuse."""
    rows = [FetchedCodeKey(item) for item in (FetchedCodeObligation.PREFIX, FetchedCodeObligation.SOURCE, FetchedCodeObligation.INITIALIZATION,
                                            FetchedCodeObligation.AFTER, FetchedCodeObligation.MODEL)]
    for side, blocks in enumerate(requests):
        rows.extend(FetchedCodeKey(item, side) for item in (FetchedCodeObligation.LOAD,
                     FetchedCodeObligation.WITNESS, FetchedCodeObligation.SEED))
        rows.extend(FetchedCodeKey(FetchedCodeObligation.PRESERVATION, side, block.address) for block in blocks)
    return tuple(rows)


class _CodeStop(Exception):
    """One specific proof boundary; other programming errors stay loud."""

    def __init__(self, reason: FetchedCodeReason, detail: str) -> None:
        """Retain the enum and cause without text-based classification."""
        self.reason = reason
        super().__init__(detail)


def _query(predicate: z3.BoolRef, limits: LoadedRelationLimits, *, witness: bool) -> FetchedCodeFact:
    """One seed-domain check under the original deadline, with no new budget."""
    limits.check_time()
    remaining = int((limits.deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "code seed original deadline exhausted")
    solver = z3.Solver()
    solver.set(timeout=remaining)
    solver.add(predicate if witness else z3.Not(predicate))
    result = solver.check()
    limits.check_time()
    expected = z3.sat if witness else z3.unsat
    key = FetchedCodeKey(FetchedCodeObligation.WITNESS if witness else FetchedCodeObligation.SEED)
    if result == expected:
        return FetchedCodeFact(key, ProofStatus.PROVED, native_result=result)
    status = ProofStatus.COUNTEREXAMPLE if result == z3.sat else ProofStatus.UNKNOWN
    detail = str(solver.model()) if result == z3.sat else solver.reason_unknown() if result == z3.unknown else "seed domain is empty"
    limits.check_time()
    return FetchedCodeFact(key, status, detail, result)


def _seed_side(side: int, load: BoundReal16Load, requests: tuple[NativeBlockRequest, ...],
               source: Real16CodePrefixProof, limits: LoadedRelationLimits,
               facts: list[FetchedCodeFact], domains: list[FetchedCodeDomain]) -> None:
    """Bind literals, establish their seed and consume every preservation witness."""
    load.verify(limits=limits)
    binding = _BindingRun(load, requests, limits)
    spans = tuple(FetchedCodeSpan(row.address, _block_bytes(binding, row)) for row in requests)
    expected = tuple((span.address, hashlib.sha256(span.data).hexdigest()) for span in spans)
    actual = tuple((block.address, block.byte_hash) for block in source.blocks if block.side == side)
    if actual != expected:
        raise _CodeStop(FetchedCodeReason.SOURCE, "current fetched bytes differ from the prefix proof")
    facts.append(FetchedCodeFact(FetchedCodeKey(FetchedCodeObligation.LOAD, side), ProofStatus.PROVED))
    domain = FetchedCodeDomain(side, load.binding.file_sha256, load.binding.snapshot.sparse_byte_sha256, spans)
    domains.append(domain)
    background = z3.Array(f"fetched_code_background_{side}", z3.BitVecSort(32), z3.BitVecSort(8))
    seeded = seed_loaded_array(load.binding.snapshot, background, limits)
    initial = z3.Array(f"fetched_code_initial_{side}", z3.BitVecSort(32), z3.BitVecSort(8))
    predicate = domain.predicate(seeded, limits)
    witness = _query(cast(z3.BoolRef, z3.And(initial == seeded, domain.predicate(initial, limits))), limits, witness=True)
    facts.append(replace(witness, key=FetchedCodeKey(FetchedCodeObligation.WITNESS, side)))
    if witness.status is not ProofStatus.PROVED:
        raise _CodeStop(FetchedCodeReason.UNKNOWN, witness.detail)
    seed = _query(predicate, limits, witness=False)
    facts.append(replace(seed, key=FetchedCodeKey(FetchedCodeObligation.SEED, side)))
    if seed.status is not ProofStatus.PROVED:
        reason = FetchedCodeReason.COUNTERMODEL if seed.status is ProofStatus.COUNTEREXAMPLE else FetchedCodeReason.UNKNOWN
        raise _CodeStop(reason, seed.detail)
    for row in requests:
        limits.check_time()
        facts.append(FetchedCodeFact(FetchedCodeKey(FetchedCodeObligation.PRESERVATION, side, row.address), ProofStatus.PROVED))


def _report(required: tuple[FetchedCodeKey, ...], facts: list[FetchedCodeFact], domains: list[FetchedCodeDomain],
            reason: FetchedCodeReason, model: str, proposal: str, detail: str,
            consumption: BoundDomainConsumption | None) -> Real16FetchedCodeInvariant:
    """Keep every unattempted row and duplicate in the failure denominator."""
    ids = tuple(fact.key for fact in facts)
    missing = len(set(required) - set(ids))
    invalid = len(set(ids) - set(required)) + len(ids) - len(set(ids)) + len(required) - len(set(required))
    failed = missing + invalid + sum(fact.status is not ProofStatus.PROVED for fact in facts)
    status = ProofStatus.PROVED if reason is FetchedCodeReason.PRESERVED and failed == 0 else ProofStatus.UNKNOWN
    if any(fact.status is ProofStatus.COUNTEREXAMPLE for fact in facts):
        status = ProofStatus.COUNTEREXAMPLE
    count = len(required)
    return Real16FetchedCodeInvariant(status, reason, model, proposal, required, tuple(facts), tuple(domains),
                                     FactCounters(count, count, count, len(facts), failed), detail, consumption)


@dataclass(slots=True)
class _CodeEvidence:
    """Retain partial identity, seed domains and exact attempted facts on refusal."""

    required: tuple[FetchedCodeKey, ...]
    facts: list[FetchedCodeFact] = field(default_factory=list)
    domains: list[FetchedCodeDomain] = field(default_factory=list)
    model: str = ""
    proposal: str = ""
    consumption: BoundDomainConsumption | None = None


def _establish(source: Real16CodePrefixProof, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    selected: LoadedRelationLimits, run: _CodeEvidence) -> None:
    """Check current prerequisites, initiate seeds and consume universal preservation."""
    intake = establish_prefix_intake(source, system, loads, initialized, bootstrap, requests, limits=selected)
    run.model = _model_hash(intake.prefix_model) if intake.prefix_model else ""
    run.proposal, run.consumption = intake.proposal_hash, intake.consumption
    if intake.prefix_current:
        run.facts.append(FetchedCodeFact(FetchedCodeKey(FetchedCodeObligation.PREFIX), ProofStatus.PROVED))
    if intake.consumption is not None:
        status = ProofStatus.PROVED if intake.consumption.complete else ProofStatus.UNKNOWN
        run.facts.append(FetchedCodeFact(FetchedCodeKey(FetchedCodeObligation.SOURCE), status))
    if intake.reason is not PrefixIntakeReason.CURRENT:
        reasons = {PrefixIntakeReason.SOURCE: FetchedCodeReason.SOURCE,
                   PrefixIntakeReason.MODEL: FetchedCodeReason.MODEL,
                   PrefixIntakeReason.DEADLINE: FetchedCodeReason.DEADLINE}
        raise _CodeStop(reasons[intake.reason], intake.detail)
    guard = _TransitionRun(initialized, selected, 262144, 128)
    if _consume_initialized(guard) is not Architecture.REAL16:
        raise _CodeStop(FetchedCodeReason.INITIALIZATION, "requires real16 loaded snapshots")
    if (initialized.proposal.original, initialized.proposal.candidate) != tuple(load.binding.snapshot for load in loads):
        raise _CodeStop(FetchedCodeReason.INITIALIZATION, "loaded relation belongs to different images")
    run.facts.append(FetchedCodeFact(FetchedCodeKey(FetchedCodeObligation.INITIALIZATION), ProofStatus.PROVED))
    for side in range(2):
        _seed_side(side, loads[side], requests[side], source, selected, run.facts, run.domains)
    fresh_prefix = code_prefix_model_hash()
    selected.check_time()
    if source.model_hash != fresh_prefix or source.proposal_hash != joint_proposal_hash(system, bootstrap):
        raise _CodeStop(FetchedCodeReason.MODEL, "prefix context changed during establishment")
    run.facts.append(FetchedCodeFact(FetchedCodeKey(FetchedCodeObligation.AFTER), ProofStatus.PROVED))
    if run.model != _model_hash(fresh_prefix):
        raise _CodeStop(FetchedCodeReason.MODEL, "code invariant owner changed")
    selected.check_time()
    run.facts.append(FetchedCodeFact(FetchedCodeKey(FetchedCodeObligation.MODEL), ProofStatus.PROVED))


def check_fetched_code_invariant(source: Real16CodePrefixProof, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, timeout_ms: int = 15000, limits: LoadedRelationLimits | None = None) -> Real16FetchedCodeInvariant:
    """Establish actual loaded literals and invariant preservation on both sides.

    Complete atomic dispatch, scalar-domain preservation and physical-address
    interpretation must still be proved by the composing checker. Only code
    bytes are constrained at later cutpoints; mutable data remains unrestricted.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("fetched code invariant requires a nonnegative millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    selected = replace(selected, deadline=min(deadline, selected.deadline) if selected.deadline >= 0 else deadline)
    run = _CodeEvidence(_requirements(requests))
    reason, detail = FetchedCodeReason.PRESERVED, ""
    try:
        _establish(source, system, loads, initialized, bootstrap, requests, selected, run)
    except _CodeStop as refusal:
        reason, detail = refusal.reason, str(refusal)
    except LoadedRelationRefusal as refusal:
        reason = FetchedCodeReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else FetchedCodeReason.RESOURCE
        detail = refusal.detail
    except _TransitionRefusal as refusal:
        reason = FetchedCodeReason.DEADLINE if refusal.reason is LoadedTransitionReason.DEADLINE else FetchedCodeReason.INITIALIZATION
        detail = refusal.detail
    except _NativeRefusal as refusal:
        reason = FetchedCodeReason.DEADLINE if refusal.reason is NativeBindingReason.DEADLINE else FetchedCodeReason.SOURCE
        detail = refusal.detail
    except ImageBindingRefusal as refusal:
        reason, detail = FetchedCodeReason.SOURCE, str(refusal)
    return _report(run.required, run.facts, run.domains, reason, run.model, run.proposal, detail, run.consumption)
