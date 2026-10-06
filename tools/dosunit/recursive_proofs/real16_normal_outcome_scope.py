"""Layer: dosunit image-bound normal-outcome scope closure (staging).

Responsibility: close FAULT_DOMAIN and ENVIRONMENT for the admitted joint
transition set under a precisely declared supported domain.  FAULT_DOMAIN is
source-proved: for every admitted transition on both sides plus each actual
entry block, this owner extracts fresh bytes, requires a bound block from a
proved independent native binding, re-runs the byte-level instruction/scope
classifiers and requires a complete physical access bound.  ENVIRONMENT is a
declared machine premise, not byte evidence: the caller must supply a typed
``Real16EnvironmentScope`` inside the joint proposal, content-bound to both
binaries; without it the asynchronous/external scope stays open and visible.
It cannot establish allocation, service, observer or binary equivalence.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from tools.dosunit import binary_environment as _binary_environment
from tools.dosunit import flat32_replay as _flat32_replay
from tools.dosunit import replay_machine_inputs as _replay_machine_inputs
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import (
    native_model_hash_snapshot,
    native_model_hash_snapshot_active,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
    image_bound_domain_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBindingReason,
    NativeBlockBinding,
    NativeBlockKind,
    NativeBlockRequest,
    _BindingRun,
    _block_bytes,
    _check_instruction_scope,
    _NativeRefusal,
    native_binding_model_hash,
)
from tools.dosunit.recursive_proofs.real16_physical_access_bounds import (
    PhysicalAccessBlock,
    Real16PhysicalAccessBounds,
    physical_access_model_hash,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointStepKind,
    JointSystem,
    Real16EnvironmentScope,
)
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.register_state_relations import MachineState


class OutcomeScopeReason(StrEnum):
    """The exact closure discharged or the boundary that refused it."""

    DISCHARGED = "every_admitted_transition_has_normal_outcomes_only"
    RECEIPT = "outcome_scope_prerequisite_receipt_refused"
    SOURCES = "outcome_scope_native_outcome_sources_incomplete"
    BOUNDS = "outcome_scope_physical_access_bounds_unproved"
    COVERAGE = "admitted_transition_request_or_identity_missing"
    SOURCE = "admitted_transition_byte_or_decode_refused"
    FAULT = "admitted_transition_fault_outcome_unclosed"
    ENVIRONMENT = "admitted_transition_external_event_unclosed"
    PREMISE = "declared_environment_scope_premise_absent_or_unbound"
    MODEL = "outcome_scope_model_identity_changed"
    DEADLINE = "outcome_scope_original_deadline_exhausted"
    UNKNOWN = "outcome_scope_evidence_unknown"


class OutcomeScopeObligation(StrEnum):
    """Every required premise remains in the ledger on early refusal."""

    RECEIPT_BEFORE = "complete_image_bound_receipt_before_outcome_scope"
    SOURCES = "complete_proved_native_outcome_sources"
    BOUNDS = "proved_physical_access_bounds_certificate"
    BLOCK = "admitted_transition_normal_outcome_evidence"
    PREMISE = "declared_environment_scope_premise_content_bound"
    RECEIPT_AFTER = "complete_image_bound_receipt_after_outcome_scope"
    MODEL = "stable_outcome_scope_model_seal"


class OutcomeScopeOmission(StrEnum):
    """Obligations this closure deliberately does not discharge."""

    ALLOCATION = "dos_allocation_and_permission_scope_unclosed"
    SERVICES = "dos_bios_service_contracts_unclosed"
    OBSERVERS = "final_observers_and_unmatched_regions_unclosed"
    EQUIVALENCE = "whole_binary_equivalence_not_established"


_STEP_KINDS: dict[JointStepKind, NativeBlockKind] = {
    JointStepKind.BRANCH: NativeBlockKind.BRANCH,
    JointStepKind.CALL: NativeBlockKind.CALL,
    JointStepKind.RETURN: NativeBlockKind.RETURN,
}


class _KindConflict:
    """Marker for contradictory declared step kinds at one admitted coordinate."""


_KIND_CONFLICT = _KindConflict()


@dataclass(frozen=True, slots=True)
class OutcomeScopeFact:
    """One attempted premise, including retained non-results."""

    obligation: OutcomeScopeObligation
    key: str
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class OutcomeScopeBlock:
    """One admitted transition verified against source-proved normal scope."""

    side: int
    address: int
    size: int
    byte_hash: str
    kind: NativeBlockKind


@dataclass(frozen=True, slots=True)
class Real16NormalOutcomeScope:
    """Outcome certificate for every admitted joint transition.

    ``premise`` is the caller-declared closed-machine scope actually consumed;
    ``None`` records that no typed premise was supplied, in which case
    ENVIRONMENT stays open while synchronous FAULT evidence may still close.
    This certificate compares outcome scope for admitted transitions only and
    grants no reachability, allocation, service or binary equivalence.
    """

    status: ProofStatus
    reason: OutcomeScopeReason
    model_hash: str
    proposal_hash: str
    premise: Real16EnvironmentScope | None
    required: tuple[tuple[OutcomeScopeObligation, str], ...]
    blocks: tuple[OutcomeScopeBlock, ...]
    facts: tuple[OutcomeScopeFact, ...]
    consumers: tuple[BoundDomainConsumption, ...]
    omissions: tuple[OutcomeScopeOmission, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def _ledger_consistent(self) -> bool:
        """Require exact raw fact coverage plus counter/status agreement.

        Duplicate, missing or extra fact identities reject before any status
        projection, so an UNKNOWN row can never be hidden behind a later
        PROVED row. Counters must agree with the retained statuses.
        """
        ids = tuple((fact.obligation, fact.key) for fact in self.facts)
        if (len(ids) != len(set(ids)) or len(self.required) != len(set(self.required))
                or set(ids) != set(self.required)):
            return False
        proved = sum(fact.status is ProofStatus.PROVED for fact in self.facts)
        return bool(self.counters.raw_fact_count == len(self.required)
                    and self.counters.normalized_fact_count == len(self.required)
                    and self.counters.classified_fact_count == len(self.facts)
                    and self.counters.materialized_count == proved
                    and self.counters.failure_count == len(self.facts) - proved)

    @property
    def synchronous_closed(self) -> bool:
        """Require every synchronous row proved; the premise may stay open."""
        if not self._ledger_consistent:
            return False
        statuses = {(fact.obligation, fact.key): fact.status for fact in self.facts}
        sync = [row for row in self.required if row[0] is not OutcomeScopeObligation.PREMISE]
        return bool(self.facts) and all(statuses.get(row) is ProofStatus.PROVED for row in sync)

    @property
    def complete(self) -> bool:
        """Require every required row proved once, premise included."""
        return (self.status is ProofStatus.PROVED and self.reason is OutcomeScopeReason.DISCHARGED
                and self.premise is not None
                and self._ledger_consistent
                and all(fact.status is ProofStatus.PROVED for fact in self.facts)
                and self.omissions == tuple(OutcomeScopeOmission)
                and self.counters.failure_count == 0)

    @property
    def declared_scope_assumptions(self) -> tuple[str, ...]:
        """Name each declared exclusion, bound to both binaries, for callers.

        A complete scope rests on a caller declaration, not byte proof; the
        shared obligation evidence must carry these assumption strings so no
        downstream reader mistakes the theorem for an unconditional one.
        """
        if self.premise is None or not self.complete:
            return ()
        bound = f"original={self.premise.original_hash},candidate={self.premise.candidate_hash}"
        return tuple(f"{member.value}({bound})" for member in self.premise.members)

    @property
    def binary_equivalence_proved(self) -> bool:
        """Admitted-transition outcome scope grants no whole-binary verdict."""
        return False


def outcome_scope_model_hash() -> str:
    """Seal this owner, the loaded environment classifiers and consumed owners."""
    if native_model_hash_snapshot_active():
        return _outcome_scope_model_hash()
    with native_model_hash_snapshot():
        return _outcome_scope_model_hash()


def _outcome_scope_model_hash() -> str:
    """Read the classifier and consumed-owner digests within one native capture."""
    digest = hashlib.sha256(image_bound_domain_model_hash().encode("ascii"))
    digest.update(physical_access_model_hash().encode("ascii"))
    digest.update(native_binding_model_hash().encode("ascii"))
    paths = [Path(__file__)]
    for module in (_binary_environment, _flat32_replay, _replay_machine_inputs):
        paths.append(Path(str(module.__file__)))
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _admitted_rows(system: JointSystem, loads: tuple[BoundReal16Load, BoundReal16Load],
                   ) -> tuple[tuple[int, int, NativeBlockKind | _KindConflict | None], ...]:
    """Freeze the admitted transition set: every step coordinate plus entry.

    Two steps sharing one physical coordinate must declare the same kind; a
    contradiction is retained as ``_KIND_CONFLICT`` so the row refuses instead
    of silently skipping the control-kind check.  The entry coordinate keeps no
    declared kind: its bound kind is whatever the actual entry block proved.
    """
    rows: list[tuple[int, int, NativeBlockKind | _KindConflict | None]] = []
    for side in range(2):
        expected: dict[int, NativeBlockKind | _KindConflict | None] = {}
        for step in system.steps:
            address = step.original_address if side == 0 else step.candidate_address
            kind = _STEP_KINDS[step.kind]
            if address in expected and expected[address] is not kind:
                expected[address] = _KIND_CONFLICT
            else:
                expected.setdefault(address, kind)
        expected.setdefault(loads[side].binding.entry, None)
        rows.extend((side, address, expected[address]) for address in expected)
    return tuple(rows)


def _block_key(side: int, address: int) -> str:
    """Return the stable diagnostic key for one admitted transition row."""
    return f"{side}:{address:#08x}"


@dataclass(slots=True)
class _ScopeRun:
    """One original deadline, the frozen admitted set and closed fact ledger."""

    receipt: ImageBoundReal16Domain
    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    bounds: Real16PhysicalAccessBounds
    limits: LoadedRelationLimits
    model: str = ""
    proposal: str = ""
    blocks: list[OutcomeScopeBlock] = field(default_factory=list)
    facts: list[OutcomeScopeFact] = field(default_factory=list)
    consumers: list[BoundDomainConsumption] = field(default_factory=list)

    def remaining_ms(self) -> int:
        """Charge extraction, scans and hashing to the original deadline."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE,
                                      "outcome scope original deadline exhausted")
        return remaining

    def consume(self, obligation: OutcomeScopeObligation, key: str) -> OutcomeScopeReason | None:
        """Revalidate the exact source/domain receipt before and after work."""
        self.limits.check_time()
        outcome = consume_image_bound_real16_domain(self.receipt, self.system, self.loads,
                    self.initialized, self.bootstrap, self.requests,
                    timeout_ms=2**31 - 1, limits=self.limits)
        self.consumers.append(outcome)
        accepted = outcome.status is ProofStatus.PROVED and outcome.counters.failure_count == 0
        self.facts.append(OutcomeScopeFact(obligation, key,
                          ProofStatus.PROVED if accepted else ProofStatus.UNKNOWN, outcome.detail))
        if accepted:
            return None
        return (OutcomeScopeReason.DEADLINE if outcome.reason is BoundDomainReason.DEADLINE
                else OutcomeScopeReason.RECEIPT)

    def required_rows(self) -> tuple[tuple[OutcomeScopeObligation, str], ...]:
        """Freeze the denominator from the proposal before any scan can shrink it."""
        rows = [(OutcomeScopeObligation.RECEIPT_BEFORE, "before"),
                (OutcomeScopeObligation.SOURCES, "sources"),
                (OutcomeScopeObligation.BOUNDS, "bounds")]
        rows.extend((OutcomeScopeObligation.BLOCK, _block_key(side, address))
                    for side, address, _kind in _admitted_rows(self.system, self.loads))
        rows.extend(((OutcomeScopeObligation.PREMISE, "premise"),
                     (OutcomeScopeObligation.RECEIPT_AFTER, "after"),
                     (OutcomeScopeObligation.MODEL, "seal")))
        return tuple(rows)

    def report(self, reason: OutcomeScopeReason, detail: str = "") -> Real16NormalOutcomeScope:
        """Every missing, duplicate or unproved row stays a failure."""
        required = self.required_rows()
        required_set = set(required)
        ids = tuple((fact.obligation, fact.key) for fact in self.facts)
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(required_set - set(ids)) + len(set(ids) - required_set) + len(ids) - len(set(ids))
        proved = sum(fact.status is ProofStatus.PROVED and (fact.obligation, fact.key) in required_set
                     for fact in self.facts)
        status = ProofStatus.PROVED if reason is OutcomeScopeReason.DISCHARGED and failed == 0 else ProofStatus.UNKNOWN
        if not detail and self.consumers:
            detail = self.consumers[-1].detail
        return Real16NormalOutcomeScope(status, reason, self.model, self.proposal,
            self.system.environment_scope, required, tuple(self.blocks), tuple(self.facts),
            tuple(self.consumers), tuple(OutcomeScopeOmission),
            FactCounters(len(required), len(required), len(required), proved, failed), detail)


def _byte_normal_scope(data: bytes, address: int) -> tuple[OutcomeScopeReason | None, str]:
    """Re-run the byte-level environment classifiers on fresh provenance.

    Uses the same one-pass decoded-instruction policy as the native binder:
    instruction scope, port effects and machine-state operands.  These checks
    prove only the absence of excluded synchronous effects on these bytes;
    they say nothing about asynchronous agents, which the declared premise
    covers separately.
    """
    try:
        _check_instruction_scope(data, address)
    except _NativeRefusal as refusal:
        if refusal.reason is NativeBindingReason.DECODE:
            return OutcomeScopeReason.SOURCE, refusal.detail
        if refusal.reason is NativeBindingReason.FAULT:
            return OutcomeScopeReason.ENVIRONMENT, refusal.detail
        return OutcomeScopeReason.UNKNOWN, refusal.detail
    return None, ""


def _bound_block(source: tuple[NativeBlockBinding, ...], address: int) -> NativeBlockBinding | None:
    """Find the independently bound block for one admitted coordinate."""
    matches = [block for block in source if block.address == address]
    return matches[0] if len(matches) == 1 else None


def _bounds_row(bounds: tuple[PhysicalAccessBlock, ...], side: int, address: int) -> PhysicalAccessBlock | None:
    """Find the proved access-bound row for one admitted coordinate."""
    matches = [row for row in bounds if row.side == side and row.address == address]
    return matches[0] if len(matches) == 1 else None


def _block_row(run: _ScopeRun, side: int, address: int,
               expected: NativeBlockKind | _KindConflict | None,
               ) -> tuple[OutcomeScopeReason | None, str]:
    """Close the outcome scope for one admitted transition, or retain why not."""
    key = _block_key(side, address)
    if expected is _KIND_CONFLICT:
        return OutcomeScopeReason.COVERAGE, f"{key}: contradictory declared step kinds"
    rows = [row for row in run.requests[side] if row.address == address]
    if len(rows) != 1:
        return OutcomeScopeReason.COVERAGE, f"{key}: admitted coordinate lacks exactly one request"
    row = rows[0]
    extraction = _BindingRun(run.loads[side], run.requests[side], run.limits)
    try:
        data = _block_bytes(extraction, row)
    except _NativeRefusal as refusal:
        if refusal.reason is NativeBindingReason.DEADLINE:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, refusal.detail) from refusal
        return OutcomeScopeReason.SOURCE, f"{key}: {refusal.detail}"
    byte_hash = hashlib.sha256(data).hexdigest()
    bound = _bound_block(run.receipt.sources[side].blocks, address)
    if (bound is None or bound.size != row.size or bound.byte_hash != byte_hash
            or bound.effect_hash != row.effect_hash):
        return OutcomeScopeReason.COVERAGE, f"{key}: no bound block matches the admitted bytes"
    refused, detail = _byte_normal_scope(data, address)
    if refused is not None:
        return refused, f"{key}: {detail}"
    if expected is not None and bound.kind is not expected:
        return OutcomeScopeReason.COVERAGE, f"{key}: bound control kind differs from the step kind"
    bounds_row = _bounds_row(run.bounds.blocks, side, address)
    if (bounds_row is None or bounds_row.size != row.size or bounds_row.byte_hash != byte_hash
            or not bounds_row.complete):
        return OutcomeScopeReason.BOUNDS, f"{key}: no complete access bound matches the admitted bytes"
    run.blocks.append(OutcomeScopeBlock(side, address, row.size, byte_hash, bound.kind))
    run.facts.append(OutcomeScopeFact(OutcomeScopeObligation.BLOCK, key, ProofStatus.PROVED))
    return None, ""


def _premise_row(run: _ScopeRun) -> tuple[OutcomeScopeReason | None, str]:
    """Consume the declared closed-machine premise, bound to both binaries.

    A missing premise is not refuted evidence: ENVIRONMENT simply remains an
    open declared obligation.  A premise whose binary hashes disagree with the
    joint contract is forged and likewise cannot close it.
    """
    premise = run.system.environment_scope
    if premise is None:
        return OutcomeScopeReason.PREMISE, "no declared environment scope premise in the proposal"
    contract = run.system.contract
    if (premise.original_hash != contract.original_hash
            or premise.candidate_hash != contract.candidate_hash):
        return OutcomeScopeReason.PREMISE, "environment scope premise is bound to different binaries"
    return None, ""


def _prove(run: _ScopeRun) -> OutcomeScopeReason:
    """Consume the receipt, verify certificates and close every admitted row."""
    refused = run.consume(OutcomeScopeObligation.RECEIPT_BEFORE, "before")
    if refused is not None:
        return refused
    run.model = outcome_scope_model_hash()
    run.proposal = joint_proposal_hash(run.system, run.bootstrap)
    run.remaining_ms()
    complete = (len(run.receipt.sources) == 2
                and all(source.status is ProofStatus.PROVED and source.counters.failure_count == 0
                        and source.requests == run.requests[side]
                        for side, source in enumerate(run.receipt.sources)))
    run.facts.append(OutcomeScopeFact(OutcomeScopeObligation.SOURCES, "sources",
                     ProofStatus.PROVED if complete else ProofStatus.UNKNOWN))
    if not complete:
        return OutcomeScopeReason.SOURCES
    bounded = (run.bounds.status is ProofStatus.PROVED and run.bounds.counters.failure_count == 0
               and run.bounds.proposal_hash == run.proposal
               and run.bounds.model_hash == physical_access_model_hash())
    run.facts.append(OutcomeScopeFact(OutcomeScopeObligation.BOUNDS, "bounds",
                     ProofStatus.PROVED if bounded else ProofStatus.UNKNOWN))
    if not bounded:
        return OutcomeScopeReason.BOUNDS
    for side, address, expected in _admitted_rows(run.system, run.loads):
        run.limits.check_time()
        refused, detail = _block_row(run, side, address, expected)
        if refused is not None:
            run.facts.append(OutcomeScopeFact(OutcomeScopeObligation.BLOCK,
                             _block_key(side, address), ProofStatus.UNKNOWN, detail))
            return refused
    refused, detail = _premise_row(run)
    premise_open = refused is not None
    run.facts.append(OutcomeScopeFact(OutcomeScopeObligation.PREMISE, "premise",
                     ProofStatus.PROVED if not premise_open else ProofStatus.UNKNOWN, detail))
    # An open premise is never a hard refusal: the remaining ledger rows still
    # emit so the certificate keeps the complete synchronous accounting.
    refused = run.consume(OutcomeScopeObligation.RECEIPT_AFTER, "after")
    if refused is not None:
        return refused
    stable = run.model == outcome_scope_model_hash()
    run.remaining_ms()
    run.facts.append(OutcomeScopeFact(OutcomeScopeObligation.MODEL, "seal",
                     ProofStatus.PROVED if stable else ProofStatus.UNKNOWN,
                     "" if stable else "outcome scope model changed during the proof"))
    if not stable:
        return OutcomeScopeReason.MODEL
    return OutcomeScopeReason.PREMISE if premise_open else OutcomeScopeReason.DISCHARGED


def prove_real16_normal_outcome_scope(
    receipt: ImageBoundReal16Domain, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    bounds: Real16PhysicalAccessBounds,
    *, timeout_ms: int = 30000, limits: LoadedRelationLimits | None = None,
) -> Real16NormalOutcomeScope:
    """Close fault/environment outcome scope for every admitted transition.

    Requires the complete image-bound receipt, proved native outcome sources,
    proved physical access bounds for the same proposal and, per admitted
    transition, a bound block with fresh byte-identical provenance, clean
    byte-level environment classification and a matching complete access
    bound.  ENVIRONMENT additionally requires the declared typed
    ``Real16EnvironmentScope`` premise inside ``system``; without it the
    certificate reports ``PREMISE`` and the asynchronous scope stays open.
    The result never grants reachability or binary equivalence.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("outcome scope requires a nonnegative millisecond budget")
    if not isinstance(bounds, Real16PhysicalAccessBounds):
        raise ValueError("outcome scope requires the proved physical access bounds certificate")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _ScopeRun(receipt, system, loads, initialized, bootstrap, requests, bounds,
                    replace(selected, deadline=deadline))
    try:
        reason = _prove(run)
        return run.report(reason)
    except LoadedRelationRefusal as refusal:
        emitted = {(fact.obligation, fact.key) for fact in run.facts}
        missing = next((row for row in run.required_rows() if row not in emitted),
                       run.required_rows()[-1])
        run.facts.append(OutcomeScopeFact(*missing, ProofStatus.UNKNOWN, refusal.detail))
        reason = (OutcomeScopeReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE
                  else OutcomeScopeReason.UNKNOWN)
        return run.report(reason, refusal.detail)
