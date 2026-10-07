"""Staged draft: real16 ADDRESS_MODEL closure compositor (NOT production).

Layer: dosunit recursive address-model evidence composition.

Responsibility: consume the already-discharged joint-proof children — fetched
code prefixes with per-block fetch geometry, bound operand scope, first-MiB
physical access bounds, the bound native control scope, both sides' frame
clause batches, the retained domain-scoped dispatch ledger, the entry frame
and the image-bound scalar domain — and issue one typed certificate proving
that every address the admitted machine can produce (fetch span, data operand
byte lane, stack word, call/return control target, root entry, terminal caller
exit) lies inside the declared segmented/first-MiB model.  This owner adds no
solver premises: its content is accounted evidence plus one concrete
arithmetic bound (the terminal caller-exit coordinate) that no child currently
owns.  Every child record is rebound to the exact side/address/size request
denominator and the image-bound receipt is revalidated through the
authoritative ``consume_image_bound_real16_domain`` consumer — a ``PROVED``
label alone is never evidence.  On missing, extra, mutated, stale or
countermodel evidence it returns a typed non-result; it never deletes the
requirement.

Provenance contract (integration obligation):
- ``receipt``, ``prefixes``, ``operands``, ``addresses``, ``controls`` and
  ``dispatch`` are safe retained receipts: this compositor rebinds each to the
  current run's proposal hash, scalar domain, exact request denominator and
  owner model seals, and revalidates their retained source/domain consumers,
  before crediting a single ``PROVED`` label.
- ``frames`` has no equivalent retained-receipt surface.
  ``StackInvariantProof`` retains layout, clause manifest and continuation
  identity but carries no input ``MachineState`` binding, and the joint
  producer creates each proof fresh per state inside ``_frames``.  Closure
  therefore requires private fresh-run integration: the caller must pass the
  exact ``run.frames`` sequence produced by the same
  ``check_image_bound_real16_joint`` invocation, and no API here may treat an
  arbitrary saved frame tuple as independently source-bound.

The joint checker calls this private compositor after fresh frame and dispatch
proofs, retains the certificate, and closes ADDRESS_MODEL only on complete
evidence. Its model hash consumes this owner's hash. Fault and environment
closure remain separate requirements and cannot be discharged here.
"""
from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
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
from tools.dosunit.recursive_proofs.real16_bound_control_scope import (
    BoundControlReason,
    BoundReal16ControlScope,
    bound_control_model_hash,
)
from tools.dosunit.recursive_proofs.real16_bound_operand_scope import (
    BoundReal16OperandScope,
    bound_operand_model_hash,
)
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import (
    Real16CodePrefixProof,
    _entry,
    code_prefix_model_hash,
)
from tools.dosunit.recursive_proofs.real16_domain_dispatch import (
    DomainDispatchReason,
    Real16DomainDispatchProof,
    domain_dispatch_model_hash,
)
from tools.dosunit.recursive_proofs.real16_domain_dispatch import (
    _requirements as domain_dispatch_requirements,
)
from tools.dosunit.recursive_proofs.real16_entry_domain import native_effect_hash
from tools.dosunit.recursive_proofs.real16_entry_frame import (
    Real16EntryFrameProof,
    entry_frame_model_hash,
)
from tools.dosunit.recursive_proofs.real16_fetched_code_intake import PrefixIntakeReason
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    ImageBoundReal16Domain,
    image_bound_domain_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_native_control_scope import native_control_model_hash
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBlockKind,
    NativeBlockRequest,
)
from tools.dosunit.recursive_proofs.real16_operand_access import OperandSegment
from tools.dosunit.recursive_proofs.real16_operand_scope_proof import (
    NativeOperandScopeProof,
    OperandProofKind,
    OperandProofReason,
    operand_scope_model_hash,
)
from tools.dosunit.recursive_proofs.real16_physical_access_bounds import (
    PHYSICAL_MODEL_LIMIT,
    PhysicalAccessOmission,
    Real16PhysicalAccessBounds,
    physical_access_model_hash,
)
from tools.dosunit.recursive_proofs.recursive_call_continuation import (
    CallSide,
    request_call_continuation,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import (
    JointRefusal,
    derive_joint_frame_layout,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointStepKind,
    JointSystem,
)
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import (
    StackClauseKind,
    StackClauseReason,
    required_stack_clauses,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordLayout
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import (
    StackInvariantProof,
    StackObligation,
)


class AddressModelReason(StrEnum):
    """Exact closure outcome or the typed prerequisite still withholding it."""

    CLOSED = "address_model_all_coordinate_classes_within_scope"
    RECEIPT = "address_model_source_or_domain_receipt_incomplete"
    MANIFEST = "address_model_required_ledger_not_covered"
    FETCH = "address_model_fetch_geometry_not_complete"
    OPERAND = "address_model_operand_scope_not_complete"
    BOUNDS = "address_model_physical_bounds_not_complete"
    CONTROL = "address_model_bound_control_scope_incomplete"
    FRAME = "address_model_frame_or_continuation_clause_unproved"
    DISPATCH = "address_model_control_targets_not_bound"
    TERMINAL = "address_model_root_or_terminal_coordinate_out_of_scope"
    MODEL = "address_model_child_or_owner_identity_changed"
    DEADLINE = "address_model_original_deadline_exhausted"


class AddressModelObligation(StrEnum):
    """Every ledger row required before the enum requirement may be removed."""

    RECEIPT = "authoritative_source_domain_consumption_complete"
    MANIFEST = "request_pairs_cover_every_step_and_entry_exactly"
    FETCH = "every_request_block_span_within_cs_window_and_first_mib"
    OPERAND = "every_raw_occurrence_logical_binding_and_segment_scope"
    BOUNDS = "every_raw_byte_access_within_first_mib"
    CONTROL = "every_bound_block_near_control_coordinate_proved"
    FRAME = "every_push_body_pop_clause_manifest_discharged"
    DISPATCH = "every_static_control_term_resolves_to_admitted_addresses"
    ROOT = "root_entry_and_terminal_coordinates_within_model"
    MODEL = "child_and_closure_model_identities_current"


@dataclass(frozen=True, slots=True)
class AddressModelFact:
    """One ledger row; non-results retain the owning child refusal cause."""

    obligation: AddressModelObligation
    key: str
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class SegmentCensus:
    """Typed count of decoded operand segments present in admitted evidence.

    This is diagnostic evidence only, never an admission prerequisite: an
    access through a selector the consumed scalar domain does not pin is not
    impossible in principle — a stronger proven premise could still bound it —
    but under today's ``ss``/``cs``-only domain such an access makes an
    upstream child countermodel rather than silently closing.
    """

    counts: tuple[tuple[str, int], ...]

    @property
    def beyond_pinned_selectors(self) -> bool:
        """Count accesses through segments the consumed domain does not pin."""
        pinned = {OperandSegment.CS.value, OperandSegment.SS.value}
        return any(name not in pinned for name, count in self.counts if count)


@dataclass(frozen=True, slots=True)
class AddressModelClosure:
    """The composed certificate; never a fault, environment or binary verdict."""

    status: ProofStatus
    reason: AddressModelReason
    facts: tuple[AddressModelFact, ...]
    census: tuple[SegmentCensus, ...]
    terminal_addresses: tuple[int, ...]
    consumptions: tuple[BoundDomainConsumption, ...]
    model_hash: str
    counters: FactCounters
    detail: str = ""

    @property
    def complete(self) -> bool:
        """Require the exact closed ledger; extra or duplicate rows fail."""
        ids = tuple(fact.obligation for fact in self.facts)
        expected = set(AddressModelObligation)
        count = len(expected)
        return (self.status is ProofStatus.PROVED and self.reason is AddressModelReason.CLOSED
                and set(ids) == expected and len(ids) == count and len(set(ids)) == count
                and all(fact.status is ProofStatus.PROVED for fact in self.facts)
                and self.counters == FactCounters(count, count, count, count, 0))

    @property
    def binary_equivalence_proved(self) -> bool:
        """Address scope does not close faults, environment or equivalence."""
        return False


def address_model_model_hash() -> str:
    """Seal this owner over exactly the child model identities it consumes."""
    if native_model_hash_snapshot_active():
        return _address_model_model_hash()
    with native_model_hash_snapshot():
        return _address_model_model_hash()


def _address_model_model_hash() -> str:
    """Share one fresh native leaf only across this composite digest DAG."""
    digest = hashlib.sha256(Path(__file__).read_bytes())
    for owner_hash in (image_bound_domain_model_hash, code_prefix_model_hash,
                       bound_operand_model_hash, physical_access_model_hash,
                       bound_control_model_hash, domain_dispatch_model_hash,
                       entry_frame_model_hash):
        digest.update(owner_hash().encode("ascii"))
    return digest.hexdigest()


_KIND_TO_OBLIGATION = {JointStepKind.BRANCH: StackObligation.BODY,
                       JointStepKind.CALL: StackObligation.PUSH,
                       JointStepKind.RETURN: StackObligation.POP}

_STEP_KIND_TO_BLOCK_KIND = {JointStepKind.BRANCH: NativeBlockKind.BRANCH,
                            JointStepKind.CALL: NativeBlockKind.CALL,
                            JointStepKind.RETURN: NativeBlockKind.RETURN}


@dataclass(slots=True)
class _ClosureRun:
    """One shared deadline and the frozen nine-row ledger for both sides."""

    system: JointSystem
    receipt: ImageBoundReal16Domain
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    limits: LoadedRelationLimits
    model_hash: str = ""
    layout: StackWordLayout | None = None
    facts: list[AddressModelFact] = field(default_factory=list)
    census: list[SegmentCensus] = field(default_factory=list)
    terminals: list[int] = field(default_factory=list)
    consumptions: list[BoundDomainConsumption] = field(default_factory=list)

    def check_time(self) -> None:
        """Charge structural work to the same original absolute deadline."""
        self.limits.check_time()

    def remaining_ms(self) -> int:
        """Bound each delegated consumption inside the original deadline."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE,
                                      "address closure original deadline exhausted")
        return remaining

    def fact(self, obligation: AddressModelObligation, key: str, ok: bool, detail: str = "") -> bool:
        """Append one row; a False verdict still records the attempted row."""
        self.facts.append(AddressModelFact(obligation, key,
                                           ProofStatus.PROVED if ok else ProofStatus.UNKNOWN, detail))
        return ok

    def report(self, reason: AddressModelReason, detail: str = "") -> AddressModelClosure:
        """Missing, duplicate or failed rows keep the requirement open."""
        ids = [fact.obligation for fact in self.facts]
        expected = set(AddressModelObligation)
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(expected - set(ids)) + len(set(ids) - expected) + len(ids) - len(set(ids))
        count = len(expected)
        status = ProofStatus.PROVED if reason is AddressModelReason.CLOSED and failed == 0 else ProofStatus.UNKNOWN
        return AddressModelClosure(status, reason, tuple(self.facts), tuple(self.census),
                                   tuple(self.terminals), tuple(self.consumptions), self.model_hash,
                                   FactCounters(count, count, count, len(self.facts), failed), detail)


def _request_triples(run: _ClosureRun) -> tuple[tuple[int, int, int], ...]:
    """Freeze the ordered (side, address, size) request denominator once."""
    return tuple((side, row.address, row.size)
                 for side, rows in enumerate(run.requests) for row in rows)


def _receipt_ok(run: _ClosureRun) -> bool:
    """Revalidate the receipt through the authoritative consumer.

    A ``PROVED`` label on a saved certificate is not evidence: the consumer
    rechecks the complete prerequisite ledger, proposal content, both source
    bindings down to independently re-read bytes, the derived domain's
    effects/files/root and every model identity against this invocation's
    actual inputs.  The retained consumption is kept on the certificate.
    """
    outcome = consume_image_bound_real16_domain(run.receipt, run.system, run.loads,
        run.initialized, run.bootstrap, run.requests,
        timeout_ms=run.remaining_ms(), limits=run.limits)
    run.consumptions.append(outcome)
    ok = outcome.complete
    if ok:
        domain = run.receipt.domain
        roots = [step for step in run.system.steps if step.node == run.system.root]
        ok = (domain is not None and domain.status is ProofStatus.PROVED and len(roots) == 1
              and domain.root_address == roots[0].original_address
              and 0 <= roots[0].original_address < PHYSICAL_MODEL_LIMIT)
    return run.fact(AddressModelObligation.RECEIPT, "receipt", ok,
                    "" if ok else outcome.detail or "image-bound receipt consumption incomplete")


def _manifest_ok(run: _ClosureRun) -> bool:
    """Re-derive the authoritative (address, effect) pair manifest per side.

    The denominator is the exact set of ``(address, effect_hash)`` pairs —
    every admitted step plus the bootstrap entry — matching
    ``real16_image_bound_domain._linked`` rather than ``len(steps) + 1``
    cardinality arithmetic, so duplicate rows, mutated effect hashes and an
    entry that coincides with a step coordinate are all resolved by pair
    equality.  Step kinds are additionally rebound to the retained source
    block kinds the consumer revalidated byte-for-byte.
    """
    ok = True
    for side in range(2):
        run.check_time()
        expected = {(step.original_address, native_effect_hash(step.original)) if side == 0
                    else (step.candidate_address, native_effect_hash(step.candidate))
                    for step in run.system.steps}
        expected.add((run.loads[side].binding.entry, native_effect_hash(run.bootstrap[side])))
        actual = {(row.address, row.effect_hash) for row in run.requests[side]}
        bound = {block.address: block.kind for block in run.receipt.sources[side].blocks}
        kinds_ok = all(step.kind in _STEP_KIND_TO_BLOCK_KIND
                       and bound.get(step.original_address if side == 0 else step.candidate_address)
                       is _STEP_KIND_TO_BLOCK_KIND[step.kind]
                       for step in run.system.steps)
        ok = (ok and len(actual) == len(run.requests[side]) and actual == expected
              and all(row.size > 0 for row in run.requests[side]) and kinds_ok)
    return run.fact(AddressModelObligation.MANIFEST, "requests", ok,
                    "" if ok else "request manifest differs from admitted steps plus entry")


def _fetch_ok(run: _ClosureRun, prefixes: Real16CodePrefixProof) -> bool:
    """Require the exact ordered block manifest; extra or mutated blocks fail.

    The denominator is the ordered ``(side, address, size)`` request triple —
    the identity the prefix producer itself bound — so an unrelated extra
    prefix block, a missing step block or a resized span refuses.  Retained
    ``requests``/``receipt``/``proposal_hash`` fields must name this run's
    inputs, both retained consumers must be complete, and every block's
    ``complete`` property re-checks loader-linear coordinates and span-exact
    fetch geometry.
    """
    actual = tuple((block.side, block.address, block.size) for block in prefixes.blocks)
    ok = (prefixes.status is ProofStatus.PROVED and prefixes.counters.failure_count == 0
          and actual == _request_triples(run) and len(set(actual)) == len(actual)
          and prefixes.requests == run.requests and prefixes.receipt == run.receipt
          and prefixes.proposal_hash == joint_proposal_hash(run.system, run.bootstrap)
          and len(prefixes.consumers) >= 2
          and all(item.complete for item in prefixes.consumers))
    for block in prefixes.blocks:
        run.check_time()
        ok = ok and block.complete \
            and block.fetch_scope.coordinate_domain is ControlAddressDomain.LOADER_LINEAR
    return run.fact(AddressModelObligation.FETCH, "fetch", ok,
                    "" if ok else "fetched span geometry incomplete for an admitted block")


def _operand_ledger_complete(proof: NativeOperandScopeProof) -> bool:
    """Require every collected access binding and scope theorem exactly once."""
    expected = {(OperandProofKind.SOURCE, "source"),
                (OperandProofKind.WITNESS, "input_domain"),
                (OperandProofKind.MODEL, "model")}
    for access in proof.collected.raw.required:
        key = f"{access.statement}:{access.occurrence}"
        expected.add((OperandProofKind.BINDING, key))
        expected.add((OperandProofKind.SCOPE, key))
    actual = tuple((fact.kind, fact.key) for fact in proof.facts)
    count = len(expected)
    return (proof.status is ProofStatus.PROVED and proof.reason is OperandProofReason.PROVED
            and len(actual) == count and set(actual) == expected
            and all(fact.status is ProofStatus.PROVED and not fact.deadline_exhausted
                    for fact in proof.facts)
            and proof.counters == FactCounters(count, count, count, count, 0))


def _operand_ok(run: _ClosureRun, operands: BoundReal16OperandScope,
                prefixes: Real16CodePrefixProof) -> bool:
    """Rebind every operand block to its request and independently decoded bytes.

    ``PROVED`` plus zero failures is not coverage: the certificate must hold
    exactly one block per ``(side, address, size)`` request triple; each
    block's proof must carry a complete raw-occurrence denominator
    (``collected.complete`` re-checks ``set(fact ids) == set(raw.required)``
    on the block's own raw ledger); the retained receipt consumption must be
    complete; and every collected byte hash must equal the byte identity both
    source decoders produced for the same coordinate, so a mutated record
    cannot borrow correct counters.
    """
    actual = tuple((block.side, block.address, block.size) for block in operands.blocks)
    ok = (operands.status is ProofStatus.PROVED and operands.counters.failure_count == 0
          and actual == _request_triples(run) and len(set(actual)) == len(actual)
          and operands.consumption is not None and operands.consumption.complete
          and operands.source.status is ProofStatus.PROVED
          and operands.source.receipt == run.receipt
          and operands.source.requests == run.requests
          and operands.source.proposal_hash == joint_proposal_hash(run.system, run.bootstrap)
          and operands.source.model_hash == code_prefix_model_hash())
    prefix_hashes = {(block.side, block.address): block.byte_hash for block in prefixes.blocks}
    operand_hashes = {(block.side, block.address): block.byte_hash for block in operands.source.blocks}
    census: dict[str, int] = {}
    for bound in operands.blocks:
        run.check_time()
        proof = bound.proof
        ok = ok and _operand_ledger_complete(proof)
        ok = ok and proof.collected.complete and proof.model_hash == operand_scope_model_hash()
        ok = ok and prefix_hashes.get((bound.side, bound.address)) == proof.collected.byte_hash
        ok = ok and operand_hashes.get((bound.side, bound.address)) == proof.collected.byte_hash
        for row in proof.collected.facts:
            segment = row.operand.segment.value
            census[segment] = census.get(segment, 0) + 1
    run.census.append(SegmentCensus(tuple(sorted(census.items()))))
    return run.fact(AddressModelObligation.OPERAND, "operand", ok,
                    "" if ok else "a raw occurrence lacks a discharged binding/scope clause")


def _bounds_ok(run: _ClosureRun, addresses: Real16PhysicalAccessBounds,
               prefixes: Real16CodePrefixProof) -> bool:
    """Rebind every physical certificate to its exact block and raw denominator.

    Each retained block must be the sole record for one ``(side, address,
    size)`` request triple; ``block.complete`` already demands the NONVACUITY
    row plus one proved ACCESS row per ``access_key`` of that block's own raw
    ledger, so a dropped, extra or mutated raw occurrence cannot pass on clean
    counters.  The retained proposal hash and both receipt consumers must name
    this run's inputs, and the certificate must still carry its explicit
    non-closure omissions.
    """
    actual = tuple((block.side, block.address, block.size) for block in addresses.blocks)
    ok = (addresses.status is ProofStatus.PROVED and addresses.counters.failure_count == 0
          and addresses.model_limit == PHYSICAL_MODEL_LIMIT
          and actual == _request_triples(run) and len(set(actual)) == len(actual)
          and addresses.proposal_hash == joint_proposal_hash(run.system, run.bootstrap)
          and len(addresses.consumers) >= 2
          and all(item.complete for item in addresses.consumers)
          and addresses.omissions == tuple(PhysicalAccessOmission))
    prefix_hashes = {(block.side, block.address): block.byte_hash for block in prefixes.blocks}
    for block in addresses.blocks:
        run.check_time()
        ok = ok and block.complete and block.accesses.complete
        ok = ok and prefix_hashes.get((block.side, block.address)) == block.byte_hash
    return run.fact(AddressModelObligation.BOUNDS, "bounds", ok,
                    "" if ok else "a raw byte access is unbounded or countermodeled")


def _control_ok(run: _ClosureRun, controls: BoundReal16ControlScope,
                prefixes: Real16CodePrefixProof) -> bool:
    """Rebind every bound control block to its request and entry identity.

    ``controls.complete`` alone is not intake: the certificate must carry
    exactly one ``BoundControlBlock`` per ``(side, address, size)`` request
    triple — the denominator the bound producer itself consumed — with each
    inner ``NativeControlScope`` still sealed against the bytes both prefix
    decoders hashed (``source_sha256``), the freshly re-derived ``_entry``
    state for that coordinate (``entry_sha256``), the authoritative scalar
    ``domain``/``fixed_cs`` pair that same derivation supplies, and the
    current ``native_control_model_hash`` owner seal.  Both retained
    ``FetchedPrefixIntake`` rows must name this run's prefix model and
    proposal and hold complete retained consumptions, which are kept on the
    certificate as evidence.
    """
    triples = _request_triples(run)
    required = 3 + len(triples)
    actual = tuple((block.side, block.address, block.size) for block in controls.blocks)
    scalar = run.receipt.domain.domain if run.receipt.domain is not None else None
    ok = (controls.status is ProofStatus.PROVED and controls.reason is BoundControlReason.PROVED
          and controls.complete
          and actual == triples and len(set(actual)) == len(actual)
          and controls.counters == FactCounters(required, required, required, required, 0)
          and controls.model_hash == bound_control_model_hash()
          and scalar is not None and len(controls.intakes) == 2)
    prefix_hashes = {(block.side, block.address): block.byte_hash for block in prefixes.blocks}
    for intake in controls.intakes:
        run.check_time()
        ok = ok and intake.reason is PrefixIntakeReason.CURRENT and intake.prefix_current
        ok = ok and intake.prefix_model == code_prefix_model_hash()
        ok = ok and intake.proposal_hash == joint_proposal_hash(run.system, run.bootstrap)
        ok = ok and intake.consumption is not None and intake.consumption.complete
        if intake.consumption is not None:
            run.consumptions.append(intake.consumption)
    for bound in controls.blocks:
        run.check_time()
        proof = bound.proof
        ok = ok and proof.complete and proof.model_hash == native_control_model_hash()
        ok = ok and proof.head == bound.address and proof.size == bound.size
        ok = ok and prefix_hashes.get((bound.side, bound.address)) == proof.source_sha256
        if bound.side not in (0, 1) or scalar is None:
            ok = False
            continue
        entry_state, expected_domain = _entry(run.loads[bound.side], bound.address, scalar)
        ok = ok and proof.entry_sha256 == hashlib.sha256(canonical_json_bytes(entry_state)).hexdigest()
        ok = ok and proof.domain == expected_domain
        registers = dict(run.loads[bound.side].binding.entry_registers)
        expected_fixed = expected_domain.cs if expected_domain is not None else registers.get("cs")
        ok = ok and proof.fixed_cs == expected_fixed
    return run.fact(AddressModelObligation.CONTROL, "control", ok,
                    "" if ok else "a bound control block is missing, foreign or unproved")


def _dispatch_ok(run: _ClosureRun, dispatch: Real16DomainDispatchProof) -> bool:
    """Consume the retained source-bound dispatch ledger, never re-resolve it.

    ``dispatch.complete`` inspects only the status and failure counter, so
    this stage re-derives the authoritative ``_requirements`` denominator for
    this system: the certificate must retain that exact ledger, hold one
    PROVED fact per required row with no gaps or duplicates, keep complete
    before/after source-domain consumers, and name the current proposal and
    owner model seals.  RETURN steps still contribute no static control
    terms, a boundary the dispatch denominator deliberately skips.
    """
    required = domain_dispatch_requirements(run.system)
    count = len(required)
    actual = tuple((fact.obligation, fact.key) for fact in dispatch.facts)
    ok = (dispatch.status is ProofStatus.PROVED and dispatch.reason is DomainDispatchReason.PROVED
          and dispatch.required == required and len(set(required)) == count
          and len(actual) == count and len(set(actual)) == len(actual)
          and set(actual) == set(required)
          and all(fact.status is ProofStatus.PROVED for fact in dispatch.facts)
          and dispatch.proposal_hash == joint_proposal_hash(run.system, run.bootstrap)
          and dispatch.model_hash == domain_dispatch_model_hash()
          and len(dispatch.consumers) >= 2
          and all(item.complete for item in dispatch.consumers)
          and dispatch.counters == FactCounters(count, count, count, count, 0))
    run.consumptions.extend(dispatch.consumers)
    by_node = {step.node: step for step in run.system.steps}
    for step in run.system.steps:
        run.check_time()
        if step.kind is JointStepKind.RETURN:
            ok = ok and not step.successors and step.callee is None and step.continuation is None
            continue
        ok = ok and bool(step.successors) and all(node in by_node for node in step.successors)
    return run.fact(AddressModelObligation.DISPATCH, "dispatch", ok,
                    "" if ok else "the retained dispatch ledger does not cover this system's denominator")


def _frames_ok(run: _ClosureRun, frames: tuple[StackInvariantProof, ...]) -> bool:
    """Require the exact kind/clause manifest per side, with continuation proof."""
    if len(frames) != 2 * len(run.system.steps):
        return run.fact(AddressModelObligation.FRAME, "frames", False,
                        "frame evidence does not cover every step on both sides")
    # Frame layout consumes structure only. Actual domain-bound control is
    # discharged separately by the mandatory retained dispatch stage.
    layout = derive_joint_frame_layout(run.system)
    run.layout = layout
    ok = True
    position = 0
    for step in run.system.steps:
        for side in (CallSide.ORIGINAL, CallSide.CANDIDATE):
            run.check_time()
            frame = frames[position]
            position += 1
            obligation = _KIND_TO_OBLIGATION[step.kind]
            request = request_call_continuation(run.system, step, side)
            expected = request.address if request is not None else None
            required = required_stack_clauses(layout, obligation, expected_continuation=expected)
            clauses_ok = (frame.obligation is obligation and frame.layout == layout
                          and frame.expected_continuation == expected
                          and frame.required_clauses == required
                          and tuple(row.kind for row in frame.clauses) == required
                          and frame.counters.failure_count == 0
                          and all(row.status is ProofStatus.PROVED and row.attempted
                                  and row.reason is StackClauseReason.DISCHARGED
                                  for row in frame.clauses))
            if step.kind is JointStepKind.CALL:
                clauses_ok = clauses_ok and request is not None and request.accepts(frame, layout)
            if step.kind is JointStepKind.RETURN:
                clauses_ok = clauses_ok and StackClauseKind.RETURN_TARGET in frame.required_clauses
            ok = ok and clauses_ok and frame.status is ProofStatus.PROVED
    return run.fact(AddressModelObligation.FRAME, "frames", ok,
                    "" if ok else "a stack obligation is missing, rejected or unproved")


def _root_terminal_ok(run: _ClosureRun, entry: Real16EntryFrameProof) -> bool:
    """Bind the root entry and each terminal caller exit inside the model.

    This is the one fact no existing child owns: fetched spans are bounded,
    but the terminal control value ``cs*16 + caller_word`` is only implied by
    the POP ``RETURN_TARGET`` clause's ``physical_control`` term.  The saved
    word ``(caller - cs_entry*16) & 0xFFFF`` is rebound to the receipt's own
    retained bootstrap block — the authoritative record the entry frame
    consumed — and to this run's bootstrap effect hash; the wrapped coordinate
    is then required inside the first MiB under the proved domain ``cs``.
    """
    domain = run.receipt.domain
    if domain is None or run.layout is None:
        return run.fact(AddressModelObligation.ROOT, "root", False,
                        "scalar domain or admitted layout absent")
    cs = domain.domain.cs
    ok = (entry.status is ProofStatus.PROVED and entry.counters.failure_count == 0
          and entry.proposal_hash == joint_proposal_hash(run.system, run.bootstrap))
    if len(entry.sides) != 2:
        return run.fact(AddressModelObligation.ROOT, "root", False,
                        "entry frame must retain both side certificates")
    for side in range(2):
        run.check_time()
        load = run.loads[side]
        side_entry = entry.sides[side]
        blocks = [block for block in run.receipt.sources[side].blocks
                  if block.address == load.binding.entry]
        block = blocks[0] if len(blocks) == 1 else None
        entry_cs = dict(load.binding.entry_registers).get("cs")
        caller = side_entry.caller_address
        terminal = (cs << 4) + ((caller - ((entry_cs if entry_cs is not None else 0) << 4)) & 0xFFFF)
        run.terminals.append(terminal)
        ok = ok and side_entry.effect_hash == native_effect_hash(run.bootstrap[side])
        ok = ok and side_entry.layout == run.layout and side_entry.clauses.proved
        ok = ok and block is not None and block.kind is NativeBlockKind.CALL
        ok = ok and block is not None and caller == load.binding.entry + block.size
        ok = ok and entry_cs == cs and 0 <= terminal < PHYSICAL_MODEL_LIMIT
        ok = ok and 0 <= load.binding.entry < PHYSICAL_MODEL_LIMIT
    return run.fact(AddressModelObligation.ROOT, "root", ok,
                    "" if ok else "root entry or terminal caller exit leaves the modeled space")


@dataclass(frozen=True, slots=True)
class _FinalSealInputs:
    """The eight owner seals this run and its consumed children retained."""

    closure: str
    receipt: str
    prefixes: str
    operands: str
    addresses: str
    controls: str
    dispatch: str
    entry: str


def _final_model_seal(retained: _FinalSealInputs) -> bool:
    """Re-derive every consumed owner seal inside one fresh traversal.

    The eight composite digests overlap heavily in the dependency DAG, so one
    shared ``native_model_hash_snapshot`` lets their ``native_binding_model_hash``
    leaf read the source tree once instead of once per owner.  The scope opens
    only here — after the earlier ``run.model_hash`` traversal has closed — so
    a source mutation between the two traversals still yields different
    digests and refuses.  No capture crosses an independent seal boundary, the
    original comparison order and short-circuit are unchanged, and every owner
    still reads its complete dependency content.
    """
    with native_model_hash_snapshot():
        return (retained.closure == address_model_model_hash()
                and retained.receipt == image_bound_domain_model_hash()
                and retained.prefixes == code_prefix_model_hash()
                and retained.operands == bound_operand_model_hash()
                and retained.addresses == physical_access_model_hash()
                and retained.controls == bound_control_model_hash()
                and retained.dispatch == domain_dispatch_model_hash()
                and retained.entry == entry_frame_model_hash())


def _check_address_model_closure(system: JointSystem, receipt: ImageBoundReal16Domain,
                                loads: tuple[BoundReal16Load, BoundReal16Load],
                                initialized: LoadedRelationProof,
                                bootstrap: tuple[MachineState, MachineState],
                                requests: tuple[tuple[NativeBlockRequest, ...],
                                                tuple[NativeBlockRequest, ...]],
                                prefixes: Real16CodePrefixProof,
                                operands: BoundReal16OperandScope,
                                addresses: Real16PhysicalAccessBounds,
                                controls: BoundReal16ControlScope,
                                frames: tuple[StackInvariantProof, ...],
                                dispatch: Real16DomainDispatchProof,
                                entry: Real16EntryFrameProof, *,
                                timeout_ms: int = 60000,
                                limits: LoadedRelationLimits | None = None) -> AddressModelClosure:
    """Compose retained child evidence into the address-model certificate.

    Order is fixed: receipt/manifest first so later rows assume coverage,
    then the children in joint production order — fetched geometry, operand
    scope, physical bounds, bound control scope, frame clauses, dispatch
    ledger and terminal coordinates.  Every stage records its row even when
    an earlier one refuses.  ``controls`` and ``dispatch`` are consumed as
    retained receipts against this run's proposal, domain and owner seals;
    ``frames`` must be the same-run private sequence described in the module
    docstring.  On ``reason is CLOSED`` and ``complete`` the caller may
    remove ``JointModelRequirement.ADDRESS_MODEL``; any other verdict keeps
    it.  Fault outcomes, io/device spaces and asynchronous events remain
    ``FAULT_DOMAIN``/``ENVIRONMENT`` and are never discharged here.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("address model closure requires a nonnegative millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _ClosureRun(system, receipt, loads, initialized, bootstrap, requests,
                      replace(selected, deadline=deadline))
    try:
        run.model_hash = address_model_model_hash()
        stages: tuple[tuple[AddressModelReason, Callable[[], bool]], ...] = (
            (AddressModelReason.RECEIPT, lambda: _receipt_ok(run)),
            (AddressModelReason.MANIFEST, lambda: _manifest_ok(run)),
            (AddressModelReason.FETCH, lambda: _fetch_ok(run, prefixes)),
            (AddressModelReason.OPERAND, lambda: _operand_ok(run, operands, prefixes)),
            (AddressModelReason.BOUNDS, lambda: _bounds_ok(run, addresses, prefixes)),
            (AddressModelReason.CONTROL, lambda: _control_ok(run, controls, prefixes)),
            (AddressModelReason.FRAME, lambda: _frames_ok(run, frames)),
            (AddressModelReason.DISPATCH, lambda: _dispatch_ok(run, dispatch)),
            (AddressModelReason.TERMINAL, lambda: _root_terminal_ok(run, entry)),
        )
        for reason, check in stages:
            if not check():
                return run.report(reason)
        stable = _final_model_seal(_FinalSealInputs(
            closure=run.model_hash, receipt=run.receipt.model_hash,
            prefixes=prefixes.model_hash, operands=operands.model_hash,
            addresses=addresses.model_hash, controls=controls.model_hash,
            dispatch=dispatch.model_hash, entry=entry.model_hash))
        run.fact(AddressModelObligation.MODEL, "seal", stable,
                 "" if stable else "a consumed child model identity is stale")
        run.check_time()
        return run.report(AddressModelReason.CLOSED if stable else AddressModelReason.MODEL)
    except LoadedRelationRefusal as refusal:
        reason = (AddressModelReason.DEADLINE
                  if refusal.reason is LoadedRelationReason.DEADLINE
                  else AddressModelReason.MODEL)
        return run.report(reason, refusal.detail)
    except JointRefusal as refusal:
        return run.report(AddressModelReason.MANIFEST, refusal.detail)
