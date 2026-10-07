"""Layer: dosunit raw physical access bounds theorem (staging).

Responsibility: prove every raw native byte access of each independently
decoded MZ block — reads and writes, dead or live — stays inside the declared
normal first-MiB linear physical model.  The fresh per-request MZ decode and
its complete raw occurrence ledger come solely from the tested code-prefix
source connector; this owner keeps only the physical-address algebra.  Access
addresses are composed with the actual bootstrap register constants for the
entry block and with the consumed scalar domain predicate for every later
cutpoint, keeping the memory and I/O arrays distinct.  This removes A20/wrap
ambiguity for these byte accesses only.  It does NOT establish architectural
segment-end scope for the original wide operands, DOS memory
allocation/permissions, device spaces, fault outcomes, asynchronous events or
any binary equivalence.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import angr
import pyvex
import z3

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
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
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import (
    CodePrefixBlock,
    CodePrefixReason,
    _entry,
    code_prefix_model_hash,
    prove_real16_code_prefixes,
)
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain
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
    NativeBlockRequest,
    _NativeRefusal,
)
from tools.dosunit.recursive_proofs.real16_native_memory_access import (
    NativeAccessFact,
    NativeAccessId,
    NativeAccessReason,
    NativeAccessReport,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs

PHYSICAL_MODEL_LIMIT: int = 0x100000
MAX_ACCESS_ASSIGNMENTS: int = 4096


class PhysicalAccessReason(StrEnum):
    """The exact local bounds closure or the retained unproved boundary."""

    IN_BOUNDS = "raw_native_byte_accesses_within_first_mib"
    RECEIPT = "physical_access_prerequisite_receipt_refused"
    SOURCE = "physical_access_independent_decode_or_bytes_refused"
    ACCESS = "physical_access_raw_occurrence_ledger_incomplete"
    VACUOUS = "physical_access_input_domain_vacuous"
    COUNTERMODEL = "physical_access_out_of_first_mib_countermodel"
    UNKNOWN = "physical_access_solver_unknown"
    MODEL = "physical_access_model_identity_changed"
    DEADLINE = "physical_access_original_deadline_exhausted"
    RESOURCE = "physical_access_work_budget_exhausted"


class PhysicalAccessObligation(StrEnum):
    """Every receipt, block, nonvacuity and per-occurrence ledger row."""

    RECEIPT_BEFORE = "complete_image_bound_receipt_before_bounds"
    BLOCK = "independent_block_decode_and_complete_raw_ledger"
    NONVACUITY = "nonempty_access_input_domain"
    ACCESS = "raw_byte_access_within_first_mib"
    RECEIPT_AFTER = "complete_image_bound_receipt_after_bounds"
    MODEL = "stable_physical_access_model_seal"


class PhysicalAccessOmission(StrEnum):
    """The architectural obligations this byte-access theorem does not close."""

    WIDE_OPERAND = "original_wide_operand_segment_end_scope_unclosed"
    ALLOCATION = "dos_memory_allocation_and_permissions_unclosed"
    DEVICES = "device_and_io_address_spaces_unclosed"
    FAULTS = "access_fault_and_trap_outcomes_unclosed"
    ASYNC = "asynchronous_event_scope_unclosed"
    EQUIVALENCE = "binary_equivalence_not_established"


@dataclass(frozen=True, slots=True)
class AccessBoundFact:
    """One ledger row, including retained countermodels and refusals."""

    obligation: PhysicalAccessObligation
    key: str
    status: ProofStatus
    detail: str = ""
    model: str = ""
    native_result: z3.CheckSatResult | None = None
    deadline_exhausted: bool = False


@dataclass(frozen=True, slots=True)
class PhysicalAccessBlock:
    """Exact block bytes, the closed raw ledger and every per-access verdict."""

    side: int
    address: int
    size: int
    byte_hash: str
    accesses: NativeAccessReport
    facts: tuple[AccessBoundFact, ...]

    @property
    def complete(self) -> bool:
        """Require a closed raw ledger, nonempty domain and all accesses proved."""
        key = f"{self.side}:{self.address:#08x}"
        ids = tuple((fact.obligation, fact.key) for fact in self.facts)
        expected = {(PhysicalAccessObligation.NONVACUITY, key),
                    *((PhysicalAccessObligation.ACCESS, access_key(self.side, self.address, row))
                      for row in self.accesses.required)}
        return (self.accesses.complete and len(ids) == len(set(ids)) and set(ids) == expected
                and all(fact.status is ProofStatus.PROVED for fact in self.facts))


@dataclass(frozen=True, slots=True)
class Real16PhysicalAccessBounds:
    """Source/domain-bound first-MiB access certificate; not a binary verdict."""

    status: ProofStatus
    reason: PhysicalAccessReason
    model_hash: str
    proposal_hash: str
    model_limit: int
    blocks: tuple[PhysicalAccessBlock, ...]
    facts: tuple[AccessBoundFact, ...]
    consumers: tuple[BoundDomainConsumption, ...]
    omissions: tuple[PhysicalAccessOmission, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Byte-address bounds grant no fault, environment or binary closure."""
        return False


def access_key(side: int, address: int, occurrence: NativeAccessId) -> str:
    """Bind one access row to its exact block and raw occurrence identity."""
    return f"{side}:{address:#08x}:{occurrence.statement}:{occurrence.occurrence}"


def physical_access_model_hash() -> str:
    """Seal this owner, the source connector, the raw collector and prerequisites."""
    if native_model_hash_snapshot_active():
        return _physical_access_model_hash()
    with native_model_hash_snapshot():
        return _physical_access_model_hash()


def _physical_access_model_hash() -> str:
    """Read the dependency DAG within one digest-local native capture."""
    digest = hashlib.sha256(image_bound_domain_model_hash().encode("ascii"))
    digest.update(code_prefix_model_hash().encode("ascii"))
    stage = Path(__file__).parent
    for name in (Path(__file__).name, "real16_code_prefix_proof.py", "real16_native_memory_access.py"):
        digest.update(name.encode("ascii"))
        digest.update((stage / name).read_bytes())
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class _BoundQuery:
    """One solver outcome, retaining the original-budget stop state."""

    result: z3.CheckSatResult
    deadline_exhausted: bool = False
    model: str = ""
    detail: str = ""


def _query(condition: z3.BoolRef, deadline: float) -> _BoundQuery:
    """Run one finite solver check charged to the original absolute deadline."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        return _BoundQuery(z3.unknown, deadline_exhausted=True)
    solver = z3.Solver()
    solver.set(timeout=remaining)
    solver.add(condition)
    result = solver.check()
    if time.monotonic() >= deadline:
        return _BoundQuery(z3.unknown, deadline_exhausted=True)
    model = str(solver.model()) if result == z3.sat else ""
    detail = solver.reason_unknown() if result == z3.unknown else ""
    if time.monotonic() >= deadline:
        return _BoundQuery(z3.unknown, deadline_exhausted=True, model=model, detail=detail)
    return _BoundQuery(result, model=model, detail=detail)


def _access_document(address: S.SsaExpr) -> dict[str, Any]:
    """Materialize one raw physical address keeping named scalar/array inputs."""
    state = S._IrsbLowerState(S._initial_reg_versions(),
                              S.SsaExpr("mem_input", 0, name="mem"),
                              S.SsaExpr("mem_input", 0, name="io"))
    result = S._materialize_irsb_outputs(state, {"access": address},
                                         max_assignments_per_function=MAX_ACCESS_ASSIGNMENTS)
    if isinstance(result, S.LowerFailure):
        raise result
    outputs, assignments = result
    return {"inputs": S._input_items(S._collect_inputs((address,))),
            "outputs": outputs, "assignments": assignments}


def _premise(entry: MachineState, domain: Real16ScalarDomain | None,
             inputs: dict[str, tuple[z3.ExprRef, int]]) -> z3.BoolRef:
    """Bootstrap constants already narrow the entry; cutpoints add the predicate."""
    if domain is None:
        return z3.BoolVal(True)
    return domain.predicate(_state_exprs(entry, inputs))


def _access_row(occurrence: NativeAccessId, fact: NativeAccessFact | None, entry: MachineState,
                domain: Real16ScalarDomain | None, before: dict[str, Any], nonempty: bool,
                key: str, deadline: float) -> AccessBoundFact:
    """Prove one raw byte access inside the first MiB, or retain why not."""
    row_key = f"{key}:{occurrence.statement}:{occurrence.occurrence}"
    refused = PhysicalAccessObligation.ACCESS
    if not nonempty:
        return AccessBoundFact(refused, row_key, ProofStatus.UNKNOWN, "nonempty input domain has not been established")
    if fact is None or fact.reason is not NativeAccessReason.COLLECTED or fact.address is None:
        detail = "raw occurrence lacks collected lowered evidence"
        if fact is not None:
            detail = f"raw occurrence unclosed: {fact.reason.value}"
        return AccessBoundFact(refused, row_key, ProofStatus.UNKNOWN, detail)
    if fact.width <= 0 or fact.width % 8:
        return AccessBoundFact(refused, row_key, ProofStatus.UNKNOWN,
                               "native access width is not a positive whole-byte count")
    width_bytes = fact.width // 8
    try:
        document = _access_document(fact.address)
        post = S._compose_block_outputs(document, document["outputs"], entry,
                                        compose_stats={"deadline": deadline})
    except S.LowerFailure as refusal:
        return AccessBoundFact(refused, row_key, ProofStatus.UNKNOWN,
                               f"{refusal.reason}: {refusal.message}")
    post_document = materialize_function("access-bounds:post", post)
    inputs = S._z3_inputs(before, post_document, z3)
    address = _state_exprs(post, inputs)["access"]
    if not isinstance(address, z3.BitVecRef) or address.size() != 32:
        return AccessBoundFact(refused, row_key, ProofStatus.UNKNOWN,
                               "raw physical address is not a native32 term")
    extent = z3.ZeroExt(32, address) + width_bytes
    violation = cast(z3.BoolRef, z3.And(_premise(entry, domain, inputs),
                                      z3.UGT(extent, PHYSICAL_MODEL_LIMIT)))
    outcome = _query(violation, deadline)
    if outcome.result == z3.unsat:
        return AccessBoundFact(refused, row_key, ProofStatus.PROVED, native_result=outcome.result)
    if outcome.result == z3.sat:
        return AccessBoundFact(refused, row_key, ProofStatus.COUNTEREXAMPLE,
                               "raw byte extent exceeds the first-MiB physical model", outcome.model,
                               native_result=outcome.result)
    detail = "original deadline exhausted" if outcome.deadline_exhausted else outcome.detail
    return AccessBoundFact(refused, row_key, ProofStatus.UNKNOWN, detail,
                           native_result=outcome.result, deadline_exhausted=outcome.deadline_exhausted)


def check_native_access_bounds(accesses: NativeAccessReport, entry: MachineState,
                               domain: Real16ScalarDomain | None, *, deadline: float,
                               key: str = "local") -> tuple[AccessBoundFact, ...]:
    """Discharge nonvacuity then prove each required raw access stays < 1 MiB.

    Every occurrence the raw collector required keeps a ledger row, including
    dead reads and occurrences whose lowering or solving could not close.  A
    SAT violation is a retained local countermodel, not a binary mismatch.
    This helper cannot grant byte provenance, fault behavior or equivalence.
    """
    if type(deadline) not in {float, int} or not math.isfinite(deadline):
        raise ValueError("access bounds require a finite absolute deadline")
    if not accesses.complete:
        refused = [AccessBoundFact(PhysicalAccessObligation.NONVACUITY, key,
                                    ProofStatus.UNKNOWN, "raw occurrence ledger is incomplete")]
        refused.extend(AccessBoundFact(PhysicalAccessObligation.ACCESS,
                         f"{key}:{row.statement}:{row.occurrence}", ProofStatus.UNKNOWN,
                         "raw occurrence ledger is incomplete") for row in accesses.required)
        return tuple(refused)
    found = {fact.id: fact for fact in accesses.facts}
    before = materialize_function("access-bounds:entry", entry)
    premise = _premise(entry, domain, S._z3_inputs(before, before, z3))
    witness = _query(premise, deadline)
    nonempty = witness.result == z3.sat
    detail = "native input domain is vacuous" if witness.result == z3.unsat else witness.detail
    if witness.deadline_exhausted:
        detail = "original deadline exhausted"
    rows = [AccessBoundFact(PhysicalAccessObligation.NONVACUITY, key,
                            ProofStatus.PROVED if nonempty else ProofStatus.UNKNOWN, detail,
                            native_result=witness.result, deadline_exhausted=witness.deadline_exhausted)]
    rows.extend(_access_row(occurrence, found.get(occurrence), entry, domain, before,
                            nonempty, key, deadline) for occurrence in accesses.required)
    return tuple(rows)


@dataclass(slots=True)
class _BoundsRun:
    """One original deadline, retained consumers and a closed required ledger."""

    receipt: ImageBoundReal16Domain
    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    limits: LoadedRelationLimits
    model: str = ""
    proposal: str = ""
    source_blocks: tuple[CodePrefixBlock, ...] = ()
    blocks: list[PhysicalAccessBlock] = field(default_factory=list)
    facts: list[AccessBoundFact] = field(default_factory=list)
    consumers: list[BoundDomainConsumption] = field(default_factory=list)

    def consume(self, obligation: PhysicalAccessObligation, key: str) -> PhysicalAccessReason | None:
        """Revalidate the exact source/domain receipt before and after the work."""
        self.limits.check_time()
        outcome = consume_image_bound_real16_domain(self.receipt, self.system, self.loads,
                    self.initialized, self.bootstrap, self.requests,
                    timeout_ms=2**31 - 1, limits=self.limits)
        self.consumers.append(outcome)
        accepted = outcome.status is ProofStatus.PROVED and outcome.counters.failure_count == 0
        self.facts.append(AccessBoundFact(obligation, key,
                          ProofStatus.PROVED if accepted else ProofStatus.UNKNOWN, outcome.detail))
        if accepted:
            return None
        return (PhysicalAccessReason.DEADLINE if outcome.reason is BoundDomainReason.DEADLINE
                else PhysicalAccessReason.RECEIPT)

    def required_rows(self) -> tuple[tuple[PhysicalAccessObligation, str], ...]:
        """Freeze required graph/request rows from the completed source intake.

        Raw access identities come only from ``source_blocks`` — the complete
        ledger fixed before any bounds query — never from already bounded
        blocks, so an early countermodel or refusal cannot shrink the
        later-block denominator.  Requests absent from the source intake keep
        their graph block/nonvacuity rows as missing evidence.
        """
        rows: list[tuple[PhysicalAccessObligation, str]] = [
            (PhysicalAccessObligation.RECEIPT_BEFORE, "before"),
            (PhysicalAccessObligation.RECEIPT_AFTER, "after"),
            (PhysicalAccessObligation.MODEL, "seal")]
        source = {(block.side, block.address): block for block in self.source_blocks}
        for side in range(2):
            addresses = [step.original_address if side == 0 else step.candidate_address
                         for step in self.system.steps]
            addresses.append(self.loads[side].binding.entry)
            addresses.extend(row.address for row in self.requests[side])
            sizes = {row.address: row.size for row in self.requests[side]}
            for address in dict.fromkeys(addresses):
                key = f"{side}:{address:#08x}"
                rows.append((PhysicalAccessObligation.BLOCK, key))
                rows.append((PhysicalAccessObligation.NONVACUITY, key))
                block = source.get((side, address))
                if (block is not None and block.accesses.complete
                        and block.size == sizes.get(address)):
                    rows.extend((PhysicalAccessObligation.ACCESS,
                                 access_key(side, address, occurrence))
                                for occurrence in block.accesses.required)
        return tuple(rows)

    def report(self, reason: PhysicalAccessReason, detail: str = "") -> Real16PhysicalAccessBounds:
        """Every missing, duplicate, refused or countermodel row stays a failure."""
        rows = self.required_rows()
        required = set(rows)
        all_facts = [*self.facts, *(fact for block in self.blocks for fact in block.facts)]
        ids = [(fact.obligation, fact.key) for fact in all_facts]
        proved = sum(fact.status is ProofStatus.PROVED and (fact.obligation, fact.key) in required
                     for fact in all_facts)
        failed = sum(fact.status is not ProofStatus.PROVED for fact in all_facts)
        failed += len(required - set(ids)) + len(set(ids) - required) + len(ids) - len(set(ids))
        status = ProofStatus.PROVED if reason is PhysicalAccessReason.IN_BOUNDS and failed == 0 else ProofStatus.UNKNOWN
        if any(fact.status is ProofStatus.COUNTEREXAMPLE for fact in all_facts):
            status = ProofStatus.COUNTEREXAMPLE
        if not detail and self.consumers:
            detail = self.consumers[-1].detail
        return Real16PhysicalAccessBounds(status, reason, self.model, self.proposal,
            PHYSICAL_MODEL_LIMIT, tuple(self.blocks), tuple(all_facts), tuple(self.consumers),
            tuple(PhysicalAccessOmission), FactCounters(len(rows), len(rows), len(rows), proved, failed), detail)


def _source_reason(reason: CodePrefixReason) -> PhysicalAccessReason:
    """Map the independent source-intake refusal onto this theorem's boundary."""
    if reason is CodePrefixReason.DEADLINE:
        return PhysicalAccessReason.DEADLINE
    if reason is CodePrefixReason.RESOURCE:
        return PhysicalAccessReason.RESOURCE
    return PhysicalAccessReason.SOURCE


def _bounded_source_block(run: _BoundsRun, block: CodePrefixBlock,
                          scalar: Real16ScalarDomain) -> PhysicalAccessReason | None:
    """Bound every raw access of one request-matched fresh source block."""
    key = f"{block.side}:{block.address:#08x}"
    entry, domain = _entry(run.loads[block.side], block.address, scalar)
    facts = check_native_access_bounds(block.accesses, entry, domain,
                                       deadline=run.limits.deadline, key=key)
    run.blocks.append(PhysicalAccessBlock(block.side, block.address, block.size,
                      block.byte_hash, block.accesses, facts))
    run.facts.append(AccessBoundFact(PhysicalAccessObligation.BLOCK, key,
                     ProofStatus.PROVED if block.accesses.complete else ProofStatus.UNKNOWN,
                     block.accesses.detail or block.accesses.reason.value))
    if time.monotonic() >= run.limits.deadline:
        raise TimeoutError("original physical-access deadline exhausted")
    if not block.accesses.complete:
        return PhysicalAccessReason.ACCESS
    if any(fact.status is ProofStatus.COUNTEREXAMPLE for fact in facts):
        return PhysicalAccessReason.COUNTERMODEL
    if not all(fact.status is ProofStatus.PROVED for fact in facts):
        vacuous = any(fact.obligation is PhysicalAccessObligation.NONVACUITY
                      and fact.native_result == z3.unsat for fact in facts)
        return PhysicalAccessReason.VACUOUS if vacuous else PhysicalAccessReason.UNKNOWN
    return None


def _bound_accesses(run: _BoundsRun) -> PhysicalAccessReason:
    """Consume prerequisites, freeze the source ledger, then bound raw accesses."""
    refused = run.consume(PhysicalAccessObligation.RECEIPT_BEFORE, "before")
    if refused is not None:
        return refused
    run.model = physical_access_model_hash()
    run.proposal = joint_proposal_hash(run.system, run.bootstrap)
    scalar = run.receipt.domain
    if scalar is None or scalar.status is not ProofStatus.PROVED:
        return PhysicalAccessReason.RECEIPT
    source = prove_real16_code_prefixes(run.receipt, run.system, run.loads,
                run.initialized, run.bootstrap, run.requests,
                timeout_ms=2**31 - 1, limits=run.limits)
    run.source_blocks = source.blocks
    run.consumers.extend(source.consumers)
    run.limits.check_time()
    if source.status is not ProofStatus.PROVED or source.counters.failure_count:
        return _source_reason(source.reason)
    for side, rows in enumerate(run.requests):
        run.limits.check_time()
        produced = tuple(block for block in source.blocks if block.side == side)
        for index, row in enumerate(rows):
            run.limits.check_time()
            block = produced[index] if index < len(produced) else None
            if block is None or block.address != row.address or block.size != row.size:
                key = f"{side}:{row.address:#08x}"
                run.facts.append(AccessBoundFact(PhysicalAccessObligation.BLOCK, key,
                                 ProofStatus.UNKNOWN,
                                 f"independent source intake refused: "
                                 f"{source.detail or source.reason.value}"))
                return _source_reason(source.reason)
            reason = _bounded_source_block(run, block, scalar.domain)
            if reason is not None:
                return reason
    refused = run.consume(PhysicalAccessObligation.RECEIPT_AFTER, "after")
    if refused is not None:
        return refused
    run.limits.check_time()
    stable = run.model == physical_access_model_hash()
    run.facts.append(AccessBoundFact(PhysicalAccessObligation.MODEL, "seal",
                     ProofStatus.PROVED if stable else ProofStatus.UNKNOWN,
                     "" if stable else "physical access model changed during the proof"))
    return PhysicalAccessReason.IN_BOUNDS if stable else PhysicalAccessReason.MODEL


def prove_real16_physical_access_bounds(receipt: ImageBoundReal16Domain, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, timeout_ms: int = 15000, limits: LoadedRelationLimits | None = None) -> Real16PhysicalAccessBounds:
    """Prove every raw byte access of each bound block stays inside 1 MiB.

    Consumes the complete image-bound receipt before and after work.  The
    independent code-prefix connector owns fresh MZ project creation, byte
    extraction and ``opt_level=0`` lifting; its per-request blocks fix the
    complete raw occurrence manifest before any bounds query, so an early
    countermodel cannot shrink the later-block denominator.  Requires a
    complete raw occurrence ledger per block and an independently nonempty
    input domain.  Local countermodels are retained; this theorem closes
    byte-address bounds only and never grants binary equivalence.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("physical access bounds require a nonnegative millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _BoundsRun(receipt, system, loads, initialized, bootstrap, requests,
                     replace(selected, deadline=deadline))
    reason, detail = PhysicalAccessReason.UNKNOWN, ""
    try:
        reason = _bound_accesses(run)
    except TimeoutError as refusal:
        reason, detail = PhysicalAccessReason.DEADLINE, str(refusal)
    except LoadedRelationRefusal as refusal:
        reason = (PhysicalAccessReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE
                  else PhysicalAccessReason.RESOURCE)
        detail = refusal.detail
    except _NativeRefusal as refusal:
        reason = (PhysicalAccessReason.DEADLINE if refusal.reason is NativeBindingReason.DEADLINE
                  else PhysicalAccessReason.SOURCE)
        detail = refusal.detail
    except ImageBindingRefusal as refusal:
        reason, detail = PhysicalAccessReason.SOURCE, refusal.detail
    except S.LowerFailure as refusal:
        reason = (PhysicalAccessReason.DEADLINE if time.monotonic() >= run.limits.deadline
                  else PhysicalAccessReason.RESOURCE)
        detail = f"{refusal.reason}: {refusal.message}"
    except RecursionError as refusal:
        reason, detail = PhysicalAccessReason.RESOURCE, f"SSA operand recursion boundary: {refusal}"
    except (angr.errors.SimEngineError, pyvex.errors.PyVEXError) as refusal:
        reason, detail = PhysicalAccessReason.SOURCE, str(refusal)
    return run.report(reason, detail)
