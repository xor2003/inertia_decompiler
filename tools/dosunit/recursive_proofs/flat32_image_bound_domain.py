"""Layer: dosunit PE32 image/domain access prerequisites.

Responsibility: bind the declared entry/stack domain to actual CLE permission
mappings and discharge every modeled memory access's dynamic bounds under the
ghost frame domain. Section permission metadata alone is never proof: each
access is a separate solver discharge under the declared rank budget.
Unbounded-depth physical backing, faults, imports, environment and the caller
frame remain explicit composed-proof requirements, never silently discharged.
"""
from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import z3

from tools.dosunit import flat32_call_contracts, flat32_call_lowering, flat32_pe_loader, ssa_provenance
from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_contracts import CallCompositionRefusal, _term_nodes
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import Architecture, FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import materialize_function
from tools.dosunit.recursive_proofs import (
    flat32_pe_component,
    loaded_byte_image_binding,
    loaded_byte_native_transition,
    loaded_byte_relation,
    loaded_byte_relation_proof,
    real16_entry_domain,
    recursive_joint_admission,
    recursive_joint_contracts,
)
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import (
    BoundFlat32Load,
    ImageBindingRefusal,
    LoadedMapping,
)
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    _check_states,
    _consume_initialized,
    _native_initial,
    _TransitionRefusal,
    _TransitionRun,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import (
    native_model_snapshot_owner_hash,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import (
    JointRefusal,
    derive_joint_frame_layout,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason, JointSystem
from tools.dosunit.recursive_proofs.stack import recursive_stack_domains as stack_domains
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import (
    StackWordDomain,
    StackWordLayout,
)
from tools.dosunit.register_state_relations import MachineState

MAX_DOMAIN_ACCESSES: int = 4096
MAX_DOMAIN_EFFECT_NODES: int = 262144
_ARRAY_OPS: frozenset[str] = frozenset({"loadle", "loadbe", "storele", "storebe"})


class Flat32DomainReason(StrEnum):
    """The exact image/mapping/domain premise discharged or still unproved."""

    DISCHARGED = "flat32_image_bound_entry_access_domain_discharged"
    IMAGE = "flat32_domain_executable_or_initialization_mismatch"
    STATE = "flat32_domain_native_state_or_initialization_refused"
    MAPPING = "flat32_domain_declared_or_actual_mapping_scope_unproved"
    DOMAIN = "flat32_domain_declared_entry_stack_scope_unproved"
    ACCESS = "flat32_domain_modeled_access_outside_declared_regions"
    MODEL = "flat32_domain_prerequisite_model_changed"
    DEADLINE = "flat32_domain_original_deadline_exhausted"
    RESOURCE = "flat32_domain_term_or_access_budget_exhausted"


class Flat32DomainObligation(StrEnum):
    """Every consumed fact remains required on early refusals."""

    PREMISE = "immutable_loads_and_complete_initialization"
    EXECUTABLE = "component_executable_mapping_coverage"
    STACK = "declared_stack_writable_and_code_disjoint"
    CODE = "component_code_write_disjointness"
    DOMAIN = "declared_entry_interval_and_rank_domain_nonvacuous"
    ACCESS = "modeled_memory_access_within_declared_regions"
    MODEL = "stable_flat32_domain_model"


class AccessKind(StrEnum):
    """One modeled native memory access class for region discharge."""

    LOAD = "load"
    STORE = "store"


@dataclass(frozen=True, slots=True)
class Flat32AccessDomain:
    """The caller-declared entry stack window and recursion frame budget.

    ``stack_lo``/``stack_hi`` bound the declared writable stack region, which
    must lie inside actual writable CLE mappings and must provably contain the
    ghost push frontier ``root_offset - (rank + 1) * frame_bytes`` for every
    ``rank <= max_frames``. ``esp_min``/``esp_max`` are the admitted top-level
    entry ``esp`` interval. ``max_frames`` is the declared recursion frame
    budget: every per-step access is discharged under the ghost hypothesis
    ``rank <= max_frames``. Nothing here proves reachable executions respect
    the budget; the composed theorem must keep that as an explicit conditional
    requirement.
    """

    stack_lo: int
    stack_hi: int
    esp_min: int
    esp_max: int
    max_frames: int

    def __post_init__(self) -> None:
        """Reject Boolean, out-of-word, empty and budgetless declarations."""
        for value in (self.stack_lo, self.stack_hi, self.esp_min, self.esp_max):
            if type(value) is not int or not 0 <= value < 1 << 32:
                raise ValueError("flat32 access domain coordinates must be unsigned32 integers")
        if type(self.max_frames) is not int or not 1 <= self.max_frames < 1 << 30:
            raise ValueError("flat32 rank budget requires a positive bounded frame count")
        if not self.stack_lo < self.stack_hi:
            raise ValueError("flat32 stack region requires a nonempty half-open interval")
        if not self.stack_lo <= self.esp_min <= self.esp_max < self.stack_hi:
            raise ValueError("flat32 entry esp interval must lie inside the declared stack region")


@dataclass(frozen=True, slots=True)
class MemoryAccess:
    """One modeled native access extracted from an actual SSA effect tree."""

    kind: AccessKind
    address: dict[str, Any]
    byte_width: int


@dataclass(frozen=True, slots=True)
class Flat32DomainFact:
    """One attempted premise or access discharge, including non-results."""

    obligation: Flat32DomainObligation
    key: str
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ImageBoundFlat32Domain:
    """Connected PE mapping/domain/access evidence, never binary equivalence."""

    status: ProofStatus
    reason: Flat32DomainReason
    system: JointSystem
    domain: Flat32AccessDomain
    model_hash: str
    facts: tuple[Flat32DomainFact, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Transitions, frames, outcomes and environment closure are separate."""
        return False


class _DomainRefusal(Exception):
    """A named domain-boundary refusal retained verbatim in the ledger."""

    def __init__(self, reason: Flat32DomainReason, detail: str) -> None:
        """Retain the typed missing premise and its original diagnostic."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def flat32_domain_model_hash() -> str:
    """Seal this owner and every consumed module at its actual loaded path.

    This is a complete owner fingerprint, not the real16 native leaf: it is
    always recomputed and never joined to an enclosing snapshot traversal, so
    no foreign owner can return this identity or write theirs into it.
    """
    owners = (flat32_call_contracts, flat32_call_lowering, flat32_pe_loader, flat32_pe_component,
              loaded_byte_image_binding, loaded_byte_native_transition, loaded_byte_relation,
              loaded_byte_relation_proof, recursive_joint_admission, recursive_joint_contracts,
              real16_entry_domain, stack_domains)
    description = {"version": "flat32-image-bound-access-domain-v1", "z3": z3.get_version_string(),
                   "self": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "sources": [hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                               for module in owners if module.__file__ is not None],
                   "stack_owners": [hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in sorted(
                                        Path(stack_domains.__file__ or "").parent.glob(
                                            "recursive_stack_*.py"))],
                   "snapshot_owner": native_model_snapshot_owner_hash(),
                   "semantic": ssa_provenance._semantic_hash(),
                   "registers": S._ssa_register_widths()}
    return hashlib.sha256(canonical_json_bytes(description)).hexdigest()


def _walk_terms(term: object) -> Iterable[dict[str, Any]]:
    """Yield each distinct dict node of one shared SSA term DAG once."""
    seen: set[int] = set()
    pending = [term]
    while pending:
        node = pending.pop()
        if not isinstance(node, dict):
            if isinstance(node, (list, tuple)):
                pending.extend(node)
            continue
        key = id(node)
        if key in seen:
            continue
        seen.add(key)
        yield node
        pending.extend(node.values())


def _access_bytes(term: dict[str, Any], kind: AccessKind) -> int:
    """Derive the exact byte extent of one array operator or refuse malformed."""
    if kind is AccessKind.LOAD:
        width = term.get("width")
        if type(width) is not int or width <= 0 or width % 8:
            raise _DomainRefusal(Flat32DomainReason.STATE, "native load width is not a byte multiple")
        return width // 8
    args = term.get("args", [])
    value = args[2] if len(args) == 3 else {}
    width = value.get("width") if isinstance(value, dict) else None
    if type(width) is not int or width <= 0 or width % 8:
        raise _DomainRefusal(Flat32DomainReason.STATE, "native store value width is not a byte multiple")
    return width // 8


def _operand_address(term: dict[str, Any]) -> dict[str, Any]:
    """Require a typed address operand on one array operator."""
    args = term.get("args", [])
    if len(args) < 2 or not isinstance(args[1], dict):
        raise _DomainRefusal(Flat32DomainReason.STATE, "native array operand lacks a typed address")
    return args[1]


def extract_flat32_accesses(state: MachineState) -> tuple[MemoryAccess, ...]:
    """Collect every modeled byte-array access with its operator identity.

    The ``memory`` output owns all byte stores; loads may appear under any
    scalar output. Accesses on the ``io`` port array are unmodeled events and
    refuse outright: they require the separately scoped environment contract.
    """
    accesses: list[MemoryAccess] = []
    for field_name, term in state.items():
        for node in _walk_terms(term):
            op = node.get("op")
            if op not in _ARRAY_OPS:
                continue
            if field_name == "io":
                raise _DomainRefusal(Flat32DomainReason.DOMAIN,
                                     "port io array access requires an environment contract")
            if op in {"storele", "storebe"}:
                if field_name != "memory":
                    raise _DomainRefusal(Flat32DomainReason.STATE,
                                         f"native store escaped the memory output: {field_name}")
                accesses.append(MemoryAccess(AccessKind.STORE, _operand_address(node),
                                             _access_bytes(node, AccessKind.STORE)))
            else:
                accesses.append(MemoryAccess(AccessKind.LOAD, _operand_address(node),
                                             _access_bytes(node, AccessKind.LOAD)))
            if len(accesses) > MAX_DOMAIN_ACCESSES:
                raise _DomainRefusal(Flat32DomainReason.RESOURCE, "modeled access budget exhausted")
    return tuple(accesses)


@dataclass(slots=True)
class _DomainRun:
    """One deadline and the complete required access/fact ledger."""

    system: JointSystem
    loads: tuple[BoundFlat32Load, BoundFlat32Load]
    initialized: LoadedRelationProof
    access: Flat32AccessDomain
    limits: LoadedRelationLimits
    layout: StackWordLayout | None = None
    model_hash: str = ""
    facts: list[Flat32DomainFact] = field(default_factory=list)
    accesses: list[tuple[str, MemoryAccess, MachineState]] = field(default_factory=list)
    current: tuple[Flat32DomainObligation, str] = (Flat32DomainObligation.PREMISE, "premise")

    def remaining_ms(self) -> int:
        """Charge mapping scans, state checks and solver work to one deadline."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "flat32 domain deadline exhausted")
        return remaining

    def fact(self, obligation: Flat32DomainObligation, key: str,
             status: ProofStatus, detail: str = "") -> None:
        """Record one retained premise or access result under its exact key."""
        self.facts.append(Flat32DomainFact(obligation, key, status, detail))

    def report(self, reason: Flat32DomainReason, detail: str = "") -> ImageBoundFlat32Domain:
        """Missing, repeated or unproved premises never complete the ledger."""
        required: set[tuple[Flat32DomainObligation, str]] = {(kind, "premise") for kind in Flat32DomainObligation
                    if kind not in {Flat32DomainObligation.ACCESS, Flat32DomainObligation.MODEL}}
        required.add((Flat32DomainObligation.DOMAIN, "frontier"))
        required.add((Flat32DomainObligation.MODEL, "model"))
        required.update((Flat32DomainObligation.ACCESS, key) for key, _, _ in self.accesses)
        ids = [(fact.obligation, fact.key) for fact in self.facts]
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(required - set(ids)) + len(set(ids) - required) + len(ids) - len(set(ids))
        proved = reason is Flat32DomainReason.DISCHARGED and failed == 0
        count = len(required)
        return ImageBoundFlat32Domain(ProofStatus.PROVED if proved else ProofStatus.UNKNOWN, reason,
            self.system, self.access, self.model_hash, tuple(self.facts),
            FactCounters(count, count, count, len(self.facts), failed), detail)


def _regions(mappings: tuple[LoadedMapping, ...], *, readable: bool = False,
             writable: bool = False, executable: bool = False) -> tuple[tuple[int, int], ...]:
    """Project actual loader permission metadata into half-open regions."""
    regions = []
    for mapping in mappings:
        if readable and not mapping.readable:
            continue
        if writable and not mapping.writable:
            continue
        if executable and not mapping.executable:
            continue
        if mapping.size <= 0 or mapping.address < 0 or mapping.address + mapping.size > 1 << 32:
            raise _DomainRefusal(Flat32DomainReason.MAPPING, "loader mapping has an invalid span")
        regions.append((mapping.address, mapping.address + mapping.size))
    return tuple(regions)


def _covers(span: tuple[int, int], regions: tuple[tuple[int, int], ...]) -> bool:
    """Require one actual mapping to cover the entire declared span."""
    start, end = span
    return any(lo <= start and end <= hi for lo, hi in regions)


def _mapping_facts(run: _DomainRun) -> None:
    """Discharge static coverage facts that still grant no dynamic proof.

    These checks bind the declared domain to actual loader metadata. The
    dynamic access discharges below are what prove runtime bounds; metadata
    coverage is a necessary but not sufficient premise.
    """
    for side, load in enumerate(run.loads):
        tag = ("original", "candidate")[side]
        executable = _regions(load.binding.mappings, readable=True, executable=True)
        for start, end in run.system.component_ranges:
            if not _covers((start, end), executable):
                raise _DomainRefusal(Flat32DomainReason.MAPPING,
                                     f"{tag}: component range {start:#x}-{end:#x} lacks readable+executable mapping")
        readable = _regions(load.binding.mappings, readable=True)
        writable = _regions(load.binding.mappings, writable=True)
        stack = (run.access.stack_lo, run.access.stack_hi)
        if not _covers(stack, writable) or not _covers(stack, readable):
            raise _DomainRefusal(Flat32DomainReason.MAPPING,
                                 f"{tag}: declared stack lacks readable+writable mapping")
        for start, end in run.system.component_ranges:
            if start < stack[1] and stack[0] < end:
                raise _DomainRefusal(Flat32DomainReason.MAPPING,
                                     f"{tag}: declared stack overlaps component code")
            for lo, hi in writable:
                if lo < end and start < hi:
                    raise _DomainRefusal(Flat32DomainReason.MAPPING,
                                         f"{tag}: writable mapping {lo:#x}-{hi:#x} overlaps component code")
    run.fact(Flat32DomainObligation.EXECUTABLE, "premise", ProofStatus.PROVED)
    run.fact(Flat32DomainObligation.STACK, "premise", ProofStatus.PROVED)
    run.fact(Flat32DomainObligation.CODE, "premise", ProofStatus.PROVED)


def _domain_witness(run: _DomainRun) -> None:
    """Prove the declared entry/rank domain nonvacuous under INITIATION premises."""
    if run.layout is None:
        raise ValueError("domain discharge requires the admitted frame layout")
    domain = StackWordDomain.create(run.layout)
    memory = z3.Array("flat32_domain_witness_mem", z3.BitVecSort(32), z3.BitVecSort(8))
    solver = z3.Solver()
    solver.set(timeout=run.remaining_ms())
    solver.add(domain.bounds(domain.rank, domain.allocated),
               domain.rank == 0, domain.allocated == 0,
               z3.UGE(domain.root_offset, z3.BitVecVal(run.access.esp_min, 32)),
               z3.ULE(domain.root_offset, z3.BitVecVal(run.access.esp_max, 32)),
               domain.word(memory, z3.BitVecVal(0, run.layout.rank_bits)) == domain.caller_word)
    checked = solver.check()
    run.limits.check_time()
    if checked != z3.sat:
        detail = solver.reason_unknown() if checked == z3.unknown else "declared entry domain is vacuous"
        raise _DomainRefusal(Flat32DomainReason.DOMAIN, detail)
    run.fact(Flat32DomainObligation.DOMAIN, "premise", ProofStatus.PROVED)


def _frontier_closure(run: _DomainRun) -> None:
    """Prove the declared stack window contains the rank-bounded push frontier.

    ``esp`` alone is the entry pointer; reachability under the declared budget
    is the ghost relation ``offset(rank) = root_offset - rank * frame_bytes``.
    The deepest word a further recursive call can write is one slot below the
    frontier, so the discharged goal is
    ``stack_lo <= offset(rank + 1) <= root_offset`` for every
    ``rank <= max_frames``. A window too small for the declared rank budget
    (or one requiring a physical wrap) produces a countermodel, never a pass.
    """
    if run.layout is None:
        raise ValueError("frontier closure requires the admitted frame layout")
    domain = StackWordDomain.create(run.layout)
    rank, root = domain.rank, domain.root_offset
    hypotheses = [
        domain.bounds(rank, domain.allocated),
        z3.UGE(root, z3.BitVecVal(run.access.esp_min, 32)),
        z3.ULE(root, z3.BitVecVal(run.access.esp_max, 32)),
        z3.ULE(z3.ZeroExt(1, rank), z3.BitVecVal(run.access.max_frames, run.layout.rank_bits + 1)),
    ]
    # Widen before the +1 so a maximal rank cannot wrap back to the root slot.
    deepest = domain.offset(z3.ZeroExt(2, rank) + z3.BitVecVal(1, 32))
    goal = z3.And(z3.UGE(deepest, z3.BitVecVal(run.access.stack_lo, 32)),
                  z3.ULE(deepest, root))
    solver = z3.Solver()
    solver.set(timeout=run.remaining_ms())
    solver.add(*hypotheses)
    solver.add(z3.Not(goal))
    checked = solver.check()
    run.limits.check_time()
    if checked != z3.unsat:
        detail = solver.reason_unknown() if checked == z3.unknown else (
            f"declared stack window cannot contain the rank frontier: {solver.model()}"
            if checked == z3.sat else "declared rank frontier undischarged")
        raise _DomainRefusal(Flat32DomainReason.DOMAIN, detail)
    run.fact(Flat32DomainObligation.DOMAIN, "frontier", ProofStatus.PROVED)


def _state_inputs(run: _DomainRun, state: MachineState) -> dict[str, tuple[z3.ExprRef, int]]:
    """Materialize one effect's z3 inputs once per state."""
    document = materialize_function("flat32:access", state)
    inputs = S._z3_inputs(document, document, z3)
    run.limits.check_time()
    return inputs


def _z3_address(inputs: dict[str, tuple[z3.ExprRef, int]], access: MemoryAccess) -> z3.ExprRef:
    """Translate one extracted access address at the opaque solver boundary.

    ``materialize_function`` ref-ifies the raw address tree so the shared
    ``_z3_term``/``_z3_assignment`` interpreter sees only leaf and ref terms.
    """
    document = materialize_function("flat32:access_address", {"access_addr": access.address})
    assignments = {item["id"]: item for item in document["assignments"]}
    return cast(z3.ExprRef, S._z3_term(document["outputs"]["access_addr"], document=document,
                                       inputs=inputs, assignments=assignments, cache={}, z3=z3))


def _access_goal(run: _DomainRun, access: MemoryAccess, address: z3.ExprRef,
                 regions: tuple[tuple[int, int], ...]) -> z3.BoolRef:
    """Build the no-wrap plus region-membership goal for one actual access."""
    if not isinstance(address, z3.BitVecRef) or address.size() != 32:
        raise _DomainRefusal(Flat32DomainReason.STATE, "modeled access address is not a 32-bit term")
    end = address + access.byte_width - 1
    no_wrap = z3.UGE(end, address)
    inside = z3.Or(*[z3.And(z3.UGE(address, z3.BitVecVal(lo, 32)),
                            z3.ULE(end, z3.BitVecVal(hi - 1, 32))) for lo, hi in regions])
    goal: z3.BoolRef = z3.And(no_wrap, inside)
    if access.kind is AccessKind.STORE:
        # Writable coverage is statically code-disjoint; the explicit clause
        # retains the discharged code-write condition as solver evidence.
        outside = z3.And(*[z3.Or(z3.ULT(end, z3.BitVecVal(lo, 32)),
                                 z3.UGT(address, z3.BitVecVal(hi - 1, 32)))
                           for lo, hi in run.system.component_ranges])
        goal = z3.And(goal, outside)
    return cast(z3.BoolRef, goal)


def _access_discharge(run: _DomainRun) -> None:
    """Discharge every extracted access under the declared ghost frame domain."""
    if run.layout is None:
        raise ValueError("access discharge requires the admitted frame layout")
    materialized: dict[int, dict[str, tuple[z3.ExprRef, int]]] = {}
    for key, access, state in run.accesses:
        run.current = (Flat32DomainObligation.ACCESS, key)
        side, _, _ = key.partition(":")
        load = run.loads[0 if side == "original" else 1]
        regions = _regions(load.binding.mappings,
                           readable=access.kind is AccessKind.LOAD,
                           writable=access.kind is AccessKind.STORE)
        if id(state) not in materialized:
            materialized[id(state)] = _state_inputs(run, state)
        inputs = materialized[id(state)]
        if "esp" not in inputs or "mem" not in inputs:
            raise _DomainRefusal(Flat32DomainReason.STATE, "access state lacks native esp/mem inputs")
        esp = inputs["esp"][0]
        memory = inputs["mem"][0]
        if not isinstance(esp, z3.BitVecRef) or not isinstance(memory, z3.ArrayRef):
            raise _DomainRefusal(Flat32DomainReason.STATE, "native esp/memory input sorts are invalid")
        domain = StackWordDomain.create(run.layout)
        index = z3.BitVec(f"flat32_access_slot_{key}", run.layout.rank_bits)
        hypotheses = [
            domain.local_invariant(memory, domain.rank, domain.allocated, index),
            domain.slot_clause(memory, domain.rank, domain.allocated),
            esp == domain.offset(domain.rank),
            z3.UGE(domain.root_offset, z3.BitVecVal(run.access.esp_min, 32)),
            z3.ULE(domain.root_offset, z3.BitVecVal(run.access.esp_max, 32)),
            z3.ULE(z3.ZeroExt(1, domain.rank), z3.BitVecVal(run.access.max_frames, run.layout.rank_bits + 1)),
        ]
        address = _z3_address(inputs, access)
        goal = _access_goal(run, access, address, regions)
        solver = z3.Solver()
        solver.add(*hypotheses)
        solver.add(z3.Not(goal))
        solver.set(timeout=run.remaining_ms())
        checked = solver.check()
        run.limits.check_time()
        if checked == z3.unsat:
            run.fact(Flat32DomainObligation.ACCESS, key, ProofStatus.PROVED)
            continue
        detail = solver.reason_unknown() if checked == z3.unknown else ""
        if checked == z3.sat:
            detail = f"flat32 access countermodel: {solver.model()}"
        raise _DomainRefusal(Flat32DomainReason.ACCESS, detail or f"access {key} undischarged")


def _collect(run: _DomainRun) -> None:
    """Enumerate every modeled access on both sides before any discharge."""
    for step in run.system.steps:
        for tag, state in (("original", step.original), ("candidate", step.candidate)):
            if _term_nodes(state, MAX_DOMAIN_EFFECT_NODES) > MAX_DOMAIN_EFFECT_NODES:
                raise _DomainRefusal(Flat32DomainReason.RESOURCE, "domain effect term budget exhausted")
            for index, access in enumerate(extract_flat32_accesses(state)):
                run.accesses.append((f"{tag}:{step.node.key()}:{index}", access, state))
            if len(run.accesses) > MAX_DOMAIN_ACCESSES:
                raise _DomainRefusal(Flat32DomainReason.RESOURCE, "component access budget exhausted")


def _prove(run: _DomainRun) -> ImageBoundFlat32Domain:
    """Connect immutable premises before consuming any dynamic discharge."""
    run.remaining_ms()
    guard = _TransitionRun(run.initialized, run.limits, 262144, 128)
    if _consume_initialized(guard) is not Architecture.FLAT32:
        raise JointRefusal(JointReason.OUTPUTS, "flat32 domain requires flat32 initialized memory")
    proposal = run.initialized.proposal
    if (proposal.original.sparse_byte_sha256 != run.loads[0].binding.snapshot.sparse_byte_sha256
            or proposal.candidate.sparse_byte_sha256 != run.loads[1].binding.snapshot.sparse_byte_sha256):
        raise _DomainRefusal(Flat32DomainReason.IMAGE, "initialized relation does not bind these loaded images")
    for load in run.loads:
        load.verify(limits=run.limits)
    baseline = _native_initial(Architecture.FLAT32)
    for pair in ((step.original, step.candidate) for step in run.system.steps):
        _check_states(baseline, *pair)
        for state in pair:
            guard.guard(state)
    if run.system.contract.architecture is not Architecture.FLAT32:
        raise _DomainRefusal(Flat32DomainReason.IMAGE, "joint contract is not flat32")
    run.layout = derive_joint_frame_layout(run.system)
    run.fact(Flat32DomainObligation.PREMISE, "premise", ProofStatus.PROVED)
    run.model_hash = flat32_domain_model_hash()
    run.current = (Flat32DomainObligation.EXECUTABLE, "premise")
    _mapping_facts(run)
    run.current = (Flat32DomainObligation.DOMAIN, "premise")
    _domain_witness(run)
    run.current = (Flat32DomainObligation.DOMAIN, "frontier")
    _frontier_closure(run)
    run.current = (Flat32DomainObligation.ACCESS, "collect")
    _collect(run)
    _access_discharge(run)
    run.current = (Flat32DomainObligation.MODEL, "model")
    if flat32_domain_model_hash() != run.model_hash:
        raise _DomainRefusal(Flat32DomainReason.MODEL, "flat32 domain model changed during discharge")
    run.remaining_ms()
    run.fact(Flat32DomainObligation.MODEL, "model", ProofStatus.PROVED)
    return run.report(Flat32DomainReason.DISCHARGED)


def prove_image_bound_flat32_domain(system: JointSystem,
                                    loads: tuple[BoundFlat32Load, BoundFlat32Load],
                                    initialized: LoadedRelationProof,
                                    access: Flat32AccessDomain, *,
                                    timeout_ms: int = 60000,
                                    limits: LoadedRelationLimits | None = None) -> ImageBoundFlat32Domain:
    """Prove declared entry/stack access bounds on actual PE-loaded premises.

    Static facts bind declared regions to real permission mappings only; every
    modeled byte-array access is separately discharged under the ghost frame
    invariant plus the declared rank budget. A discharged receipt still leaves
    unbounded-depth backing, faults, imports, environment and the caller frame
    to the composed theorem's explicit requirement set.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("flat32 domain requires a nonnegative millisecond budget")
    if not isinstance(access, Flat32AccessDomain):
        raise ValueError("flat32 domain requires a typed declared access domain")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _DomainRun(system, loads, initialized, access, replace(selected, deadline=deadline))
    try:
        return _prove(run)
    except (_DomainRefusal, JointRefusal, _TransitionRefusal, ImageBindingRefusal,
            LoadedRelationRefusal, CallCompositionRefusal, S.LowerFailure,
            z3.Z3Exception, TimeoutError, RecursionError) as error:
        reason, detail = _refusal_fields(error)
    run.fact(*run.current, ProofStatus.UNKNOWN, detail)
    return run.report(reason, detail)


def _refusal_fields(error: Exception) -> tuple[Flat32DomainReason, str]:
    """Map one named boundary failure to its domain reason and detail."""
    if isinstance(error, _DomainRefusal):
        return error.reason, error.detail
    if isinstance(error, JointRefusal):
        return (Flat32DomainReason.DEADLINE if error.reason is JointReason.DEADLINE
                else Flat32DomainReason.STATE), error.detail
    if isinstance(error, _TransitionRefusal):
        return Flat32DomainReason.STATE, error.detail
    if isinstance(error, ImageBindingRefusal):
        return Flat32DomainReason.IMAGE, error.detail
    if isinstance(error, LoadedRelationRefusal):
        return (Flat32DomainReason.DEADLINE if error.reason is LoadedRelationReason.DEADLINE
                else Flat32DomainReason.IMAGE), error.detail
    if isinstance(error, CallCompositionRefusal):
        return Flat32DomainReason.STATE, str(error)
    if isinstance(error, S.LowerFailure):
        return (Flat32DomainReason.DEADLINE if error.reason == "compose_budget_exceeded"
                else Flat32DomainReason.STATE), f"{error.reason}: {error.message}"
    if isinstance(error, z3.Z3Exception):
        return Flat32DomainReason.STATE, f"z3 boundary: {error}"
    if isinstance(error, TimeoutError):
        return Flat32DomainReason.DEADLINE, str(error)
    return Flat32DomainReason.RESOURCE, str(error)


__all__ = [
    "AccessKind",
    "Flat32AccessDomain",
    "Flat32DomainFact",
    "Flat32DomainObligation",
    "Flat32DomainReason",
    "ImageBoundFlat32Domain",
    "MemoryAccess",
    "extract_flat32_accesses",
    "flat32_domain_model_hash",
    "prove_image_bound_flat32_domain",
]
