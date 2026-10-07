"""Layer: dosunit PE-bound recursive component proposals.

Responsibility: build complete matched atomic ``JointSystem`` manifests from
actual lifted PE32/ELF32 blocks inside declared function byte ranges, along
with the independent byte-binding requests each side must still pass. A
proposed manifest supplies no admission, source-binding or theorem evidence;
the joint admission, native binding and composed proof owners decide that.
"""
from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionLimits,
    CallCompositionRefusal,
    _ComposeSession,
    _initial_state,
    _LiftedBlock,
    _normalize_function_map,
    _register_widths,
    _term_nodes,
)
from tools.dosunit.compare.flat32_call_lowering import _lift_block
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.proof_contracts import Architecture, ContractIdentity
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.flat32_native_effect_binding import Flat32NativeBlockRequest
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundFlat32Load
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.recursive_call_components import FunctionId
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointNodeId,
    JointStepKind,
    JointStepPair,
    JointSystem,
)

MAX_COMPONENT_BLOCKS: int = 1024
MAX_COMPONENT_EFFECT_NODES: int = 262144

_STEP_KINDS: dict[str, JointStepKind] = {
    "Ijk_Boring": JointStepKind.BRANCH,
    "Ijk_Call": JointStepKind.CALL,
    "Ijk_Ret": JointStepKind.RETURN,
}


class Flat32ProposalReason(StrEnum):
    """The exact manifest-building boundary; none denotes a proof result."""

    LOADS = "flat32_component_load_coordinates_differ"
    FUNCTIONS = "flat32_component_function_declaration_invalid"
    LIFT = "flat32_component_block_lift_refused"
    MANIFEST = "flat32_component_manifest_mismatch"
    STATE = "flat32_component_native_state_malformed"
    DEADLINE = "flat32_component_original_deadline_exhausted"
    RESOURCE = "flat32_component_work_budget_exhausted"


class Flat32ProposalRefusal(Exception):
    """A typed proposal failure; the adapter keeps it as a refusal, never a verdict."""

    def __init__(self, reason: Flat32ProposalReason, detail: str) -> None:
        """Retain the exact typed boundary and its original diagnostic."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class Flat32PeComponent:
    """An untrusted complete manifest plus per-side source-binding requests."""

    system: JointSystem
    requests: tuple[tuple[Flat32NativeBlockRequest, ...], tuple[Flat32NativeBlockRequest, ...]]
    bootstrap: tuple[MachineState, MachineState]
    blocks: tuple[tuple[int, ...], tuple[int, ...]]

    @property
    def binary_equivalence_proved(self) -> bool:
        """Admission, source binding and every proof obligation remain separate."""
        return False


@dataclass(slots=True)
class _SideBlocks:
    """One side's lifted block walk over the declared function ranges."""

    session: _ComposeSession
    functions: dict[int, int]
    rows: dict[int, tuple[_LiftedBlock, MachineState, JointStepKind]] = field(default_factory=dict)

    def owner(self, address: int) -> int:
        """Resolve the declared function owning a lifted coordinate."""
        for entry, size in self.functions.items():
            if entry <= address < entry + size:
                return entry
        raise Flat32ProposalRefusal(Flat32ProposalReason.MANIFEST,
                                    f"lifted block {address:#x} lies outside declared functions")

    def walk(self, limits: LoadedRelationLimits) -> None:
        """Close the reachable block set over all declared entries, budgeted."""
        pending = sorted(self.functions)
        while pending:
            limits.check_time()
            if len(self.rows) >= MAX_COMPONENT_BLOCKS:
                raise Flat32ProposalRefusal(Flat32ProposalReason.RESOURCE, "component block budget exhausted")
            address = pending.pop(0)
            if address in self.rows:
                continue
            entry = self.owner(address)
            block = _lift_block(self.session, entry, address, entry + self.functions[entry])
            kind = _STEP_KINDS[block.jumpkind]
            state = S._compose_block_outputs(block.part, block.part["outputs"],
                                             _initial_state(self.session.reg_widths),
                                             compose_stats=self.session.compose_stats)
            if _term_nodes(state, MAX_COMPONENT_EFFECT_NODES) > MAX_COMPONENT_EFFECT_NODES:
                raise Flat32ProposalRefusal(Flat32ProposalReason.RESOURCE, "component effect term budget exhausted")
            self.rows[address] = (block, state, kind)
            if block.tail_targets:
                raise Flat32ProposalRefusal(Flat32ProposalReason.MANIFEST,
                                            "tail transfers leave the atomic component closure")
            if kind is JointStepKind.CALL:
                if block.call_target is None or block.fallthrough is None:
                    raise Flat32ProposalRefusal(Flat32ProposalReason.LIFT,
                                                "flat32 recursive component requires direct calls with continuations")
                if block.call_target not in self.functions:
                    raise Flat32ProposalRefusal(Flat32ProposalReason.MANIFEST,
                                                "direct call target is not a declared member entry")
                pending.append(block.fallthrough)
            elif kind is JointStepKind.BRANCH:
                pending.extend(sorted(set(block.successors)))


def _step(side: _SideBlocks, address: int, member_of: dict[int, FunctionId],
          original: MachineState, candidate: MachineState,
          original_hash: str, candidate_hash: str) -> JointStepPair:
    """Project one matched node into its complete atomic joint transition."""
    block, _, kind = side.rows[address]
    owner = side.owner(address)
    node = JointNodeId(member_of[owner], address - owner)
    callee: JointNodeId | None = None
    continuation: JointNodeId | None = None
    successors: tuple[JointNodeId, ...]
    if kind is JointStepKind.CALL:
        assert block.call_target is not None and block.call_target in member_of
        assert block.fallthrough is not None
        callee = JointNodeId(member_of[block.call_target], 0)
        continuation = JointNodeId(member_of[owner], block.fallthrough - owner)
        successors = (callee,)
    elif kind is JointStepKind.RETURN:
        successors = ()
    else:
        successors = tuple(JointNodeId(member_of[side.owner(target)], target - side.owner(target))
                           for target in sorted(set(block.successors)))
    return JointStepPair(node, address, address, original_hash, candidate_hash,
                         kind, original, candidate, successors, callee, continuation)


def _request_for(block: _LiftedBlock, state: MachineState) -> Flat32NativeBlockRequest:
    """Bind the exact lifted extent and complete effect as an immutable artifact."""
    if block.irsb.size <= 0:
        raise Flat32ProposalRefusal(Flat32ProposalReason.MANIFEST, "lifted block has no byte extent")
    document = canonical_json_bytes(state)
    return Flat32NativeBlockRequest(block.address, int(block.irsb.size),
                                    hashlib.sha256(document).hexdigest(), document)


def _matched_steps(left: _SideBlocks, right: _SideBlocks,
                   member_of: dict[int, FunctionId], original_hash: str,
                   candidate_hash: str) -> tuple[JointStepPair, ...]:
    """Require matching control shape before proposing paired native effects."""
    steps: list[JointStepPair] = []
    for address in sorted(left.rows):
        left_block, original_state, kind = left.rows[address]
        right_block, candidate_state, candidate_kind = right.rows[address]
        if (candidate_kind is not kind or left_block.successors != right_block.successors
                or left_block.call_target != right_block.call_target
                or left_block.fallthrough != right_block.fallthrough):
            raise Flat32ProposalRefusal(Flat32ProposalReason.MANIFEST,
                                        f"matched block {address:#x} differs in control shape")
        steps.append(_step(left, address, member_of, original_state, candidate_state,
                           original_hash, candidate_hash))
    return tuple(steps)


def build_flat32_pe_component(loads: tuple[BoundFlat32Load, BoundFlat32Load],
                              functions: Mapping[int, int], *, timeout_ms: int = 30000,
                              limits: LoadedRelationLimits | None = None) -> Flat32PeComponent:
    """Build the same-coordinate matched manifest from two loaded PE32 images.

    Every lifted coordinate must exist identically on both sides; all native
    effects come from the current flat32 lowering over the complete register
    contract. Calls must target declared member entries and every cutpoint is
    retained with its independent byte-binding request. The result is still a
    proposal: joint admission, independent binding and the composed proof own
    the actual theorems.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("flat32 component building requires a nonnegative millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    selected = replace(selected, deadline=deadline)
    original, candidate = loads
    for load in loads:
        load.verify(limits=selected)
    identity = (original.binding.mapped_base, original.binding.linked_base, original.binding.entry)
    if identity != (candidate.binding.mapped_base, candidate.binding.linked_base, candidate.binding.entry):
        raise Flat32ProposalRefusal(Flat32ProposalReason.LOADS,
                                    "same-coordinate component requires equal loader coordinates")
    selected.check_time()
    try:
        normalized = _normalize_function_map(functions)
    except CallCompositionRefusal as refusal:
        raise Flat32ProposalRefusal(Flat32ProposalReason.FUNCTIONS, str(refusal)) from refusal
    if not normalized:
        raise Flat32ProposalRefusal(Flat32ProposalReason.FUNCTIONS, "component requires declared functions")
    reg_widths = _register_widths()
    sides: list[_SideBlocks] = []
    try:
        for load in loads:
            session = _ComposeSession(load.project, dict(normalized), {}, CallCompositionLimits(),
                                      dict(reg_widths), compose_stats={"deadline": deadline})
            side = _SideBlocks(session, dict(normalized))
            side.walk(selected)
            sides.append(side)
    except CallCompositionRefusal as refusal:
        raise Flat32ProposalRefusal(Flat32ProposalReason.LIFT, str(refusal)) from refusal
    left, right = sides
    if set(left.rows) != set(right.rows):
        raise Flat32ProposalRefusal(Flat32ProposalReason.MANIFEST,
                                    "matched sides lifted different block manifests")
    member_of = {entry: FunctionId(f"flat32-{entry:x}") for entry in normalized}
    original_hash = original.binding.file_sha256
    candidate_hash = candidate.binding.file_sha256
    steps = _matched_steps(left, right, member_of, original_hash, candidate_hash)
    initial = _initial_state(reg_widths)
    initial["ip"] = {"op": "input", "name": "ip", "width": 32}
    members = tuple(member_of[entry] for entry in sorted(normalized))
    root = JointNodeId(member_of[min(normalized)], 0)
    component_ranges = tuple((entry, entry + size) for entry, size in sorted(normalized.items()))
    semantic_hash = hashlib.sha256(
        canonical_json_bytes(tuple((step.original, step.candidate) for step in steps))).hexdigest()
    contract = ContractIdentity(Architecture.FLAT32, original_hash, candidate_hash, semantic_hash,
                                hashlib.sha256(b"flat32-pe32-recursive-model").hexdigest(),
                                hashlib.sha256(b"strict-near32-frame").hexdigest())
    system = JointSystem(contract, root, members, tuple(steps), tuple(sorted(initial)),
                         expected_nodes=tuple(step.node for step in steps), initial_state=initial,
                         control_field="ip", component_ranges=component_ranges)
    original_requests = tuple(_request_for(left.rows[address][0], left.rows[address][1])
                              for address in sorted(left.rows))
    candidate_requests = tuple(_request_for(right.rows[address][0], right.rows[address][1])
                               for address in sorted(right.rows))
    selected.check_time()
    return Flat32PeComponent(system, (original_requests, candidate_requests), (initial, initial),
                           (tuple(sorted(left.rows)), tuple(sorted(right.rows))))


__all__ = [
    "Flat32PeComponent",
    "Flat32ProposalReason",
    "Flat32ProposalRefusal",
    "build_flat32_pe_component",
]
