"""Layer: dosunit immutable-byte flat32 native effect admission.

Responsibility: independently lift verified CLE-loaded PE32/ELF32 bytes and
bind each requested full SSA effect to that actual block. Provenance metadata
alone is insufficient. This receipt establishes source binding, never program
equality, reachability, recursive frame safety or an operating-system contract.
Effects use the current ``flat32_call_lowering`` register contract; no second
lifter or normalization is introduced.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from importlib.metadata import version
from pathlib import Path
from typing import Any, cast

import angr
import capstone
import pyvex
import z3

from tools.dosunit import (
    binary_environment,
    flat32_call_contracts,
    flat32_call_lowering,
    flat32_pe_loader,
    flat32_replay,
    ssa_provenance,
)
from tools.dosunit import straightline_ssa as S
from tools.dosunit.binary_environment import (
    external_effects,
    instruction_port_effect,
    instruction_requires_machine_state,
    requires_environment_contract,
)
from tools.dosunit.flat32_call_contracts import (
    CallCompositionRefusal,
    _initial_state,
    _register_widths,
)
from tools.dosunit.flat32_call_lowering import _accepted_jumpkind, _check_exits, _static_next
from tools.dosunit.flat32_replay import _instruction_scope
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import (
    loaded_byte_image_binding,
    loaded_byte_native_transition,
    native_effect_equality,
    real16_native_effect_binding,
    recursive_joint_proof,
)
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import (
    BoundFlat32Load,
    ImageBindingRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.native_effect_equality import (
    MAX_PROPOSAL_BYTES,
    NativeProposalReason,
    NativeProposalRefusal,
)
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import (
    native_model_snapshot_owner_hash,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockKind
from tools.dosunit.recursive_proofs.recursive_joint_proof import strict_state_document
from tools.dosunit.register_state_relations import MachineState
from tools.dosunit.ssa_output_lemmas import OutputEqualityResult, prove_output_equalities

MAX_NATIVE_REQUESTS: int = 4096
MAX_NATIVE_BLOCK_BYTES: int = 4096
MAX_NATIVE_ASSIGNMENTS: int = 4096
MAX_NATIVE_INSTRUCTIONS: int = 256
MAX_TOTAL_PROPOSAL_BYTES: int = 4194304
MAX_PROPOSAL_NODES: int = 262144
MAX_PROPOSAL_DEPTH: int = 128


class Flat32BindingReason(StrEnum):
    """The exact independent binary binding premise discharged or refused."""

    DISCHARGED = "flat32_native_block_bytes_and_effects_bound"
    LOAD = "flat32_native_load_receipt_invalid"
    MANIFEST = "flat32_native_block_manifest_incomplete"
    UNMAPPED = "flat32_native_block_bytes_not_initialized"
    DECODE = "flat32_native_block_decode_incomplete"
    EFFECT = "flat32_native_effect_differs_from_independent_lift"
    FAULT = "flat32_native_trap_or_external_effect_unclosed"
    MODEL = "flat32_native_binding_model_changed"
    DEADLINE = "flat32_native_binding_original_deadline_exhausted"
    RESOURCE = "flat32_native_decode_or_expression_budget_exhausted"
    UNKNOWN = "flat32_native_binding_effect_comparison_unknown"


class Flat32BindingObligation(StrEnum):
    """The fixed loader/model premises and every requested effect identity."""

    LOAD = "immutable_cle_loaded_image"
    MODEL = "stable_flat32_native_binding_model"
    BLOCK = "independent_flat32_native_block_effect"


@dataclass(frozen=True, slots=True)
class Flat32NativeBlockRequest:
    """An untrusted coordinate/extent/effect proposal, not a decoder receipt."""

    address: int
    size: int
    effect_hash: str
    effect_json: bytes

    def __post_init__(self) -> None:
        """Bound intake before memory allocation or invoking recursive SSA code."""
        if type(self.address) is not int or not 0 <= self.address < 1 << 32:
            raise ValueError("flat32 native block requires an unsigned32 coordinate")
        if type(self.size) is not int or not 0 < self.size <= MAX_NATIVE_BLOCK_BYTES:
            raise ValueError("flat32 native block requires a positive bounded byte extent")
        if self.address + self.size > 1 << 32:
            raise ValueError("flat32 native block extent exceeds the address domain")
        if not isinstance(self.effect_hash, str) or len(self.effect_hash) != 64:
            raise ValueError("flat32 effect proposal requires a SHA256 identity")
        if any(char not in "0123456789abcdef" for char in self.effect_hash):
            raise ValueError("flat32 effect identity must be canonical hexadecimal")
        if type(self.effect_json) is not bytes or not self.effect_json or len(self.effect_json) > MAX_PROPOSAL_BYTES:
            raise ValueError("flat32 effect proposal requires bounded immutable JSON bytes")
        if hashlib.sha256(self.effect_json).hexdigest() != self.effect_hash:
            raise ValueError("flat32 effect identity differs from its immutable JSON proposal")


@dataclass(frozen=True, slots=True)
class Flat32NativeBlockBinding:
    """One actual independently decoded block and its complete composed effect."""

    address: int
    size: int
    byte_hash: str
    effect_hash: str
    kind: NativeBlockKind
    decoded_effect_hash: str


@dataclass(frozen=True, slots=True)
class Flat32BindingFact:
    """One retained source-binding result, including the refused premise."""

    obligation: Flat32BindingObligation
    key: str
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Flat32NativeBinding:
    """Source binding under the current decoder, distinct from binary equality."""

    status: ProofStatus
    reason: Flat32BindingReason
    file_hash: str
    snapshot_hash: str
    model_hash: str
    requests: tuple[Flat32NativeBlockRequest, ...]
    blocks: tuple[Flat32NativeBlockBinding, ...]
    facts: tuple[Flat32BindingFact, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Complete dispatch/frame/progress/outcome comparison is separate."""
        return False


class _Flat32Refusal(Exception):
    """A named source-binding boundary, preserved verbatim in the report."""

    def __init__(self, reason: Flat32BindingReason, detail: str) -> None:
        """Retain the reason and original diagnostic without a guessed fallback."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def flat32_native_binding_model_hash() -> str:
    """Seal this owner, the active flat32 lowering owners and installed tools.

    This is a complete owner fingerprint, not the real16 native leaf: it is
    always recomputed and never joined to an enclosing snapshot traversal, so
    no foreign owner can return this identity or write theirs into it.
    """
    owners = (flat32_call_contracts, flat32_call_lowering, flat32_pe_loader, binary_environment,
              flat32_replay, loaded_byte_image_binding, loaded_byte_native_transition,
              native_effect_equality, recursive_joint_proof, real16_native_effect_binding)
    description = {"version": "flat32-independent-native-byte-binding-v1",
                   "self": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "sources": [hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                               for module in owners if module.__file__ is not None],
                   "snapshot_owner": native_model_snapshot_owner_hash(),
                   "semantic": ssa_provenance._semantic_hash(),
                   "registers": S._ssa_register_widths(),
                   "packages": {name: version(name) for name in
                                ("angr", "archinfo", "capstone", "cle", "pyvex", "z3-solver")}}
    return hashlib.sha256(canonical_json_bytes(description)).hexdigest()


@dataclass(slots=True)
class _Flat32BindingRun:
    """One original deadline and complete ledger for all proposed blocks."""

    load: BoundFlat32Load
    requests: tuple[Flat32NativeBlockRequest, ...]
    limits: LoadedRelationLimits
    model_hash: str = ""
    blocks: list[Flat32NativeBlockBinding] = field(default_factory=list)
    facts: list[Flat32BindingFact] = field(default_factory=list)
    current: tuple[Flat32BindingObligation, str] = (Flat32BindingObligation.LOAD, "load")

    def remaining_ms(self) -> int:
        """Check the original deadline before every expensive foreign boundary."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise _Flat32Refusal(Flat32BindingReason.DEADLINE, "flat32 binding original deadline exhausted")
        return remaining

    def report(self, reason: Flat32BindingReason, detail: str = "") -> Flat32NativeBinding:
        """Missing or failed premises remain visible in the required denominator."""
        required = {(Flat32BindingObligation.LOAD, "load"), (Flat32BindingObligation.MODEL, "model")}
        required.update((Flat32BindingObligation.BLOCK, str(index)) for index in range(len(self.requests)))
        ids = [(fact.obligation, fact.key) for fact in self.facts]
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(required - set(ids)) + len(set(ids) - required) + len(ids) - len(set(ids))
        proved = reason is Flat32BindingReason.DISCHARGED and failed == 0 and len(self.blocks) == len(self.requests)
        status = ProofStatus.PROVED if proved else ProofStatus.UNKNOWN
        if reason is Flat32BindingReason.DISCHARGED and not proved:
            reason = Flat32BindingReason.MANIFEST
        count = len(required)
        return Flat32NativeBinding(status, reason, self.load.binding.file_sha256,
            self.load.binding.snapshot.sparse_byte_sha256, self.model_hash, self.requests,
            tuple(self.blocks), tuple(self.facts), FactCounters(count, count, count, len(self.facts), failed), detail)


def _block_bytes(run: _Flat32BindingRun, row: Flat32NativeBlockRequest) -> bytes:
    """Read only proven initialized bytes, never loader defaults or guessed zeros."""
    run.remaining_ms()
    for start, data in run.load.binding.snapshot.chunks:
        if not isinstance(data, bytes):
            raise _Flat32Refusal(Flat32BindingReason.LOAD, "initialized snapshot chunk is not immutable bytes")
        if start <= row.address and row.address + row.size <= start + len(data):
            offset = row.address - start
            return data[offset:offset + row.size]
    raise _Flat32Refusal(Flat32BindingReason.UNMAPPED, "requested block bytes absent from initialized snapshot")


def _check_instruction_scope(data: bytes, address: int) -> None:
    """Reject external effects from complete mode32 decoding before lowering.

    Reuse one decode for instruction scope, port and machine-state checks.
    Neither unused values nor an incomplete lifter can erase a native event.
    These exclusions establish no asynchronous-environment or fault theorem.
    """
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = tuple(decoder.disasm(data, address))
    if sum(instruction.size for instruction in instructions) != len(data):
        raise _Flat32Refusal(Flat32BindingReason.DECODE, "flat32 decode does not cover all proposed bytes")
    for instruction in instructions:
        reason = _instruction_scope(instruction)
        if reason is not None:
            raise _Flat32Refusal(Flat32BindingReason.FAULT, f"flat32 instruction scope requires a contract: {reason.value}")
        if instruction_port_effect(instruction) is not None:
            raise _Flat32Refusal(Flat32BindingReason.FAULT, "flat32 port event requires an environment contract")
        if instruction_requires_machine_state(instruction):
            raise _Flat32Refusal(Flat32BindingReason.FAULT, "flat32 machine-state instruction requires a system contract")


def _check_lifted_control(irsb: pyvex.IRSB, ip_offset: int) -> NativeBlockKind:
    """Require the same statically closed dispatch the shared lifter admits."""
    jumpkind = _accepted_jumpkind(irsb)
    kind = {"Ijk_Boring": NativeBlockKind.BRANCH, "Ijk_Call": NativeBlockKind.CALL,
            "Ijk_Ret": NativeBlockKind.RETURN}.get(jumpkind)
    if kind is None:
        raise _Flat32Refusal(Flat32BindingReason.FAULT, f"flat32 control outcome requires its own contract: {jumpkind}")
    exits = _check_exits(irsb, ip_offset)
    if kind is NativeBlockKind.RETURN and exits:
        raise _Flat32Refusal(Flat32BindingReason.FAULT, "conditional return block requires its own contract")
    if kind is NativeBlockKind.CALL and exits:
        raise _Flat32Refusal(Flat32BindingReason.FAULT, "conditional call block requires its own contract")
    if kind is not NativeBlockKind.RETURN and _static_next(irsb) is None:
        raise _Flat32Refusal(Flat32BindingReason.FAULT, "flat32 indirect control requires its own contract")
    return kind


def _effect(run: _Flat32BindingRun, row: Flat32NativeBlockRequest,
            data: bytes) -> tuple[MachineState, NativeBlockKind]:
    """Decode exactly the proposed bytes and lower the complete native state."""
    reg_widths = _register_widths()
    with S._timeout_alarm(run.remaining_ms(), message="flat32 independent block lift deadline"):
        _check_instruction_scope(data, row.address)
        block = run.load.project.factory.block(row.address, byte_string=data, size=row.size, opt_level=0)
        irsb = block.vex
        if (not isinstance(irsb, pyvex.IRSB) or not isinstance(irsb.jumpkind, str)
                or irsb.size != row.size or irsb.jumpkind == "Ijk_NoDecode"):
            raise _Flat32Refusal(Flat32BindingReason.DECODE, "flat32 source requires a complete VEX block of the proposed extent")
        if irsb.instructions > MAX_NATIVE_INSTRUCTIONS:
            raise _Flat32Refusal(Flat32BindingReason.RESOURCE, "flat32 block exceeds independent instruction budget")
        if requires_environment_contract(irsb):
            raise _Flat32Refusal(Flat32BindingReason.FAULT, "opaque flat32 helper requires an environment contract")
        ip_offset = run.load.project.arch.ip_offset
        if ip_offset is None:
            raise _Flat32Refusal(Flat32BindingReason.DECODE, "flat32 arch lacks an instruction-pointer offset")
        kind = _check_lifted_control(irsb, int(ip_offset))
        lowered = S._lower_irsb(irsb, output_regs=(*reg_widths, "ip"),
                                max_assignments_per_function=MAX_NATIVE_ASSIGNMENTS)
        if isinstance(lowered, S.LowerFailure):
            raise _Flat32Refusal(Flat32BindingReason.DECODE, f"{lowered.reason}: {lowered.message}")
        if lowered.get("trap_exits") or external_effects(lowered):
            raise _Flat32Refusal(Flat32BindingReason.FAULT, "flat32 trap or external event requires its own contract")
        state = S._compose_block_outputs(lowered, lowered["outputs"], _initial_state(reg_widths),
                                          compose_stats={"deadline": run.limits.deadline})
    run.remaining_ms()
    return state, kind


def _guard_flat32_proposal(state: dict[str, Any], limits: LoadedRelationLimits) -> None:
    """Bound the JSON term tree before owned recursive SSA materialization."""
    pending = [(term, 1) for term in state.values()]
    count = 0
    while pending:
        limits.check_time()
        node, depth = pending.pop()
        count += 1
        if count > MAX_PROPOSAL_NODES or depth > MAX_PROPOSAL_DEPTH:
            raise NativeProposalRefusal(NativeProposalReason.RESOURCE, "flat32 term tree exceeds budget")
        if not isinstance(node, dict) or not isinstance(node.get("op"), str):
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "flat32 effect operand lacks a typed operation")
        width = node.get("width", 0)
        if type(width) is not int or not 0 <= width <= 64:
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "flat32 effect operand width is invalid")
        args = node.get("args", [])
        if not isinstance(args, list):
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "flat32 effect operand list is invalid")
        pending.extend((child, depth + 1) for child in args)


def _decode_flat32_proposal(data: bytes, limits: LoadedRelationLimits,
                            baseline: MachineState) -> MachineState:
    """Parse one canonical bounded JSON proposal against the flat32 manifest."""
    import json

    limits.check_time()
    if type(data) is not bytes or not data or len(data) > MAX_PROPOSAL_BYTES:
        raise NativeProposalRefusal(NativeProposalReason.RESOURCE, "flat32 proposal byte intake is invalid or oversized")
    try:
        parsed = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, str(error)) from error
    except RecursionError as error:
        raise NativeProposalRefusal(NativeProposalReason.RESOURCE, str(error)) from error
    if not isinstance(parsed, dict):
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "flat32 proposal is not an output mapping")
    _guard_flat32_proposal(parsed, limits)
    if canonical_json_bytes(parsed) != data:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "flat32 proposal is not canonical or contains duplicate keys")
    if set(parsed) != set(baseline):
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "flat32 proposal full output manifest differs")
    for name, expected in baseline.items():
        if name not in {"memory", "io"} and parsed[name].get("width") != expected["width"]:
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, f"flat32 proposal output width differs: {name}")
    # JSON is a dynamic third-party boundary; the complete term tree and
    # manifest have been validated before narrowing to the owned state type.
    return cast(MachineState, parsed)


def _compare_flat32(independent: MachineState, claimed: MachineState,
                    limits: LoadedRelationLimits) -> OutputEqualityResult:
    """Materialize and compare every flat32 output at the SMT-library boundary."""
    before = strict_state_document("flat32:independent", independent)
    after = strict_state_document("flat32:claimed", claimed)
    limits.check_time()
    inputs = S._z3_inputs(before, after, z3)
    names = sorted(before["outputs"])
    pairs, skipped = S._z3_output_pairs(names, oracle=before, candidate=after,
        oracle_outputs=before["outputs"], candidate_outputs=after["outputs"],
        inputs=inputs, z3=z3, simplify_terms=False)
    if skipped or len(pairs) != len(names) or {name for name, _, _ in pairs} != set(names):
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "flat32 output comparison omitted fields")
    limits.check_time()
    return prove_output_equalities(pairs, z3.Solver(), deadline=limits.deadline)


def prove_flat32_effect_identity(independent: MachineState, proposal: bytes,
                                 limits: LoadedRelationLimits) -> OutputEqualityResult:
    """Compare all flat32 native outputs with unrestricted inputs and no callee premise."""
    baseline = _initial_state(_register_widths())
    baseline["ip"] = {"op": "input", "width": 32, "name": "ip"}
    claimed = _decode_flat32_proposal(proposal, limits, baseline)
    try:
        return _compare_flat32(independent, claimed, limits)
    except z3.Z3Exception as error:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, f"flat32 expression sort: {error}") from error
    except S.LowerFailure as error:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, f"{error.reason}: {error.message}") from error


def _bind(run: _Flat32BindingRun) -> Flat32NativeBinding:
    """Check immutable loading, each independent effect and final model stability."""
    run.remaining_ms()
    if len({row.address for row in run.requests}) != len(run.requests):
        raise _Flat32Refusal(Flat32BindingReason.MANIFEST, "duplicate flat32 block coordinate")
    if sum(len(row.effect_json) for row in run.requests) > MAX_TOTAL_PROPOSAL_BYTES:
        raise _Flat32Refusal(Flat32BindingReason.RESOURCE, "cumulative flat32 proposal byte budget exhausted")
    run.load.verify(limits=run.limits)
    run.facts.append(Flat32BindingFact(*run.current, ProofStatus.PROVED))
    run.model_hash = flat32_native_binding_model_hash()
    run.remaining_ms()
    for index, row in enumerate(run.requests):
        run.current = (Flat32BindingObligation.BLOCK, str(index))
        data = _block_bytes(run, row)
        state, kind = _effect(run, row, data)
        digest = hashlib.sha256(canonical_json_bytes(state)).hexdigest()
        if digest != row.effect_hash:
            comparison = prove_flat32_effect_identity(state, row.effect_json, run.limits)
            if comparison.status is ProofStatus.COUNTEREXAMPLE:
                raise _Flat32Refusal(Flat32BindingReason.EFFECT, f"flat32 effect countermodel: {comparison.model}")
            if comparison.status is not ProofStatus.PROVED:
                raise _Flat32Refusal(Flat32BindingReason.UNKNOWN, comparison.detail)
        run.remaining_ms()
        run.blocks.append(Flat32NativeBlockBinding(row.address, row.size, hashlib.sha256(data).hexdigest(),
                                                  row.effect_hash, kind, digest))
        run.facts.append(Flat32BindingFact(*run.current, ProofStatus.PROVED))
    run.current = (Flat32BindingObligation.MODEL, "model")
    if flat32_native_binding_model_hash() != run.model_hash:
        raise _Flat32Refusal(Flat32BindingReason.MODEL, "decoder/SSA model changed during flat32 binding")
    run.remaining_ms()
    run.facts.append(Flat32BindingFact(*run.current, ProofStatus.PROVED))
    return run.report(Flat32BindingReason.DISCHARGED)


def _checked_bind(run: _Flat32BindingRun) -> Flat32NativeBinding:
    """Translate only the named loader, lifter and proposal boundary failures."""
    try:
        return _bind(run)
    except _Flat32Refusal as refusal:
        reason, detail = refusal.reason, refusal.detail
    except LoadedRelationRefusal as refusal:
        reason = Flat32BindingReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else Flat32BindingReason.LOAD
        detail = refusal.detail
    except ImageBindingRefusal as refusal:
        reason, detail = Flat32BindingReason.LOAD, refusal.detail
    except TimeoutError as refusal:
        reason, detail = Flat32BindingReason.DEADLINE, str(refusal)
    except RecursionError as refusal:
        reason, detail = Flat32BindingReason.RESOURCE, f"flat32 SSA expression boundary: {refusal}"
    except NativeProposalRefusal as refusal:
        reason = Flat32BindingReason.RESOURCE if refusal.reason is NativeProposalReason.RESOURCE else Flat32BindingReason.EFFECT
        detail = refusal.detail
    except CallCompositionRefusal as refusal:
        reason, detail = Flat32BindingReason.DECODE, str(refusal)
    except (angr.errors.SimEngineError, pyvex.errors.PyVEXError) as refusal:
        reason, detail = Flat32BindingReason.DECODE, f"{type(refusal).__name__}: {refusal}"
    except S.LowerFailure as refusal:
        reason = Flat32BindingReason.DEADLINE if refusal.reason == "compose_budget_exceeded" else Flat32BindingReason.DECODE
        detail = f"{refusal.reason}: {refusal.message}"
    run.facts.append(Flat32BindingFact(*run.current, ProofStatus.UNKNOWN, detail))
    return run.report(reason, detail)


def bind_flat32_native_effects(load: BoundFlat32Load, requests: tuple[Flat32NativeBlockRequest, ...],
                               *, timeout_ms: int = 15000,
                               limits: LoadedRelationLimits | None = None) -> Flat32NativeBinding:
    """Bind each proposed effect to a new lift of actual loaded PE32/ELF32 bytes.

    Coordinates and sizes are candidates; byte extent must match decoding and
    the complete native effect must equal the immutable proposal. Fresh lifting
    reads the proven initialized snapshot bytes through the existing flat32
    lowering. A complete receipt grants no recursive/program equivalence; it is
    one premise of those proofs.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("flat32 binding requires a nonnegative millisecond budget")
    if not requests or len(requests) > MAX_NATIVE_REQUESTS:
        raise ValueError("flat32 binding requires one through4096 bounded block requests")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _Flat32BindingRun(load, requests, replace(selected, deadline=deadline))
    return _checked_bind(run)


__all__ = [
    "Flat32BindingFact",
    "Flat32BindingObligation",
    "Flat32BindingReason",
    "Flat32NativeBinding",
    "Flat32NativeBlockBinding",
    "Flat32NativeBlockRequest",
    "bind_flat32_native_effects",
    "flat32_native_binding_model_hash",
    "prove_flat32_effect_identity",
]
