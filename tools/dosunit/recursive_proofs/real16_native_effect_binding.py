"""Layer: dosunit immutable-byte native effect admission (staging).

Responsibility: independently lift verified relocated MZ bytes and bind each
requested full SSA effect to that actual block. Provenance metadata alone is
insufficient. This receipt establishes source binding, never program equality,
reachability, recursive frame safety or an operating-system contract.
"""
from __future__ import annotations

import hashlib
import io
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from importlib.metadata import version
from pathlib import Path

import angr
import capstone
import pyvex

from tools.dosunit import ssa_provenance
from tools.dosunit import straightline_ssa as S
from tools.dosunit.binary_environment import (
    external_effects,
    instruction_port_effect,
    instruction_requires_machine_state,
    requires_environment_contract,
)
from tools.dosunit.flat32_replay import _instruction_scope
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import initial_state
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.native_effect_equality import (
    MAX_PROPOSAL_BYTES,
    NativeProposalReason,
    NativeProposalRefusal,
    prove_native_effect_identity,
)
from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch
from tools.dosunit.register_state_relations import MachineState

MAX_NATIVE_REQUESTS: int = 4096
MAX_NATIVE_BLOCK_BYTES: int = 4096
MAX_NATIVE_ASSIGNMENTS: int = 4096
MAX_NATIVE_INSTRUCTIONS: int = 256
MAX_TOTAL_PROPOSAL_BYTES: int = 4194304


class NativeBindingReason(StrEnum):
    """The exact independent binary binding premise discharged or refused."""

    DISCHARGED = "native_block_bytes_and_effects_bound"
    LOAD = "native_load_receipt_invalid"
    MANIFEST = "native_block_manifest_incomplete"
    UNMAPPED = "native_block_bytes_not_initialized"
    DECODE = "native_block_decode_incomplete"
    EFFECT = "native_effect_differs_from_independent_lift"
    FAULT = "native_trap_or_external_effect_unclosed"
    MODEL = "native_binding_model_changed"
    DEADLINE = "native_binding_original_deadline_exhausted"
    RESOURCE = "native_binding_decode_or_expression_budget_exhausted"
    UNKNOWN = "native_binding_effect_comparison_unknown"


class NativeBindingObligation(StrEnum):
    """The fixed loader/model premises and every requested effect identity."""

    LOAD = "immutable_relocated_load"
    MODEL = "stable_native_binding_model"
    BLOCK = "independent_native_block_effect"


class NativeBlockKind(StrEnum):
    """Owned control classes derived from the VEX jumpkind boundary."""

    BRANCH = "branch"
    CALL = "call"
    RETURN = "return"


_VEX_BLOCK_KINDS: dict[str, NativeBlockKind] = {
    "Ijk_Boring": NativeBlockKind.BRANCH, "Ijk_Call": NativeBlockKind.CALL, "Ijk_Ret": NativeBlockKind.RETURN}


@dataclass(frozen=True, slots=True)
class NativeBlockRequest:
    """An untrusted coordinate/extent/effect proposal, not a decoder receipt."""

    address: int
    size: int
    effect_hash: str
    effect_json: bytes

    def __post_init__(self) -> None:
        """Bound intake before memory allocation or invoking recursive SSA code."""
        if type(self.address) is not int or not 0 <= self.address < 0x100000:
            raise ValueError("native block requires a normal real-mode physical address")
        if type(self.size) is not int or not 0 < self.size <= MAX_NATIVE_BLOCK_BYTES:
            raise ValueError("native block requires a positive bounded byte extent")
        if self.address + self.size > 0x100000:
            raise ValueError("native block extent exceeds the normal physical domain")
        if not isinstance(self.effect_hash, str) or len(self.effect_hash) != 64:
            raise ValueError("native effect proposal requires a SHA256 identity")
        if any(char not in "0123456789abcdef" for char in self.effect_hash):
            raise ValueError("native effect identity must be canonical hexadecimal")
        if type(self.effect_json) is not bytes or not self.effect_json or len(self.effect_json) > MAX_PROPOSAL_BYTES:
            raise ValueError("native effect proposal requires bounded immutable JSON bytes")
        if hashlib.sha256(self.effect_json).hexdigest() != self.effect_hash:
            raise ValueError("native effect identity differs from its immutable JSON proposal")


@dataclass(frozen=True, slots=True)
class NativeBlockBinding:
    """One actual independently decoded block and its complete composed effect."""

    address: int
    size: int
    byte_hash: str
    effect_hash: str
    kind: NativeBlockKind
    decoded_effect_hash: str


@dataclass(frozen=True, slots=True)
class NativeBindingFact:
    """One retained source-binding result, including the refused premise."""

    obligation: NativeBindingObligation
    key: str
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Real16NativeBinding:
    """Source binding under the current decoder, distinct from binary equality."""

    status: ProofStatus
    reason: NativeBindingReason
    file_hash: str
    snapshot_hash: str
    model_hash: str
    requests: tuple[NativeBlockRequest, ...]
    blocks: tuple[NativeBlockBinding, ...]
    facts: tuple[NativeBindingFact, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Complete dispatch/frame/progress/outcome comparison is separate."""
        return False


class _NativeRefusal(Exception):
    """A named source-binding boundary, preserved verbatim in the report."""

    def __init__(self, reason: NativeBindingReason, detail: str) -> None:
        """Retain the reason and original diagnostic without a guessed fallback."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def native_binding_model_hash() -> str:
    """Seal this owner, all active dosunit/frontend sources and installed tools."""
    from tools.dosunit.recursive_proofs.native_model_hash_snapshot import (
        capture_native_model_hash,
        captured_native_model_hash,
        native_model_snapshot_owner_hash,
    )

    captured: str | None = captured_native_model_hash()
    if captured is not None:
        return captured
    description = {"version": "real16-independent-native-byte-binding-v1",
                   "owner": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "loader_arch": hashlib.sha256(Path(__file__).with_name("real16_loader_arch.py").read_bytes()).hexdigest(),
                   "snapshot_owner": native_model_snapshot_owner_hash(),
                   "equality_owner": hashlib.sha256(Path(__file__).with_name("native_effect_equality.py").read_bytes()).hexdigest(),
                   "semantic": ssa_provenance._semantic_hash(),
                   "registers": S._ssa_register_widths(),
                   "packages": {name: version(name) for name in
                                ("angr", "archinfo", "capstone", "cle", "pyvex", "z3-solver")}}
    sealed: str = capture_native_model_hash(hashlib.sha256(canonical_json_bytes(description)).hexdigest())
    return sealed


@dataclass(slots=True)
class _BindingRun:
    """One original deadline and complete ledger for all proposed blocks."""

    load: BoundReal16Load
    requests: tuple[NativeBlockRequest, ...]
    limits: LoadedRelationLimits
    model_hash: str = ""
    blocks: list[NativeBlockBinding] = field(default_factory=list)
    facts: list[NativeBindingFact] = field(default_factory=list)
    current: tuple[NativeBindingObligation, str] = (NativeBindingObligation.LOAD, "load")

    def remaining_ms(self) -> int:
        """Check the original deadline before every expensive foreign boundary."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise _NativeRefusal(NativeBindingReason.DEADLINE, "native binding original deadline exhausted")
        return remaining

    def report(self, reason: NativeBindingReason, detail: str = "") -> Real16NativeBinding:
        """Missing or failed premises remain visible in the required denominator."""
        required = {(NativeBindingObligation.LOAD, "load"), (NativeBindingObligation.MODEL, "model")}
        required.update((NativeBindingObligation.BLOCK, str(index)) for index in range(len(self.requests)))
        ids = [(fact.obligation, fact.key) for fact in self.facts]
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(required - set(ids)) + len(set(ids) - required) + len(ids) - len(set(ids))
        proved = reason is NativeBindingReason.DISCHARGED and failed == 0 and len(self.blocks) == len(self.requests)
        status = ProofStatus.PROVED if proved else ProofStatus.UNKNOWN
        if reason is NativeBindingReason.DISCHARGED and not proved:
            reason = NativeBindingReason.MANIFEST
        count = len(required)
        return Real16NativeBinding(status, reason, self.load.binding.file_sha256,
            self.load.binding.snapshot.sparse_byte_sha256, self.model_hash, self.requests,
            tuple(self.blocks), tuple(self.facts), FactCounters(count, count, count, len(self.facts), failed), detail)


def _block_bytes(run: _BindingRun, row: NativeBlockRequest) -> bytes:
    """Read only proven initialized bytes, never loader defaults or guessed zeros."""
    run.remaining_ms()
    for start, data in run.load.binding.snapshot.chunks:
        if not isinstance(data, bytes):
            raise _NativeRefusal(NativeBindingReason.LOAD, "initialized snapshot chunk is not immutable bytes")
        if start <= row.address and row.address + row.size <= start + len(data):
            offset = row.address - start
            return data[offset:offset + row.size]
    raise _NativeRefusal(NativeBindingReason.UNMAPPED, "requested block bytes absent from initialized snapshot")


def _check_instruction_scope(data: bytes, address: int) -> None:
    """Reject external effects from complete decoding before integer lowering.

    Reuse one decode for instruction scope, port and machine-state checks.
    Neither unused values nor an incomplete lifter can erase a native event.
    These exclusions establish no asynchronous-environment or fault theorem.
    """
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    instructions = tuple(decoder.disasm(data, address))
    if sum(instruction.size for instruction in instructions) != len(data):
        raise _NativeRefusal(NativeBindingReason.DECODE, "native instruction decode does not cover all proposed bytes")
    for instruction in instructions:
        reason = _instruction_scope(instruction)
        if reason is not None:
            raise _NativeRefusal(NativeBindingReason.FAULT, f"native instruction scope requires a contract: {reason.value}")
        if instruction_port_effect(instruction) is not None:
            raise _NativeRefusal(NativeBindingReason.FAULT, "native port event requires an environment contract")
        if instruction_requires_machine_state(instruction):
            raise _NativeRefusal(NativeBindingReason.FAULT, "native machine-state instruction requires a system contract")


def _effect(run: _BindingRun, project: angr.Project, row: NativeBlockRequest, data: bytes) -> tuple[MachineState, NativeBlockKind]:
    """Decode exactly the proposed bytes and lower the complete native state."""
    with S._timeout_alarm(run.remaining_ms(), message="independent native block lift deadline"):
        _check_instruction_scope(data, row.address)
        block = project.factory.block(row.address, byte_string=data, size=row.size, opt_level=0)
        irsb = block.vex
        if (not isinstance(irsb, pyvex.IRSB) or not isinstance(irsb.jumpkind, str)
                or irsb.size != row.size or irsb.jumpkind == "Ijk_NoDecode"):
            raise _NativeRefusal(NativeBindingReason.DECODE, "native source requires a complete VEX block of the proposed extent")
        if irsb.instructions > MAX_NATIVE_INSTRUCTIONS:
            raise _NativeRefusal(NativeBindingReason.RESOURCE, "native block exceeds independent instruction budget")
        kind = _VEX_BLOCK_KINDS.get(irsb.jumpkind)
        if kind is None:
            raise _NativeRefusal(NativeBindingReason.FAULT, f"native control outcome requires its own contract: {irsb.jumpkind}")
        if requires_environment_contract(irsb):
            raise _NativeRefusal(NativeBindingReason.FAULT, "opaque native helper requires an environment contract")
        lowered = S._lower_irsb(irsb, output_regs=tuple(S.INTERNAL_STATE_REGS),
                                max_assignments_per_function=MAX_NATIVE_ASSIGNMENTS)
        if isinstance(lowered, S.LowerFailure):
            raise _NativeRefusal(NativeBindingReason.DECODE, f"{lowered.reason}: {lowered.message}")
        if lowered.get("trap_exits") or external_effects(lowered):
            raise _NativeRefusal(NativeBindingReason.FAULT, "native trap or external event requires its own contract")
        state = S._compose_block_outputs(lowered, lowered["outputs"], initial_state(),
                                          compose_stats={"deadline": run.limits.deadline})
    run.remaining_ms()
    return state, kind


def _bind(run: _BindingRun) -> Real16NativeBinding:
    """Check immutable loading, each independent effect and final model stability."""
    run.remaining_ms()
    if len({row.address for row in run.requests}) != len(run.requests):
        raise _NativeRefusal(NativeBindingReason.MANIFEST, "duplicate native block coordinate")
    if sum(len(row.effect_json) for row in run.requests) > MAX_TOTAL_PROPOSAL_BYTES:
        raise _NativeRefusal(NativeBindingReason.RESOURCE, "cumulative native proposal byte budget exhausted")
    run.load.verify(limits=run.limits)
    run.facts.append(NativeBindingFact(*run.current, ProofStatus.PROVED))
    run.model_hash = native_binding_model_hash()
    run.remaining_ms()
    if len(run.load.image.chunks) != 1:
        raise _NativeRefusal(NativeBindingReason.LOAD, "MZ loader must retain its one contiguous relocated module")
    address, image = run.load.image.chunks[0]
    with S._timeout_alarm(run.remaining_ms(), message="independent native project creation deadline"):
        project = angr.Project(io.BytesIO(image), auto_load_libs=False,
                               main_opts={"backend": "blob", "arch": real16_loader_arch(), "base_addr": address,
                                          "entry_point": run.load.binding.entry})
    for index, row in enumerate(run.requests):
        run.current = (NativeBindingObligation.BLOCK, str(index))
        data = _block_bytes(run, row)
        state, kind = _effect(run, project, row, data)
        digest = hashlib.sha256(canonical_json_bytes(state)).hexdigest()
        if digest != row.effect_hash:
            comparison = prove_native_effect_identity(state, row.effect_json, run.limits)
            if comparison.status is ProofStatus.COUNTEREXAMPLE:
                raise _NativeRefusal(NativeBindingReason.EFFECT, f"native effect countermodel: {comparison.model}")
            if comparison.status is not ProofStatus.PROVED:
                raise _NativeRefusal(NativeBindingReason.UNKNOWN, comparison.detail)
        run.remaining_ms()
        run.blocks.append(NativeBlockBinding(row.address, row.size, hashlib.sha256(data).hexdigest(),
                                            row.effect_hash, kind, digest))
        run.facts.append(NativeBindingFact(*run.current, ProofStatus.PROVED))
    run.current = (NativeBindingObligation.MODEL, "model")
    if native_binding_model_hash() != run.model_hash:
        raise _NativeRefusal(NativeBindingReason.MODEL, "decoder/SSA model changed during native binding")
    run.remaining_ms()
    run.facts.append(NativeBindingFact(*run.current, ProofStatus.PROVED))
    return run.report(NativeBindingReason.DISCHARGED)


def _checked_bind(run: _BindingRun) -> Real16NativeBinding:
    """Translate only the named loader, lifter and proposal boundary failures."""
    try:
        return _bind(run)
    except _NativeRefusal as refusal:
        reason, detail = refusal.reason, refusal.detail
    except LoadedRelationRefusal as refusal:
        reason = NativeBindingReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else NativeBindingReason.LOAD
        detail = refusal.detail
    except ImageBindingRefusal as refusal:
        reason, detail = NativeBindingReason.LOAD, refusal.detail
    except TimeoutError as refusal:
        reason, detail = NativeBindingReason.DEADLINE, str(refusal)
    except RecursionError as refusal:
        reason, detail = NativeBindingReason.RESOURCE, f"native SSA expression boundary: {refusal}"
    except NativeProposalRefusal as refusal:
        reason = NativeBindingReason.RESOURCE if refusal.reason is NativeProposalReason.RESOURCE else NativeBindingReason.EFFECT
        detail = refusal.detail
    except (angr.errors.SimEngineError, pyvex.errors.PyVEXError) as refusal:
        reason, detail = NativeBindingReason.DECODE, f"{type(refusal).__name__}: {refusal}"
    except S.LowerFailure as refusal:
        reason = NativeBindingReason.DEADLINE if refusal.reason == "compose_budget_exceeded" else NativeBindingReason.DECODE
        detail = f"{refusal.reason}: {refusal.message}"
    run.facts.append(NativeBindingFact(*run.current, ProofStatus.UNKNOWN, detail))
    return run.report(reason, detail)


def bind_real16_native_effects(load: BoundReal16Load, requests: tuple[NativeBlockRequest, ...],
                               *, timeout_ms: int = 15000,
                               limits: LoadedRelationLimits | None = None) -> Real16NativeBinding:
    """Bind each proposed effect to a new lift of actual relocated MZ bytes.

    Coordinates and sizes are candidates; byte extent must match decoding and
    the complete native effect must equal the immutable proposal. Different
    expression forms require unrestricted SMT proof over every output. Fresh
    lifting uses no artifact cache or rendered text. A complete receipt grants
    no recursive/program equivalence; it is one premise of those proofs.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("native binding requires a nonnegative millisecond budget")
    if not requests or len(requests) > MAX_NATIVE_REQUESTS:
        raise ValueError("native binding requires one through4096 bounded block requests")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _BindingRun(load, requests, replace(selected, deadline=deadline))
    return _checked_bind(run)
