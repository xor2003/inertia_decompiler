"""Transfer typed segment-register state through one IR block.

Layer: IR.
Responsibility: own the segment-state lattice and consume typed restore-source
relations already proved by Alias. Owns typed Value, Address, Condition,
instruction facts, and lossless normalization. Do not perform alias-state
ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here. Never infer stack identity here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast

from .core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace, SegmentOrigin

if TYPE_CHECKING:
    from ..declared_external_call_evidence import DeclaredCallAdmission8616
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .segment_call_preservation import SegmentCallPreservationResult8616

__all__ = [
    "SEGMENT_REGISTERS",
    "SEGMENT_REGISTER_SET",
    "InstructionStateKey",
    "SegmentRegisterState",
    "SegmentRestoreSource",
    "SegmentValueKind8616",
    "architectural_live_in_state",
    "call_boundary_segment_state",
    "declared_call_effect_at_instruction_8616",
    "join_register_states",
    "transfer_block_with_instruction_states",
    "unknown_segment_state",
]

SEGMENT_REGISTERS: tuple[str, ...] = ("cs", "ds", "es", "ss", "fs", "gs")
SEGMENT_REGISTER_SET: frozenset[str] = frozenset(SEGMENT_REGISTERS)
type InstructionStateKey = int | tuple[int, int]


class SegmentValueKind8616(StrEnum):
    """Typed provenance class for one segment-register state."""

    UNKNOWN = "unknown"
    ARCHITECTURAL_LIVE_IN = "architectural_live_in"
    CALL_ENTRY_RELATION = "call_entry_relation"
    MERGED_PROVEN = "merged_proven"
    MERGED = "merged"
    STACK_RESTORE = "stack_restore"
    CONST_WRITE = "const_write"
    SEGMENT_COPY = "segment_copy"
    REGISTER_COPY = "register_copy"
    UNKNOWN_WRITE = "unknown_write"
    CALL_BOUNDARY = "call_boundary"


@dataclass(frozen=True, slots=True)
class SegmentRegisterState:
    """Proven state for one segment register at a program point."""

    register: str
    value_kind: SegmentValueKind8616
    source: str | None
    origin: SegmentOrigin

    def __post_init__(self) -> None:
        """Normalize legacy construction sites to the typed state enum."""
        if not isinstance(self.value_kind, SegmentValueKind8616):
            object.__setattr__(self, "value_kind", SegmentValueKind8616(self.value_kind))

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "register": self.register,
            "value_kind": self.value_kind.value,
            "source": self.source,
            "origin": self.origin.value,
        }

    def constant_value(self) -> int | None:
        """Return the proven numeric segment value carried by this state."""
        if self.origin is not SegmentOrigin.PROVEN or self.source is None:
            return None
        if self.value_kind is SegmentValueKind8616.ARCHITECTURAL_LIVE_IN:
            return None
        try:
            return int(self.source, 0) & 0xFFFF
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class SegmentRestoreSource:
    """Alias-proved relation from one segment write to an earlier segment read.

    ``source_artifact`` is the exact in-process ``IRFunctionArtifact`` object
    the Alias proof consumed when establishing this relation. It is local
    object identity only: excluded from equality and ``repr``, dropped by
    diagnostic serialization, and never reconstructed from serialized fields.
    Legacy constructions without it remain valid for this module's
    intra-function segment-state transfer, but an unbound source cannot
    authorize a cross-function lineage proof.
    """

    block_addr: int
    restore_instruction_addr: int
    restore_register: str
    saved_instruction_addr: int
    saved_register: str
    source_artifact: IRFunctionArtifact | None = field(
        default=None, repr=False, compare=False
    )


def unknown_segment_state(register: str) -> SegmentRegisterState:
    """Return the lattice unknown state for one register."""
    return SegmentRegisterState(register, SegmentValueKind8616.UNKNOWN, None, SegmentOrigin.UNKNOWN)


def call_boundary_segment_state(register: str) -> SegmentRegisterState:
    """Return the typed refusal state for one segment register at a CALL exit."""
    return SegmentRegisterState(register, SegmentValueKind8616.CALL_BOUNDARY, None, SegmentOrigin.UNKNOWN)


def _drop_unproved_call_boundary_identities(
    state: dict[str, SegmentRegisterState],
    preserved_registers: frozenset[str] = frozenset(),
) -> None:
    """Drop every identity that lacks a proof of preservation across a CALL.

    Only separately bound preservation evidence can retain a segment identity.
    General-register proxies are always dropped. ``call_stack_effect`` proves
    BP/SP storage only, not segments; a known target is not a callee model.
    """
    for register in tuple(state):
        if register in SEGMENT_REGISTER_SET:
            if register not in preserved_registers:
                state[register] = call_boundary_segment_state(register)
        else:
            del state[register]


def call_preservation_at_instruction_8616(
    artifact: IRFunctionArtifact | None,
    block: IRBlock,
    instruction: IRInstr,
    proofs: tuple[SegmentCallPreservationResult8616, ...],
    invocation_scope: Real16InvocationDomain8616 | None = None,
) -> SegmentCallPreservationResult8616 | None:
    """Select one complete exact-call proof bound to this identical raw body."""
    candidates = tuple(
        proof for proof in proofs
        if proof.caller.artifact is artifact and proof.callsite_addr == instruction.addr
    )
    if len(candidates) != 1 or artifact is None:
        return None
    if instruction.op != "CALL" or not any(candidate is block for candidate in artifact.blocks):
        return None
    proof = candidates[0]
    return proof if proof.complete_for(invocation_scope) else None


class _LoaderMemorySurface8616(Protocol):
    """Third-party loader memory API used for exact mapped bytes."""

    def load(self, address: int, size: int) -> bytes:
        """Read a mapped byte range or raise for an unmapped address."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader boundary for exact loaded-image bytes."""

    memory: _LoaderMemorySurface8616


class _ProjectLoaderBoundary8616(Protocol):
    """Minimal third-party project view for whole-image byte identity."""

    loader: _LoaderSurface8616


def _current_image_digest_matches_8616(
    project: object,
    admission: DeclaredCallAdmission8616,
) -> bool:
    """Re-hash the entire currently loaded image against the admission.

    The retained ``image_base``/``image_size`` window covers caller and
    synthetic-stub bytes alike, so a stale or mutated source byte anywhere
    in the image invalidates consumption. An unmapped or malformed loader
    surface refuses rather than guessing.
    """
    boundary = cast(_ProjectLoaderBoundary8616, project)
    try:
        loaded = bytes(
            boundary.loader.memory.load(
                cast(int, admission.image_base), cast(int, admission.image_size)
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return hashlib.sha256(loaded).hexdigest() == admission.image_sha256


def _declared_call_target_bound_8616(
    project: object,
    block: IRBlock,
    instruction: IRInstr,
    admission: DeclaredCallAdmission8616,
) -> bool:
    """Bind the consumed CALL's exact target and distance via native proof.

    Near calls rerun the shared declared-stub binding owner against the
    current project, proving the symbolic operand DAG, origin provenance,
    native re-lift, current E8 bytes, and registered stub target anew. Far
    declarations cannot be consumed until a shared exact native/provenance
    theorem authenticates their operands and frame distance.
    """
    if admission.is_far:
        # A constant-valued operand alone does not bind this IR to native bytes.
        return False
    from ..semantics.direct_near_call_target_binding import (
        DirectNearCallCoordinates8616,
        prove_declared_direct_near_call_target_binding_at_coordinates_8616,
    )

    # Admitted near callsites are unprefixed E8: exactly three bytes, so the
    # continuation is callsite + 3. The binding owner re-verifies the current
    # bytes; no decoding result is trusted here.
    binding = prove_declared_direct_near_call_target_binding_at_coordinates_8616(
        project,
        block=block,
        instruction=instruction,
        coordinates=DirectNearCallCoordinates8616(
            callsite_addr=admission.callsite_addr,
            next_addr=admission.callsite_addr + 3,
            target_addr=admission.target_addr,
        ),
    )
    return bool(
        binding.complete
        and binding.callsite_addr == admission.callsite_addr
        and binding.target_addr == admission.target_addr
    )


def _declared_call_consumption_bound_8616(
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
    admission: DeclaredCallAdmission8616,
) -> bool:
    """Re-authenticate one admitted declaration against current authority.

    Consumption requires: the admission's retained project with image window,
    the closed current declaration registry containing this identical object,
    the caller's identical registered raw IR or authenticated semantic projection,
    the current whole-image digest, current synthetic-stub membership, the
    exact ``("ds",)`` relation, and the target/distance bound by the shared
    exact native evidence. A receipt's presence is never proof.
    """
    project = admission.project
    if (
        project is None
        or type(admission.image_base) is not int
        or type(admission.image_size) is not int
        or admission.image_size < 0
        or admission.retained_registers != ("ds",)
    ):
        return False
    from ..declared_external_call_evidence import declared_external_call_registry_8616
    from ..synthetic_call_stub_evidence import is_synthetic_call_stub_8616
    from .function_ir_registry import (
        FunctionIRArtifactVerdict8616,
        registered_function_ir_artifact_8616,
    )

    registry = declared_external_call_registry_8616(project)
    if (
        registry is None
        or not registry.closes_evidence
        or registry.image_sha256 != admission.image_sha256
        or not any(item is admission for item in registry.admissions)
    ):
        return False
    resolution = registered_function_ir_artifact_8616(project, admission.caller_addr)
    if resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN:
        return False
    if resolution.artifact is not artifact:
        from ..semantics.call_projection_blocks import projected_call_source_8616
        from ..semantics.call_target_evidence_8616 import resolve_call_ir_projection_8616

        projection = resolve_call_ir_projection_8616(project, artifact)
        if not projection.complete or projection.projection is None:
            return False
        source = projected_call_source_8616(projection.projection, block, instruction)
        if source is None:
            return False
        block, instruction = source
    if not _current_image_digest_matches_8616(project, admission):
        return False
    if not is_synthetic_call_stub_8616(project, admission.target_addr):
        return False
    return _declared_call_target_bound_8616(project, block, instruction, admission)


def declared_call_effect_at_instruction_8616(
    artifact: IRFunctionArtifact | None,
    block: IRBlock,
    instruction: IRInstr,
    admissions: tuple[DeclaredCallAdmission8616, ...],
) -> DeclaredCallAdmission8616 | None:
    """Select the unique admitted declaration bound to this exact CALL.

    A declaration authorizes only its enumerated segment relation and only at
    the bound caller/callsite coordinate on the identical analyzed artifact;
    it is never a universal callee summary and cannot displace a real proof.
    The identical instruction must be an object member of ``block.instrs``,
    ``block`` an object member of ``artifact.blocks``, and the admission must
    still authenticate against the current project registry, registered
    artifact, whole-image digest, stub membership, and native call binding.
    """
    from ..declared_external_call_evidence import DeclaredCallAdmission8616

    if artifact is None or instruction.op != "CALL" or type(instruction.addr) is not int:
        return None
    if not any(item is instruction for item in block.instrs):
        return None
    if not any(candidate is block for candidate in artifact.blocks):
        return None
    candidates = tuple(
        admission for admission in admissions
        if type(admission) is DeclaredCallAdmission8616
        and admission.binds_callsite(artifact.function_addr, instruction.addr)
    )
    if len(candidates) != 1:
        return None
    admission = candidates[0]
    if not _declared_call_consumption_bound_8616(artifact, block, instruction, admission):
        return None
    return admission


def architectural_live_in_state(register: str) -> SegmentRegisterState:
    """Return a proven physical identity with an unknown runtime value."""
    return SegmentRegisterState(
        register,
        SegmentValueKind8616.ARCHITECTURAL_LIVE_IN,
        register,
        SegmentOrigin.PROVEN,
    )


def join_register_states(states: tuple[SegmentRegisterState, ...], register: str) -> SegmentRegisterState:
    """Join predecessor states as a must lattice."""
    if not states or any(state.origin is not SegmentOrigin.PROVEN or state.source is None for state in states):
        return unknown_segment_state(register)
    first = states[0]
    if all(state.source == first.source for state in states[1:]):
        if all(state.value_kind == first.value_kind for state in states[1:]):
            return first
        return SegmentRegisterState(register, SegmentValueKind8616.MERGED_PROVEN, first.source, SegmentOrigin.PROVEN)
    return SegmentRegisterState(register, SegmentValueKind8616.MERGED, None, SegmentOrigin.UNKNOWN)


def _visible_segment_states(state: dict[str, SegmentRegisterState]) -> dict[str, SegmentRegisterState]:
    """Keep general-register aliases internal to one block transfer."""
    return {register: state[register] for register in SEGMENT_REGISTERS if register in state}


def _restore_source_map(
    block_addr: int,
    restore_sources: tuple[SegmentRestoreSource, ...],
) -> dict[tuple[int, str], SegmentRestoreSource]:
    """Index proven restore relations for one block."""
    return {
        (source.restore_instruction_addr, source.restore_register): source
        for source in restore_sources
        if source.block_addr == block_addr
    }


def _restored_register_state(
    dst_name: str,
    instruction_addr: int | None,
    instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]],
    restore_map: dict[tuple[int, str], SegmentRestoreSource],
    saved_instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]],
) -> SegmentRegisterState | None:
    """Resolve an Alias-proved restoration to the saved pre-instruction state."""
    if instruction_addr is None:
        return None
    source = restore_map.get((instruction_addr, dst_name))
    if source is None:
        return None
    saved = instruction_entries.get(source.saved_instruction_addr, {}).get(source.saved_register)
    if saved is None:
        saved = saved_instruction_entries.get(source.saved_instruction_addr, {}).get(source.saved_register)
    if saved is None or saved.origin is not SegmentOrigin.PROVEN or saved.source is None:
        return unknown_segment_state(dst_name)
    return SegmentRegisterState(dst_name, SegmentValueKind8616.STACK_RESTORE, saved.source, SegmentOrigin.PROVEN)


def _written_register_state(
    dst_name: str,
    src: IRValue,
    state: dict[str, SegmentRegisterState],
    restored: SegmentRegisterState | None,
) -> SegmentRegisterState | None:
    """Propagate typed segment identities through proven register writes."""
    if restored is not None:
        return restored
    if src.space is MemSpace.CONST and src.const is not None:
        return SegmentRegisterState(
            dst_name,
            SegmentValueKind8616.CONST_WRITE,
            hex(int(src.const)),
            SegmentOrigin.PROVEN,
        )
    if src.space is MemSpace.REG and src.name is not None:
        inherited = state.get(src.name)
        if inherited is not None and inherited.origin is SegmentOrigin.PROVEN and inherited.source is not None:
            value_kind = (
                SegmentValueKind8616.SEGMENT_COPY
                if dst_name in SEGMENT_REGISTERS
                else SegmentValueKind8616.REGISTER_COPY
            )
            return SegmentRegisterState(dst_name, value_kind, inherited.source, SegmentOrigin.PROVEN)
    if dst_name in SEGMENT_REGISTERS:
        return SegmentRegisterState(dst_name, SegmentValueKind8616.UNKNOWN_WRITE, None, SegmentOrigin.UNKNOWN)
    return None


def transfer_block_with_instruction_states(
    block: IRBlock,
    entry_state: dict[str, SegmentRegisterState],
    restore_sources: tuple[SegmentRestoreSource, ...] = (),
    saved_instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] | None = None,
    *,
    call_preservations: tuple[SegmentCallPreservationResult8616, ...] = (),
    source_artifact: IRFunctionArtifact | None = None,
    invocation_scope: Real16InvocationDomain8616 | None = None,
    declared_call_effects: tuple[DeclaredCallAdmission8616, ...] = (),
) -> tuple[
    dict[str, SegmentRegisterState],
    dict[InstructionStateKey, dict[str, SegmentRegisterState]],
    dict[InstructionStateKey, dict[str, SegmentRegisterState]],
]:
    """Transfer one block and retain exact before/after instruction states.

    A typed CALL without complete bound evidence is an unmodeled boundary: the state
    recorded at the CALL's instruction entry keeps the proven pre-call
    identities (still valid for the call's own argument reads), while the
    recorded exit and all later states drop every segment and general-register
    proxy identity lacking an explicit preservation proof.

    ``declared_call_effects`` carries only already-admitted frontend
    declarations bound to the identical analyzed artifact, caller, callsite,
    synthetic-stub target, and call distance. A bound admission retains its
    enumerated segment registers across that one CALL boundary; it never
    substitutes for a real callee proof and grants nothing else.
    """
    state = dict(entry_state)
    instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    instruction_exits: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    restore_map = _restore_source_map(block.addr, restore_sources)
    saved_entries = saved_instruction_entries or {}
    for instruction_index, instr in enumerate(tuple(block.instrs or ())):
        # Output markers retain the originating callsite as provenance only;
        # their snapshots must not replace that native CALL's entry or exit.
        instruction_key = (
            instr.addr
            if isinstance(instr, IRInstr) and isinstance(instr.addr, int) and instr.op != "CALL_OUTPUT"
            else (block.addr, instruction_index)
        )
        instruction_entries.setdefault(instruction_key, _visible_segment_states(state))
        if not isinstance(instr, IRInstr):
            instruction_exits[instruction_key] = _visible_segment_states(state)
            continue
        if instr.op == "CALL":
            # Both reads consume the same validation snapshot. Close the scope
            # before state updates so later CALLs recheck retained evidence.
            from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

            with segment_call_dependency_traversal_scope_8616():
                proof = call_preservation_at_instruction_8616(source_artifact, block, instr, call_preservations, invocation_scope)
                preserved = frozenset() if proof is None else frozenset(proof.preserved_registers_for(invocation_scope))
            declared = declared_call_effect_at_instruction_8616(
                source_artifact, block, instr, declared_call_effects
            )
            if declared is not None:
                preserved |= frozenset(declared.retained_registers)
            _drop_unproved_call_boundary_identities(state, preserved)
            # CALL args describe the target, not an assigned output value.
            instruction_exits[instruction_key] = _visible_segment_states(state)
            continue
        dst = instr.dst
        if not isinstance(dst, IRValue) or dst.space is not MemSpace.REG or dst.name is None:
            instruction_exits[instruction_key] = _visible_segment_states(state)
            continue
        # CALL_OUTPUT carries a target marker, not the value returned in dst.
        # It must kill prior register provenance, including GP proxies of DS.
        src = instr.args[0] if instr.args and instr.op != "CALL_OUTPUT" else None
        if not isinstance(src, IRValue):
            if dst.name in SEGMENT_REGISTERS:
                state[dst.name] = unknown_segment_state(dst.name)
            else:
                state.pop(dst.name, None)
            instruction_exits[instruction_key] = _visible_segment_states(state)
            continue
        restored = _restored_register_state(
            dst.name,
            instr.addr,
            instruction_entries,
            restore_map,
            saved_entries,
        )
        written_state = _written_register_state(dst.name, src, state, restored)
        if written_state is None:
            state.pop(dst.name, None)
        else:
            state[dst.name] = written_state
        instruction_exits[instruction_key] = _visible_segment_states(state)
    return _visible_segment_states(state), instruction_entries, instruction_exits
