"""Prove DS and SS hold the same runtime segment value at one direct CALL.

Layer: IR.
Responsibility: evaluate one typed candidate proving that an Alias-proved local
PUSH SS / POP DS stack copy leaves DS and SS equal at one exact direct near
CALL. Consumes typed IR blocks, an exact closed caller boundary, an exact
callee boundary, the decoded direct-callsite index, and IR-owned Alias
SegmentRestoreSource relations. A proof additionally requires the supplied
artifact to be the project's own registered raw IR object and the Alias
source to name that identical object as its owner, so foreign or unbound
evidence cannot borrow the local window checks. The proof is nonpublishing:
it never mutates project state, prototypes, or emitted C, and never uses
source, COD, symbol names, rendered assembly, or rendered C as evidence.
Insufficient evidence produces a reason-coded UNKNOWN_REFUSE, never a
guessed equality.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.saved_stack_store_window import unproved_cross_selector_store_on_restore_path_8616
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from .direct_call_segment_entry_binding import (
    DirectCallSegmentEntryBindingFailure8616,
    segment_entry_lineage_refusal_8616,
)
from .ir_boundary_cfg import closed_ir_boundary_cfg_8616
from .real16_invocation_domain import Real16InvocationDomain8616
from .segment_state_transfer import SegmentRestoreSource

__all__ = [
    "DirectCallSegmentEntryCandidate8616",
    "DirectCallSegmentEntryProof8616",
    "DirectCallSegmentEntryRefusal8616",
    "DirectCallSegmentEntryStats8616",
    "DirectCallSegmentEntryVerdict8616",
    "prove_x86_16_direct_call_segment_entry_8616",
]

_SAVED_SEGMENT_REGISTER = "ss"
_RESTORED_SEGMENT_REGISTER = "ds"


class DirectCallSegmentEntryVerdict8616(StrEnum):
    """Whether DS == SS is proven at the candidate call boundary."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class DirectCallSegmentEntryRefusal8616(StrEnum):
    """Typed reason a call-site segment-equality candidate was refused."""

    CALLER_IDENTITY_CONFLICT = "caller_identity_conflict"
    CALLEE_IDENTITY_CONFLICT = "callee_identity_conflict"
    PROJECT_MISMATCH = "project_mismatch"
    IR_REFUSAL_PRESENT = "ir_refusal_present"
    CFG_NOT_CLOSED = "cfg_not_closed"
    CALLSITE_UNREACHABLE = "callsite_unreachable"
    CALL_MISSING = "call_missing"
    CALL_AMBIGUOUS = "call_ambiguous"
    CALL_NOT_DIRECT_NEAR = "call_not_direct_near"
    TARGET_INDEX_MISSING = "target_index_missing"
    TARGET_INDEX_INCOMPLETE = "target_index_incomplete"
    TARGET_INDEX_AMBIGUOUS = "target_index_ambiguous"
    TARGET_MISMATCH = "target_mismatch"
    ALIAS_SOURCE_MISSING = "alias_source_missing"
    ALIAS_SOURCE_AMBIGUOUS = "alias_source_ambiguous"
    ALIAS_RESTORE_WRITE_MISSING = "alias_restore_write_missing"
    STACK_SAVE_ALIAS_UNPROVEN = "stack_save_alias_unproven"
    SAVE_RESTORE_OUTSIDE_BLOCK = "save_restore_outside_block"
    AMBIGUOUS_BLOCK_PATH = "ambiguous_block_path"
    INSTRUCTION_ADDR_UNKNOWN = "instruction_addr_unknown"
    ORDERING_VIOLATION = "ordering_violation"
    INTERVENING_CALL = "intervening_call"
    SS_WRITE_AFTER_SAVE = "ss_write_after_save"
    DS_WRITE_AFTER_RESTORE = "ds_write_after_restore"
    IR_NOT_REGISTERED = "ir_not_registered"
    IR_REGISTRY_REFUSED = "ir_registry_refused"
    IR_NOT_PROJECT_OWNED = "ir_not_project_owned"
    ALIAS_SOURCE_UNBOUND = "alias_source_unbound"
    ALIAS_SOURCE_FOREIGN = "alias_source_foreign"


_BINDING_FAILURE_REFUSAL_8616: dict[
    DirectCallSegmentEntryBindingFailure8616, DirectCallSegmentEntryRefusal8616
] = {
    DirectCallSegmentEntryBindingFailure8616.IR_NOT_REGISTERED:
        DirectCallSegmentEntryRefusal8616.IR_NOT_REGISTERED,
    DirectCallSegmentEntryBindingFailure8616.IR_REGISTRY_REFUSED:
        DirectCallSegmentEntryRefusal8616.IR_REGISTRY_REFUSED,
    DirectCallSegmentEntryBindingFailure8616.IR_NOT_PROJECT_OWNED:
        DirectCallSegmentEntryRefusal8616.IR_NOT_PROJECT_OWNED,
    DirectCallSegmentEntryBindingFailure8616.ALIAS_SOURCE_UNBOUND:
        DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_UNBOUND,
    DirectCallSegmentEntryBindingFailure8616.ALIAS_SOURCE_FOREIGN:
        DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_FOREIGN,
}


@dataclass(frozen=True, slots=True)
class DirectCallSegmentEntryCandidate8616:
    """One proposed DS==SS equality site at an exact direct CALL."""

    caller_start: int
    callsite_addr: int
    callee_addr: int

    def __post_init__(self) -> None:
        """Reject malformed identities instead of weakening them downstream."""
        if type(self.caller_start) is not int or self.caller_start < 0:
            raise ValueError(f"invalid caller_start: {self.caller_start!r}")
        if type(self.callsite_addr) is not int or self.callsite_addr < 0:
            raise ValueError(f"invalid callsite_addr: {self.callsite_addr!r}")
        if type(self.callee_addr) is not int or self.callee_addr < 0:
            raise ValueError(f"invalid callee_addr: {self.callee_addr!r}")


@dataclass(frozen=True, slots=True)
class DirectCallSegmentEntryStats8616:
    """Closed five-stage accounting for one evaluated candidate."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether the candidate fully resolved to proof or refusal."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count == 1
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class DirectCallSegmentEntryProof8616:
    """Verdict and exact evidence identities for one evaluated candidate.

    A PROVEN verdict asserts only that the DS and SS registers carry the same
    runtime segment value at ``callsite_addr``; the numeric segment value may
    remain unknown. Nothing here publishes call effects, prototypes, or segment
    values into project state.
    """

    candidate: DirectCallSegmentEntryCandidate8616
    verdict: DirectCallSegmentEntryVerdict8616
    refusal: DirectCallSegmentEntryRefusal8616 | None
    stats: DirectCallSegmentEntryStats8616
    block_addr: int | None = None
    saved_instruction_addr: int | None = None
    saved_register: str | None = None
    restore_instruction_addr: int | None = None
    restore_register: str | None = None
    invocation: Real16InvocationDomain8616 | None = None

    @property
    def complete(self) -> bool:
        """Require closed, ordered evidence before a caller consumes this proof.

        This checks the retained value contract; a consumer must additionally
        bind it to the exact project-owned IR and caller/callee boundaries.
        """
        block_addr = self.block_addr
        saved_addr = self.saved_instruction_addr
        restore_addr = self.restore_instruction_addr
        if block_addr is None or saved_addr is None or restore_addr is None:
            return False
        return bool(
            self.verdict is DirectCallSegmentEntryVerdict8616.PROVEN
            and self.refusal is None
            and self.stats == DirectCallSegmentEntryStats8616(1, 1, 1, 1, 0)
            and self.stats.closed
            and self.saved_register == _SAVED_SEGMENT_REGISTER
            and self.restore_register == _RESTORED_SEGMENT_REGISTER
            and all(
                type(site) is int
                for site in (block_addr, saved_addr, restore_addr)
            )
            and block_addr <= saved_addr < restore_addr < self.candidate.callsite_addr
            and (self.invocation is None or self.invocation.complete)
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize this proof for diagnostics and worker handoff."""
        return {
            "caller_start": self.candidate.caller_start,
            "callsite_addr": self.candidate.callsite_addr,
            "callee_addr": self.candidate.callee_addr,
            "verdict": self.verdict.value,
            "refusal": None if self.refusal is None else self.refusal.value,
            "block_addr": self.block_addr,
            "saved_instruction_addr": self.saved_instruction_addr,
            "saved_register": self.saved_register,
            "restore_instruction_addr": self.restore_instruction_addr,
            "restore_register": self.restore_register,
            "invocation": (
                None if self.invocation is None else self.invocation.to_dict()
            ),
            "complete": self.complete,
            "stats": {
                "raw_fact_count": self.stats.raw_fact_count,
                "normalized_fact_count": self.stats.normalized_fact_count,
                "classified_fact_count": self.stats.classified_fact_count,
                "materialized_count": self.stats.materialized_count,
                "failure_count": self.stats.failure_count,
                "closed": self.stats.closed,
            },
        }


def _refuse_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    refusal: DirectCallSegmentEntryRefusal8616,
    *,
    block_addr: int | None = None,
    source: SegmentRestoreSource | None = None,
) -> DirectCallSegmentEntryProof8616:
    """Retain one refused candidate in the five-stage evidence count."""
    return DirectCallSegmentEntryProof8616(
        candidate=candidate,
        verdict=DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE,
        refusal=refusal,
        stats=DirectCallSegmentEntryStats8616(1, 1, 0, 0, 1),
        block_addr=block_addr,
        saved_instruction_addr=None if source is None else source.saved_instruction_addr,
        saved_register=None if source is None else source.saved_register,
        restore_instruction_addr=None if source is None else source.restore_instruction_addr,
        restore_register=None if source is None else source.restore_register,
    )


def _identity_refusal_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    caller_boundary: ExactFunctionRangeBoundary8616,
    callee_boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> DirectCallSegmentEntryRefusal8616 | None:
    """Require exact caller/callee identities on one binary image."""
    if candidate.caller_start != caller_boundary.addr or artifact.function_addr != caller_boundary.addr:
        return DirectCallSegmentEntryRefusal8616.CALLER_IDENTITY_CONFLICT
    if (
        candidate.callee_addr != callee_boundary.addr
        or candidate.callee_addr not in callee_boundary.reachable_instruction_addrs
    ):
        return DirectCallSegmentEntryRefusal8616.CALLEE_IDENTITY_CONFLICT
    if caller_boundary.project is not callee_boundary.project:
        return DirectCallSegmentEntryRefusal8616.PROJECT_MISMATCH
    return None


def _closed_caller_refusal_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    caller_boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> DirectCallSegmentEntryRefusal8616 | None:
    """Require refusal-free IR and the exact closed caller CFG."""
    if artifact.refusals or any(block.refusals for block in artifact.blocks):
        return DirectCallSegmentEntryRefusal8616.IR_REFUSAL_PRESENT
    if not _closed_caller_cfg_8616(caller_boundary, artifact):
        return DirectCallSegmentEntryRefusal8616.CFG_NOT_CLOSED
    if candidate.callsite_addr not in caller_boundary.reachable_instruction_addrs:
        return DirectCallSegmentEntryRefusal8616.CALLSITE_UNREACHABLE
    return None


def _closed_caller_cfg_8616(
    caller_boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> bool:
    """Match the exact reachable CFG without restricting earlier branches.

    Equality is re-established by the save/restore pair on every entrance to
    its block. Other branches are harmless; an edge entering the local window
    is separately refused by its exact instruction ownership checks.
    """
    return closed_ir_boundary_cfg_8616(caller_boundary, artifact)


def _unique_call_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    artifact: IRFunctionArtifact,
) -> tuple[IRBlock, int] | DirectCallSegmentEntryRefusal8616:
    """Require exactly one CALL instruction at the candidate address."""
    call_sites = tuple(
        (block, instruction_index)
        for block in artifact.blocks
        for instruction_index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL" and instruction.addr == candidate.callsite_addr
    )
    if not call_sites:
        return DirectCallSegmentEntryRefusal8616.CALL_MISSING
    if len(call_sites) != 1:
        return DirectCallSegmentEntryRefusal8616.CALL_AMBIGUOUS
    return call_sites[0]


def _decoded_entry_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    caller_boundary: ExactFunctionRangeBoundary8616,
    callsite_index: DecodedDirectCallsiteIndex8616,
) -> DecodedDirectCallsite8616 | DirectCallSegmentEntryRefusal8616:
    """Require one unique decoded near callsite to the exact callee entry."""
    if not callsite_index.stats.closed or callsite_index.stats.failure_count:
        return DirectCallSegmentEntryRefusal8616.TARGET_INDEX_INCOMPLETE
    index_entries = tuple(
        entry
        for entry in callsite_index.for_target(candidate.callee_addr)
        if _index_entry_matches_caller_8616(caller_boundary, candidate.callsite_addr, entry)
    )
    if not index_entries:
        return DirectCallSegmentEntryRefusal8616.TARGET_INDEX_MISSING
    if len(index_entries) != 1:
        return DirectCallSegmentEntryRefusal8616.TARGET_INDEX_AMBIGUOUS
    entry = index_entries[0]
    if entry.is_far:
        return DirectCallSegmentEntryRefusal8616.CALL_NOT_DIRECT_NEAR
    # The near index permits low-word lookup aliases. An exact entry relation
    # must not promote a different physical code segment through that lookup.
    if entry.target_addr != candidate.callee_addr:
        return DirectCallSegmentEntryRefusal8616.TARGET_MISMATCH
    return entry


def _index_entry_matches_caller_8616(
    caller_boundary: ExactFunctionRangeBoundary8616,
    callsite_addr: int,
    entry: DecodedDirectCallsite8616,
) -> bool:
    """Require the decoded entry to name this exact caller and instruction."""
    return bool(
        entry.callsite_addr == callsite_addr
        and (
            entry.caller_start == caller_boundary.addr
            or (
                entry.entry_identity is not None
                and entry.entry_identity.decode_start == caller_boundary.addr
            )
        )
    )


def _call_target_evidence_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    call_instruction: IRInstr,
    *,
    project: object,
    call_block: IRBlock,
    decoded_entry: DecodedDirectCallsite8616,
    invocation: Real16InvocationDomain8616 | None = None,
) -> tuple[DirectCallSegmentEntryRefusal8616 | None, Real16InvocationDomain8616 | None]:
    """Bind control and retain only the invocation the target proof consumed.

    A target already valid for every fetch selector does not consume a
    narrower invocation premise. An unused or refused supplied premise
    must not turn that independent proof into an exception or an extra
    assumption at the segment-entry consumer.
    """
    target = call_instruction.args[0] if call_instruction.args else None
    if not isinstance(target, IRValue):
        return DirectCallSegmentEntryRefusal8616.CALL_NOT_DIRECT_NEAR, None
    if target.space is MemSpace.CONST:
        if type(target.const) is not int or target.const != candidate.callee_addr:
            return DirectCallSegmentEntryRefusal8616.TARGET_MISMATCH, None
        return None, None
    # Resolve the Semantics owner after package initialization, as in the
    # segment-preservation consumer. No ABI summary or control rewrite is made.
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallTargetBindingFailure8616,
        prove_direct_near_call_target_binding_from_decoded_8616,
    )

    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        project, block=call_block, instruction=call_instruction, decoded=decoded_entry,
        invocation=invocation,
    )
    if binding.failure in (
        DirectNearCallTargetBindingFailure8616.DECODED_TARGET_MISMATCH,
        DirectNearCallTargetBindingFailure8616.DISPLACEMENT_MISMATCH,
    ):
        return DirectCallSegmentEntryRefusal8616.TARGET_MISMATCH, None
    if (not binding.complete or binding.callsite_addr != candidate.callsite_addr
            or binding.target_addr != candidate.callee_addr):
        return DirectCallSegmentEntryRefusal8616.CALL_NOT_DIRECT_NEAR, None
    used_invocation = None if binding.invocation is None else binding.invocation.premise
    return None, used_invocation


def _alias_copy_source_8616(
    call_block: IRBlock,
    restore_sources: tuple[SegmentRestoreSource, ...],
) -> SegmentRestoreSource | DirectCallSegmentEntryRefusal8616:
    """Require one unique Alias-proved SS->DS stack copy in the call block."""
    matching_sources = tuple(
        source
        for source in restore_sources
        if source.block_addr == call_block.addr
        and source.saved_register == _SAVED_SEGMENT_REGISTER
        and source.restore_register == _RESTORED_SEGMENT_REGISTER
    )
    if not matching_sources:
        return DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_MISSING
    if len(matching_sources) != 1:
        return DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_AMBIGUOUS
    return matching_sources[0]


def _is_register_write_8616(instruction: IRInstr, register: str) -> bool:
    """Return whether one typed instruction writes the named register."""
    destination = instruction.dst
    return (
        isinstance(destination, IRValue)
        and destination.space is MemSpace.REG
        and destination.name == register
    )


def _instruction_positions_8616(
    artifact: IRFunctionArtifact,
    call_block: IRBlock,
) -> tuple[dict[int, int], dict[int, int]] | None:
    """Map first/last instruction-list positions per address in the call block.

    Returns None when any instruction in the artifact lacks an exact address:
    an unaddressed instruction cannot be bounded inside or outside the proof
    window.
    """
    if any(
        not isinstance(instruction.addr, int)
        for block in artifact.blocks
        for instruction in block.instrs
    ):
        return None
    first_index: dict[int, int] = {}
    last_index: dict[int, int] = {}
    for position, instruction in enumerate(call_block.instrs):
        address = instruction.addr
        if not isinstance(address, int):
            continue
        first_index.setdefault(address, position)
        last_index[address] = position
    return first_index, last_index


def _window_ordering_refusal_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    caller_boundary: ExactFunctionRangeBoundary8616,
    call_op_index: int,
    source: SegmentRestoreSource,
    positions: tuple[dict[int, int], dict[int, int]],
) -> DirectCallSegmentEntryRefusal8616 | None:
    """Require saved -> restored -> callsite as one exact in-block order."""
    first_index, last_index = positions
    saved_addr = source.saved_instruction_addr
    restored_addr = source.restore_instruction_addr
    if saved_addr not in first_index or restored_addr not in first_index:
        return DirectCallSegmentEntryRefusal8616.SAVE_RESTORE_OUTSIDE_BLOCK
    reachable = caller_boundary.reachable_instruction_addrs
    if saved_addr not in reachable or restored_addr not in reachable:
        return DirectCallSegmentEntryRefusal8616.CALLSITE_UNREACHABLE
    ordered = (
        saved_addr < restored_addr < candidate.callsite_addr
        and last_index[saved_addr] < first_index[restored_addr]
        and last_index[restored_addr] < call_op_index
        and call_op_index == last_index[candidate.callsite_addr]
    )
    if not ordered:
        return DirectCallSegmentEntryRefusal8616.ORDERING_VIOLATION
    return None


def _window_path_refusal_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    artifact: IRFunctionArtifact,
    call_block: IRBlock,
    first_index: dict[int, int],
    saved_addr: int,
) -> DirectCallSegmentEntryRefusal8616 | None:
    """Refuse any second block that could own or enter the proof window."""
    window_addrs = frozenset(
        address
        for address in first_index
        if saved_addr <= address <= candidate.callsite_addr
    )
    for block in artifact.blocks:
        if block is call_block:
            continue
        if block.addr in window_addrs or any(
            instruction.addr in window_addrs for instruction in block.instrs
        ):
            return DirectCallSegmentEntryRefusal8616.AMBIGUOUS_BLOCK_PATH
    return None


def _window_effects_refusal_8616(
    instructions: tuple[IRInstr, ...],
    first_index: dict[int, int],
    last_index: dict[int, int],
    call_op_index: int,
    source: SegmentRestoreSource,
) -> DirectCallSegmentEntryRefusal8616 | None:
    """Bind the Alias restore to its IR write and refuse all later clobbers.

    Several IR effects can share one machine-instruction address. The restore
    is its DS destination, not the last effect at that address: ignoring the
    entire instruction would hide a conflicting later write or stale Alias
    evidence whose destination no longer exists.
    """
    saved_first = first_index[source.saved_instruction_addr]
    restored_first = first_index[source.restore_instruction_addr]
    restored_last = last_index[source.restore_instruction_addr]
    if any(
        instruction.op == "CALL" for instruction in instructions[saved_first:call_op_index]
    ):
        return DirectCallSegmentEntryRefusal8616.INTERVENING_CALL
    if any(
        _is_register_write_8616(instruction, _SAVED_SEGMENT_REGISTER)
        for instruction in instructions[saved_first:call_op_index + 1]
    ):
        return DirectCallSegmentEntryRefusal8616.SS_WRITE_AFTER_SAVE
    restore_writes = tuple(
        position for position in range(restored_first, restored_last + 1)
        if _is_register_write_8616(instructions[position], _RESTORED_SEGMENT_REGISTER)
    )
    if not restore_writes:
        return DirectCallSegmentEntryRefusal8616.ALIAS_RESTORE_WRITE_MISSING
    if any(
        _is_register_write_8616(instruction, _RESTORED_SEGMENT_REGISTER)
        for instruction in instructions[restore_writes[0] + 1:call_op_index + 1]
    ):
        return DirectCallSegmentEntryRefusal8616.DS_WRITE_AFTER_RESTORE
    return None


def _prove_block_window_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    caller_boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    call_block: IRBlock,
    call_op_index: int,
    source: SegmentRestoreSource,
    invocation: Real16InvocationDomain8616 | None = None,
) -> DirectCallSegmentEntryProof8616:
    """Prove the Alias copy still holds inside the call block at the CALL."""
    positions = _instruction_positions_8616(artifact, call_block)
    if positions is None:
        return _refuse_8616(
            candidate,
            DirectCallSegmentEntryRefusal8616.INSTRUCTION_ADDR_UNKNOWN,
            block_addr=call_block.addr,
            source=source,
        )
    ordering_refusal = _window_ordering_refusal_8616(
        candidate, caller_boundary, call_op_index, source, positions
    )
    if ordering_refusal is not None:
        return _refuse_8616(
            candidate, ordering_refusal, block_addr=call_block.addr, source=source
        )
    path_refusal = _window_path_refusal_8616(
        candidate, artifact, call_block, positions[0], source.saved_instruction_addr
    )
    if path_refusal is not None:
        return _refuse_8616(
            candidate, path_refusal, block_addr=call_block.addr, source=source
        )
    effects_refusal = _window_effects_refusal_8616(
        call_block.instrs, positions[0], positions[1], call_op_index, source
    )
    if effects_refusal is not None:
        return _refuse_8616(
            candidate, effects_refusal, block_addr=call_block.addr, source=source
        )
    binding_failure = segment_entry_lineage_refusal_8616(
        caller_boundary.project, artifact, source
    )
    if binding_failure is not None:
        return _refuse_8616(
            candidate,
            _BINDING_FAILURE_REFUSAL_8616[binding_failure],
            block_addr=call_block.addr,
            source=source,
        )
    if unproved_cross_selector_store_on_restore_path_8616(
        artifact, (call_block.addr, source.saved_instruction_addr),
        (call_block.addr, source.restore_instruction_addr),
    ):
        return _refuse_8616(
            candidate, DirectCallSegmentEntryRefusal8616.STACK_SAVE_ALIAS_UNPROVEN,
            block_addr=call_block.addr, source=source,
        )
    proof = DirectCallSegmentEntryProof8616(
        candidate=candidate,
        verdict=DirectCallSegmentEntryVerdict8616.PROVEN,
        refusal=None,
        stats=DirectCallSegmentEntryStats8616(1, 1, 1, 1, 0),
        block_addr=call_block.addr,
        saved_instruction_addr=source.saved_instruction_addr,
        saved_register=source.saved_register,
        restore_instruction_addr=source.restore_instruction_addr,
        restore_register=source.restore_register,
        invocation=invocation,
    )
    if not proof.complete:
        raise RuntimeError("direct-call segment-entry proof lost owned evidence")
    return proof


def prove_x86_16_direct_call_segment_entry_8616(
    candidate: DirectCallSegmentEntryCandidate8616,
    *,
    caller_boundary: ExactFunctionRangeBoundary8616,
    callee_boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    callsite_index: DecodedDirectCallsiteIndex8616,
    restore_sources: tuple[SegmentRestoreSource, ...] = (),
    invocation: Real16InvocationDomain8616 | None = None,
) -> DirectCallSegmentEntryProof8616:
    """Prove DS == SS at one exact direct near CALL, or refuse with a reason.

    The proof is equality of two live registers, not a numeric segment value:
    Alias proved that a local PUSH SS / POP DS pair copied the SS value into
    DS, and this module proves no SS write after the save, no DS write after
    the restore, and no intervening CALL inside one exact IR block on a closed
    caller CFG. Branches outside this local interval do not weaken the proof.

    ``invocation`` is an optional source-bound ``Real16InvocationDomain8616``
    premise retained only when the target proof consumes it; it can discharge only the symbolic
    CALL-target selector-window obligation for this exact callsite and is
    revalidated whenever the retained proof is consumed.
    """
    identity_refusal = _identity_refusal_8616(
        candidate, caller_boundary, callee_boundary, artifact
    )
    if identity_refusal is not None:
        return _refuse_8616(candidate, identity_refusal)
    path_refusal = _closed_caller_refusal_8616(candidate, caller_boundary, artifact)
    if path_refusal is not None:
        return _refuse_8616(candidate, path_refusal)

    call_site = _unique_call_8616(candidate, artifact)
    if isinstance(call_site, DirectCallSegmentEntryRefusal8616):
        return _refuse_8616(candidate, call_site)
    call_block, call_op_index = call_site

    decoded_entry = _decoded_entry_8616(candidate, caller_boundary, callsite_index)
    if isinstance(decoded_entry, DirectCallSegmentEntryRefusal8616):
        return _refuse_8616(candidate, decoded_entry, block_addr=call_block.addr)
    target_refusal, used_invocation = _call_target_evidence_8616(
        candidate, call_block.instrs[call_op_index],
        project=caller_boundary.project, call_block=call_block, decoded_entry=decoded_entry,
        invocation=invocation,
    )
    if target_refusal is not None:
        return _refuse_8616(candidate, target_refusal, block_addr=call_block.addr)

    source = _alias_copy_source_8616(call_block, restore_sources)
    if isinstance(source, DirectCallSegmentEntryRefusal8616):
        return _refuse_8616(candidate, source, block_addr=call_block.addr)
    return _prove_block_window_8616(
        candidate,
        caller_boundary,
        artifact,
        call_block,
        call_op_index,
        source,
        used_invocation,
    )
