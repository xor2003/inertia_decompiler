"""Prove architectural CALL positions relative to the caller's entry SP.

Layer: Alias.
Responsibility: derive caller-before, callee-entry and caller-after positions
from the canonical must-state stack solver and authenticated CALL effects.
Frame/effect decomposition remains owned by IRCallStackCoordinates8616.
These scalar offsets do not flatten segmented memory or authorize C lowering.
Owns storage identity
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import StrEnum

from inertia.ir.call_stack_coordinates import IRCallStackCoordinates8616
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace

from .segment_stack_restore import _predecessor_map as _predecessor_map
from .segment_stack_restore import _solve_stack_states, _transfer_block
from .stack_restore_state import StackRestoreState8616, join_stack_restore_states_8616


class CallStackPositionRefusal8616(StrEnum):
    """Why one exact source CALL cannot supply a complete position proof."""

    INVALID_SOURCE = "invalid_source"
    INVALID_CALL = "invalid_call"
    UNKNOWN_POSITION = "unknown_position"
    UNPROVEN_EFFECT = "unproven_effect"
    FRAME_MISMATCH = "frame_mismatch"


@dataclass(frozen=True, slots=True)
class CallStackPosition8616:
    """Exact word-SP offsets at one machine CALL, excluding later cleanup.

    Offsets are signed arithmetic relative to the caller's entry SP; consumers
    apply word wrapping when materializing values. The callee-entry position
    includes the physical frame push exactly once. The caller-after position
    consumes the authenticated body/RET transfer, never caller ADD SP cleanup.
    """

    function_addr: int
    block_addr: int
    instruction_index: int
    callsite_addr: int
    target_addr: int
    return_addr: int
    return_frame_bytes: int
    caller_before_offset: int
    callee_entry_offset: int
    caller_after_offset: int


@dataclass(frozen=True, slots=True)
class CallStackPositionResult8616:
    """Closed one-CALL evidence outcome, including refusals without defaults."""

    proof: CallStackPosition8616 | None
    refusal: CallStackPositionRefusal8616 | None

    @property
    def raw_fact_count(self) -> int:
        """Account for the one requested CALL position proof."""
        return 1

    @property
    def normalized_fact_count(self) -> int:
        """Retain one exact source occurrence, including invalid requests."""
        return 1

    @property
    def classified_fact_count(self) -> int:
        """Count complete source proofs only."""
        return int(self.proof is not None)

    @property
    def materialized_count(self) -> int:
        """Count published Alias proofs, without claiming C materialization."""
        return self.classified_fact_count

    @property
    def failure_count(self) -> int:
        """Count explicitly refused source candidates."""
        return int(self.refusal is not None)

    def to_dict(self) -> dict[str, object]:
        """Serialize positions and the closed proof census for diagnostics."""
        return {
            "proof": asdict(self.proof) if self.proof is not None else None,
            "refusal": self.refusal.value if self.refusal is not None else None,
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass
class _CallObserver:
    """Observe canonical physical preparation without simulating a second SP."""

    target: IRInstr
    caller_before: int | None = None
    callee_entry: int | None = None

    def observe(self, instruction: IRInstr, before: int | None, entry: int | None) -> None:
        """Retain only the requested source occurrence, before CALL transfer."""
        if instruction is self.target:
            self.caller_before, self.callee_entry = before, entry


def _call_coordinates(call: IRInstr) -> IRCallStackCoordinates8616 | None:
    """Authenticate frame width and net transfer against current source/body."""
    effect = call.call_stack_effect
    coordinates = effect.stack_coordinates if effect is not None else None
    if coordinates is None or effect is None:
        return None
    if (coordinates.source is None or coordinates.return_addr is None
            or coordinates.return_frame_bytes is None):
        return None
    if (not coordinates.source.matches_call(call) or coordinates.callsite_addr != call.addr
            or type(coordinates.target_addr) is not int):
        return None
    target = call.args[0] if call.args else None
    if (isinstance(target, IRValue) and target.space is MemSpace.CONST
            and target.const != coordinates.target_addr):
        return None
    if (not coordinates.has_proven_sp_delta or coordinates.net_sp_delta is None
            or effect.net_stack_delta != coordinates.net_sp_delta):
        return None
    return coordinates


def _observed_call_positions_8616(
    artifact: IRFunctionArtifact, block: IRBlock, instruction_index: int, call: IRInstr,
) -> tuple[int, int] | None:
    """Solve the caller's stack state through one exact CALL instruction."""
    states = _solve_stack_states(artifact)
    predecessors = _predecessor_map(artifact)
    incoming = tuple(states[pred] for pred in predecessors[block.addr])
    if block.addr == artifact.function_addr:
        incoming = (StackRestoreState8616(0), *incoming)
    if not incoming:
        return None
    observer = _CallObserver(call)
    _transfer_block(
        block.addr, block.instrs[:instruction_index + 1], join_stack_restore_states_8616(incoming),
        call_observer=observer.observe,
    )
    before, entry = observer.caller_before, observer.callee_entry
    if before is None or entry is None:
        return None
    return before, entry


def _stack_probe_helper_position_8616(
    artifact: IRFunctionArtifact, block: IRBlock, instruction_index: int, call: IRInstr,
) -> CallStackPosition8616 | None:
    """Prove one CALL position against a byte-matched stack-probe helper.

    The helper template certifies that its guarded failure exits branch past
    the returning tail into the runtime's non-returning error path, so the
    only stack pointer the caller observes at the return address is
    ``+frame - request`` where ``request`` is the reaching constant AX write.
    An unidentified helper, a dynamic request, or an unbound frame keeps the
    generic refusal. Semantics imports stay function-local: the helper census
    is needed only on the refused path.
    """
    from inertia.semantics.call_stack_allocation import (
        collect_call_stack_allocation_candidates_8616,
    )
    from inertia.semantics.compiler_helpers import (
        CompilerHelperEvidenceKind8616,
        identify_x86_16_compiler_helper_at_8616,
    )

    effect = call.call_stack_effect
    coordinates = effect.stack_coordinates if effect is not None else None
    source = coordinates.source if coordinates is not None else None
    project = source.project if source is not None else None
    if coordinates is None or project is None or coordinates.callsite_addr != call.addr:
        return None
    if (type(coordinates.return_addr) is not int
            or type(coordinates.return_frame_bytes) is not int
            or type(coordinates.target_addr) is not int):
        return None
    evidence = identify_x86_16_compiler_helper_at_8616(project, coordinates.target_addr)
    expected_frame = (
        {CompilerHelperEvidenceKind8616.STACK_PROBE: 2,
         CompilerHelperEvidenceKind8616.STACK_PROBE_FAR: 4}.get(evidence.kind)
        if evidence is not None
        else None
    )
    if expected_frame is None or expected_frame != coordinates.return_frame_bytes:
        return None
    # The lifted CALL target is a TMP expression; bind the coordinate's
    # already-authenticated target into a CONST view so the semantics census
    # sees the same proven call it records for summary-fed consumers.
    bound_call = replace(
        call, args=(IRValue(MemSpace.CONST, const=coordinates.target_addr, size=4),))
    bound_artifact = replace(artifact, blocks=(replace(
        block, instrs=tuple(bound_call if entry is call else entry
                            for entry in block.instrs)),))
    candidate = collect_call_stack_allocation_candidates_8616(
        project, bound_artifact).get(call.addr)
    allocation = candidate.allocation_size if candidate is not None else None
    if type(allocation) is not int or not 0 <= allocation <= 0xFFFF:
        return None
    positions = _observed_call_positions_8616(artifact, block, instruction_index, call)
    if positions is None:
        return None
    before, entry = positions
    if (entry - before) & 0xffff != (-coordinates.return_frame_bytes) & 0xffff:
        return None
    return CallStackPosition8616(
        artifact.function_addr, block.addr, instruction_index, call.addr,
        coordinates.target_addr, coordinates.return_addr,
        coordinates.return_frame_bytes, before, entry, before - allocation,
    )


def prove_call_stack_position_8616(
    artifact: IRFunctionArtifact, block_addr: int, instruction_index: int,
) -> CallStackPositionResult8616:
    """Reproduce one CALL position from current CFG, preparation, and callee.

    Authenticated current frame/body SP effects prove the boundary transfer;
    uncertain memory, arguments and caller cleanup do not prevent this
    independent proof. Conflicting incoming paths and unmodeled SP writes refuse.
    Byte-matched stack-probe helpers carry their returning effect in the
    caller's proven allocation request instead of a body transfer.
    """
    blocks = {block.addr: block for block in artifact.blocks}
    if (artifact.refusals or len(blocks) != len(artifact.blocks)
            or artifact.function_addr not in blocks
            or any(block.refusals for block in artifact.blocks)
            or any(successor not in blocks for block in artifact.blocks for successor in block.successor_addrs)):
        return CallStackPositionResult8616(None, CallStackPositionRefusal8616.INVALID_SOURCE)
    block = blocks.get(block_addr)
    if block is None or not 0 <= instruction_index < len(block.instrs):
        return CallStackPositionResult8616(None, CallStackPositionRefusal8616.INVALID_CALL)
    call = block.instrs[instruction_index]
    if call.op != "CALL" or call.addr is None:
        return CallStackPositionResult8616(None, CallStackPositionRefusal8616.INVALID_CALL)
    coordinates = _call_coordinates(call)
    if (coordinates is None or coordinates.return_addr is None
            or coordinates.return_frame_bytes is None or coordinates.net_sp_delta is None
            or coordinates.target_addr is None):
        helper_position = _stack_probe_helper_position_8616(
            artifact, block, instruction_index, call)
        if helper_position is not None:
            return CallStackPositionResult8616(helper_position, None)
        return CallStackPositionResult8616(None, CallStackPositionRefusal8616.UNPROVEN_EFFECT)
    positions = _observed_call_positions_8616(artifact, block, instruction_index, call)
    if positions is None:
        return CallStackPositionResult8616(None, CallStackPositionRefusal8616.UNKNOWN_POSITION)
    before, entry = positions
    if (entry - before) & 0xffff != (-coordinates.return_frame_bytes) & 0xffff:
        return CallStackPositionResult8616(None, CallStackPositionRefusal8616.FRAME_MISMATCH)
    proof = CallStackPosition8616(
        artifact.function_addr, block_addr, instruction_index, call.addr, coordinates.target_addr,
        coordinates.return_addr, coordinates.return_frame_bytes,
        before, entry, before + coordinates.net_sp_delta,
    )
    return CallStackPositionResult8616(proof, None)


def call_stack_position_is_current_8616(artifact: IRFunctionArtifact, proof: CallStackPosition8616) -> bool:
    """Require fresh source/callee reproduction before consuming a saved proof."""
    return prove_call_stack_position_8616(artifact, proof.block_addr, proof.instruction_index).proof == proof
