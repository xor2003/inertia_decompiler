"""Solve typed segment-register state across a function CFG.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and
lossless normalization. Iteratively consumes Alias-proved restore relations
without owning stack identity. Do not perform alias-state ownership, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .direct_call_segment_context import SegmentEntryContext8616
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import (
        ScopedFunctionCFGProjection8616,
        ScopedFunctionIRView8616,
    )
    from .segment_call_preservation import SegmentCallPreservationResult8616

from .core import IRFunctionArtifact
from .segment_state_transfer import (
    SEGMENT_REGISTERS,
    InstructionStateKey,
    SegmentRegisterState,
    SegmentRestoreSource,
    SegmentValueKind8616,
    architectural_live_in_state,
    join_register_states,
    transfer_block_with_instruction_states,
    unknown_segment_state,
)
from .ssa_function import SSAFunctionArtifact, build_x86_16_ir_predecessor_map

__all__ = ["SegmentStateSolution8616", "solve_segment_state_8616"]


@dataclass(frozen=True, slots=True)
class SegmentStateSolution8616:
    """Raw block and instruction state maps from the IR fixed point.

    ``scoped_projection`` retains the single authenticated CFG projection
    the solve consumed when a scoped view supplied the predecessor
    relation; ``None`` marks the universal route. It is this operation's
    bounded evidence, never a cache: another consumer must revalidate the
    view itself.
    """

    entry_states: dict[int, dict[str, SegmentRegisterState]]
    exit_states: dict[int, dict[str, SegmentRegisterState]]
    instruction_entry_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]]
    instruction_exit_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]]
    scoped_projection: ScopedFunctionCFGProjection8616 | None = field(
        default=None, repr=False, compare=False
    )


def _predecessor_register_states(
    predecessors: tuple[int, ...],
    exit_states: dict[int, dict[str, SegmentRegisterState]],
    register: str,
) -> tuple[SegmentRegisterState, ...]:
    """Return initialized predecessor facts, treating absent maps as dataflow bottom."""
    return tuple(
        state
        for predecessor in predecessors
        if (state := exit_states.get(predecessor, {}).get(register)) is not None
    )


def _join_entry_state(
    predecessor_map: dict[int, tuple[int, ...]],
    exit_states: dict[int, dict[str, SegmentRegisterState]],
    block_addr: int,
    function_addr: int,
    entry_context: SegmentEntryContext8616 | None,
) -> dict[str, SegmentRegisterState]:
    """Join predecessor segment identities as must-state."""
    predecessors = predecessor_map.get(block_addr, ())
    if not predecessors and block_addr != function_addr:
        return {register: unknown_segment_state(register) for register in SEGMENT_REGISTERS}
    result: dict[str, SegmentRegisterState] = {}
    for register in SEGMENT_REGISTERS:
        states = (
            ((_contextual_live_in_8616(register, entry_context),) if block_addr == function_addr else ())
            + _predecessor_register_states(predecessors, exit_states, register)
        )
        if states:
            result[register] = join_register_states(states, register)
    return result


def _contextual_live_in_8616(
    register: str, entry_context: SegmentEntryContext8616 | None,
) -> SegmentRegisterState:
    """Name a proved equality relative to this callee's SS live-in value."""
    state = architectural_live_in_state("ss" if entry_context is not None and register == "ds" else register)
    kind = SegmentValueKind8616.CALL_ENTRY_RELATION if entry_context is not None and register == "ds" else state.value_kind
    return SegmentRegisterState(register, kind, state.source, state.origin)


def _scoped_predecessor_map_8616(
    artifact: IRFunctionArtifact,
    scoped_view: ScopedFunctionIRView8616,
    invocation_scope: Real16InvocationDomain8616 | None,
) -> tuple[dict[int, tuple[int, ...]], ScopedFunctionCFGProjection8616]:
    """Authenticate the scoped view once and return its effective CFG.

    The consuming entry is independently supplied — never read back from
    the view's retained scope — and the whole retained chain is validated
    through one ``cfg_projection_for`` replay per solve. The projection
    census is then reconciled against the raw block census: a missing or
    foreign block, a foreign recorded in-edge, or a pending block that
    still publishes an outgoing-edge claim is a caller-contract error,
    not a tolerated repair. A pending block contributes only its recorded
    census in-edges; its withheld successor claim is never turned into an
    exit. Blocks the effective CFG cannot reach carry an empty
    predecessor tuple and join to honest unknowns exactly like the
    universal route.
    """
    from .real16_invocation_domain import (
        Real16InvocationDomain8616,
        same_real16_entry_scope_8616,
    )

    if type(invocation_scope) is not Real16InvocationDomain8616:
        raise ValueError(
            "scoped segment state requires an independently supplied "
            "typed consuming entry"
        )
    if scoped_view.source_artifact is not artifact:
        raise ValueError(
            "scoped view is not bound to the identical raw IR artifact"
        )
    retained_scope = scoped_view.invocation_scope
    if retained_scope is None or not same_real16_entry_scope_8616(
        invocation_scope, retained_scope
    ):
        raise ValueError(
            "supplied entry does not authenticate the retained scoped view"
        )
    projection = scoped_view.cfg_projection_for(invocation_scope)
    if (
        projection is None
        or projection.source_artifact is not artifact
        or projection.scope is not invocation_scope
        or projection.function_addr != artifact.function_addr
    ):
        raise ValueError(
            "scoped view refused its CFG projection under the supplied entry"
        )
    census = {block.addr for block in artifact.blocks}
    if (
        set(projection.predecessors) != census
        or set(projection.pending) != census
    ):
        raise ValueError(
            "scoped projection census diverges from the raw IR census"
        )
    for block_addr in census:
        if projection.pending[block_addr] and (
            projection.successors_for(block_addr) is not None
        ):
            raise ValueError(
                "a pending block must not publish an outgoing-edge claim"
            )
    predecessor_map: dict[int, tuple[int, ...]] = {}
    for block_addr in sorted(census):
        predecessors = projection.predecessors[block_addr]
        if any(predecessor not in census for predecessor in predecessors):
            raise ValueError(
                "scoped projection records a foreign predecessor edge"
            )
        predecessor_map[block_addr] = tuple(predecessors)
    return predecessor_map, projection


def _require_supplied_predecessor_map_8616(
    function_ssa: SSAFunctionArtifact,
    census: set[int],
    predecessor_map: dict[int, tuple[int, ...]],
) -> None:
    """Reject a supplied SSA map that conflicts with the effective CFG.

    A supplied ``function_ssa`` is cross-checked, never silently preferred:
    its predecessor map is completed over the authenticated census —
    omitted entries read as empty — and must equal the effective
    predecessor relation exactly. A foreign block address, a foreign
    recorded predecessor, or any edge disagreement refuses the solve;
    the scoped route never falls back to either graph alone.
    """
    supplied = function_ssa.predecessor_map
    for block_addr, predecessors in supplied.items():
        if block_addr not in census or any(
            predecessor not in census for predecessor in predecessors
        ):
            raise ValueError(
                "supplied SSA predecessor map names a foreign CFG address"
            )
    completed = {
        block_addr: tuple(sorted(supplied.get(block_addr, ())))
        for block_addr in census
    }
    if completed != predecessor_map:
        raise ValueError(
            "supplied SSA predecessor map conflicts with the "
            "authenticated scoped CFG"
        )


def _solve_once(
    artifact: IRFunctionArtifact,
    predecessor_map: dict[int, tuple[int, ...]],
    restore_sources: tuple[SegmentRestoreSource, ...],
    saved_instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]],
    call_preservations: tuple[SegmentCallPreservationResult8616, ...],
    entry_context: SegmentEntryContext8616 | None,
    invocation_scope: Real16InvocationDomain8616 | None,
) -> SegmentStateSolution8616:
    """Solve one CFG fixed point using the prior restore-source state surface."""
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    entry_states: dict[int, dict[str, SegmentRegisterState]] = {addr: {} for addr in blocks_by_addr}
    exit_states: dict[int, dict[str, SegmentRegisterState]] = {addr: {} for addr in blocks_by_addr}
    changed = True
    while changed:
        changed = False
        for block_addr in sorted(blocks_by_addr):
            new_entry = _join_entry_state(
                predecessor_map,
                exit_states,
                block_addr,
                artifact.function_addr,
                entry_context,
            )
            new_exit = transfer_block_with_instruction_states(
                blocks_by_addr[block_addr],
                new_entry,
                restore_sources,
                saved_instruction_entries,
                call_preservations=call_preservations,
                source_artifact=artifact, invocation_scope=invocation_scope,
            )[0]
            if new_entry != entry_states[block_addr]:
                entry_states[block_addr] = new_entry
                changed = True
            if new_exit != exit_states[block_addr]:
                exit_states[block_addr] = new_exit
                changed = True

    instruction_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    instruction_exits: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    for block_addr, block in sorted(blocks_by_addr.items()):
        _, block_entries, block_exits = transfer_block_with_instruction_states(
            block,
            entry_states[block_addr],
            restore_sources,
            saved_instruction_entries,
            call_preservations=call_preservations,
            source_artifact=artifact, invocation_scope=invocation_scope,
        )
        instruction_entries.update(block_entries)
        instruction_exits.update(block_exits)
    return SegmentStateSolution8616(
        entry_states,
        exit_states,
        instruction_entries,
        instruction_exits,
    )


def solve_segment_state_8616(
    artifact: IRFunctionArtifact,
    function_ssa: SSAFunctionArtifact | None,
    restore_sources: tuple[SegmentRestoreSource, ...],
    call_preservations: tuple[SegmentCallPreservationResult8616, ...] = (),
    *,
    entry_context: SegmentEntryContext8616 | None = None,
    invocation_scope: Real16InvocationDomain8616 | None = None,
    scoped_view: ScopedFunctionIRView8616 | None = None,
) -> SegmentStateSolution8616:
    """Solve local restore chains with an optional exact-callsite entry relation.

    Invalid supplied contexts are caller contract errors, never permission to
    substitute a guessed relation. The default remains universal architectural
    live-ins; no contextual fact is published to project state.

    A supplied ``scoped_view`` switches only the predecessor relation to the
    view's authenticated effective CFG: the view must be bound to this
    identical raw artifact, the consuming entry must be supplied
    independently (never read back from the view) and must authenticate
    the retained view, and the universal registry route
    (``coverage.artifact is artifact``) is not required for the
    already-authenticated in-flight chain. A supplied ``function_ssa``
    must carry a predecessor map identical to the effective CFG —
    conflicting or vacuous supplied maps refuse rather than silently
    preferring one graph. Effect transfer and call-proof binding still
    run over the original source blocks and instruction objects; the
    conditional view is retained as scoped evidence, never published as
    universal function state.
    """
    if entry_context is not None and (
        not entry_context.complete or entry_context.callee.artifact is not artifact
    ):
        raise ValueError("segment entry context is not bound to this callee IR")
    scoped_projection: ScopedFunctionCFGProjection8616 | None = None
    if scoped_view is None:
        if invocation_scope is not None:
            from .real16_invocation_domain import same_real16_entry_scope_8616

            if (
                not same_real16_entry_scope_8616(invocation_scope, invocation_scope)
                or invocation_scope.coverage is None
                or invocation_scope.coverage.artifact is not artifact
            ):
                raise ValueError("invocation scope is not bound to this registered IR")
        predecessor_map = (
            dict(function_ssa.predecessor_map)
            if function_ssa is not None and function_ssa.predecessor_map
            else build_x86_16_ir_predecessor_map(artifact)
        )
    else:
        from .scoped_function_ir_view import ScopedFunctionIRView8616

        if type(scoped_view) is not ScopedFunctionIRView8616:
            raise TypeError(
                "scoped segment state requires a typed "
                "ScopedFunctionIRView8616"
            )
        predecessor_map, scoped_projection = _scoped_predecessor_map_8616(
            artifact, scoped_view, invocation_scope
        )
        if function_ssa is not None:
            _require_supplied_predecessor_map_8616(
                function_ssa, set(predecessor_map), predecessor_map
            )
    saved_entries: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = {}
    solution = _solve_once(artifact, predecessor_map, restore_sources, saved_entries, call_preservations, entry_context, invocation_scope)
    for _ in range(len(restore_sources) + 2):
        if solution.instruction_entry_states == saved_entries:
            break
        saved_entries = solution.instruction_entry_states
        solution = _solve_once(artifact, predecessor_map, restore_sources, saved_entries, call_preservations, entry_context, invocation_scope)
    if scoped_projection is not None:
        solution = replace(solution, scoped_projection=scoped_projection)
    return solution
