"""Scope-bound caller CALL positions from authenticated call evidence.

Layer: Alias.
Responsibility: derive caller-before, callee-entry and caller-after word-SP
positions for one exact CALL through the canonical must-state stack solver,
with the callee's caller-visible SP effect supplied by a callsite-keyed
``ScopedCallStackContext8616`` overlay instead of universal effect fields.
The raw caller artifact is never mutated or re-sealed — the overlay lives
outside the instruction. A position projects only while the carrier's dual
scopes re-authenticate and its physical source still matches this exact
CALL; SP-only evidence never upgrades BP or stack-byte proof.
Owns storage identity. Do not perform semantics decoding, IR production,
lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.real16_invocation_domain import (
    Real16InvocationDomain8616,
    same_real16_entry_scope_8616,
)
from inertia.ir.scoped_call_stack_coordinates import (
    IRScopedCallStackCoordinates8616,
)

from .call_stack_positions import (
    CallStackPosition8616,
    _CallObserver,
    _predecessor_map,
)
from .scoped_call_stack_context import (
    ScopedCallEntryBinding8616,
    ScopedCallStackContext8616,
    _call_row_matches_carrier_8616,
)
from .segment_stack_restore import _solve_stack_states, _transfer_block
from .stack_restore_state import (
    StackRestoreState8616,
    join_stack_restore_states_8616,
)

__all__ = [
    "ScopedCallStackPositionFailure8616",
    "ScopedCallStackPositionResult8616",
    "prove_scoped_call_stack_position_8616",
    "solve_scoped_stack_states_8616",
]


class ScopedCallStackPositionFailure8616(StrEnum):
    """Why one exact source CALL cannot supply a scoped position proof."""

    SCOPE_ABSENT = "scope_absent"
    INVALID_SOURCE = "invalid_source"
    INVALID_CALL = "invalid_call"
    CONTEXT_UNBOUND = "context_unbound"
    SOURCE_MISMATCH = "source_mismatch"
    DELTA_UNPROVEN = "delta_unproven"
    UNKNOWN_POSITION = "unknown_position"
    FRAME_MISMATCH = "frame_mismatch"


@dataclass(frozen=True, slots=True)
class ScopedCallStackPositionResult8616:
    """Scope-bound position proof, or one explicit refusal.

    ``proof`` reuses the universal position record — it is a plain offset
    triple, never authority. ``complete`` stays permanently false; reading a
    position requires ``position_for(caller_scope, callee_scope)``, which
    re-runs the same scoped proof under the offered domains and requires an
    identical result.
    """

    artifact: IRFunctionArtifact | None = field(
        default=None, compare=False, repr=False,
    )
    call: IRInstr | None = field(default=None, compare=False, repr=False)
    carrier: IRScopedCallStackCoordinates8616 | None = field(
        default=None, compare=False, repr=False,
    )
    caller_scope: Real16InvocationDomain8616 | None = field(
        default=None, compare=False, repr=False,
    )
    callee_scope: Real16InvocationDomain8616 | None = field(
        default=None, compare=False, repr=False,
    )
    context: ScopedCallStackContext8616 | None = field(
        default=None, compare=False, repr=False,
    )
    block_addr: int = 0
    instruction_index: int = 0
    proof: CallStackPosition8616 | None = None
    failure: ScopedCallStackPositionFailure8616 | None = None
    detail: str = ""
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 1

    def _retained_position_is_accepted(self) -> bool:
        """Require an accepted publication, independent of current source."""
        counts = (
            self.raw_fact_count, self.normalized_fact_count,
            self.classified_fact_count, self.materialized_count,
            self.failure_count,
        )
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in counts)
        )

    @property
    def complete(self) -> bool:
        """Scoped evidence is never context-free; see ``position_for``."""
        return self.complete_for(None, None)

    def complete_for(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> bool:
        """Re-run the scoped proof under the offered domains.

        The offered scopes must share provenance with both retained domains,
        and a fresh solve under the retained context must reproduce the
        retained position exactly — source drift or foreign scopes refuse.
        """
        if not self._retained_position_is_accepted() or self.proof is None:
            return False
        if self.artifact is None or self.context is None:
            return False
        if type(offered_caller_scope) is not Real16InvocationDomain8616:
            return False
        if type(offered_callee_scope) is not Real16InvocationDomain8616:
            return False
        if not (
            same_real16_entry_scope_8616(offered_caller_scope, self.caller_scope)
            and same_real16_entry_scope_8616(offered_callee_scope, self.callee_scope)
        ):
            return False
        fresh = prove_scoped_call_stack_position_8616(
            self.artifact, self.block_addr, self.instruction_index,
            offered_caller_scope, offered_callee_scope,
            context=self.context,
        )
        return fresh.failure is None and fresh.proof == self.proof

    def position_for(
        self,
        offered_caller_scope: object,
        offered_callee_scope: object,
    ) -> CallStackPosition8616 | None:
        """Project the retained position only under revalidated scopes."""
        if not self.complete_for(offered_caller_scope, offered_callee_scope):
            return None
        return self.proof



def _scoped_call_target_8616(
    artifact: IRFunctionArtifact,
    block_addr: int,
    instruction_index: int,
) -> tuple[IRBlock | None, IRInstr | None, ScopedCallStackPositionFailure8616 | None]:
    """Validate the raw artifact and resolve the exact CALL row."""
    blocks = {block.addr: block for block in artifact.blocks}
    if (artifact.refusals or len(blocks) != len(artifact.blocks)
            or artifact.function_addr not in blocks
            or any(block.refusals for block in artifact.blocks)
            or any(successor not in blocks for block in artifact.blocks
                   for successor in block.successor_addrs)):
        return None, None, ScopedCallStackPositionFailure8616.INVALID_SOURCE
    block = blocks.get(block_addr)
    if block is None or not 0 <= instruction_index < len(block.instrs):
        return None, None, ScopedCallStackPositionFailure8616.INVALID_CALL
    call = block.instrs[instruction_index]
    if call.op != "CALL" or call.addr is None:
        return None, None, ScopedCallStackPositionFailure8616.INVALID_CALL
    return block, call, None


def _scoped_position_evidence_8616(
    call: IRInstr,
    context: ScopedCallStackContext8616,
    caller_scope: Real16InvocationDomain8616,
    callee_scope: Real16InvocationDomain8616,
) -> tuple[
    IRScopedCallStackCoordinates8616 | None,
    int | None,
    ScopedCallStackPositionFailure8616 | None,
]:
    """Authenticate the callsite binding and project the scoped net delta."""
    binding = context.for_callsite(call.addr)
    if binding is None or type(binding) is not ScopedCallEntryBinding8616:
        return None, None, ScopedCallStackPositionFailure8616.CONTEXT_UNBOUND
    carrier = binding.carrier
    if not (
        type(carrier) is IRScopedCallStackCoordinates8616
        and carrier.failure is None
        and _call_row_matches_carrier_8616(call, carrier)
        and same_real16_entry_scope_8616(caller_scope, binding.caller_scope)
        and same_real16_entry_scope_8616(callee_scope, binding.callee_scope)
    ):
        return carrier, None, ScopedCallStackPositionFailure8616.SOURCE_MISMATCH
    net = carrier.net_sp_delta_for(caller_scope, callee_scope)
    if net is None:
        return carrier, None, ScopedCallStackPositionFailure8616.DELTA_UNPROVEN
    return carrier, net, None


def _failure_result_8616(
    artifact: IRFunctionArtifact,
    call: IRInstr | None,
    block_addr: int,
    instruction_index: int,
    failure: ScopedCallStackPositionFailure8616,
    detail: str = "",
    *,
    carrier: IRScopedCallStackCoordinates8616 | None = None,
    caller_scope: Real16InvocationDomain8616 | None = None,
    callee_scope: Real16InvocationDomain8616 | None = None,
    context: ScopedCallStackContext8616 | None = None,
) -> ScopedCallStackPositionResult8616:
    """Publish one atomic scoped non-result with closed refusal counters."""
    return ScopedCallStackPositionResult8616(
        artifact, call, carrier, caller_scope, callee_scope, context,
        block_addr, instruction_index, None, failure, detail, 1, 1, 0, 0, 1,
    )


def solve_scoped_stack_states_8616(
    artifact: IRFunctionArtifact,
    offered_caller_scope: object,
    *,
    context: ScopedCallStackContext8616,
) -> dict[int, StackRestoreState8616] | None:
    """Run the shared solver with the context's fully-projected delta map.

    The offered caller domain must share provenance with every bound caller
    execution and the artifact must be the chain-bound caller artifact —
    a foreign artifact, foreign domain or unprojectable binding refuses
    the whole solve rather than silently dropping a call's effect.
    """
    if type(context) is not ScopedCallStackContext8616:
        return None
    deltas = context.call_deltas_for(offered_caller_scope, artifact)
    if deltas is None:
        return None
    return _solve_stack_states(artifact, call_deltas=deltas)


def prove_scoped_call_stack_position_8616(
    artifact: IRFunctionArtifact,
    block_addr: int,
    instruction_index: int,
    caller_scope: Real16InvocationDomain8616 | None,
    callee_scope: Real16InvocationDomain8616 | None,
    *,
    context: ScopedCallStackContext8616 | None,
) -> ScopedCallStackPositionResult8616:
    """Reproduce one CALL's scoped positions from current CFG and scopes.

    Authentication order mirrors the universal owner: exact source artifact,
    exact CALL row, callsite-keyed scoped binding with physical source
    match, projected net delta under both scopes, then the shared solver
    with that single callsite's overlay delta. The solver applies the
    callee's caller-visible effect at the exact instruction — downstream
    instructions see the real post-call SP.
    """
    if (
        type(caller_scope) is not Real16InvocationDomain8616
        or type(callee_scope) is not Real16InvocationDomain8616
        or type(context) is not ScopedCallStackContext8616
    ):
        return _failure_result_8616(
            artifact, None, block_addr, instruction_index,
            ScopedCallStackPositionFailure8616.SCOPE_ABSENT,
        )
    block, call, call_failure = _scoped_call_target_8616(
        artifact, block_addr, instruction_index,
    )
    if call_failure is not None or block is None or call is None or call.addr is None:
        return _failure_result_8616(
            artifact, call, block_addr, instruction_index,
            call_failure or ScopedCallStackPositionFailure8616.INVALID_CALL,
            caller_scope=caller_scope, callee_scope=callee_scope, context=context,
        )
    carrier, net, evidence_failure = _scoped_position_evidence_8616(
        call, context, caller_scope, callee_scope,
    )
    if evidence_failure is not None or carrier is None or net is None:
        return _failure_result_8616(
            artifact, call, block_addr, instruction_index,
            evidence_failure or ScopedCallStackPositionFailure8616.DELTA_UNPROVEN,
            caller_scope=caller_scope, callee_scope=callee_scope,
            carrier=carrier, context=context,
        )
    coordinates = carrier.coordinates
    if (coordinates is None or coordinates.return_addr is None
            or coordinates.return_frame_bytes is None
            or coordinates.target_addr is None):
        return _failure_result_8616(
            artifact, call, block_addr, instruction_index,
            ScopedCallStackPositionFailure8616.DELTA_UNPROVEN,
            caller_scope=caller_scope, callee_scope=callee_scope,
            carrier=carrier, context=context,
        )
    states = solve_scoped_stack_states_8616(
        artifact, caller_scope, context=context,
    )
    if states is None:
        return _failure_result_8616(
            artifact, call, block_addr, instruction_index,
            ScopedCallStackPositionFailure8616.CONTEXT_UNBOUND,
            caller_scope=caller_scope, callee_scope=callee_scope,
            carrier=carrier, context=context,
        )
    predecessors = _predecessor_map(artifact)
    incoming = tuple(states[pred] for pred in predecessors[block_addr])
    if block_addr == artifact.function_addr:
        incoming = (StackRestoreState8616(0), *incoming)
    if not incoming:
        return _failure_result_8616(
            artifact, call, block_addr, instruction_index,
            ScopedCallStackPositionFailure8616.UNKNOWN_POSITION,
            caller_scope=caller_scope, callee_scope=callee_scope,
            carrier=carrier, context=context,
        )
    observer = _CallObserver(call)
    _transfer_block(
        block_addr, block.instrs[:instruction_index + 1],
        join_stack_restore_states_8616(incoming),
        call_observer=observer.observe,
    )
    before, entry = observer.caller_before, observer.callee_entry
    if before is None or entry is None:
        return _failure_result_8616(
            artifact, call, block_addr, instruction_index,
            ScopedCallStackPositionFailure8616.UNKNOWN_POSITION,
            caller_scope=caller_scope, callee_scope=callee_scope,
            carrier=carrier, context=context,
        )
    if (entry - before) & 0xFFFF != (-coordinates.return_frame_bytes) & 0xFFFF:
        return _failure_result_8616(
            artifact, call, block_addr, instruction_index,
            ScopedCallStackPositionFailure8616.FRAME_MISMATCH,
            caller_scope=caller_scope, callee_scope=callee_scope,
            carrier=carrier, context=context,
        )
    proof = CallStackPosition8616(
        artifact.function_addr, block_addr, instruction_index, call.addr,
        coordinates.target_addr, coordinates.return_addr,
        coordinates.return_frame_bytes, before, entry, before + net,
    )
    return ScopedCallStackPositionResult8616(
        artifact, call, carrier, caller_scope, callee_scope, context,
        block_addr, instruction_index, proof, None, "", 1, 1, 1, 1, 0,
    )
