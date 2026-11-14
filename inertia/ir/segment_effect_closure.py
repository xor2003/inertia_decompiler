# cython: language_level=3, infer_types=True
"""Certify the local body and state census before publishing segment effects.

Layer: IR.
Responsibility: consume raw-IR coverage and its exact segment-state lineage,
classify returning exits and retain the complete local call census. Supplied
nested-call proofs are revalidated under one shared bounded traversal, so a
direct ``complete`` call cannot fan out into repeated dependency-graph walks.
This does not prove callee effects, infer segment equality, or authorize C
changes.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING
import dataclasses
import operator
import builtins
Real16InvocationDomain8616 = typing.TypeVar("Real16InvocationDomain8616")

if TYPE_CHECKING:
    from .real16_invocation_domain import Real16InvocationDomain8616

from .core import IRBlock, IRFunctionArtifact, SegmentOrigin
from .ir_boundary_cfg import IRBoundaryCoverageResult8616
from .segment_state import SegmentStateArtifact
from .segment_state_transfer import SEGMENT_REGISTERS


class SegmentEffectClosureFailure8616(StrEnum):
    """Explicit reasons local effects cannot be treated as complete."""

    COVERAGE_INCOMPLETE = "coverage_incomplete"
    STATE_LINEAGE_MISMATCH = "state_lineage_mismatch"
    CONTEXTUAL_ENTRY = "contextual_entry"
    CALL_EVIDENCE_STALE = "call_evidence_stale"
    STATE_CENSUS_INCOMPLETE = "state_census_incomplete"
    RETURN_EXIT_UNPROVEN = "return_exit_unproven"


@dataclasses.dataclass(frozen=True, )
class SegmentEffectClosureResult8616:
    """Retained local closure proof; call targets remain summary obligations."""

    coverage: IRBoundaryCoverageResult8616
    state: SegmentStateArtifact
    failure: SegmentEffectClosureFailure8616 | None
    callsite_addrs: object
    return_block_addrs: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Require retained lineage, census and closed evidence accounting."""
        return self.complete_for(None)

    def complete_for(self, invocation_scope: Real16InvocationDomain8616 | None) -> cython.bint:
        """Revalidate a universal closure or its exact retained invocation domain."""
        failure: object
        from .real16_invocation_domain import same_real16_entry_scope_8616

        if self.state.invocation_scope is not None and not same_real16_entry_scope_8616(
            invocation_scope, self.state.invocation_scope,
        ):
            return False
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in iter(counts)):
            return False
        failure, calls, exits = _bounded_closure_evidence_8616(self.coverage, self.state)
        return failure is None and operator.eq(calls, self.callsite_addrs) and operator.eq(exits, self.return_block_addrs)


def _closure_evidence_8616(
    coverage: IRBoundaryCoverageResult8616,
    state: SegmentStateArtifact,
) -> tuple[SegmentEffectClosureFailure8616 | None, tuple[cython.longlong, ...], tuple[cython.longlong, ...]]:
    """Require a bound complete state census and classified returning exits."""
    candidates: object
    owner: object
    if not coverage.complete_for(state.invocation_scope):
        return SegmentEffectClosureFailure8616.COVERAGE_INCOMPLETE, (), ()
    artifact: IRFunctionArtifact = coverage.artifact
    owner = state.source_artifact
    if owner is None or owner is not artifact:
        return SegmentEffectClosureFailure8616.STATE_LINEAGE_MISMATCH, (), ()
    if state.scoped_view is not coverage.scoped_view:
        return SegmentEffectClosureFailure8616.STATE_LINEAGE_MISMATCH, (), ()
    if state.entry_context is not None:
        # A theorem for one incoming CALL is not a universal callee summary.
        return SegmentEffectClosureFailure8616.CONTEXTUAL_ENTRY, (), ()
    if any(not proof.complete_for(state.invocation_scope) or proof.caller.artifact is not artifact for proof in iter(state.call_preservations)):
        return SegmentEffectClosureFailure8616.CALL_EVIDENCE_STALE, (), ()
    if not _state_census_complete_8616(artifact, state):
        return SegmentEffectClosureFailure8616.STATE_CENSUS_INCOMPLETE, (), ()
    candidates = _return_candidates_8616(coverage, state)
    if candidates is None:
        return SegmentEffectClosureFailure8616.RETURN_EXIT_UNPROVEN, (), ()
    exit_addrs, exits, live_blocks = candidates
    if not exits or any(not block.instrs or block.instrs[-1].op != "RET" for block in iter(exits)):
        return SegmentEffectClosureFailure8616.RETURN_EXIT_UNPROVEN, (), ()
    calls = tuple(sorted({
        instruction.addr for block in iter(artifact.blocks) if block.addr in live_blocks for instruction in iter(block.instrs)
        if instruction.op == "CALL" and type(instruction.addr) is int
    }))
    return None, calls, tuple(sorted(exit_addrs))


def _state_census_complete_8616(
    artifact: IRFunctionArtifact,
    state: SegmentStateArtifact,
) -> cython.bint:
    """Require every source block's segment state and proven root live-ins."""
    block_addrs = {block.addr for block in iter(artifact.blocks)}
    if operator.ne(set(state.entry_states), block_addrs) or operator.ne(set(state.exit_states), block_addrs):
        return False
    entry = state.entry_states[artifact.function_addr]
    if any(register not in entry or entry[register].origin is not SegmentOrigin.PROVEN
           for register in iter(SEGMENT_REGISTERS)):
        return False
    return all(
        register in state.entry_states[block_addr] and register in state.exit_states[block_addr]
        for block_addr in iter(block_addrs) for register in iter(SEGMENT_REGISTERS)
    )


def _return_candidates_8616(
    coverage: IRBoundaryCoverageResult8616,
    state: SegmentStateArtifact,
) -> object:
    """Select closed CFG exits, preserving raw instruction identities.

    A scoped pending edge has no successor claim: it must not become a
    return by confusing a missing map entry with an empty successor tuple.
    Only this operation's freshly authenticated projection is consumed.
    The returned blocks are the surface a returning-exit check may read:
    raw blocks on the universal route, effective projection blocks on
    the scoped route, so a conditionally discharged terminal is read
    from the authenticated surface — never from the retained raw JMP.
    """
    projection: object
    view: object
    artifact = coverage.artifact
    view = state.scoped_view
    if view is None:
        exits = tuple(
            block for block in iter(artifact.blocks) if not block.successor_addrs
        )
        return frozenset(block.addr for block in iter(exits)), exits, frozenset(block.addr for block in iter(artifact.blocks))
    projection = view.cfg_projection_for(state.invocation_scope)
    if projection is None or projection.source_artifact is not artifact:
        return None
    block_addrs = frozenset(block.addr for block in iter(artifact.blocks))
    live_blocks = block_addrs - projection.unreachable_block_addrs
    if operator.ne(set(projection.successors), live_blocks) or any(
        refusals for addr, refusals in builtins.iter(projection.pending.items()) if addr in live_blocks
    ):
        return None
    exits = tuple(
        block
        for block in iter(projection.blocks)
        if block.addr in live_blocks and not projection.successors[block.addr]
    )
    return frozenset(block.addr for block in iter(exits)), exits, live_blocks


@cython.ccall
def _bounded_closure_evidence_8616(
    coverage: IRBoundaryCoverageResult8616,
    state: SegmentStateArtifact,
) -> object:
    """Run local closure evidence under one shared bounded traversal.

    Revalidating supplied ``call_preservations`` invokes each proof's
    ``complete``; without a shared traversal every such property call would
    open a fresh dependency walk, multiplying work per supplied proof. The
    traversal owner is deferred to call time because ``segment_state`` binds
    this package before ``segment_call_preservation`` finishes initializing.
    """
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616():
        return _closure_evidence_8616(coverage, state)


@cython.ccall
def prove_segment_effect_closure_8616(
    coverage: IRBoundaryCoverageResult8616,
    state: SegmentStateArtifact,
) -> SegmentEffectClosureResult8616:
    """Return local effect closure or a typed nonpublishing refusal."""
    failure: object
    failure, calls, exits = _bounded_closure_evidence_8616(coverage, state)
    accepted = int(failure is None)
    return SegmentEffectClosureResult8616(
        coverage, state, failure, calls, exits, 1, 1, accepted, accepted, 1 - accepted,
    )
