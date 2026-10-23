"""Match raw IR control flow to the authoritative frontend boundary.

Layer: IR.
Responsibility: share CFG census agreement and bind full instruction coverage
to the existing raw IR registry and frontend boundary. CFG agreement alone
does not authorize instruction completeness; neither result proves effects.
A second explicit route covers conditionally transformed bodies: a retained
``ScopedFunctionIRView8616`` may certify the effective CFG for one
authenticated consuming entry through ``complete_for`` while the raw
artifact, the context-free ``complete`` verdict, and the universal registry
contract stay unchanged. The consuming entry is the view's own retained
scope — either a ``Real16InvocationDomain8616`` or the distinct
``NearCallJumpScope8616`` carried on the view's ``near_call_scope`` field;
the near-call premise is never laundered into the invocation-domain
contract, and the near-return continuation view stays invocation-domain
only.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRFunctionArtifact
from .entry_projection_mode import EntryProjectionMode8616
from .function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from .no_effect_instructions import (
    NO_EFFECT_INSTRUCTION_OP_8616,
    BoundNoEffectBlock8616,
    bound_no_effect_block_8616,
    bound_no_effect_instr_8616,
)
from .source_graph_binding import (
    ImmutableSourceGraphFacts8616,
    capture_immutable_source_graph_facts_8616,
)

if TYPE_CHECKING:
    from .near_return_continuation_view import (
        ScopedNearReturnContinuationView8616,
    )
    from .scoped_function_ir_view import (
        EntryJumpConsumingScope8616,
        ScopedFunctionCFGProjection8616,
        ScopedFunctionIRView8616,
    )


def _typed_scoped_view_8616(
    scoped_view: object,
) -> ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None:
    """Return the offered object when it is a typed owned scoped view.

    The scoped coverage route is conditional-evidence only; two typed
    view owners may carry it: the retained-application view and the
    premise-derived near-return continuation view. Both expose
    ``invocation_scope`` and ``cfg_projection_for`` with the same
    scope-authenticated contract. Anything else is not evidence and the
    caller refuses through its typed reason.
    """
    from .near_return_continuation_view import (
        ScopedNearReturnContinuationView8616 as _NearView8616,
    )
    from .scoped_function_ir_view import ScopedFunctionIRView8616

    if type(scoped_view) is ScopedFunctionIRView8616 or type(
        scoped_view
    ) is _NearView8616:
        return scoped_view
    return None


def _unmetered_cfg_work_8616(units: int) -> None:
    """Keep the existing unbudgeted CFG consumers unchanged."""


def _closed_boundary_census_8616(
    function_addr: int,
    boundary: ExactFunctionRangeBoundary8616,
    block_addrs: frozenset[int],
    edges: frozenset[tuple[int, int]],
    *, charge: Callable[[int], None] = _unmetered_cfg_work_8616,
) -> bool:
    """Require identical closed, entry-reachable block and edge censuses.

    This is the single census owner shared by the universal artifact route
    and the scoped effective-surface route: identical function root, exact
    block membership, exact edge set with no foreign endpoints, and closed
    reachability from the boundary root.
    """
    charge(len(block_addrs) + 1)
    if (
        function_addr != boundary.addr
        or block_addrs != boundary.block_addrs_set
        or boundary.addr not in block_addrs
    ):
        return False
    charge(len(boundary.successor_edges))
    boundary_edges = frozenset(boundary.successor_edges)
    charge(len(edges))
    if edges != boundary_edges:
        return False
    charge(len(block_addrs))
    successors: dict[int, list[int]] = {addr: [] for addr in block_addrs}
    for source_addr, target_addr in boundary_edges:
        charge(1)
        if source_addr not in block_addrs or target_addr not in block_addrs:
            return False
        successors[source_addr].append(target_addr)
    reachable: set[int] = set()
    pending = [boundary.addr]
    while pending:
        charge(1)
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            charge(len(successors[current]))
            pending.extend(successors[current])
    charge(len(block_addrs))
    return reachable == block_addrs


def closed_ir_boundary_cfg_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> bool:
    """Require identical closed, entry-reachable block and edge censuses.

    This deliberately proves only CFG agreement. Consumers must separately
    establish registered artifact identity, instruction coverage, and effects.
    """
    block_addrs = frozenset(block.addr for block in artifact.blocks)
    if len(block_addrs) != len(artifact.blocks):
        return False
    return _closed_boundary_census_8616(
        artifact.function_addr,
        boundary,
        block_addrs,
        frozenset(
            (block.addr, successor)
            for block in artifact.blocks
            for successor in block.successor_addrs
        ),
    )


class IRBoundaryCoverageFailure8616(StrEnum):
    """Typed reasons a raw IR body cannot certify frontend coverage."""

    PROJECT_MISMATCH = "project_mismatch"
    IR_NOT_PROJECT_OWNED = "ir_not_project_owned"
    IR_REFUSAL = "ir_refusal"
    CFG_MISMATCH = "cfg_mismatch"
    INSTRUCTION_CENSUS_MISMATCH = "instruction_census_mismatch"
    NATIVE_CENSUS_MISMATCH = "native_census_mismatch"
    CENSUS_BUDGET_EXHAUSTED = "census_budget_exhausted"
    SCOPED_EVIDENCE_INCONSISTENT = "scoped_evidence_inconsistent"
    SCOPED_SCOPE_UNBOUND = "scoped_scope_unbound"
    SCOPED_VIEW_REFUSED = "scoped_view_refused"
    SCOPED_SURFACE_MISMATCH = "scoped_surface_mismatch"
    SCOPED_REFUSAL = "scoped_refusal"
    SCOPED_CFG_MISMATCH = "scoped_cfg_mismatch"
    SCOPED_CENSUS_MISMATCH = "scoped_census_mismatch"
    SCOPED_NATIVE_MISMATCH = "scoped_native_mismatch"


@dataclass(frozen=True, slots=True)
class IRBoundaryCoverageResult8616:
    """Coverage proof retaining its exact raw IR and frontend authority.

    This is not segment-effect or terminal-behavior proof. Consumers must add
    their own classified-effects obligations before claiming preservation.

    ``scoped_view`` is the explicit conditional-evidence attachment: when it
    is ``None`` the result is universal evidence exactly as before, and
    ``complete_for`` ignores the offered entry. When it retains a typed
    scoped view — ``ScopedFunctionIRView8616`` for a retained
    application, or ``ScopedNearReturnContinuationView8616`` for a
    premise-derived near-return continuation — ``artifact`` stays the
    identical *raw* pending body — never a transformed or publishable
    artifact — and only ``complete_for(scope)`` may authenticate the
    conditional surface; ``complete`` delegates to ``complete_for(None)``
    and therefore stays permanently false for scoped evidence. The offered
    entry is the view's own typed consuming scope: a retained application
    view admits either its ``Real16InvocationDomain8616`` or its distinct
    ``NearCallJumpScope8616`` retained on ``near_call_scope``, while the
    near-return continuation view admits only the invocation domain. The
    field is identity-bound provenance, so it is excluded from equality and
    the repr.
    """

    artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    failure: IRBoundaryCoverageFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    scoped_view: (
        ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None
    ) = field(default=None, compare=False, repr=False)

    @property
    def complete(self) -> bool:
        """Require closed accounting and still-matching retained evidence.

        Delegates to ``complete_for(None)``: a result carrying scoped
        evidence can never certify context-free, because the conditional
        body only closes under its authenticated consuming entry.
        """
        return self.complete_for(None)

    def complete_for(
        self, consuming_scope: EntryJumpConsumingScope8616 | None
    ) -> bool:
        """Return the coverage verdict under one explicit consuming entry.

        The universal branch is unchanged: without a retained scoped view
        the verdict re-verifies registry identity, refusal-free blocks,
        and the exact frontend census, and the offered entry is
        irrelevant. With a retained scoped view the verdict re-runs the
        full scoped authentication under the offered entry — see
        ``_scoped_coverage_failure_8616`` — so a stale view, a foreign
        entry, or a mutated native surface revokes it.
        """
        if self.scoped_view is None:
            if self.failure is not None:
                return False
            counts = (
                self.raw_fact_count, self.normalized_fact_count,
                self.classified_fact_count, self.materialized_count,
                self.failure_count,
            )
            if any(type(count) is not int for count in counts) or counts != (1, 1, 1, 1, 0):
                return False
            return _coverage_failure_8616(
                self.boundary.project, self.boundary, self.artifact
            ) is None
        return _scoped_coverage_failure_8616(self, consuming_scope) is None


def _instruction_census_matches_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> bool:
    """Require every IR instruction to belong to the nonempty binary census.

    Multiple IR operations may share one machine instruction address. Comparing
    sets permits that lossless expansion, but not an absent or extra address.
    A no-effect instruction counts as its head's coverage only when the bound
    project authenticates it: the claim must match the decoded extent, the
    exact native bytes, the relifted ``Ist_IMark`` identity and empty span,
    and the bound terminal fallthrough — artifact-carried provenance alone is
    never evidence, so a fabricated ``NOP`` cannot conceal a real instruction.
    Bound-block facts are collected once per census block, never per
    instruction. Only immutable exact-byte lift facts may be cached; all
    current-byte and boundary binding checks run on every evaluation.
    """
    addresses: set[int] = set()
    bound_blocks: dict[int, BoundNoEffectBlock8616 | None] = {}
    for block in artifact.blocks:
        for instruction in block.instrs:
            if type(instruction.addr) is not int:
                return False
            if instruction.op == NO_EFFECT_INSTRUCTION_OP_8616:
                if block.addr not in bound_blocks:
                    bound_blocks[block.addr] = bound_no_effect_block_8616(
                        boundary, block.addr
                    )
                context = bound_blocks[block.addr]
                if context is None or not bound_no_effect_instr_8616(
                    context, instruction
                ):
                    return False
            addresses.add(instruction.addr)
    return bool(addresses) and frozenset(addresses) == boundary.reachable_instruction_addrs


def _universal_native_census_failure_8616(
    boundary: ExactFunctionRangeBoundary8616,
) -> IRBoundaryCoverageFailure8616 | None:
    """Rebind every decoded block to current bytes independently of normalized IR.

    Normalized jumps need not equal raw lifted instructions. The existing
    bound-block owner authenticates decoded extents and exact native bytes;
    universal coverage must perform that check for effectful rows too.
    """
    from .real16_invocation_domain import _nested_capture_admitted_8616

    units = len(boundary.block_addrs_set) + len(boundary.reachable_instruction_addrs)
    if not _nested_capture_admitted_8616(units):
        return IRBoundaryCoverageFailure8616.CENSUS_BUDGET_EXHAUSTED
    for block_addr in boundary.block_addrs_set:
        if bound_no_effect_block_8616(boundary, block_addr) is None:
            return IRBoundaryCoverageFailure8616.NATIVE_CENSUS_MISMATCH
    return None


def _coverage_failure_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> IRBoundaryCoverageFailure8616 | None:
    """Check identity before examining control flow and instruction coverage."""
    if boundary.project is not project:
        return IRBoundaryCoverageFailure8616.PROJECT_MISMATCH
    resolution = registered_function_ir_artifact_8616(project, artifact.function_addr)
    if (resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN
            or resolution.artifact is None or resolution.artifact is not artifact):
        return IRBoundaryCoverageFailure8616.IR_NOT_PROJECT_OWNED
    if any(block.refusals for block in artifact.blocks):
        return IRBoundaryCoverageFailure8616.IR_REFUSAL
    if not closed_ir_boundary_cfg_8616(boundary, artifact):
        return IRBoundaryCoverageFailure8616.CFG_MISMATCH
    if not _instruction_census_matches_8616(boundary, artifact):
        return IRBoundaryCoverageFailure8616.INSTRUCTION_CENSUS_MISMATCH
    return _universal_native_census_failure_8616(boundary)


def _scoped_projection_census_failure_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    projection: ScopedFunctionCFGProjection8616,
) -> IRBoundaryCoverageFailure8616 | None:
    """Require the authenticated effective CFG to equal the boundary census.

    Every effective block must carry an outgoing claim (a block that kept
    a residual hole was already refused), duplicate blocks or duplicate
    edges are forged censuses, and the shared closed-census owner decides
    membership, edge identity, foreign endpoints, and reachability —
    never a forked comparison. The effective surface must also preserve
    the raw instruction address census exactly: a dropped, extra, or
    foreign instruction on the transformed surface is a census mismatch.
    """
    block_addrs = frozenset(block.addr for block in projection.blocks)
    if len(block_addrs) != len(projection.blocks):
        return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
    edge_list: list[tuple[int, int]] = []
    for block in projection.blocks:
        if block.addr in projection.unreachable_block_addrs:
            continue
        successors = projection.successors.get(block.addr)
        if successors is None:
            return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
        edge_list.extend((block.addr, target) for target in successors)
    if len(edge_list) != len(frozenset(edge_list)):
        return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
    if len(boundary.successor_edges) != len(frozenset(boundary.successor_edges)):
        return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
    closed = (
        _closed_reachable_projection_8616(boundary, block_addrs, frozenset(edge_list), projection)
        if projection.unreachable_block_addrs
        else _closed_boundary_census_8616(
            artifact.function_addr, boundary, block_addrs, frozenset(edge_list)
        )
    )
    if not closed:
        return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
    if Counter(
        instruction.addr for block in projection.blocks for instruction in block.instrs
    ) != Counter(
        instruction.addr for block in artifact.blocks for instruction in block.instrs
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_CENSUS_MISMATCH
    return None


def _closed_reachable_projection_8616(
    boundary: ExactFunctionRangeBoundary8616, block_addrs: frozenset[int],
    edges: frozenset[tuple[int, int]], projection: ScopedFunctionCFGProjection8616,
) -> bool:
    """Check the partition supplied by a freshly authenticated scoped producer.

    Raw membership remains complete. Only the producer's proven dead blocks
    may lack outgoing claims; all surviving edges must be native boundary edges
    and every live block must remain reachable from the original root.
    """
    dead = projection.unreachable_block_addrs
    live = block_addrs - dead
    if (block_addrs != boundary.block_addrs_set or not dead <= block_addrs
            or boundary.addr not in live or set(projection.successors) != live
            or not edges <= frozenset(boundary.successor_edges)):
        return False
    if any(source not in live or target not in live for source, target in edges):
        return False
    reachable: set[int] = set()
    pending = [boundary.addr]
    while pending:
        addr = pending.pop()
        if addr not in reachable:
            reachable.add(addr)
            pending.extend(projection.successors[addr])
    return reachable == live


def _native_boundary_facts_8616(
    boundary: ExactFunctionRangeBoundary8616,
) -> tuple[object, ...]:
    """Detach all owned boundary coordinates without invoking loader callbacks."""
    continuations = boundary.near_return_continuations
    # The premise is identity-bound authority, excluded from artifact equality
    # and freshly authenticated by the scoped owner. It contains native decoder
    # handles and must not be pickled while copying the comparable facts.
    detached = None if continuations is None else deepcopy(replace(continuations, premise=None))
    return (id(boundary.project), boundary.addr, boundary.size, boundary.block_addrs_set,
            boundary.reachable_instruction_addrs, boundary.successor_edges,
            tuple(id(block) for block in boundary.blocks), deepcopy(boundary.info),
            detached, boundary.decode_lower_bound)


@dataclass(frozen=True, slots=True)
class ScopedNativeSurfaceSnapshot8616:
    """Pre-callback immutable graph facts and detached boundary coordinates.

    ``graph`` is the deeply immutable canonical record set captured before
    the first producer or authority callback, so equality replays the full
    field surface and post-callback mutation through live IR aliases cannot
    rewrite it; no graph objects are retained. ``boundary_facts`` keeps the
    prior detached behavior — exact deep copies of the owned coordinates —
    so its ``==`` compares live container types verbatim.
    """

    graph: ImmutableSourceGraphFacts8616
    boundary_facts: tuple[object, ...]


def _capture_scoped_native_surface_8616(
    boundary: ExactFunctionRangeBoundary8616, artifact: IRFunctionArtifact,
) -> ScopedNativeSurfaceSnapshot8616:
    """Capture immutable facts before any producer or authority callback runs."""
    return ScopedNativeSurfaceSnapshot8616(
        capture_immutable_source_graph_facts_8616(
            artifact.function_addr, artifact.blocks, artifact.refusals),
        _native_boundary_facts_8616(boundary),
    )


@dataclass(frozen=True, slots=True)
class ScopedNativeRebindFacts8616:
    """Detached immutable native facts and authenticated no-effect census.

    ``graph`` carries the canonical record set of the freshly imported
    artifact — never the live objects — so the pure seal can compare exact
    fields without touching native or loader callbacks again.
    """

    boundary: ExactFunctionRangeBoundary8616
    graph: ImmutableSourceGraphFacts8616 | None
    reachable: frozenset[int]
    failure: IRBoundaryCoverageFailure8616 | None


def _rebind_scoped_native_facts_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    caller: IRFunctionArtifact,
    snapshot: ImmutableSourceGraphFacts8616 | None = None,
) -> ScopedNativeRebindFacts8616 | None:
    """Rebind caller facts to the retained native record, else decline.

    ``None`` means no validated record applies and the caller must run the
    ordinary guarded census import. On AUTHENTICATED the freshly captured
    caller snapshot already proved field-equal to the record's private
    canonical facts — it may stand for the native graph in the pure seal
    while the record's retained graph itself is never exposed. REFUSED
    carries the verdict the fresh import would seal: an unreconciled
    caller function-level refusal or an expired deadline refuses, foreign
    caller facts mismatch. The reachable-instruction census and every
    no-effect byte/IMark/extent check still run freshly on the caller's
    live rows.

    An operation may supply its immutable pre-callback ``snapshot`` instead
    of encoding the caller again. This only authenticates that snapshot
    against native facts; the caller must still seal the live graph after
    every callback. It never authorizes reusing an earlier CFG projection.
    """
    from .direct_evidence_deadline import direct_evidence_deadline_expired_8616
    from .native_import_surface_cache import NativeFactRebindState8616
    from .vex_import import native_census_facts_rebind_8616

    captured: list[ImmutableSourceGraphFacts8616] = []

    def caller_facts() -> ImmutableSourceGraphFacts8616:
        if not captured:
            captured.append(
                snapshot if snapshot is not None
                else capture_immutable_source_graph_facts_8616(
                    caller.function_addr, caller.blocks, caller.refusals)
            )
        return captured[0]

    rebound = native_census_facts_rebind_8616(project, boundary, caller_facts)
    if rebound.state is NativeFactRebindState8616.UNRESOLVED:
        return None
    if rebound.state is NativeFactRebindState8616.REFUSED:
        failure: IRBoundaryCoverageFailure8616 | None = (
            IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH)
        if (
            direct_evidence_deadline_expired_8616(project)
            or (captured
                and Counter(captured[0].function_refusals)
                - Counter(captured[0].block_refusals))
        ):
            failure = IRBoundaryCoverageFailure8616.SCOPED_REFUSAL
        return ScopedNativeRebindFacts8616(
            boundary, None, boundary.reachable_instruction_addrs, failure)
    failure = (None if _instruction_census_matches_8616(boundary, caller)
               else IRBoundaryCoverageFailure8616.SCOPED_CENSUS_MISMATCH)
    return ScopedNativeRebindFacts8616(
        boundary, captured[0] if captured else None,
        boundary.reachable_instruction_addrs, failure,
    )


def _prepare_scoped_native_rebind_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    caller: IRFunctionArtifact | None = None,
) -> ScopedNativeRebindFacts8616:
    """Complete native import/no-effect callbacks and detach facts for a pure seal.

    When ``caller`` carries the artifact under proof, a live request-local
    native record may authenticate the caller's freshly captured canonical
    facts instead of a second whole import; a missing, stale or replaced
    authority falls back to the guarded census import unchanged.
    """
    if caller is not None:
        rebound = _rebind_scoped_native_facts_8616(project, boundary, caller)
        if rebound is not None:
            return rebound
    from .real16_invocation_domain import real16_native_census_import_8616

    rederived: IRFunctionArtifact | None = real16_native_census_import_8616(project, boundary)
    if (
        type(rederived) is not IRFunctionArtifact
        or rederived.function_addr != boundary.addr
    ):
        return ScopedNativeRebindFacts8616(
            boundary, None, boundary.reachable_instruction_addrs,
            IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH,
        )
    failure = (None if _instruction_census_matches_8616(boundary, rederived)
               else IRBoundaryCoverageFailure8616.SCOPED_CENSUS_MISMATCH)
    return ScopedNativeRebindFacts8616(
        boundary,
        capture_immutable_source_graph_facts_8616(
            rederived.function_addr, rederived.blocks, rederived.refusals),
        boundary.reachable_instruction_addrs, failure,
    )


def _scoped_native_rebind_failure_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    facts: ScopedNativeRebindFacts8616,
    before: ScopedNativeSurfaceSnapshot8616 | None = None,
) -> IRBoundaryCoverageFailure8616 | None:
    """Seal current whole IR against detached facts without native/loader callbacks.

    The current graph is encoded exactly once into the same immutable
    canonical facts, then compared against the pre-callback capture and the
    freshly detached native facts; detached graphs are never re-walked.
    """
    if facts.failure is not None:
        return facts.failure
    native = facts.graph
    if (facts.boundary is not boundary or native is None
            or boundary.reachable_instruction_addrs != facts.reachable
            or artifact.function_addr != boundary.addr):
        return IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    current = capture_immutable_source_graph_facts_8616(
        artifact.function_addr, artifact.blocks, artifact.refusals)
    if before is not None and (
        before.graph.function_addr != current.function_addr
        or before.graph.function_refusals != current.function_refusals
        or before.boundary_facts != _native_boundary_facts_8616(boundary)
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    # Importers mirror block refusals at function level. Only those already
    # reconciled by the scoped projection may be discharged; unrelated
    # function-only failures are absent from the canonical block digest.
    if any(
        Counter(graph.function_refusals) - Counter(graph.block_refusals)
        for graph in (current, native)
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_REFUSAL
    if current != native or (before is not None and before.graph != current):
        return IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    addresses = frozenset(
        instruction.addr
        for block in artifact.blocks for instruction in block.instrs
    )
    if not addresses or addresses != facts.reachable:
        return IRBoundaryCoverageFailure8616.SCOPED_CENSUS_MISMATCH
    return None


def _scoped_native_failure_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> IRBoundaryCoverageFailure8616 | None:
    """Re-derive native facts and seal every retained IR field and census freshly."""
    before = _capture_scoped_native_surface_8616(boundary, artifact)
    facts = _rebind_scoped_native_facts_8616(project, boundary, artifact, before.graph)
    if facts is None:
        facts = _prepare_scoped_native_rebind_8616(project, boundary)
    return _scoped_native_rebind_failure_8616(boundary, artifact, facts, before)


def _scoped_evidence_failure_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616, artifact: IRFunctionArtifact,
    scoped_view: ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None,
    consuming_scope: EntryJumpConsumingScope8616 | None,
) -> IRBoundaryCoverageFailure8616 | None:
    """Recheck scoped evidence while discarding its ephemeral CFG projection."""
    failure, _projection = _scoped_evidence_projection_8616(
        project, boundary, artifact, scoped_view, consuming_scope,
    )
    return failure


def _scoped_evidence_projection_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    scoped_view: (
        ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None
    ),
    consuming_scope: EntryJumpConsumingScope8616 | None,
    *, projection_mode: EntryProjectionMode8616 = EntryProjectionMode8616.CONTROL_ONLY,
) -> tuple[IRBoundaryCoverageFailure8616 | None, ScopedFunctionCFGProjection8616 | None]:
    """Authenticate the full scoped evidence chain under one entry.

    Scoped evidence never reuses the universal registry branch: the raw
    artifact stays pending and unregistered, so authentication revalidates
    the retained view once through its bulk CFG projection under the
    offered entry, requires the effective surface to expose no refusal,
    then defers to the independent native rederivation. First failure
    wins; every refusal is a typed non-result. The offered entry's admitted
    type is owned by the typed view: a retained application view may
    authenticate its distinct ``NearCallJumpScope8616`` premise as well as
    an invocation domain, while the near-return continuation view admits
    the invocation domain only — the near-call record is never accepted as
    a ``Real16InvocationDomain8616`` stand-in.
    """
    # Deferred: the scoped route binds the view/domain/scope owners lazily
    # so loading this universal coverage owner cannot deadlock the package
    # on the sibling imports that depend on it.
    from .near_call_jump_scope import NearCallJumpScope8616
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import (
        ScopedFunctionCFGProjection8616,
        ScopedFunctionIRView8616,
    )

    view = _typed_scoped_view_8616(scoped_view)
    if view is None or view.failure is not None:
        return IRBoundaryCoverageFailure8616.SCOPED_VIEW_REFUSED, None
    scoped_view = view
    if (
        scoped_view.source_artifact is not artifact
        or scoped_view.boundary is not boundary
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_SURFACE_MISMATCH, None
    if type(scoped_view) is ScopedFunctionIRView8616:
        scope_types: tuple[type, ...] = (
            Real16InvocationDomain8616, NearCallJumpScope8616,
        )
    else:
        scope_types = (Real16InvocationDomain8616,)
    if (
        consuming_scope is None
        or type(consuming_scope) not in scope_types
        or consuming_scope.project is not project
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_SCOPE_UNBOUND, None
    projection = (scoped_view.cfg_projection_for(consuming_scope, mode=projection_mode)
                  if type(scoped_view) is ScopedFunctionIRView8616
                  else scoped_view.cfg_projection_for(
                      cast(Real16InvocationDomain8616, consuming_scope)))
    if type(projection) is not ScopedFunctionCFGProjection8616:
        return IRBoundaryCoverageFailure8616.SCOPED_VIEW_REFUSED, None
    if (
        projection.source_artifact is not artifact
        or projection.scope is not consuming_scope
        or projection.function_addr != artifact.function_addr
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_SURFACE_MISMATCH, None
    if any(refusals for addr, refusals in projection.pending.items()
           if addr not in projection.unreachable_block_addrs):
        return IRBoundaryCoverageFailure8616.SCOPED_REFUSAL, None
    census_failure = _scoped_projection_census_failure_8616(
        boundary, artifact, projection
    )
    if census_failure is not None:
        return census_failure, None
    native_failure = _scoped_native_failure_8616(project, boundary, artifact)
    return native_failure, projection if native_failure is None else None


def _scoped_coverage_failure_8616(
    coverage: IRBoundaryCoverageResult8616,
    consuming_scope: EntryJumpConsumingScope8616 | None,
) -> IRBoundaryCoverageFailure8616 | None:
    """Re-run the scoped verdict on the retained result under one entry.

    The recorded failure is terminal; a live result then requires the
    closed five-counter ledger before any evidence is consulted, so a
    forged or partial ledger can never launder coverage. An entry that
    cites this very result as its own coverage authority is a bootstrap
    cycle — the scope must be authenticated independently of the
    conditional evidence it is about to authorize — and refuses. Only an
    invocation domain can carry that coverage back-reference, so the cycle
    check stays ``Real16InvocationDomain8616``-exact; a near-call scope
    holds conditional callee closures instead and is re-authenticated end
    to end by its own owner below.
    """
    if coverage.failure is not None:
        return coverage.failure
    counts = (
        coverage.raw_fact_count, coverage.normalized_fact_count,
        coverage.classified_fact_count, coverage.materialized_count,
        coverage.failure_count,
    )
    if any(type(count) is not int for count in counts) or counts != (1, 1, 1, 1, 0):
        return IRBoundaryCoverageFailure8616.SCOPED_EVIDENCE_INCONSISTENT
    from .real16_invocation_domain import Real16InvocationDomain8616

    if (
        consuming_scope is not None
        and type(consuming_scope) is Real16InvocationDomain8616
        and consuming_scope.coverage is coverage
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_SCOPE_UNBOUND
    return _scoped_evidence_failure_8616(
        coverage.boundary.project,
        coverage.boundary,
        coverage.artifact,
        coverage.scoped_view,
        consuming_scope,
    )


def prove_ir_boundary_coverage_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> IRBoundaryCoverageResult8616:
    """Produce a nonpublishing raw-IR coverage proof or typed refusal."""
    failure = _coverage_failure_8616(project, boundary, artifact)
    accepted = int(failure is None)
    return IRBoundaryCoverageResult8616(
        artifact, boundary, failure, 1, 1, accepted, accepted, 1 - accepted,
    )


def prove_scoped_ir_boundary_coverage_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    scoped_view: (
        ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None
    ),
) -> IRBoundaryCoverageResult8616:
    """Produce a scoped coverage proof bound to one consuming entry.

    The result retains the identical raw ``artifact`` — never a
    transformed body — the exact ``boundary``, and the typed
    ``scoped_view`` as its only conditional evidence. A retained
    application view and a premise-derived near-return continuation view
    are both accepted; any other object is not evidence. Construction
    evaluates the whole scoped surface once under the view's own retained
    entry — the application view's distinct ``near_call_scope`` when it
    carries one, else its ``invocation_scope`` — so a stale or forged
    chain records a typed non-result instead of coverage a consumer could
    inherit. Nothing here registers, publishes, or converts the
    conditional body: ``complete`` remains context-free-false and only
    ``complete_for(scope)`` re-authenticates.
    """
    from .scoped_function_ir_view import ScopedFunctionIRView8616

    typed_view = _typed_scoped_view_8616(scoped_view)
    consuming_scope: EntryJumpConsumingScope8616 | None = None
    if typed_view is not None and type(typed_view) is ScopedFunctionIRView8616:
        consuming_scope = (
            typed_view.near_call_scope or typed_view.invocation_scope
        )
    elif typed_view is not None:
        consuming_scope = typed_view.invocation_scope
    failure = (
        IRBoundaryCoverageFailure8616.PROJECT_MISMATCH
        if boundary.project is not project
        else _scoped_evidence_failure_8616(
            project, boundary, artifact, scoped_view, consuming_scope
        )
    )
    accepted = int(failure is None)
    return IRBoundaryCoverageResult8616(
        artifact, boundary, failure, 1, 1, accepted, accepted, 1 - accepted,
        scoped_view=scoped_view,
    )


@dataclass(frozen=True, slots=True)
class ScopedIRBoundaryConsumption8616:
    """Fresh coverage ledger and CFG projection for one synchronous consumption.

    Neither field authorizes later reuse. A later operation must call the
    producer again; retained coverage.complete_for keeps its full replay.
    """

    coverage: IRBoundaryCoverageResult8616
    projection: ScopedFunctionCFGProjection8616 | None


def consume_scoped_ir_boundary_projection_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616, artifact: IRFunctionArtifact,
    scoped_view: ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None,
    consuming_scope: EntryJumpConsumingScope8616 | None,
    *, projection_mode: EntryProjectionMode8616 = EntryProjectionMode8616.CONTROL_ONLY,
) -> ScopedIRBoundaryConsumption8616:
    """Authenticate one live surface once and return its corresponding projection.

    The exact same source, scope, refusal, instruction census and native-byte
    checks used by retained coverage run here. No proof is cached or published.
    """
    failure: IRBoundaryCoverageFailure8616 | None
    projection: ScopedFunctionCFGProjection8616 | None
    if boundary.project is not project:
        failure, projection = IRBoundaryCoverageFailure8616.PROJECT_MISMATCH, None
    else:
        failure, projection = _scoped_evidence_projection_8616(
            project, boundary, artifact, scoped_view, consuming_scope,
            projection_mode=projection_mode,
        )
    accepted = int(failure is None)
    coverage = IRBoundaryCoverageResult8616(
        artifact, boundary, failure, 1, 1, accepted, accepted, 1 - accepted,
        scoped_view=scoped_view,
    )
    return ScopedIRBoundaryConsumption8616(coverage, projection)
