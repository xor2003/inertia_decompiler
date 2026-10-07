"""Match raw IR control flow to the authoritative frontend boundary.

Layer: IR.
Responsibility: share CFG census agreement and bind full instruction coverage
to the existing raw IR registry and frontend boundary. CFG agreement alone
does not authorize instruction completeness; neither result proves effects.
A second explicit route covers conditionally transformed bodies: a retained
``ScopedFunctionIRView8616`` may certify the effective CFG for one
authenticated consuming entry through ``complete_for`` while the raw
artifact, the context-free ``complete`` verdict, and the universal registry
contract stay unchanged.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRFunctionArtifact
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

if TYPE_CHECKING:
    from .near_return_continuation_view import (
        ScopedNearReturnContinuationView8616,
    )
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import (
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


def _closed_boundary_census_8616(
    function_addr: int,
    boundary: ExactFunctionRangeBoundary8616,
    block_addrs: frozenset[int],
    edges: frozenset[tuple[int, int]],
) -> bool:
    """Require identical closed, entry-reachable block and edge censuses.

    This is the single census owner shared by the universal artifact route
    and the scoped effective-surface route: identical function root, exact
    block membership, exact edge set with no foreign endpoints, and closed
    reachability from the boundary root.
    """
    if (
        function_addr != boundary.addr
        or block_addrs != boundary.block_addrs_set
        or boundary.addr not in block_addrs
    ):
        return False
    boundary_edges = frozenset(boundary.successor_edges)
    if edges != boundary_edges:
        return False
    successors: dict[int, list[int]] = {addr: [] for addr in block_addrs}
    for source_addr, target_addr in boundary_edges:
        if source_addr not in block_addrs or target_addr not in block_addrs:
            return False
        successors[source_addr].append(target_addr)
    reachable: set[int] = set()
    pending = [boundary.addr]
    while pending:
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            pending.extend(successors[current])
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
    and therefore stays permanently false for scoped evidence. The field
    is identity-bound provenance, so it is excluded from equality and
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
        self, consuming_scope: Real16InvocationDomain8616 | None
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
    return None


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
        successors = projection.successors.get(block.addr)
        if successors is None:
            return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
        edge_list.extend((block.addr, target) for target in successors)
    if len(edge_list) != len(frozenset(edge_list)):
        return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
    if len(boundary.successor_edges) != len(frozenset(boundary.successor_edges)):
        return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
    if not _closed_boundary_census_8616(
        artifact.function_addr, boundary, block_addrs, frozenset(edge_list)
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_CFG_MISMATCH
    if Counter(
        instruction.addr for block in projection.blocks for instruction in block.instrs
    ) != Counter(
        instruction.addr for block in artifact.blocks for instruction in block.instrs
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_CENSUS_MISMATCH
    return None


def _scoped_native_failure_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
) -> IRBoundaryCoverageFailure8616 | None:
    """Independently re-derive the raw native surface and compare it whole.

    A view verdict alone is transport admission, never native coverage:
    the guarded census importer re-imports the raw artifact under the
    current boundary, and the comparison covers the full canonical
    source — every IR field including compare-excluded provenance — so
    changed bytes, metadata, ordering, or a ``None``/foreign import
    result all refuse. The retained artifact's instruction census must
    still equal the boundary's current reachable census.
    """
    from .entry_jump_domain import _canonical_source_8616
    from .real16_invocation_domain import real16_native_census_import_8616

    rederived = real16_native_census_import_8616(project, boundary)
    if (
        type(rederived) is not IRFunctionArtifact
        or rederived.function_addr != boundary.addr
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    # Importers mirror block refusals at function level. Only those already
    # reconciled by the scoped projection may be discharged; unrelated
    # function-only failures are absent from the canonical block digest.
    if any(
        Counter(source.refusals) - Counter(
            refusal for block in source.blocks for refusal in block.refusals
        )
        for source in (artifact, rederived)
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_REFUSAL
    if _canonical_source_8616(
        rederived.function_addr, rederived.blocks
    ) != _canonical_source_8616(artifact.function_addr, artifact.blocks):
        return IRBoundaryCoverageFailure8616.SCOPED_NATIVE_MISMATCH
    if not _instruction_census_matches_8616(boundary, artifact):
        return IRBoundaryCoverageFailure8616.SCOPED_CENSUS_MISMATCH
    return None


def _scoped_evidence_failure_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    artifact: IRFunctionArtifact,
    scoped_view: (
        ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None
    ),
    consuming_scope: Real16InvocationDomain8616 | None,
) -> IRBoundaryCoverageFailure8616 | None:
    """Authenticate the full scoped evidence chain under one entry.

    Scoped evidence never reuses the universal registry branch: the raw
    artifact stays pending and unregistered, so authentication revalidates
    the retained view once through its bulk CFG projection under the
    offered entry, requires the effective surface to expose no refusal,
    then defers to the independent native rederivation. First failure
    wins; every refusal is a typed non-result.
    """
    # Deferred: the scoped route binds the view/domain owners lazily so
    # loading this universal coverage owner cannot deadlock the package
    # on the sibling imports that depend on it.
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import (
        ScopedFunctionCFGProjection8616,
    )

    view = _typed_scoped_view_8616(scoped_view)
    if view is None or view.failure is not None:
        return IRBoundaryCoverageFailure8616.SCOPED_VIEW_REFUSED
    scoped_view = view
    if (
        scoped_view.source_artifact is not artifact
        or scoped_view.boundary is not boundary
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_SURFACE_MISMATCH
    if (
        consuming_scope is None
        or type(consuming_scope) is not Real16InvocationDomain8616
        or consuming_scope.project is not project
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_SCOPE_UNBOUND
    projection = scoped_view.cfg_projection_for(consuming_scope)
    if type(projection) is not ScopedFunctionCFGProjection8616:
        return IRBoundaryCoverageFailure8616.SCOPED_VIEW_REFUSED
    if (
        projection.source_artifact is not artifact
        or projection.scope is not consuming_scope
        or projection.function_addr != artifact.function_addr
    ):
        return IRBoundaryCoverageFailure8616.SCOPED_SURFACE_MISMATCH
    if any(projection.pending.values()):
        return IRBoundaryCoverageFailure8616.SCOPED_REFUSAL
    census_failure = _scoped_projection_census_failure_8616(
        boundary, artifact, projection
    )
    if census_failure is not None:
        return census_failure
    return _scoped_native_failure_8616(project, boundary, artifact)


def _scoped_coverage_failure_8616(
    coverage: IRBoundaryCoverageResult8616,
    consuming_scope: Real16InvocationDomain8616 | None,
) -> IRBoundaryCoverageFailure8616 | None:
    """Re-run the scoped verdict on the retained result under one entry.

    The recorded failure is terminal; a live result then requires the
    closed five-counter ledger before any evidence is consulted, so a
    forged or partial ledger can never launder coverage. An entry that
    cites this very result as its own coverage authority is a bootstrap
    cycle — the scope must be authenticated independently of the
    conditional evidence it is about to authorize — and refuses.
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
    entry so a stale or forged chain records a typed non-result instead
    of coverage a consumer could inherit. Nothing here registers,
    publishes, or converts the conditional body: ``complete`` remains
    context-free-false and only ``complete_for(scope)`` re-authenticates.
    """
    typed_view = _typed_scoped_view_8616(scoped_view)
    consuming_scope = (
        typed_view.invocation_scope if typed_view is not None else None
    )
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
