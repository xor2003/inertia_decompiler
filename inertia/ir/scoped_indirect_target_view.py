"""Compose an invocation-proven indirect edge with ordinary selector discharge.

Layer: IR.
Responsibility: retain conditional raw input and expose a freshly authenticated
CFG projection only under its exact consuming call-chain entry.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRBlock, IRFunctionArtifact, IRValue, MemSpace
from .entry_jump_domain import (
    EntryJumpDomainApplicationStatus8616,
    _source_digest_8616,
    apply_entry_jump_domain_8616,
    prove_entry_jump_domains_8616,
)
from .invocation_indirect_target import (
    InvocationIndirectTarget8616,
    _seed_authority,
    discover_invocation_indirect_target_8616,
)
from .real16_invocation_domain import Real16CallChainLink8616, Real16InvocationDomain8616, same_real16_entry_scope_8616
from .scoped_function_ir_view import ScopedFunctionCFGProjection8616
from .segment_call_preservation import segment_call_dependency_traversal_scope_8616
from .vex_import import IRImportRefusalReason8616, raw_x86_16_import_bundle_for_artifact_8616
from .vex_terminal_jump import TerminalJumpEvidence8616


class ScopedIndirectTargetFailure8616(StrEnum):
    """A scoped indirect edge never converts missing authority into coverage."""

    UNPROVED = "scoped_indirect_target_unproved"


@dataclass(frozen=True, slots=True)
class ScopedIndirectTargetView8616:
    """Raw native ownership plus a replay recipe; no context-free completeness."""

    project: object = field(compare=False, repr=False)
    source_artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    discovery: InvocationIndirectTarget8616
    invocation_scope: Real16InvocationDomain8616
    terminal_evidence: Mapping[int, TerminalJumpEvidence8616]
    invocation_resolver: Callable[[int], Real16InvocationDomain8616 | None] | None
    source_digest: str
    failure: ScopedIndirectTargetFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def cfg_projection_for(self, invocation: Real16InvocationDomain8616) -> ScopedFunctionCFGProjection8616 | None:
        """Reauthenticate the indirect theorem and relative obligations each use."""
        if self.failure is not None:
            return None
        with segment_call_dependency_traversal_scope_8616():
            return _projection(self, invocation)


def prove_scoped_indirect_target_view_8616(
    project: object, artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
    discovery: InvocationIndirectTarget8616, invocation_scope: Real16InvocationDomain8616,
    terminal_evidence: Mapping[int, TerminalJumpEvidence8616], *,
    invocation_resolver: Callable[[int], Real16InvocationDomain8616 | None] | None = None,
) -> ScopedIndirectTargetView8616:
    """Build one conditional view without mutating or publishing its raw source."""
    view = ScopedIndirectTargetView8616(
        project, artifact, boundary, discovery, invocation_scope,
        MappingProxyType(dict(terminal_evidence)), invocation_resolver,
        _source_digest_8616(artifact.function_addr, artifact.blocks), None,
        1, 1, 1, 0, 1,
    )
    with segment_call_dependency_traversal_scope_8616():
        projection = _projection(view, invocation_scope)
    if projection is None:
        return replace(view, failure=ScopedIndirectTargetFailure8616.UNPROVED)
    count = 1 + len(projection.applied)
    return replace(view, raw_fact_count=count, normalized_fact_count=count,
                   classified_fact_count=count, materialized_count=count, failure_count=0)


def _bound_scope(view: ScopedIndirectTargetView8616, scope: Real16InvocationDomain8616) -> bool:
    """Bind the same exact native CALL and raw callee, then replay entry authority."""
    if type(scope) is not Real16InvocationDomain8616 or scope.project is not view.project:
        return False
    chain = scope.chain
    if type(chain) is not Real16CallChainLink8616:
        return False
    return bool(
        view.boundary.project is view.project and scope.coverage is None
        and chain.parent is view.discovery.invocation
        and chain.callsite is view.discovery.decoded_call
        and chain.callee_artifact is view.source_artifact
        and chain.callee_boundary is view.boundary
        and same_real16_entry_scope_8616(scope, view.invocation_scope)
    )


def _effective_source(view: ScopedIndirectTargetView8616) -> IRFunctionArtifact | None:
    """Discharge only the singleton's pending terminal, retaining every other fact."""
    raw, receipt, boundary = view.source_artifact, view.discovery, view.boundary
    if (raw.function_addr != receipt.function_addr or boundary.addr != raw.function_addr
            or _source_digest_8616(raw.function_addr, raw.blocks) != view.source_digest):
        return None
    edges = boundary.conditional_edges
    if len(edges) != 1 or (edges[0].block_addr, edges[0].instruction_addr, edges[0].target_addr) != (
        receipt.block_addr, receipt.instruction_addr, receipt.target,
    ):
        return None
    if {block.addr for block in raw.blocks} != boundary.block_addrs_set:
        return None
    changed: list[IRBlock] = []
    matches = 0
    for block in raw.blocks:
        if block.addr != receipt.block_addr:
            changed.append(block)
            continue
        replacement = _effective_block(block, receipt)
        if replacement is None:
            return None
        changed.append(replacement)
        matches += 1
    if matches != 1 or not all(
        any(item in block.refusals for block in raw.blocks if block.addr == item.block_addr)
        for item in raw.refusals
    ):
        return None
    return replace(raw, blocks=tuple(changed), refusals=tuple(
        item for item in raw.refusals
        if not (item.kind == IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING and item.block_addr == receipt.block_addr)
    ))


def _effective_block(block: IRBlock, receipt: InvocationIndirectTarget8616) -> IRBlock | None:
    """Keep the native origin and all effects while binding the proved control value."""
    if not block.instrs or block.successor_addrs != (receipt.target,):
        return None
    terminal = block.instrs[-1]
    marker = IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING
    if (terminal.op != "JMP" or terminal.addr != receipt.instruction_addr or terminal.origin is None
            or len(terminal.args) != 1 or not isinstance(terminal.args[0], IRValue)):
        return None
    if not any(item.kind == marker for item in block.refusals):
        return None
    return replace(
        block, instrs=(*block.instrs[:-1], replace(terminal, args=(IRValue(MemSpace.CONST, const=receipt.target, size=4),))),
        refusals=tuple(item for item in block.refusals if item.kind != marker),
    )


def _projection(
    view: ScopedIndirectTargetView8616, scope: Real16InvocationDomain8616,
) -> ScopedFunctionCFGProjection8616 | None:
    """Replay the singleton before composing the existing relative-jump theorem."""
    if not _bound_scope(view, scope):
        return None
    seed = _seed_authority(view.discovery.invocation)
    if seed is None:
        return None
    native = raw_x86_16_import_bundle_for_artifact_8616(view.project, view.boundary, view.source_artifact)
    if native is None:
        return None
    fresh = discover_invocation_indirect_target_8616(view.discovery.invocation, view.discovery.decoded_call)
    if fresh != view.discovery:
        return None
    effective = _effective_source(view)
    if effective is None:
        return None
    proof = prove_entry_jump_domains_8616(
        effective, native.terminal_evidence, project=view.project, invocation_resolver=view.invocation_resolver,
    )
    application = apply_entry_jump_domain_8616(effective, proof, invocation_scope=scope)
    if application.status is EntryJumpDomainApplicationStatus8616.STALE_INPUT:
        return None
    blocks = application.blocks
    if any(block.refusals for block in blocks):
        return None
    if (not _bound_scope(view, scope) or _effective_source(view) is None
            or raw_x86_16_import_bundle_for_artifact_8616(view.project, view.boundary, view.source_artifact) is None):
        return None
    # Later relative-proof/native callbacks must not invalidate the earlier
    # singleton's explicit data premise while leaving callee entry unchanged.
    if _seed_authority(view.discovery.invocation) != seed:
        return None
    successors = {block.addr: block.successor_addrs for block in blocks}
    predecessors = {address: tuple(block.addr for block in blocks if address in block.successor_addrs) for address in successors}
    return ScopedFunctionCFGProjection8616(
        effective.function_addr, view.source_artifact, scope, application.applied, blocks,
        MappingProxyType(successors), MappingProxyType(predecessors),
        MappingProxyType({block.addr: block.refusals for block in blocks}),
    )
