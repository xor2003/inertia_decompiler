"""Layer: IR.
Responsibility: consume a native invocation proof as a conditional CFG partition.

The backward cone of a returning path is insufficient: full entry reachability
after removing proved-dead edges must equal that cone. Raw blocks remain owned
by the native artifact; nothing here publishes a universal body or deletes code.
"""
from __future__ import annotations

from types import MappingProxyType

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRBlock, IRFunctionArtifact
from .direct_evidence_deadline import direct_evidence_deadline_expired_8616
from .near_return_continuation_view import ScopedNearReturnContinuationView8616, _scope_binds_premise_8616
from .real16_invocation_domain import (
    Real16CallChainLink8616,
    Real16InvocationDomain8616,
    prove_fresh_real16_chained_invocation_domain_8616,
)
from .scoped_control_obligations import _continuation_effective_blocks_8616, _obligation_surface_failure_8616
from .scoped_function_ir_view import ScopedFunctionCFGProjection8616
from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

_MAX_BLOCKS = 4096


def _return_address(
    artifact: IRFunctionArtifact, proven: frozenset[int],
) -> int | None:
    """Select the single native terminal covered by this bounded return rule."""
    if len(proven) != 1:
        return None
    matches = tuple(block for block in artifact.blocks if block.addr in proven)
    if len(matches) != 1 or not matches[0].instrs:
        return None
    address = matches[0].instrs[-1].addr
    return address if type(address) is int else None


def _domain_bound(
    view: ScopedNearReturnContinuationView8616, scope: Real16InvocationDomain8616,
) -> bool:
    """Reauthenticate the same native entry, return target, and closed ledger."""
    domain = view.reachability_domain
    if (type(domain) is not Real16InvocationDomain8616
            or type(scope.chain) is not Real16CallChainLink8616
            or domain.chain is not scope.chain or domain.project is not scope.project
            or domain.boot is not scope.boot):
        return False
    if domain.boot_recompute is not scope.boot_recompute:
        return False
    if (view.failure is not None or view.invocation_scope is not scope
            or view.selector_proof is not None or view.selector_application is not None
            or domain.coverage is not None):
        return False
    failure, _detail, premise, proven = _obligation_surface_failure_8616(view.source_artifact, view.boundary)
    if (failure is not None or premise is not view.premise or proven != view.proven_block_addrs
            or domain.callsite_addr != _return_address(view.source_artifact, proven)):
        return False
    counts = (view.raw_fact_count, view.normalized_fact_count, view.classified_fact_count,
              view.materialized_count, view.failure_count)
    count = len(proven) + len(domain.infeasible_edges)
    if any(type(value) is not int for value in counts) or counts != (count, count, count, count, 0):
        return False
    with segment_call_dependency_traversal_scope_8616():
        return (premise is not None
                and _scope_binds_premise_8616(scope, premise, view.source_artifact, view.boundary)
                and domain.complete)


def _reachable_successors(
    artifact: IRFunctionArtifact, domain: Real16InvocationDomain8616,
) -> dict[int, tuple[int, ...]] | None:
    """Walk the full native graph, never equating a backward cone with liveness."""
    if len(artifact.blocks) > _MAX_BLOCKS:
        return None
    blocks = {block.addr: block for block in artifact.blocks}
    if len(blocks) != len(artifact.blocks) or artifact.function_addr not in blocks:
        return None
    edges = frozenset((block.addr, target) for block in artifact.blocks for target in block.successor_addrs)
    dead = frozenset(domain.infeasible_edges)
    if len(dead) != len(domain.infeasible_edges) or not dead <= edges:
        return None
    successors: dict[int, tuple[int, ...]] = {}
    pending = [artifact.function_addr]
    while pending:
        if direct_evidence_deadline_expired_8616(domain.project):
            return None
        addr = pending.pop()
        if addr in successors:
            continue
        if addr not in blocks:
            return None
        targets = tuple(target for target in blocks[addr].successor_addrs if (addr, target) not in dead)
        if len(targets) != len(set(targets)):
            return None
        successors[addr] = targets
        pending.extend(targets)
    if set(successors) != set(domain.path_block_addrs):
        return None
    return successors


def _live_effective_blocks(
    view: ScopedNearReturnContinuationView8616, successors: dict[int, tuple[int, ...]],
) -> tuple[IRBlock, ...] | None:
    """Keep the raw census, refusing every residual obligation on a live block."""
    blocks: tuple[IRBlock, ...] | None = _continuation_effective_blocks_8616(
        view.source_artifact.blocks, view.proven_block_addrs,
    )
    if blocks is None:
        return None
    exits = {addr for addr, targets in successors.items() if not targets}
    if exits != view.proven_block_addrs:
        return None
    for block in blocks:
        if block.addr not in successors:
            continue
        if block.refusals or not block.instrs:
            return None
        if block.addr in exits and block.instrs[-1].op != "RET":
            return None
    return blocks


def scoped_reachable_return_projection_8616(
    view: ScopedNearReturnContinuationView8616,
    consuming_scope: Real16InvocationDomain8616 | None,
) -> ScopedFunctionCFGProjection8616 | None:
    """Replay the proof and expose only its entry-reachable conditional edges."""
    if (consuming_scope is None or type(consuming_scope) is not Real16InvocationDomain8616
            or direct_evidence_deadline_expired_8616(consuming_scope.project)
            or not _domain_bound(view, consuming_scope)):
        return None
    domain = view.reachability_domain
    assert domain is not None
    successors = _reachable_successors(view.source_artifact, domain)
    if successors is None:
        return None
    blocks = _live_effective_blocks(view, successors)
    if blocks is None:
        return None
    predecessors: dict[int, list[int]] = {block.addr: [] for block in blocks}
    for source, targets in successors.items():
        for target in targets:
            predecessors[target].append(source)
    return ScopedFunctionCFGProjection8616(
        function_addr=view.source_artifact.function_addr,
        source_artifact=view.source_artifact, scope=consuming_scope, applied=(), blocks=blocks,
        successors=MappingProxyType(successors),
        predecessors=MappingProxyType({addr: tuple(sorted(rows)) for addr, rows in predecessors.items()}),
        pending=MappingProxyType({block.addr: block.refusals for block in blocks}),
        unreachable_block_addrs=frozenset(predecessors) - frozenset(successors),
    )


def prove_scoped_reachable_return_view_8616(
    project: object, artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
    *, invocation_scope: Real16InvocationDomain8616 | None,
) -> ScopedNearReturnContinuationView8616 | None:
    """Construct a conditional return view without accepting a merely returning cone."""
    scope = invocation_scope
    if (scope is None or type(scope) is not Real16InvocationDomain8616 or scope.project is not project
            or type(scope.chain) is not Real16CallChainLink8616
            or direct_evidence_deadline_expired_8616(project)):
        return None
    failure, _detail, premise, proven = _obligation_surface_failure_8616(artifact, boundary)
    terminal = _return_address(artifact, proven)
    if failure is not None or premise is None or terminal is None:
        return None
    if not _scope_binds_premise_8616(scope, premise, artifact, boundary):
        return None
    domain = prove_fresh_real16_chained_invocation_domain_8616(
        project, None, terminal, boot=scope.boot, boot_recompute=scope.boot_recompute,
        chain=scope.chain, declared_services=scope.declared_services,
    )
    if domain is None:
        return None
    count = len(proven) + len(domain.infeasible_edges)
    view = ScopedNearReturnContinuationView8616(
        source_artifact=artifact, boundary=boundary, failure=None, detail="",
        proven_block_addrs=proven, raw_fact_count=count, normalized_fact_count=count,
        classified_fact_count=count, materialized_count=count, failure_count=0,
        premise=premise, invocation_scope=scope, reachability_domain=domain,
    )
    return view if scoped_reachable_return_projection_8616(view, scope) is not None else None
