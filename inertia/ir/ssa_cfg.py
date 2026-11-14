# cython: language_level=3, infer_types=True
"""Build deterministic CFG proof artifacts from function-level SSA.

Layer: IR.
Responsibility: own closed SSA CFG snapshots, dominator relations, and exact
natural-loop facts used by later typed evidence producers.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from .ssa_cfg_contracts import (
    SSACFGEvidenceStats8616,
    SSACFGFailureKind8616,
    SSACFGSnapshot8616,
    SSADominators8616,
    SSANaturalLoop8616,
    ssa_cfg_neighbors_8616,
)
from .ssa_function import SSAFunctionArtifact
import operator
import builtins


@cython.ccall
def _stats_8616(*, proven: cython.bint, normalized: cython.bint) -> SSACFGEvidenceStats8616:
    """Build closed counters for one proven or refused proof candidate."""
    return SSACFGEvidenceStats8616(1, int(normalized), int(proven), int(proven), int(not proven))


@cython.ccall
def _refused_snapshot_8616(
    function_addr: cython.longlong,
    failure: SSACFGFailureKind8616,
    nodes: object = (),
    *,
    normalized: cython.bint = False,
) -> SSACFGSnapshot8616:
    """Return a refusal without publishing partial adjacency as exact."""
    return SSACFGSnapshot8616(
        function_addr, (), (), (), (), _stats_8616(proven=False, normalized=normalized),
        failure, tuple(sorted(tuple(set(nodes))))
    )


def _validated_block_addrs_8616(
    artifact: SSAFunctionArtifact,
) -> object:
    """Return sorted unique block addresses or a typed refusal snapshot."""
    observed_blocks = tuple(block.addr for block in iter(artifact.blocks))
    block_addrs = tuple(sorted(tuple(set(observed_blocks))))
    if not block_addrs:
        return _refused_snapshot_8616(artifact.function_addr, SSACFGFailureKind8616.EMPTY_CFG)
    if operator.ne(len(block_addrs), len(observed_blocks)):
        return _refused_snapshot_8616(artifact.function_addr, SSACFGFailureKind8616.DUPLICATE_BLOCK, block_addrs)
    if artifact.function_addr not in set(block_addrs):
        return _refused_snapshot_8616(artifact.function_addr, SSACFGFailureKind8616.ENTRY_BLOCK_MISSING)
    return block_addrs


def _normalized_predecessors_8616(
    artifact: SSAFunctionArtifact,
    block_addrs: object,
) -> object:
    """Return sorted per-node predecessors or a typed refusal snapshot."""
    block_set = set(block_addrs)
    map_keys = set(artifact.predecessor_map)
    missing = tuple(sorted(block_set - map_keys))
    if missing:
        return _refused_snapshot_8616(
            artifact.function_addr, SSACFGFailureKind8616.SUCCESSOR_EVIDENCE_INCOMPLETE, missing
        )
    unknown_successors = tuple(sorted(map_keys - block_set))
    if unknown_successors:
        return _refused_snapshot_8616(
            artifact.function_addr, SSACFGFailureKind8616.UNKNOWN_SUCCESSOR, unknown_successors
        )
    unknown_predecessors = tuple(
        sorted(
            {
                predecessor
                for predecessors in builtins.iter(artifact.predecessor_map.values())
                for predecessor in iter(predecessors)
                if predecessor not in block_set
            }
        )
    )
    if unknown_predecessors:
        return _refused_snapshot_8616(
            artifact.function_addr, SSACFGFailureKind8616.UNKNOWN_PREDECESSOR, unknown_predecessors
        )
    predecessors = tuple(
        (node, tuple(sorted(tuple(set(artifact.predecessor_map[node]))))) for node in iter(block_addrs)
    )
    entry_predecessors = ssa_cfg_neighbors_8616(
        predecessors,
        artifact.function_addr,
    )
    if entry_predecessors:
        return _refused_snapshot_8616(
            artifact.function_addr, SSACFGFailureKind8616.ENTRY_HAS_PREDECESSOR,
            entry_predecessors, normalized=True
        )
    return predecessors


@cython.ccall
def _successor_sets_8616(
    block_addrs: object,
    predecessors: object,
) -> object:
    """Invert the predecessor relation into per-node successor sets."""
    source: object
    sources: object
    target: object
    successor_sets = {node: set[int]() for node in iter(block_addrs)}
    for target, sources in predecessors:
        for source in sources:
            successor_sets[source].add(target)
    return successor_sets


@cython.ccall
def _reachable_blocks_8616(
    function_addr: cython.longlong,
    successor_sets: object,
) -> object:
    """Return every block reachable from the function entry."""
    node: object
    successor: object
    reachable = {function_addr}
    pending = [function_addr]
    while pending:
        node = pending.pop()
        for successor in successor_sets[node]:
            if successor not in reachable:
                reachable.add(successor)
                pending.append(successor)
    return reachable


def build_ssa_cfg_snapshot_8616(artifact: SSAFunctionArtifact) -> SSACFGSnapshot8616:
    """Validate and freeze the SSA predecessor relation and its exact inverse."""
    block_addrs = _validated_block_addrs_8616(artifact)
    if isinstance(block_addrs, SSACFGSnapshot8616):
        return block_addrs
    predecessors = _normalized_predecessors_8616(artifact, block_addrs)
    if isinstance(predecessors, SSACFGSnapshot8616):
        return predecessors
    successor_sets = _successor_sets_8616(block_addrs, predecessors)
    successors = tuple((node, tuple(sorted(successor_sets[node]))) for node in iter(block_addrs))
    edges = tuple(sorted((source, target) for source, targets in iter(successors) for target in iter(targets)))
    unreachable = tuple(
        sorted(set(block_addrs) - _reachable_blocks_8616(artifact.function_addr, successor_sets))
    )
    if unreachable:
        return _refused_snapshot_8616(
            artifact.function_addr, SSACFGFailureKind8616.UNREACHABLE_BLOCK,
            unreachable, normalized=True
        )
    return SSACFGSnapshot8616(
        artifact.function_addr, block_addrs, predecessors, successors, edges,
        _stats_8616(proven=True, normalized=True)
    )


def compute_ssa_dominators_8616(snapshot: SSACFGSnapshot8616) -> SSADominators8616:
    """Compute exact deterministic dominator sets for one proven SSA CFG."""
    node: object
    predecessor: object
    if not snapshot.complete:
        return SSADominators8616(
            snapshot.function_addr, (), (), (), _stats_8616(proven=False, normalized=False),
            SSACFGFailureKind8616.SNAPSHOT_UNPROVEN
        )
    all_blocks = frozenset(snapshot.block_addrs)
    dominators = {
        node: ({node} if operator.eq(node, snapshot.function_addr) else set(all_blocks))
        for node in iter(snapshot.block_addrs)
    }
    changed = True
    while changed:
        changed = False
        for node in snapshot.block_addrs:
            if operator.eq(node, snapshot.function_addr):
                continue
            predecessors = snapshot.predecessors(node)
            if not predecessors:
                raise ValueError("proven reachable SSA CFG node has no predecessor")
            common = set(dominators[predecessors[0]])
            for predecessor in predecessors[1:]:
                common.intersection_update(dominators[predecessor])
            updated = {node, *common}
            if operator.ne(updated, dominators[node]):
                dominators[node] = updated
                changed = True
    frozen = tuple((node, tuple(sorted(dominators[node]))) for node in iter(snapshot.block_addrs))
    return SSADominators8616(
        snapshot.function_addr, snapshot.block_addrs, snapshot.edges, frozen,
        _stats_8616(proven=True, normalized=True)
    )


@cython.ccall
def _refused_loop_8616(
    header: cython.longlong,
    latch: cython.longlong,
    failure: SSACFGFailureKind8616,
    *,
    normalized: cython.bint = False,
) -> SSANaturalLoop8616:
    """Return a loop refusal without publishing a partial body or edge set."""
    return SSANaturalLoop8616(
        header, latch, (), (), (), (), _stats_8616(proven=False, normalized=normalized), failure
    )


@cython.ccall
def _loop_input_refusal_8616(
    snapshot: SSACFGSnapshot8616,
    dominators: SSADominators8616,
    header: cython.longlong,
    latch: cython.longlong,
) -> SSANaturalLoop8616 | None:
    """Return a refusal when loop inputs are not proven or consistent."""
    latch_successors: object
    if not snapshot.complete or not dominators.complete:
        return _refused_loop_8616(header, latch, SSACFGFailureKind8616.SNAPSHOT_UNPROVEN)
    if (
        operator.ne(dominators.function_addr, snapshot.function_addr)
        or operator.ne(dominators.block_addrs, snapshot.block_addrs)
        or operator.ne(dominators.cfg_edges, snapshot.edges)
    ):
        return _refused_loop_8616(header, latch, SSACFGFailureKind8616.CFG_MISMATCH)
    missing = tuple(sorted({header, latch} - set(snapshot.block_addrs)))
    if missing:
        return _refused_loop_8616(header, latch, SSACFGFailureKind8616.LOOP_NODE_MISSING)
    latch_successors = snapshot.successors(latch)
    if latch_successors is None or header not in latch_successors:
        return _refused_loop_8616(header, latch, SSACFGFailureKind8616.LATCH_BACKEDGE_MISSING, normalized=True)
    if dominators.dominates(header, latch) is not True:
        return _refused_loop_8616(header, latch, SSACFGFailureKind8616.HEADER_DOMINANCE_UNPROVEN, normalized=True)
    return None


def _forward_region_8616(
    snapshot: SSACFGSnapshot8616,
    header: cython.longlong,
    latch: cython.longlong,
) -> object:
    """Return nodes reachable forward from the header without re-entering it."""
    node: object
    successors: object
    forward: set[cython.longlong] = set()
    pending = [header]
    while pending:
        node = pending.pop()
        if node in forward:
            continue
        forward.add(node)
        successors = snapshot.successors(node)
        if successors is None:
            return _refused_loop_8616(header, latch, SSACFGFailureKind8616.SNAPSHOT_UNPROVEN)
        pending.extend(reversed(tuple(target for target in iter(successors) if target != header)))
    return forward


@cython.ccall
def _loop_body_8616(
    snapshot: SSACFGSnapshot8616,
    dominators: SSADominators8616,
    header: cython.longlong,
    latch: cython.longlong,
) -> object:
    """Close the latch predecessors over header-dominated nodes."""
    node: object
    predecessors: object
    predecessor: object
    body = {header, latch}
    pending = [latch]
    while pending:
        node = pending.pop()
        predecessors = snapshot.predecessors(node)
        if predecessors is None:
            return _refused_loop_8616(header, latch, SSACFGFailureKind8616.SNAPSHOT_UNPROVEN)
        for predecessor in reversed(predecessors):
            if predecessor not in body:
                if dominators.dominates(header, predecessor) is not True:
                    continue
                body.add(predecessor)
                if predecessor != header:
                    pending.append(predecessor)
    return body


def _unique_loop_boundary_8616(
    snapshot: SSACFGSnapshot8616,
    header: cython.longlong,
    latch: cython.longlong,
    forward: object,
    body: object,
) -> object:
    """Prove a unique latch, unique entry target, and single exit target."""
    header_predecessors: object
    header_predecessors = snapshot.predecessors(header)
    if header_predecessors is None:
        return _refused_loop_8616(header, latch, SSACFGFailureKind8616.SNAPSHOT_UNPROVEN)
    latches = tuple(source for source in iter(header_predecessors) if source in forward)
    if latches != (latch,):
        return _refused_loop_8616(header, latch, SSACFGFailureKind8616.NON_UNIQUE_LATCH, normalized=True)
    entry_edges = tuple(edge for edge in iter(snapshot.edges) if edge[0] not in body and edge[1] in body)
    if any(target != header for _source, target in iter(entry_edges)):
        return _refused_loop_8616(
            header,
            latch,
            SSACFGFailureKind8616.NON_UNIQUE_ENTRY,
            normalized=True,
        )
    exit_edges = tuple(edge for edge in iter(snapshot.edges) if edge[0] in body and edge[1] not in body)
    if len({target for _source, target in iter(exit_edges)}) != 1:
        return _refused_loop_8616(
            header, latch, SSACFGFailureKind8616.NON_UNIQUE_EXIT_TARGET, normalized=True
        )
    return entry_edges, exit_edges


@cython.ccall
def classify_ssa_natural_loop_8616(
    snapshot: SSACFGSnapshot8616,
    dominators: SSADominators8616,
    header: cython.longlong,
    latch: cython.longlong,
) -> SSANaturalLoop8616:
    """Prove one single-entry, single-latch, single-exit-target natural loop."""
    refusal: object
    refusal = _loop_input_refusal_8616(snapshot, dominators, header, latch)
    if refusal is not None:
        return refusal
    forward = _forward_region_8616(snapshot, header, latch)
    if isinstance(forward, SSANaturalLoop8616):
        return forward
    body = _loop_body_8616(snapshot, dominators, header, latch)
    if isinstance(body, SSANaturalLoop8616):
        return body
    boundary = _unique_loop_boundary_8616(snapshot, header, latch, forward, body)
    if isinstance(boundary, SSANaturalLoop8616):
        return boundary
    entry_edges, exit_edges = boundary
    return SSANaturalLoop8616(
        header, latch, tuple(sorted(body)), entry_edges, ((latch, header),), exit_edges,
        _stats_8616(proven=True, normalized=True)
    )


__all__ = [
    "SSACFGEvidenceStats8616", "SSACFGFailureKind8616", "SSACFGSnapshot8616",
    "SSADominators8616", "SSANaturalLoop8616", "build_ssa_cfg_snapshot_8616",
    "classify_ssa_natural_loop_8616", "compute_ssa_dominators_8616",
]
