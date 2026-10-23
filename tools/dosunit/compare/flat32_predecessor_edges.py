"""Layer: flat32 native control-flow simplification.

Responsibility: remove a branch alternative only after exact SSA proves it
impossible following the block's sole predecessor. Preserve all non-control
effects and keep the evidence independent of cross-image register relations.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _initial_state,
    _LiftedBlock,
    _term_nodes,
)
from tools.dosunit.compare.flat32_constant_branches import (
    BranchValue,
    ConstantBranchProof,
    branch_under_path,
)
from tools.dosunit.compare.flat32_dead_flags import _targets
from tools.dosunit.ssa.composition import compose_block_outputs


@dataclass(frozen=True, slots=True)
class PredecessorEdgeProof:
    """A checked control-only replacement with its sole incoming native edge."""

    predecessor: int
    block: int
    retained: int
    removed: tuple[int, ...]
    implication: ConstantBranchProof

    def to_document(self) -> dict[str, Any]:
        """Retain the precise local implication and its global admission scope."""
        return {
            "predecessor": hex(self.predecessor), "block": hex(self.block),
            "retained": hex(self.retained), "removed": [hex(a) for a in self.removed],
            "method": "sole_predecessor_ssa_implication", "entry_inputs_unrestricted": True,
            "non_control_outputs_unchanged": True, "proof": self.implication.to_document(),
        }


@dataclass(frozen=True, slots=True)
class PredecessorEdgeResult:
    """A private block map plus every consumed control simplification proof."""

    blocks: dict[int, _LiftedBlock]
    proofs: tuple[PredecessorEdgeProof, ...] = ()
    attempted: int = 0


def _ordinary(block: _LiftedBlock) -> bool:
    """Exclude calls, native exceptional obligations and unmodeled effects."""
    return (block.jumpkind == "Ijk_Boring" and not block.tail_targets
            and block.external_slot is None and block.call_target is None
            and not block.part.get("trap_exits") and not block.part.get("obligations")
            and "io" not in block.part["outputs"])


def _compose(
    block: _LiftedBlock, state: dict[str, dict[str, Any]], session: _ComposeSession,
    *, control_only: bool = False,
) -> dict[str, dict[str, Any]]:
    """Charge the existing budget for each actual SSA composition."""
    _check_compose_deadline(session.compose_stats)
    session.compositions += 1
    if session.compositions > session.limits.max_compositions:
        raise CallCompositionRefusal("region_composition_limit")
    outputs = block.part["outputs"]
    selected = {"ip": outputs["ip"]} if control_only else outputs
    result = compose_block_outputs(block.part, selected, state, compose_stats=session.compose_stats)
    if _term_nodes(result, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    return result


def _closed_predecessors(
    blocks: Mapping[int, _LiftedBlock], session: _ComposeSession,
) -> dict[int, list[int]] | None:
    """Check every native control leaf before trusting unique-predecessor metadata."""
    incoming: dict[int, list[int]] = {address: [] for address in blocks}
    for address, block in blocks.items():
        if address != block.address or not set(block.successors).issubset(blocks):
            return None
        if block.jumpkind == "Ijk_Ret":
            if block.successors:
                return None
            continue
        if not _ordinary(block) or "ip" not in block.part["outputs"]:
            return None
        state = _compose(block, _initial_state(session.reg_widths), session, control_only=True)
        if _targets(state["ip"]) != frozenset(block.successors):
            return None
        for target in set(block.successors):
            incoming[target].append(address)
    return incoming


def _at(term: dict[str, Any], address: int) -> dict[str, Any]:
    """Express an exact native control destination as a one-bit predicate."""
    return {"op": "eq", "width": 1, "args": [term, {
        "op": "const", "width": 32, "value": hex(address),
    }]}


def _prove_edge(
    predecessor: _LiftedBlock, block: _LiftedBlock, session: _ComposeSession,
    deadline: float,
) -> PredecessorEdgeProof | None:
    """Use arbitrary predecessor inputs; SAT/UNKNOWN retain both alternatives."""
    initial = _initial_state(session.reg_widths)
    incoming = _compose(predecessor, initial, session)
    path = _at(incoming["ip"], block.address)
    outgoing = _compose(block, incoming, session)
    for target in block.successors:
        remaining = min(100, int((deadline - time.monotonic()) * 1000))
        if remaining <= 0:
            return None
        proof = branch_under_path(_at(outgoing["ip"], target), path, timeout_ms=remaining)
        if proof is not None and proof.value is BranchValue.TRUE:
            return PredecessorEdgeProof(predecessor.address, block.address, target,
                                        tuple(t for t in block.successors if t != target), proof)
    return None


def prune_predecessor_edges(
    blocks: Mapping[int, _LiftedBlock], entry: int, session: _ComposeSession, *, deadline: float,
) -> PredecessorEdgeResult:
    """Prove one-pass native edge pruning in the literal address domain.

    The root has an independent initial entrance and is never simplified.
    Every retained certificate is proved against the original complete block
    map, so multiple simultaneous rewrites cannot justify one another. Only
    the oracle should consume this literal-domain transform when candidate
    constants will later be relocated. Failure keeps the complete original map.
    """
    original = dict(blocks)
    if entry not in blocks or len(blocks) > 64:
        return PredecessorEdgeResult(original)
    try:
        incoming = _closed_predecessors(blocks, session)
        if incoming is None:
            return PredecessorEdgeResult(original)
        proofs = []
        attempted = 0
        for address, block in blocks.items():
            predecessors = incoming[address]
            if address == entry or len(block.successors) != 2 or len(predecessors) != 1:
                continue
            if predecessors[0] == address or not _ordinary(block):
                continue
            attempted += 1
            proof = _prove_edge(blocks[predecessors[0]], block, session, deadline)
            if proof is not None:
                proofs.append(proof)
    except (S.LowerFailure, CallCompositionRefusal):
        return PredecessorEdgeResult(original)
    changed = dict(original)
    for proof in proofs:
        block = original[proof.block]
        outputs = {**block.part["outputs"], "ip": {
            "op": "const", "width": 32, "value": hex(proof.retained),
        }}
        changed[proof.block] = replace(block, part={**block.part, "outputs": outputs},
                                       successors=(proof.retained,))
    return PredecessorEdgeResult(changed, tuple(proofs), attempted)
