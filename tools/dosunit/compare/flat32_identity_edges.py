"""Layer: flat32 native control-flow simplification.

Responsibility: contract a non-entry single-successor boring block whose every
architectural output is an exact input passthrough. Admission requires full
coverage of the session register contract (every ``reg_widths`` field present
and passthrough, memory/io unchanged, control leaves constant); a missing or
malformed changed-state output refuses. Only predecessor ``ip``/``eip`` target
leaves and successor lists are redirected; return-slot fallthrough addresses
at call boundaries keep their original values. Cyclic all-identity chains are
retained: contracting them would erase a genuinely divergent path. Every
certificate records exactly which outputs were verified passthrough.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _LiftedBlock,
)
from tools.dosunit.compare.flat32_dead_flags import _targets
from tools.dosunit.compare.flat32_predecessor_edges import _closed_predecessors, _ordinary
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

_CONTROL_OUTPUTS = frozenset({"ip", "eip"})
_MAX_REF_HOPS = 64
_MAX_MATERIALIZE_DEPTH = 64
_MAX_MATERIALIZE_NODES = 4096


@dataclass(frozen=True, slots=True)
class IdentityEdgeProof:
    """A removed all-identity control block and the edges that redirected it."""

    block: int
    successor: int
    predecessors: tuple[int, ...]
    identity_outputs: tuple[str, ...]

    def to_document(self) -> dict[str, Any]:
        """Serialize the contraction certificate with its admission scope."""
        return {
            "block": hex(self.block), "successor": hex(self.successor),
            "predecessors": [hex(p) for p in self.predecessors],
            "method": "identity_control_block_passthrough",
            "identity_outputs": list(self.identity_outputs),
            "non_control_outputs": "input_passthrough",
            "return_slots_unchanged": True,
        }


@dataclass(frozen=True, slots=True)
class IdentityEdgeResult:
    """A private block map plus every consumed identity contraction proof."""

    blocks: dict[int, _LiftedBlock]
    proofs: tuple[IdentityEdgeProof, ...] = ()
    attempted: int = 0
    retained_cycles: tuple[int, ...] = ()


def _assignments(part: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {a["id"]: a for a in part.get("assignments", []) if isinstance(a, dict) and "id" in a}


def _resolve(term: object, assignments: Mapping[str, dict[str, Any]]) -> dict[str, Any] | None:
    """Follow a bounded ``ref`` chain; malformed or cyclic references refuse."""
    for _ in range(_MAX_REF_HOPS):
        if not isinstance(term, dict):
            return None
        if "ref" not in term:
            return term
        term = assignments.get(term["ref"])
        if term is None:
            return None
    return None


def _materialize(
    term: dict[str, Any], assignments: Mapping[str, dict[str, Any]],
    stats: dict[str, Any], budget: list[int], depth: int = _MAX_MATERIALIZE_DEPTH,
) -> dict[str, Any] | None:
    """Inline every ``ref`` along this term under node/depth/deadline bounds."""
    _check_compose_deadline(stats)
    node = _resolve(term, assignments)
    if node is None or depth <= 0 or budget[0] <= 0:
        return None
    budget[0] -= 1
    out = {k: v for k, v in node.items() if k != "id"}
    args = node.get("args")
    if isinstance(args, list):
        materialized = [
            _materialize(a, assignments, stats, budget, depth - 1) if isinstance(a, dict) else a
            for a in args
        ]
        if any(a is None for a in materialized):
            return None
        out["args"] = materialized
    return out


def _identity_fields(  # noqa: C901 — explicit architectural admission checks.
    block: _LiftedBlock, reg_widths: Mapping[str, int], stats: dict[str, Any],
) -> tuple[str, ...] | None:
    """Verified passthrough fields iff this is a fully covered identity jump."""
    part = block.part
    if not _ordinary(block) or len(block.successors) != 1:
        return None
    outputs = part.get("outputs")
    if not isinstance(outputs, dict):
        return None
    if any(key not in outputs for key in reg_widths) or "ip" not in outputs:
        return None
    target = block.successors[0]
    assignments = _assignments(part)
    for key in ("ip", "eip"):
        node = _materialize(outputs[key], assignments, stats, [_MAX_MATERIALIZE_NODES])
        literal = constant_bitvector(node) if node is not None else None
        if literal != (target, 32):
            return None
    fields = []
    for name, term in outputs.items():
        if name in _CONTROL_OUTPUTS:
            continue
        node = _resolve(term, assignments)
        if name == "memory":
            if node is None or node.get("op") != "mem_input" or node.get("name") not in {"mem", "memory"}:
                return None
        elif name not in reg_widths or (node is None or node.get("op") != "input" or node.get("name") != name
              or node.get("width") != reg_widths[name]):
            return None
        fields.append(name)
    return tuple(sorted(fields))


def _redirect_targets(term: dict[str, Any], old: int, new: int) -> dict[str, Any]:
    """Rewrite only ``ite``-arm target leaves equal to ``old``; predicates stay."""
    literal = constant_bitvector(term)
    if literal is not None:
        if literal == (old, 32):
            return {"op": "const", "width": 32, "value": hex(new)}
        return term
    args = term.get("args")
    if term.get("op") == "ite" and isinstance(args, list) and len(args) == 3:
        return {**term, "args": [args[0], _redirect_targets(args[1], old, new),
                                 _redirect_targets(args[2], old, new)]}
    return term


def _identity_cycles(blocks: Mapping[int, _LiftedBlock], eligible: frozenset[int]) -> set[int]:
    """Members of closed single-successor chains that never leave ``eligible``."""
    cyclic: set[int] = set()
    for address in eligible:
        seen = {address}
        node = blocks[address].successors[0]
        while node in eligible and node not in seen:
            seen.add(node)
            node = blocks[node].successors[0]
        if node in seen:
            cyclic.update(seen)
    return cyclic


def contract_identity_edges(  # noqa: C901 — bounded transactional graph rewrite.
    blocks: Mapping[int, _LiftedBlock], entry: int, session: _ComposeSession, *, deadline: float,
) -> IdentityEdgeResult:
    """Remove proved all-identity jump blocks and redirect their incoming edges.

    The root has an independent entrance and is never removed. Admission needs
    a closed control map: one constant successor, boring kind, no calls,
    tail/external transfers, obligations or io, complete architectural output
    coverage with every non-control output an exact input passthrough. A block
    reached through any non-ordinary predecessor or any non-ordinary
    fallthrough is kept, so call return-slot addresses never move. Each
    predecessor's ``ip``/``eip`` arms are rewritten only at constant leaves
    equal to the removed block and both target sets are re-verified against
    the new successor set; any inconsistency retains the block. All-identity
    cycles are retained rather than contracted. Failure keeps the original map.
    """
    original = dict(blocks)
    if entry not in blocks or len(blocks) > 64:
        return IdentityEdgeResult(original)
    try:
        incoming = _closed_predecessors(blocks, session)
        if incoming is None:
            return IdentityEdgeResult(original)
        eligible: dict[int, tuple[str, ...]] = {}
        for address, native_block in blocks.items():
            _check_compose_deadline({"deadline": deadline})
            if address == entry:
                continue
            fields = _identity_fields(native_block, session.reg_widths, session.compose_stats)
            if fields is not None:
                eligible[address] = fields
        cyclic = _identity_cycles(blocks, frozenset(eligible))
        for address in cyclic:
            eligible.pop(address, None)
        current = dict(original)
        predecessors = {k: list(v) for k, v in incoming.items()}
        proofs = []
        attempted = 0
        for address in list(original):
            _check_compose_deadline({"deadline": deadline})
            fields = eligible.get(address)
            block = current.get(address)
            if fields is None or block is None:
                continue
            preds = [p for p in predecessors.get(address, []) if p in current and p != address]
            boundary = any(not _ordinary(current[p]) for p in preds)
            boundary = boundary or any(
                other.fallthrough == address and not _ordinary(other)
                for other in current.values()
            )
            boundary = boundary or any(
                address in other.tail_targets for other in current.values()
            )
            if boundary:
                continue
            attempted += 1
            successor = block.successors[0]
            edits: dict[int, tuple[dict[str, Any], dict[str, Any] | None, tuple[int, ...]]] = {}
            valid = True
            for pred in preds:
                predecessor = current[pred]
                outputs = predecessor.part["outputs"]
                amap = _assignments(predecessor.part)
                budget = [_MAX_MATERIALIZE_NODES]
                ip = _materialize(outputs["ip"], amap, session.compose_stats, budget)
                eip = (_materialize(outputs["eip"], amap, session.compose_stats, budget)
                       if "eip" in outputs else None)
                if ip is None or ("eip" in outputs and eip is None):
                    valid = False
                    break
                original_targets = frozenset(predecessor.successors)
                if _targets(ip) != original_targets or (eip is not None and _targets(eip) != original_targets):
                    valid = False
                    break
                ip = _redirect_targets(ip, address, successor)
                if eip is not None:
                    eip = _redirect_targets(eip, address, successor)
                new_successors = tuple(dict.fromkeys(
                    successor if s == address else s for s in predecessor.successors))
                targets = frozenset(new_successors)
                if _targets(ip) != targets or (eip is not None and _targets(eip) != targets):
                    valid = False
                    break
                edits[pred] = (ip, eip, new_successors)
            if not valid:
                continue
            for pred, (ip, eip, new_successors) in edits.items():
                predecessor = current[pred]
                outputs = {**predecessor.part["outputs"], "ip": ip}
                if eip is not None:
                    outputs["eip"] = eip
                fallthrough = successor if predecessor.fallthrough == address else predecessor.fallthrough
                current[pred] = replace(
                    predecessor, part={**predecessor.part, "outputs": outputs},
                    successors=new_successors, fallthrough=fallthrough,
                )
            for pred in preds:
                if pred not in predecessors.setdefault(successor, []):
                    predecessors[successor].append(pred)
            predecessors[address] = []
            del current[address]
            proofs.append(IdentityEdgeProof(
                block=address, successor=successor, predecessors=tuple(preds),
                identity_outputs=fields,
            ))
        return IdentityEdgeResult(current, tuple(proofs), attempted, tuple(sorted(cyclic)))
    except (S.LowerFailure, CallCompositionRefusal):
        return IdentityEdgeResult(original)
