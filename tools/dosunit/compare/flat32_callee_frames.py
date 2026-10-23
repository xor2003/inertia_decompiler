"""Layer: validation call composition.

Responsibility: expand complete callees with proved return frames into induction.

CALL establishes its literal return slot. Every continuing callee block must
preserve that slot at a proved offset from ESP, and RET must read it. These
independent native proofs justify only return routing; all data effects and
loop divergence remain in the paired graph.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _initial_state,
    _LiftedBlock,
    _ret_proof_timeout_ms,
    _term_nodes,
)
from tools.dosunit.compare.flat32_call_lowering import _lift_function
from tools.dosunit.compare.flat32_constant_registers import _document
from tools.dosunit.compare.flat32_dead_flags import _targets
from tools.dosunit.contracts.register_affine_relations import _linear_effect
from tools.dosunit.contracts.register_state_relations import RegisterRelationRefusal
from tools.dosunit.ssa.composition import compose_block_outputs
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector


@dataclass(frozen=True)
class _FrameCertificate:
    proofs: list[dict[str, Any]]
    controls: dict[int, dict[str, Any]]


def _constant(value: int) -> dict[str, Any]:
    return {"op": "const", "width": 32, "value": hex(value)}


def _state(session: _ComposeSession, block: _LiftedBlock,
           initial: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    _check_compose_deadline(session.compose_stats)
    session.compositions += 1
    if session.compositions > session.limits.max_compositions:
        raise CallCompositionRefusal("region_composition_limit")
    result = compose_block_outputs(block.part, block.part["outputs"], initial,
                                   compose_stats=session.compose_stats)
    if _term_nodes(result, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    return result


def _prove(session: _ComposeSession, actual: dict[str, Any],
           expected: dict[str, Any]) -> dict[str, Any] | None:
    proof = S._compare_functions(_document({}, actual), _document({}, expected),
                                 timeout_ms=_ret_proof_timeout_ms(session))
    return proof if proof.get("status") == "passed" else None


def _offset(term: dict[str, Any], value: int) -> dict[str, Any]:
    return {"op": "add", "width": 32, "args": [term, _constant(value & 0xFFFFFFFF)]}


def _stack_offsets(session: _ComposeSession, blocks: dict[int, _LiftedBlock],
                   entry: int) -> tuple[dict[int, int], dict[int, dict[str, Any]]] | None:
    """Propose one native ESP displacement per cut; proofs follow independently."""
    initial = _initial_state(session.reg_widths)
    offsets, pending = {entry: 0}, deque([entry])
    controls = {}
    while pending:
        address = pending.popleft()
        block = blocks[address]
        if block.jumpkind == "Ijk_Ret":
            continue
        if block.jumpkind != "Ijk_Boring" or not set(block.successors).issubset(blocks):
            return None
        state = _state(session, block, initial)
        controls[address] = state["ip"]
        try:
            effect = _linear_effect({"op": "sub", "width": 32,
                                     "args": [state["esp"], initial["esp"]]}, 32)
        except RegisterRelationRefusal:
            return None
        if effect.multiplier != 0:
            return None
        delta = (offsets[address] + effect.offset) & 0xFFFFFFFF
        for successor in block.successors:
            if successor in offsets:
                if offsets[successor] != delta:
                    return None
            else:
                offsets[successor] = delta
                pending.append(successor)
    return (offsets, controls) if set(offsets) == set(blocks) else None


def _closed_block(block: _LiftedBlock, blocks: dict[int, _LiftedBlock]) -> bool:
    """Exclude unmodeled effects and boundaries from the return-frame proof."""
    if (block.jumpkind not in {"Ijk_Boring", "Ijk_Ret"} or block.tail_targets
            or block.external_slot is not None or block.part.get("trap_exits")
            or "io" in block.part["outputs"]):
        return False
    return set(block.successors).issubset(blocks)


def _certificate(session: _ComposeSession, call: _LiftedBlock,
                 blocks: dict[int, _LiftedBlock]) -> _FrameCertificate | None:
    """Prove initiation, preservation and return routing on literal semantics."""
    if call.fallthrough is None or call.call_target is None:
        return None
    proposed = _stack_offsets(session, blocks, call.call_target)
    if proposed is None:
        return None
    offsets, controls = proposed
    initial = _initial_state(session.reg_widths)
    called = _state(session, call, initial)
    slot = {"op": "loadle", "width": 32, "args": [called["memory"], called["esp"]]}
    proof = _prove(session, {"eax": slot, "eip": called["ip"]},
                   {"eax": _constant(call.fallthrough), "eip": _constant(call.call_target)})
    if proof is None:
        return None
    records = [{"block": hex(call.address), "obligation": "call_establishes_return_slot", "proof": proof}]
    returns = 0
    for address, block in blocks.items():
        if not _closed_block(block, blocks):
            return None
        slot_address = _offset(initial["esp"], -offsets[address])
        before = {**initial, "memory": {"op": "storele", "width": 0, "args": [
            initial["memory"], slot_address, _constant(call.fallthrough)]}}
        state = _state(session, block, before)
        if block.jumpkind == "Ijk_Ret":
            returns += 1
            proof = _prove(session, {"eip": state["ip"]}, {"eip": _constant(call.fallthrough)})
            obligation = "return_reads_preserved_slot"
        else:
            if _targets(state.get("ip", {})) != frozenset(block.successors):
                return None
            if not block.successors:
                return None
            delta = offsets[block.successors[0]]
            after_slot = {"op": "loadle", "width": 32, "args": [
                state["memory"], _offset(state["esp"], -delta)]}
            proof = _prove(session, {"eax": after_slot, "esp": state["esp"]},
                           {"eax": _constant(call.fallthrough),
                            "esp": _offset(initial["esp"], delta - offsets[address])})
            obligation = "preserves_return_slot_and_stack_offset"
        if proof is None:
            return None
        records.append({"block": hex(address), "obligation": obligation, "proof": proof,
                        "entry_stack_displacement": hex(offsets[address])})
    return _FrameCertificate(records, controls) if returns else None


def _route(term: dict[str, Any], mapping: dict[int, int]) -> dict[str, Any]:
    """Rename only native control leaves; data addresses remain literal."""
    constant = constant_bitvector(term)
    if constant is not None and constant[1] == 32 and constant[0] in mapping:
        return _constant(mapping[constant[0]])
    args = term.get("args", [])
    if term.get("op") == "ite" and len(args) == 3:
        return {**term, "args": [args[0], _route(args[1], mapping), _route(args[2], mapping)]}
    raise CallCompositionRefusal("callee_frame_control_unmapped")


def _clone(block: _LiftedBlock, address: int, mapping: dict[int, int],
           continuation: int, certificate: _FrameCertificate) -> _LiftedBlock:
    successors: tuple[int, ...]
    if block.jumpkind == "Ijk_Ret":
        control, successors = _constant(continuation), (continuation,)
    else:
        control = _route(certificate.controls[block.address], mapping)
        successors = tuple(mapping[target] for target in block.successors)
    part = {**block.part, "outputs": {**block.part["outputs"], "ip": control}}
    return replace(block, address=address, part=part, jumpkind="Ijk_Boring",
                   successors=successors, call_target=None, fallthrough=None)


def _frame_children(session: _ComposeSession, entry: int) -> set[int] | None:
    """Find only dependencies that can be represented by a complete frame graph."""
    try:
        blocks = _lift_function(session, entry)
    except CallCompositionRefusal:
        _check_compose_deadline(session.compose_stats)
        return None
    children: set[int] = set()
    for block in blocks.values():
        if block.tail_targets or block.external_slot is not None or block.part.get("trap_exits"):
            return None
        if "io" in block.part["outputs"]:
            return None
        if block.jumpkind == "Ijk_Call":
            if block.call_target not in session.functions or block.fallthrough not in blocks:
                return None
            assert block.call_target is not None
            children.add(block.call_target)
        elif block.jumpkind not in {"Ijk_Boring", "Ijk_Ret"}:
            return None
    return children


def _closed_frame_graph(session: _ComposeSession, entry: int, cache: dict[int, bool]) -> bool:
    """Reject incomplete call DAGs before spending any symbolic composition work.

    This is only a necessary structural condition. A positive result never
    substitutes for a return-slot certificate or equivalence proof.
    """
    pending = [(entry, False)]
    visiting: set[int] = set()
    examined: set[int] = set()
    while pending:
        _check_compose_deadline(session.compose_stats)
        address, leaving = pending.pop()
        if leaving:
            visiting.remove(address)
            cache[address] = True
            continue
        if address in visiting or cache.get(address) is False:
            cache[entry] = False
            return False
        if cache.get(address) is True:
            continue
        examined.add(address)
        if len(examined) > session.limits.max_inlined_calls:
            return False
        children = _frame_children(session, address)
        if children is None:
            cache[address] = cache[entry] = False
            return False
        visiting.add(address)
        pending.append((address, True))
        pending.extend((child, False) for child in sorted(children, reverse=True))
    return True


def _expand_nested_frames(
    session: _ComposeSession, root: dict[int, _LiftedBlock], active: frozenset[int],
    closed: dict[int, bool],
) -> tuple[dict[int, _LiftedBlock], list[dict[str, Any]]]:
    """Clone each admitted call context separately under existing work budgets.

    Nested bodies are certified from leaves, then the entire expanded parent
    receives its own return-slot proof. Recursive calls remain unexpanded. Failed
    candidates keep their original CALL and therefore its ordinary checker.
    Synthetic coordinates are control labels only, never rewritten data.
    """
    expanded = dict(root)
    records = []
    used = set(root) | set(session.functions)
    next_address = 0xF0000000
    for address, call in root.items():
        if (call.jumpkind != "Ijk_Call" or call.call_target is None
                or call.call_target not in session.functions or call.fallthrough not in root
                or call.call_target in active):
            continue
        if session.inlined_calls >= session.limits.max_inlined_calls or session.limits.max_inline_depth < 1:
            break
        # Reserve every attempted context before descending, including failures.
        # This bounds recursive construction without increasing the shared cap.
        session.inlined_calls += 1
        if not _closed_frame_graph(session, call.call_target, closed):
            continue
        blocks = _lift_function(session, call.call_target)
        blocks, nested = _expand_nested_frames(session, blocks, active | {call.call_target}, closed)
        certificate = _certificate(session, call, blocks)
        if certificate is None:
            continue
        cap = session.limits.retry_max_blocks_per_function or session.limits.max_blocks_per_function
        if len(expanded) + len(blocks) > cap:
            break
        mapping = {}
        for original in blocks:
            while next_address in used:
                next_address += 1
            mapping[original] = next_address
            used.add(next_address)
            next_address += 1
        assert call.fallthrough is not None
        for original, block in blocks.items():
            expanded[mapping[original]] = _clone(block, mapping[original], mapping, call.fallthrough, certificate)
        part = {**call.part, "outputs": {**call.part["outputs"], "ip": _constant(mapping[call.call_target])}}
        expanded[address] = replace(call, part=part, jumpkind="Ijk_Boring",
                                    successors=(mapping[call.call_target],), call_target=None, fallthrough=None)
        records.append({"call_block": hex(address), "callee": hex(call.call_target),
                        "fallthrough": hex(call.fallthrough), "proofs": certificate.proofs,
                        "nested_callees": nested,
                        "cloned_blocks": {hex(k): hex(v) for k, v in mapping.items()}})
    return expanded, records


def expand_frame_safe_callees(
    session: _ComposeSession, root: dict[int, _LiftedBlock],
) -> tuple[dict[int, _LiftedBlock], list[dict[str, Any]]]:
    """Expand independently certified nested frames within shared work budgets.

    Every successful outer certificate includes all child memory/stack effects.
    A child certificate alone never exempts writes to an ancestor's return slot.
    """
    return _expand_nested_frames(session, root, frozenset(), {})
