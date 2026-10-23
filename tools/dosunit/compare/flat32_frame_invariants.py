"""Layer: dosunit relational loop proofs.

Responsibility: discharge EBP == ESP + k at interior cuts on each complete graph,
then specialize inputs without removing any observable output.
"""
from __future__ import annotations

import time
from typing import Any

from tools.comparator.verdict import Status
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import _initial_state, _register_widths, _term_nodes
from tools.dosunit.compare.flat32_constant_registers import _document
from tools.dosunit.compare.flat32_dead_flags import _state, _targets
from tools.dosunit.contracts.register_affine_relations import _linear_effect
from tools.dosunit.contracts.register_state_relations import RegisterRelationRefusal
from tools.dosunit.ssa.composition import compose_block_outputs


def _frame_base(stack: dict[str, Any], offset: int) -> dict[str, Any]:
    """Construct modular frame arithmetic without changing any observed flags."""
    if not offset:
        return stack
    return {"op": "add", "width": 32, "args": [
        stack, {"op": "const", "width": 32, "value": hex(offset)}]}


def _propose_offset(document: dict[str, Any], deadline: float) -> int | None:
    """Derive a constant root frame difference as an untrusted proposal."""
    state = _state(document["functions"][0], deadline)
    if not {"ebp", "esp"}.issubset(state):
        return None
    difference = {"op": "sub", "width": 32, "args": [state["ebp"], state["esp"]]}
    effect = _linear_effect(difference, 32)
    return effect.offset if effect.multiplier == 0 else None


def _specialize(document: dict[str, Any], deadline: float, offset: int) -> list[dict[str, Any]]:
    """Keep arbitrary entry inputs and substitute only interior frame inputs."""
    states = []
    for index, function in enumerate(document["functions"]):
        initial = _initial_state(_register_widths())
        if index:
            initial["ebp"] = _frame_base(initial["esp"], offset)
        state = compose_block_outputs(function, function["outputs"], initial,
                                      compose_stats={"deadline": deadline})
        selected = {name: state[name] for name in function["outputs"]}
        if _term_nodes(selected, 50000) > 50000:
            raise S.LowerFailure("frame_invariant_expression_limit", "frame invariant expression budget")
        states.append(selected)
    return states


def _prove_side(
    document: dict[str, Any], deadline: float, offset: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """Require a closed graph and initiation/preservation on all continuing edges.

    Repeated tokens are allowed: every transition at that token must prove.
    Entry backedges are rejected because entry inputs have a different contract.
    Returns retain all observations and need not preserve the frame invariant.
    """
    functions = document["functions"]
    tokens = [function["source"].get("cutpoint_token") for function in functions]
    if any(not isinstance(token, int) for token in tokens) or tokens[0] in tokens[1:]:
        return None
    states = _specialize(document, deadline, offset)
    proofs = []
    for index, (function, state) in enumerate(zip(functions, states, strict=True)):
        kind = function["source"]["jumpkind"]
        if kind == "Ijk_Ret":
            continue
        if kind != "Ijk_Boring" or not {"ebp", "esp", "eip"}.issubset(state):
            return None
        successors = _targets(state["eip"])
        if not successors or not successors.issubset(tokens) or tokens[0] in successors:
            return None
        timeout_ms = min(250, int((deadline - time.monotonic()) * 1000))
        if timeout_ms <= 0:
            return None
        proof = S._compare_functions(
            _document({}, {"eax": state["ebp"]}), _document({}, {"eax": _frame_base(state["esp"], offset)}),
            timeout_ms=timeout_ms,
        )
        if proof["status"] != Status.PASSED.value:
            return None
        proofs.append({"transition": index, "successors": sorted(successors), "proof": proof})
    if not proofs:
        return None
    projected = [_document(function, state) for function, state in zip(functions, states, strict=True)]
    return {**document, "functions": projected}, proofs


def frame_invariant_projection(
    oracle: dict[str, Any], candidate: dict[str, Any], *, deadline: float,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Independently prove the same interior equality before comparing effects.

    This first version accepts literal coordinates only. Normalized constants
    require invariant proofs in exactly that normalized semantic domain.
    No ABI premise, memory projection or output suppression is introduced.
    """
    if not oracle["functions"] or not candidate["functions"]:
        return None
    if max(len(oracle["functions"]), len(candidate["functions"])) > 64:
        return None
    functions = oracle["functions"] + candidate["functions"]
    if any(function.get("_constant_normalization") for function in functions):
        return None
    try:
        offset = _propose_offset(oracle, deadline)
        if offset is None or offset != _propose_offset(candidate, deadline):
            return None
        left = _prove_side(oracle, deadline, offset)
        if left is None:
            return None
        right = _prove_side(candidate, deadline, offset)
    except (S.LowerFailure, RegisterRelationRefusal):
        return None
    if right is None:
        return None
    evidence = {
        "method": "inductive_interior_frame_offset",
        "relation": {"register": "ebp", "base": "esp", "offset": offset, "width": 32},
        "entry_inputs_unrestricted": True,
        "all_outputs_preserved": True,
        "oracle_initiation_and_preservation": left[1],
        "candidate_initiation_and_preservation": right[1],
    }
    return left[0], right[0], evidence
