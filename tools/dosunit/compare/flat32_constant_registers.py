"""Layer: dosunit relational loop proofs.

Responsibility: discharge constant scratch-register invariants and project only
coordinates whose oracle values have no influence on any retained observation.
"""
from __future__ import annotations

import time
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import _initial_state, _register_widths, _term_nodes
from tools.dosunit.ssa.composition import compose_block_outputs
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector


def _document(source: dict[str, Any], terms: dict[str, Any]) -> dict[str, Any]:
    """Serialize only retained dependencies, keeping native transition identity."""
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    outputs = {name: materialize_term(term, assignments=assignments, memo=memo, term_cache=cache)
               for name, term in terms.items()}
    return {**source, "outputs": outputs, "assignments": assignments,
            "inputs": input_items(outputs.values(), assignments)}


def _proposal(term: dict[str, Any]) -> dict[str, Any] | None:
    """Recognize literals and self-subtraction as proposals, never as proof."""
    literal = constant_bitvector(term)
    if literal is not None:
        value, width = literal
        return {"op": "const", "width": width, "value": hex(value)}
    args = term.get("args", [])
    if term.get("op") in {"sub", "xor"} and len(args) == 2 and args[0] == args[1]:
        return {"op": "const", "width": term["width"], "value": "0x0"}
    return None


def _states(document: dict[str, Any], deadline: float, register: str = "",
            constant: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Compose identity at entry and a proposed invariant only at interior cuts."""
    result = []
    for index, function in enumerate(document["functions"]):
        initial = _initial_state(_register_widths())
        if index and constant is not None:
            initial[register] = constant
        state = compose_block_outputs(function, function["outputs"], initial,
                                      compose_stats={"deadline": deadline})
        selected = {name: state[name] for name in function["outputs"]}
        if _term_nodes(selected, 50000) > 50000:
            raise S.LowerFailure("constant_register_expression_limit", "invariant expression budget")
        result.append(selected)
    return result


def _is_dead(document: dict[str, Any], states: list[dict[str, Any]], register: str) -> bool:
    """Require no return observation or dependency on the projected coordinate."""
    for function, state in zip(document["functions"], states, strict=True):
        if function["source"]["jumpkind"] == "Ijk_Ret" and register in function["outputs"]:
            return False
        remaining = [term for name, term in state.items() if name != register]
        if any(item["name"] == register for item in input_items(remaining, [])):
            return False
    return True


def constant_register_projection(
    oracle: dict[str, Any], candidate: dict[str, Any], *, deadline: float,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]] | None:
    """Prove successive candidate constants against dead oracle coordinates.

    Every continuing transition, including root entry, must establish the same
    constant. All final observations remain exact. The other image must never
    depend on the projected register outside its own unobserved value. These
    stronger sufficient conditions avoid any unproved liveness assumption.
    """
    if not oracle["functions"] or len(oracle["functions"]) != len(candidate["functions"]):
        return None
    if len(oracle["functions"]) > 64:
        return None
    evidence: list[dict[str, Any]] = []
    try:
        originals = _states(oracle, deadline)
        rebuilt = _states(candidate, deadline)
        for register in ("eax", "ecx", "edx"):
            projected = _project_register(oracle, candidate, originals, rebuilt, register, deadline)
            if projected is not None:
                oracle, candidate, proved = projected
                evidence.extend(proved)
                originals = _states(oracle, deadline)
                rebuilt = _states(candidate, deadline)
    except S.LowerFailure:
        return None
    return (oracle, candidate, evidence) if evidence else None


def _project_register(
    oracle: dict[str, Any], candidate: dict[str, Any], originals: list[dict[str, Any]],
    rebuilt: list[dict[str, Any]], register: str, deadline: float,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]] | None:
    """Discharge one proposed scratch coordinate before projecting either side."""
    if not _is_dead(oracle, originals, register):
        return None
    if any(f["source"]["jumpkind"] == "Ijk_Ret" and register in f["outputs"]
           for f in candidate["functions"]):
        return None
    constant = _proposal(rebuilt[0].get(register, {}))
    if constant is None or constant.get("width") != 32:
        return None
    specialized = _states(candidate, deadline, register, constant)
    proofs: list[dict[str, Any]] = []
    for index, (function, state) in enumerate(zip(candidate["functions"], specialized, strict=True)):
        if function["source"]["jumpkind"] == "Ijk_Ret":
            continue
        timeout_ms = min(250, int((deadline - time.monotonic()) * 1000))
        if timeout_ms <= 0 or register not in state:
            return None
        proof = S._compare_functions(_document({}, {"eax": constant}),
                                     _document({}, {"eax": state[register]}), timeout_ms=timeout_ms)
        proofs.append({"transition": index, "proof": proof})
        if proof["status"] != "passed":
            break
    if not proofs or any(item["proof"]["status"] != "passed" for item in proofs):
        return None
    projected = []
    for document, states in ((oracle, originals), (candidate, specialized)):
        functions = [_document(function, {key: term for key, term in state.items() if key != register})
                     for function, state in zip(document["functions"], states, strict=True)]
        projected.append({**document, "functions": functions})
    evidence = {"register": register, "candidate_constant": constant,
                "oracle_coordinate_dead": True, "return_observations_preserved": True,
                "initiation_and_preservation": proofs}
    return projected[0], projected[1], [evidence]
