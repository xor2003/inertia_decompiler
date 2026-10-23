"""Layer: dosunit relational loop proofs.

Responsibility: infer conservative low-bit demands over a closed paired CFG.
Only intermediate scratch coordinates may shrink; all return observations and
every dependency of memory, control and external effects remain exact.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import _check_compose_deadline
from tools.dosunit.compare.flat32_constant_registers import _document
from tools.dosunit.compare.flat32_dead_flags import _obligation_terms, _state, _targets
from tools.dosunit.ssa.composition import _abi_terms_equal
from tools.dosunit.ssa.x86_flag_dependencies import fixed_literal, flag_argument_demands

SCRATCH: frozenset[str] = frozenset({"eax", "ecx", "edx"})



def _argument_demands(term: dict[str, Any], bits: int, relocated: frozenset[int]) -> list[tuple[dict[str, Any], int]]:
    """Propagate low-bit needs only through operators with local bit dependence."""
    args = term.get("args", [])
    op = term.get("op")
    flag_demands = flag_argument_demands(term, relocated)
    if flag_demands is not None:
        return flag_demands
    if op in {"sub", "xor"} and len(args) == 2 and _abi_terms_equal(args[0], args[1], {}):
        return []
    if op in {"trunc", "zext", "sext", "add", "sub", "mul", "and", "or", "xor", "not"}:
        if op == "and" and len(args) == 2:
            literals = [fixed_literal(arg, relocated) for arg in args]
            for literal in literals:
                if literal is not None:
                    bits = min(bits, (literal & ((1 << bits) - 1)).bit_length())
        return [(arg, min(bits, int(arg.get("width", 32)))) for arg in args]
    if op == "ite" and len(args) == 3:
        return [(args[0], int(args[0].get("width", 32))),
                (args[1], bits), (args[2], bits)]
    # Unknown operators, comparisons, shifts and addresses require full operands.
    # Width zero is memory: traversing it still reaches every address/value.
    return [(arg, int(arg.get("width", 32))) for arg in args]


def _dependencies(term: dict[str, Any], bits: int, relocated: frozenset[int]) -> dict[str, int]:
    """Collect conservative scratch input demands, memoizing DAG visits."""
    result: dict[str, int] = {}
    pending = [(term, bits)]
    seen: set[tuple[int, int]] = set()
    while pending:
        current, needed = pending.pop()
        key = (id(current), needed)
        if key in seen:
            continue
        seen.add(key)
        if needed == 0 and current.get("width", 0) != 0:
            continue
        if current.get("op") == "input" and current.get("name") in SCRATCH:
            name = current["name"]
            result[name] = max(result.get(name, 0), needed)
        pending.extend(_argument_demands(current, needed, relocated))
    return result


@dataclass
class _Pair:
    """Expanded states and conservative successor union for one transition."""

    token: int
    terminal: bool
    successors: frozenset[int]
    states: tuple[dict[str, Any], dict[str, Any]]
    predicates: tuple[list[dict[str, Any]], list[dict[str, Any]]]


def _pairs(oracle: dict[str, Any], candidate: dict[str, Any], deadline: float) -> list[_Pair] | None:
    """Require aligned complete scratch state and a closed control graph."""
    originals, rebuilt = oracle["functions"], candidate["functions"]
    if not originals or len(originals) != len(rebuilt):
        return None
    result = []
    for left, right in zip(originals, rebuilt, strict=True):
        token = left["source"].get("cutpoint_token")
        terminal = left["source"]["jumpkind"] == "Ijk_Ret"
        if not isinstance(token, int) or token != right["source"].get("cutpoint_token"):
            return None
        if terminal != (right["source"]["jumpkind"] == "Ijk_Ret"):
            return None
        states = (_state(left, deadline), _state(right, deadline))
        if states[0].keys() != states[1].keys() or (not terminal and not SCRATCH.issubset(states[0])):
            return None
        targets = [frozenset()] if terminal else [_targets(state["eip"]) for state in states]
        if any(target is None for target in targets):
            return None
        predicates = (_obligation_terms(left, deadline), _obligation_terms(right, deadline))
        if any(len(terms) != len(function.get("obligations", ()))
               for terms, function in zip(predicates, (left, right), strict=True)):
            return None
        result.append(_Pair(token, terminal, frozenset(t for target in targets if target is not None for t in target),
                            states, predicates))
    tokens = {pair.token for pair in result}
    return result if all(pair.successors <= tokens for pair in result) else None


def _output_bits(pair: _Pair, name: str, term: dict[str, Any], live: dict[int, dict[str, int]]) -> int:
    """Return observations stay full; continuing scratch follows successor demand."""
    if pair.terminal or name not in SCRATCH:
        return int(term.get("width", 32))
    return max((live[token][name] for token in pair.successors), default=32)



def _predicate_demands(pair: _Pair, relocated: frozenset[int]) -> dict[str, int]:
    """Treat every bound precondition as a mandatory full-width observation."""
    demands: dict[str, int] = {}
    for predicates in pair.predicates:
        for predicate in predicates:
            for name, bits in _dependencies(predicate, int(predicate.get("width", 1)), relocated).items():
                demands[name] = max(demands.get(name, 0), bits)
    return demands


def _live_bits(pairs: list[_Pair], deadline: float, relocated: frozenset[int]) -> dict[int, dict[str, int]]:
    """Propagate union demands to a fixed point, keeping entry identity exact."""
    live = {pair.token: dict.fromkeys(sorted(SCRATCH), 0) for pair in pairs}
    live[pairs[0].token] = dict.fromkeys(sorted(SCRATCH), 32)
    for pair in pairs:
        for name, bits in _predicate_demands(pair, relocated).items():
            live[pair.token][name] = max(live[pair.token][name], bits)
    changed = True
    while changed:
        changed = False
        for pair in pairs:
            _check_compose_deadline({"deadline": deadline})
            for state in pair.states:
                for name, term in state.items():
                    bits = _output_bits(pair, name, term, live)
                    for register, required in _dependencies(term, bits, relocated).items():
                        if required > live[pair.token][register]:
                            live[pair.token][register] = required
                            changed = True
    return live


def _projected_document(function: dict[str, Any], state: dict[str, Any],
                        predicates: list[dict[str, Any]]) -> dict[str, Any]:
    """Materialize retained predicates with the same fresh assignment namespace."""
    names = [f"__predicate_{index}" for index in range(len(predicates))]
    document = _document(function, {**state, **dict(zip(names, predicates, strict=True))})
    document["obligations"] = [
        {**obligation, "predicate": document["outputs"].pop(name)}
        for obligation, name in zip(function.get("obligations", ()), names, strict=True)
    ]
    return document


def narrow_register_projection(
    oracle: dict[str, Any], candidate: dict[str, Any], *, deadline: float,
    candidate_normalization: Mapping[int, int] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Prove bit independence before proposing low-coordinate equality.

    The solver still proves all projected transitions. Independence on BOTH
    sides plus successor closure makes equality of retained low bits inductive.
    Entry backedges retain full scratch state because entry inputs use identity.
    No ABI is inferred: retained return registers force full-width demands.
    Relocatable mask literals never justify narrowing. Projection uses widths,
    not new integer masks that could collide with the relocation map.
    """
    try:
        pairs = _pairs(oracle, candidate, deadline)
        if pairs is None:
            return None
        live = _live_bits(pairs, deadline, frozenset(candidate_normalization or ()))
        widths = [{name: _output_bits(pair, name, pair.states[0][name], live)
                   for name in sorted(SCRATCH) if name in pair.states[0] and not pair.terminal} for pair in pairs]
        if not any(bits < 32 for row in widths for bits in row.values()):
            return None
        documents = []
        for side, document in enumerate((oracle, candidate)):
            functions = []
            for function, pair, row in zip(document["functions"], pairs, widths, strict=True):
                state = dict(pair.states[side])
                for name, bits in row.items():
                    if bits == 0:
                        del state[name]
                    elif bits < 32:
                        # Width metadata cannot collide with relocated integer literals.
                        state[name] = {"op": "zext", "width": 32, "args": [
                            {"op": "trunc", "width": bits, "args": [state[name]]}]}
                functions.append(_projected_document(function, state, pair.predicates[side]))
            documents.append({**document, "functions": functions})
    except S.LowerFailure:
        return None
    evidence = {"method": "closed_paired_low_bit_dependency_fixed_point",
                "retained_output_bits": widths,
                "live_input_bits": {str(token): row for token, row in sorted(live.items())},
                "return_observations_preserved": True, "entry_backedges_full_width": True}
    return documents[0], documents[1], evidence
