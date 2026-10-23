"""Layer: dosunit SSA dependency semantics.

Responsibility: expose the exact flag-helper argument demands only for fixed
selectors, preserving unknown and relocated expressions conservatively.
"""
from __future__ import annotations

from typing import Any

from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector
from tools.dosunit.ssa.x86_lazy_conditions import carry_contract, condition_contract, condition_dependency_bits


def fixed_literal(term: dict[str, Any], relocated: frozenset[int]) -> int | None:
    """Use only a direct literal whose raw and modular values cannot relocate.

    Constant-expression folding is unsuitable here: its operands may relocate
    even when the folded value is absent from the map.
    """
    if term.get("op") != "const":
        return None
    literal = constant_bitvector(term)
    if literal is None:
        return None
    raw = term["value"]
    value = int(raw, 0) if isinstance(raw, str) else int(raw)
    keys = {value, literal[0]}
    if literal[1] > 16:
        keys.add(literal[0] & 0xFFFF)  # The shared normalizer also tries a low-word key.
    return literal[0] if keys.isdisjoint(relocated) else None



def flag_argument_demands(
    term: dict[str, Any], relocated: frozenset[int],
) -> list[tuple[dict[str, Any], int]] | None:
    """Use exact helper contracts only with fixed, nonrelocatable selectors."""
    if term.get("op") not in {"summary_x86g_calculate_condition", "summary_x86g_calculate_eflags_c"}:
        return None
    args = term.get("args", [])
    if any(int(arg.get("width", 0)) <= 0 for arg in args):
        return None
    if term.get("op") == "summary_x86g_calculate_condition" and len(args) == 5:
        kind = condition_contract(fixed_literal(args[0], relocated), fixed_literal(args[1], relocated))
        dependencies = args[2:]
    elif term.get("op") == "summary_x86g_calculate_eflags_c" and len(args) == 4:
        kind = carry_contract(fixed_literal(args[0], relocated))
        dependencies = args[1:]
    else:
        return None
    if kind is None:
        return None
    return [(arg, min(bits, int(arg["width"])))
            for arg, bits in zip(dependencies, condition_dependency_bits(kind), strict=True)]



def project_flag_dependencies(
    term: dict[str, Any], memo: dict[int, dict[str, Any]] | None = None,
    *, relocated: frozenset[int] = frozenset(),
) -> dict[str, Any]:
    """Drop only zero-demand arguments of fixed native flag helpers.

    Retain all demanded bits and aliases, and preserve shared expression DAGs.
    Unknown or possibly relocated selectors authorize no projection. An
    iterative postorder walk avoids adding a Python recursion-depth limit.
    """
    cache = {} if memo is None else memo
    pending: dict[int, list[dict[str, Any]]] = {}
    stack = [(term, False)]
    while stack:
        current, expanded = stack.pop()
        ident = id(current)
        if ident in cache:
            continue
        if expanded:
            args = pending.pop(ident)
            cache[ident] = ({**current, "args": [cache[id(arg)] for arg in args]}
                            if args else current)
            continue
        demands = flag_argument_demands(current, relocated)
        args = current.get("args", [])
        if demands is not None:
            selectors = len(args) - len(demands)
            args = [*args[:selectors], *(arg if bits else
                    {"op": "const", "width": arg["width"], "value": "0x0"}
                    for arg, bits in demands)]
        pending[ident] = args
        stack.append((current, True))
        stack.extend((arg, False) for arg in reversed(args))
    return cache[id(term)]
