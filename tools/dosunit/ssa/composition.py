"""Compose serialized SSA DAGs with exact input and array substitution.

Layer: dosunit SSA composition.
Responsibility: retain assignment sharing, exact named memory spaces and
existing deadline refusals without importing the comparator engine.
"""

from __future__ import annotations

import time
from typing import Any, cast

from tools.dosunit.contracts.ssa import LowerFailure
from tools.dosunit.ssa.materialization import _term_width


def _compose_deadline_check(compose_stats: dict[str, Any] | None) -> None:
    """Raise ``compose_budget_exceeded`` when the wall-clock deadline is reached.

    Inner loops (block output substitution, branch-arm state merges) can spend
    minutes between block-entry budget checks on multi-million-node terms, so
    the deadline is also enforced inside those loops via this lighter check.
    """
    if compose_stats is None:
        return
    deadline = compose_stats.get("deadline")
    if isinstance(deadline, float) and time.monotonic() >= deadline:
        raise LowerFailure(
            "compose_budget_exceeded",
            "ABI compose exceeded its wall-clock deadline",
        )


def compose_block_outputs(
    block: dict[str, Any],
    block_outputs: dict[str, Any],
    incoming_state: dict[str, dict[str, Any]],
    *,
    compose_stats: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Compose block outputs into the state by inlining assignments and substituting inputs."""
    assignments = {
        str(item["id"]): item for item in block.get("assignments", []) or [] if isinstance(item, dict) and "id" in item
    }
    state = dict(incoming_state)
    inline_cache: dict[str, dict[str, Any]] = {}
    substitute_cache: dict[int, dict[str, Any]] = {}
    inlined_keepalive: list[dict[str, Any]] = []
    for name, term in block_outputs.items():
        if not isinstance(term, dict):
            continue
        _compose_deadline_check(compose_stats)
        inlined = _inline_ssa_json_term(term, assignments=assignments, cache=inline_cache)
        inlined_keepalive.append(inlined)
        state[str(name)] = substitute_inputs(inlined, incoming_state, cache=substitute_cache)
    return state


def _term_children(
    left: object,
    right: object,
) -> list[tuple[object, object]] | None:
    """Expand a JSON term pair into child pairs, or ``None`` on shape divergence."""
    if left is right:
        return []
    if type(left) is not type(right):
        return None
    if isinstance(left, dict):
        right_dict = cast(dict[object, object], right)
        if left.keys() != right_dict.keys():
            return None
        return [(left[key], right_dict[key]) for key in left]
    if isinstance(left, list):
        right_list = cast(list[object], right)
        if len(left) != len(right_list):
            return None
        return list(zip(left, right_list, strict=True))
    if left != right:
        return None
    return []


def _abi_terms_equal(
    left: object,
    right: object,
    eq_cache: dict[tuple[int, int], bool],
    *,
    compose_stats: dict[str, Any] | None = None,
) -> bool:
    """Structural equality for SSA JSON term DAGs.

    Terms preserve node sharing, so plain ``==`` walks every root-to-leaf path
    and is exponential on deep ``ite`` DAGs.  Memoizing on ``(id, id)`` pairs
    makes the comparison proportional to the DAG's node count instead.  The
    cache is only valid while every compared term stays alive (ids are reused
    after GC), so it is scoped to one ABI composition.  Pairs marked
    provisionally are rewound to ``False`` when a descendant proves unequal.
    """
    stack: list[tuple[object, object]] = [(left, right)]
    pending: list[tuple[int, int]] = []
    equal = True
    visited = 0
    try:
        while stack and equal:
            visited += 1
            if visited & 0xFFFF == 0:
                _compose_deadline_check(compose_stats)
            l_item, r_item = stack.pop()
            if l_item is r_item:
                continue
            children = _term_children(l_item, r_item)
            if children is None:
                equal = False
                break
            if not children:
                continue
            pair = (id(l_item), id(r_item))
            cached = eq_cache.get(pair)
            if cached is not None:
                if not cached:
                    equal = False
                continue
            eq_cache[pair] = True
            pending.append(pair)
            stack.extend(children)
    finally:
        if not equal:
            for pair in pending:
                eq_cache[pair] = False
    return equal


def merge_states(
    condition: dict[str, Any],
    true_state: dict[str, dict[str, Any]],
    false_state: dict[str, dict[str, Any]],
    *,
    compose_stats: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Merge guarded states without duplicating structurally equal shared DAGs."""
    eq_cache: dict[tuple[int, int], bool] | None = None
    eq_keepalive: list[tuple[object, object]] | None = None
    if compose_stats is not None:
        eq_cache = compose_stats.setdefault("eq_cache", {})
        eq_keepalive = compose_stats.setdefault("eq_keepalive", [])
    merged: dict[str, dict[str, Any]] = {}
    for key in sorted(set(true_state) | set(false_state)):
        _compose_deadline_check(compose_stats)
        left = true_state.get(key)
        right = false_state.get(key)
        if left is None:
            merged[key] = cast(dict[str, Any], right)
            continue
        if right is None:
            merged[key] = left
            continue
        if left is right:
            merged[key] = left
            continue
        if eq_cache is None:
            equal = left == right
        else:
            equal = _abi_terms_equal(left, right, eq_cache, compose_stats=compose_stats)
            if eq_keepalive is not None:
                # Pin compared roots so id() values backing eq_cache entries
                # cannot be recycled by GC while the cache remains in use.
                eq_keepalive.append((left, right))
        if equal:
            merged[key] = left
            continue
        merged[key] = {"op": "ite", "width": _term_width(left), "args": [condition, left, right]}
    return merged


def _inline_ssa_json_term(
    term: dict[str, Any], *, assignments: dict[str, dict[str, Any]], cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Resolve assignment references with a caller-scoped shared-node cache."""
    if "ref" in term:
        ident = str(term["ref"])
        if ident in cache:
            return cache[ident]
        item = assignments.get(ident)
        if item is None:
            raise LowerFailure("unsupported_ir", f"SSA ref {ident} was not found")
        inlined = {
            "op": str(item.get("op")),
            "width": int(item.get("width", 16)),
            "args": [
                _inline_ssa_json_term(arg, assignments=assignments, cache=cache)
                for arg in item.get("args", []) or []
                if isinstance(arg, dict)
            ],
        }
        cache[ident] = inlined
        return inlined
    copied = dict(term)
    if isinstance(term.get("args"), list):
        copied["args"] = [
            _inline_ssa_json_term(arg, assignments=assignments, cache=cache)
            for arg in term.get("args", []) or []
            if isinstance(arg, dict)
        ]
    return copied


def substitute_inputs(
    term: dict[str, Any],
    state: dict[str, dict[str, Any]],
    *,
    cache: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Substitute exact named scalar/array inputs without merging memory spaces.

    The canonical program array ``mem`` binds the owned ``memory`` state key;
    other array names bind only their exact state key. An unbound array remains
    an explicit input. Legacy unnamed program roots retain their ``mem`` default.
    """
    if cache is None:
        cache = {}
    key = id(term)
    if key in cache:
        return cache[key]
    op = term.get("op")
    if op == "input" and str(term.get("name")) in state:
        result = state[str(term["name"])]
        cache[key] = result
        return result
    if op == "mem_input":
        name = term.get("name", "mem")
        if not isinstance(name, str) or not name:
            raise LowerFailure("unsupported_ir", "array input requires an exact nonempty name")
        state_key = "memory" if name == "mem" else name
        result = state.get(state_key, term)
        cache[key] = result
        return result
    copied = dict(term)
    cache[key] = copied
    if isinstance(term.get("args"), list):
        copied["args"] = [
            substitute_inputs(arg, state, cache=cache) for arg in term["args"] if isinstance(arg, dict)
        ]
    return copied

