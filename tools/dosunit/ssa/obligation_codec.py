"""Layer: SSA evidence serialization.

Responsibility: encode self-contained predicates without expanding shared
nodes, and decode their local references back into a shared inline DAG.
"""

from __future__ import annotations

from typing import Any

ENCODING: str = "inline_ssa_dag_v1"
_LEAVES = frozenset({"input", "mem_input", "const"})
type Term = dict[str, Any]


def _arguments(node: Term) -> list[Term]:
    """Validate node shape without silently dropping malformed children."""
    if "ref" in node or not isinstance(node.get("op"), str):
        raise ValueError("predicate requires self-contained SSA nodes")
    args = node.get("args", [])
    if not isinstance(args, list) or any(not isinstance(arg, dict) for arg in args):
        raise ValueError("predicate arguments must be SSA objects")
    if node["op"] in _LEAVES and args:
        raise ValueError("predicate leaf has arguments")
    return args


def encode_obligation(record: Term) -> Term:
    """Copy a predicate record into a deterministic, locally scoped DAG."""
    if "predicate_encoding" in record:
        decode_obligation(record)
        return dict(record)
    root = record.get("predicate")
    if not isinstance(root, dict):
        raise ValueError("predicate must be an SSA object")
    if "predicate_assignments" in record:
        raise ValueError("unlabelled predicate assignments")
    encoded: dict[int, Term] = {}
    active: set[int] = set()
    definitions: list[Term] = []
    pending = [(root, False)]
    while pending:
        node, ready = pending.pop()
        key = id(node)
        if key in encoded:
            continue
        args = _arguments(node)
        if ready:
            body = dict(node)
            body["args"] = [encoded[id(arg)] for arg in args]
            if "id" in body:
                raise ValueError("inline predicate node contains assignment id")
            ident = f"p{len(definitions)}"
            definitions.append({"id": ident, **body})
            encoded[key] = {"ref": ident}
            active.remove(key)
        elif node["op"] in _LEAVES:
            encoded[key] = dict(node)
        else:
            if key in active:
                raise ValueError("cyclic inline predicate")
            active.add(key)
            pending.append((node, True))
            pending.extend((arg, False) for arg in reversed(args))
    return {**record, "predicate": encoded[id(root)],
            "predicate_assignments": definitions, "predicate_encoding": ENCODING}


def _resolve(term: Any, definitions: dict[str, Term]) -> Term:  # noqa: ANN401
    """Resolve a local backward reference or retain an inline leaf."""
    if not isinstance(term, dict):
        raise ValueError("encoded predicate operand must be an object")
    if "ref" in term:
        ref = term["ref"]
        if set(term) != {"ref"} or not isinstance(ref, str) or ref not in definitions:
            raise ValueError("invalid, forward or dangling predicate reference")
        return definitions[ref]
    _arguments(term)
    if term["op"] not in _LEAVES:
        raise ValueError("encoded predicate has an unassigned operator")
    return dict(term)


def decode_obligation(record: Term) -> Term:
    """Restore sharing; reject unknown encodings, duplicate IDs and cycles."""
    if record.get("predicate_encoding") != ENCODING:
        raise ValueError("unknown predicate encoding")
    items = record.get("predicate_assignments")
    if not isinstance(items, list):
        raise ValueError("predicate assignments must be a list")
    definitions: dict[str, Term] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("predicate assignment must be an object")
        ident = item.get("id")
        if not isinstance(ident, str) or not ident or ident in definitions:
            raise ValueError("invalid or duplicate predicate assignment id")
        args = _arguments(item)
        if item["op"] in _LEAVES:
            raise ValueError("predicate leaves must remain inline")
        body = {key: value for key, value in item.items() if key != "id"}
        body["args"] = [_resolve(arg, definitions) for arg in args]
        definitions[ident] = body
    return _resolve(record.get("predicate"), definitions)


def encode_bound_predicates(document: Term) -> Term:
    """Copy completed evidence, compacting bound x87 predicates after solving."""
    memo: dict[int, tuple[Any, Any]] = {}

    def visit(value: Any) -> Any:  # noqa: ANN401
        """Preserve shared evidence records without traversing predicate trees."""
        if not isinstance(value, (dict, list)):
            return value
        cached = memo.get(id(value))
        if cached is not None and cached[0] is value:
            return cached[1]
        if isinstance(value, list):
            items: list[Any] = []
            memo[id(value)] = (value, items)
            items.extend(visit(item) for item in value)
            return items
        result: Term = {}
        # Encoded assignment containers are temporary. Keep their originals
        # alive so later records cannot reuse an earlier cached object's ID.
        memo[id(value)] = (value, result)
        source = encode_obligation(value) if value.get("kind") == "x87_pending_check" else value
        result.update((key, visit(item)) for key, item in source.items())
        return result

    result = visit(document)
    assert isinstance(result, dict)
    return result
