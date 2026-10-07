"""Serialize composed SSA DAGs and discover their complete inputs.

Layer: dosunit SSA materialization.
Responsibility: preserve deterministic assignment order, memoized DAG identity
and scalar/array input widths without architecture or solver setup.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


def materialize_term(
    term: dict[str, Any],
    *,
    assignments: list[dict[str, Any]],
    memo: dict[str, str],
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Materialize each shared term once while retaining deterministic references."""
    if term_cache is None:
        term_cache = {}
    cache_key = id(term)
    cached = term_cache.get(cache_key)
    if cached is not None and cached[0] is term:
        return cached[1]
    op = term.get("op")
    if op in {"input", "mem_input", "const"}:
        result = copy.deepcopy(term)
        term_cache[cache_key] = (term, result)
        return result
    args = [
        materialize_term(arg, assignments=assignments, memo=memo, term_cache=term_cache)
        for arg in term.get("args", []) or []
        if isinstance(arg, dict)
    ]
    shallow = {"op": str(op), "width": _term_width(term), "args": args}
    key = _materialized_term_key(shallow)
    if key in memo:
        result = {"ref": memo[key]}
        term_cache[cache_key] = (term, result)
        return result
    ident = f"v{len(assignments)}"
    memo[key] = ident
    assignments.append({"id": ident, **shallow})
    result = {"ref": ident}
    term_cache[cache_key] = (term, result)
    return result


def _materialized_term_key(term: dict[str, Any]) -> str:
    """Keep the existing ordered shallow assignment identity representation."""
    parts: list[tuple[Any, ...]] = []
    for arg in term.get("args", []) or []:
        if not isinstance(arg, dict):
            continue
        if "ref" in arg:
            parts.append(("ref", str(arg["ref"])))
            continue
        op = str(arg.get("op"))
        if op == "input":
            parts.append(("input", str(arg.get("name")), int(arg.get("width", 16))))
        elif op == "mem_input":
            parts.append(
                ("mem_input", str(arg.get("name")), int(arg.get("addr_width", 32)), int(arg.get("value_width", 8)))
            )
        elif op == "const":
            parts.append(("const", str(arg.get("value")), int(arg.get("width", 16))))
        else:
            parts.append(("term", _term_identity(arg)))
    return repr((str(term.get("op")), _term_width(term), tuple(parts)))


@dataclass
class _TermInputScan:
    """Mutable scan state for collecting input items from SSA terms."""

    widths: dict[str, int] = field(default_factory=dict)
    memory_inputs: set[str] = field(default_factory=set)
    assignment_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    seen_terms: set[int] = field(default_factory=set)
    seen_refs: set[str] = field(default_factory=set)

    def visit(self, term: dict[str, Any]) -> None:
        """Visit terms iteratively, deduping by identity and ref name."""
        pending: list[object] = [term]
        while pending:
            item = pending.pop()
            if not isinstance(item, dict):
                continue
            term_key = id(item)
            if term_key in self.seen_terms:
                continue
            self.seen_terms.add(term_key)
            if "ref" in item:
                ref = str(item["ref"])
                if ref in self.seen_refs:
                    continue
                self.seen_refs.add(ref)
                assignment = self.assignment_by_id.get(ref)
                if assignment is not None:
                    pending.extend(assignment.get("args", []) or [])
                continue
            if self._visit_leaf(str(item.get("op") or ""), item):
                continue
            pending.extend(item.get("args", []) or [])

    def _visit_leaf(self, op: str, term: dict[str, Any]) -> bool:
        """Record input/mem_input leaves; True when the term is a leaf."""
        if op == "input" and term.get("name"):
            name = str(term["name"])
            self.widths[name] = max(self.widths.get(name, 0), int(term.get("width", 16)))
            return True
        if op == "mem_input" and term.get("name"):
            self.memory_inputs.add(str(term["name"]))
            return True
        return False


def input_items(terms: Iterable[object], assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Discover scalar and named-array inputs through assignment references."""
    scan = _TermInputScan(
        assignment_by_id={
            str(item.get("id")): item
            for item in assignments
            if isinstance(item, dict) and item.get("id") is not None
        }
    )
    for term in terms:
        if isinstance(term, dict):
            scan.visit(term)
    items = [
        {"kind": "memory", "name": name, "addr_width": 32, "value_width": 8}
        for name in sorted(scan.memory_inputs)
    ]
    items.extend({"name": name, "width": width} for name, width in sorted(scan.widths.items()))
    return items


def _term_width(term: dict[str, Any]) -> int:
    """Retain width zero for arrays and the historical scalar default."""
    if term.get("op") == "mem_input":
        return 0
    return int(term.get("width", 16))


def _term_identity(term: dict[str, Any]) -> str:
    """Encode the existing sorted JSON identity without changing leaf values."""
    import json

    return json.dumps(term, sort_keys=True, separators=(",", ":"))


