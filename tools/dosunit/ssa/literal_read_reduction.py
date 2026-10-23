"""Layer: SSA literal-address read simplification.

Responsibility: forward exact stores and skip proved disjoint writes in auxiliary
queries that have no relocation normalization. Preserve unknown aliases.
"""
from __future__ import annotations

import time
from typing import Any, cast

from tools.dosunit.ssa.composition import _abi_terms_equal
from tools.dosunit.ssa.materialization import materialize_term

type Term = dict[str, Any]
type Affine = tuple[str, int]
_MODULUS = 1 << 32
_SCAN_LIMIT = 256


class _ReadReduction:
    """Own bounded affine-address facts and shared equality caches for one query."""

    def __init__(self, constraints: list[Term]) -> None:
        """Accept only explicit valid unsigned32 input intervals."""
        self.bounds: dict[str, tuple[int, int]] = {}
        for item in constraints:
            low, high = item.get("min"), item.get("max")
            if (item.get("kind") == "unsigned_range" and type(low) is int
                    and type(high) is int and 0 <= low <= high < _MODULUS):
                self.bounds[item["name"]] = (low, high)
        self.affines: dict[int, Affine | None] = {}
        self.equalities: dict[tuple[int, int], bool] = {}
        self.forwarded = 0
        self.skipped = 0

    def affine(self, term: Term, depth: int = 0) -> Affine | None:
        """Recognize one input plus a modular offset without rewriting literals."""
        key = id(term)
        if key in self.affines:
            return self.affines[key]
        if depth >= 64 or term.get("width") != 32:
            return None
        self.affines[key] = None
        op, args = term.get("op"), term.get("args", [])
        result = None
        if op == "const":
            raw = term["value"]
            result = ("", (int(raw, 0) if isinstance(raw, str) else int(raw)) % _MODULUS)
        elif op == "input" and isinstance(term.get("name"), str) and term["name"]:
            result = (term["name"], 0)
        elif op in {"add", "sub"} and len(args) == 2:
            left, right = self.affine(args[0], depth + 1), self.affine(args[1], depth + 1)
            if left is not None and right is not None:
                result = self.combine(op, left, right)
        self.affines[key] = result
        return result

    @staticmethod
    def combine(op: str, left: Affine, right: Affine) -> Affine | None:
        """Combine only expressions with at most one uncancelled input."""
        if not right[0]:
            return left[0], (left[1] + (right[1] if op == "add" else -right[1])) % _MODULUS
        if op == "add" and not left[0]:
            return right[0], (left[1] + right[1]) % _MODULUS
        if op == "sub" and left[0] == right[0]:
            return "", (left[1] - right[1]) % _MODULUS
        return None

    def interval(self, address: Affine, size: int) -> tuple[int, int] | None:
        """Bound every byte only when translation of the entire interval cannot wrap."""
        name, offset = address
        if not name:
            low = high = offset
        elif name in self.bounds:
            low, high = self.bounds[name]
            low, high = (low + offset) % _MODULUS, (high + offset) % _MODULUS
        else:
            return None
        return (low, high + size) if low <= high and high + size <= _MODULUS else None

    def disjoint(self, left: Affine, size: int, right: Affine, other_size: int) -> bool:
        """Check circular relative offsets or nonwrapping declared absolute bounds."""
        if left[0] == right[0]:
            delta = (right[1] - left[1]) % _MODULUS
            return delta >= size and (-delta) % _MODULUS >= other_size
        first, second = self.interval(left, size), self.interval(right, other_size)
        return (first is not None and second is not None
                and (first[1] <= second[0] or second[1] <= first[0]))

    def read(self, term: Term) -> Term:
        """Forward same-endian whole stores; partial overlap retains the read."""
        width = term.get("width")
        if type(width) is not int or not 0 < width <= 128 or width % 8:
            return term
        memory, address = term["args"]
        affine = self.affine(address)
        if affine is None:
            return term
        for _ in range(_SCAN_LIMIT):
            args = memory.get("args", [])
            if memory.get("op") not in {"storele", "storebe"} or len(args) != 3:
                break
            previous, destination, value = args
            size = value.get("width")
            if type(size) is not int or not 0 < size <= 128 or size % 8:
                break
            other = self.affine(destination)
            if other is None:
                break
            if (affine == other and size == width
                    and memory["op"] == term["op"].replace("load", "store")):
                self.forwarded += 1
                return cast(Term, value)
            if not self.disjoint(affine, width // 8, other, size // 8):
                break
            self.skipped += 1
            memory = previous
        return {**term, "args": [memory, address]}


def reduce_literal_reads(function: Term, constraints: list[Term], *, deadline: float) -> Term:
    """Simplify a topological auxiliary SSA document with literal addresses only.

    This must precede an unnormalized query using the same input constraints.
    It must never be used on a relocatable comparison document. All original
    inputs and obligations remain. Deadline exhaustion returns the original.
    """
    reducer = _ReadReduction(constraints)
    terms: dict[str, Term] = {}
    keepalive: list[Term] = []
    for item in function.get("assignments", []):
        if time.monotonic() >= deadline:
            return function
        term = {key: value for key, value in item.items() if key != "id"}
        term["args"] = [terms[arg["ref"]] if "ref" in arg else arg for arg in term.get("args", [])]
        keepalive.append(term)
        args = term["args"]
        if term["op"] in {"loadle", "loadbe"} and len(args) == 2:
            term = reducer.read(term)
        elif term["op"] == "ite" and len(args) == 3 and _abi_terms_equal(args[1], args[2], reducer.equalities):
            term = args[1]
        terms[item["id"]] = term
    assignments: list[Term] = []
    memo: dict[str, str] = {}
    cache: dict[int, tuple[Term, Term]] = {}
    outputs = {}
    for name, term in function["outputs"].items():
        root = terms[term["ref"]] if "ref" in term else term
        outputs[name] = materialize_term(root, assignments=assignments, memo=memo, term_cache=cache)
    return {**function, "assignments": assignments, "outputs": outputs,
            "literal_read_reduction": {"forwarded": reducer.forwarded, "skipped": reducer.skipped}}
