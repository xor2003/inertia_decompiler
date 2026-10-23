"""Layer: pure SSA guard composition.

Responsibility: reduce exact one-bit identities at construction time, preserving
shared operands without traversing or expanding the histories below them.
"""

from __future__ import annotations

from typing import Any, Literal

type GuardOperator = Literal["and", "or"]
type Term = dict[str, Any]


def _constant_bit(term: Term) -> int | None:
    """Recognize canonical Boolean literals without interpreting wider values."""
    if term.get("op") != "const" or term.get("width") != 1:
        return None
    value = term.get("value")
    if value in ("0x0", "0"):
        return 0
    if value in ("0x1", "1"):
        return 1
    return None


def _operands(term: Term, op: str, arity: int) -> list[Term] | None:
    """Accept only complete Boolean nodes, retaining malformed terms unchanged."""
    if term.get("op") != op or term.get("width") != 1:
        return None
    args = term.get("args")
    if not isinstance(args, list) or len(args) != arity:
        return None
    if not all(isinstance(arg, dict) and arg.get("width") == 1 for arg in args):
        return None
    return args


def _complementary(left: Term, right: Term) -> bool:
    """Recognize a predicate and its exact shared negation in constant work."""
    left_args = _operands(left, "not", 1)
    right_args = _operands(right, "not", 1)
    return ((left_args is not None and left_args[0] is right)
            or (right_args is not None and right_args[0] is left))


def _common_factor(op: GuardOperator, left: Term, right: Term) -> Term | None:
    """Reduce (g AND c) OR (g AND NOT c), and its Boolean dual."""
    inner = "and" if op == "or" else "or"
    a, b = _operands(left, inner, 2), _operands(right, inner, 2)
    if a is None or b is None:
        return None
    for i in range(2):
        for j in range(2):
            if a[i] is b[j] and _complementary(a[1 - i], b[1 - j]):
                return a[i]
    return None


def combine_guards(op: GuardOperator, left: Term, right: Term) -> Term:
    """Compose exact guards without accumulating already reconverged branches.

    Identity checks apply only to live shared objects, never recycled integer
    IDs or hashes. Distinct but equal-looking terms conservatively retain their
    original operation. Every rule takes bounded work independent of DAG depth.
    """
    original = {"op": op, "width": 1, "args": [left, right]}
    if left.get("width") != 1 or right.get("width") != 1:
        return original
    identity = 1 if op == "and" else 0
    for literal, other in ((left, right), (right, left)):
        value = _constant_bit(literal)
        if value is not None:
            return other if value == identity else literal
    if left is right:
        return left
    if _complementary(left, right):
        return {"op": "const", "width": 1, "value": hex(1 - identity)}
    factored = _common_factor(op, left, right)
    return factored if factored is not None else original
