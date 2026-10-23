"""Evaluate literal bitvector conversions used by binary control relations.

Layer: dosunit SSA terms.
Responsibility: preserve literal modular arithmetic, truncation and signed extension when resolving a
constant control destination; unmodeled expressions remain unresolved.
"""

from __future__ import annotations

from typing import Any


def _literal_integer(raw: object) -> int | None:
    """Parse a literal JSON integer without treating Boolean values as numbers."""
    if type(raw) is int:
        return raw
    if isinstance(raw, str):
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


def constant_bitvector(term: dict[str, Any]) -> tuple[int, int] | None:
    """Return the exact unsigned bit pattern and width of a literal term."""
    width = term.get("width")
    if type(width) is not int or width <= 0:
        return None
    operation = term.get("op")
    if not isinstance(operation, str):
        return None
    if operation == "const":
        value = _literal_integer(term.get("value"))
        if value is None:
            return None
        return value & ((1 << width) - 1), width
    args = term.get("args")
    if operation in {"add", "sub"}:
        return _constant_arithmetic(operation, width, args)
    return _constant_conversion(operation, width, args)


def _constant_conversion(operation: object, width: int, args: object) -> tuple[int, int] | None:
    """Apply one admitted literal width conversion without guessing other nodes."""
    if operation not in {"trunc", "zext", "sext"} or not isinstance(args, list) or len(args) != 1:
        return None
    if not isinstance(args[0], dict):
        return None
    source = constant_bitvector(args[0])
    if source is None:
        return None
    value, source_width = source
    if operation == "trunc" and width > source_width:
        return None
    if operation in {"zext", "sext"} and width < source_width:
        return None
    if operation == "sext" and value & (1 << (source_width - 1)):
        value -= 1 << source_width
    return value & ((1 << width) - 1), width


def _constant_arithmetic(operation: str, width: int, args: object) -> tuple[int, int] | None:
    """Evaluate only same-width literal addition/subtraction, modulo that width."""
    if not isinstance(args, list) or len(args) != 2 or not all(isinstance(arg, dict) for arg in args):
        return None
    left, right = constant_bitvector(args[0]), constant_bitvector(args[1])
    if left is None or right is None or left[1] != width or right[1] != width:
        return None
    value = left[0] + right[0] if operation == "add" else left[0] - right[0]
    return value & ((1 << width) - 1), width


def constant_flag_selector(
    term: dict[str, Any], assignments: dict[str, dict[str, Any]], *, depth: int = 0,
) -> int | None:
    """Resolve bounded constant shift guards without assuming symbolic inputs."""
    if depth >= 32:
        return None
    ref = term.get("ref")
    if isinstance(ref, str):
        target = assignments.get(ref)
        return None if target is None else constant_flag_selector(target, assignments, depth=depth + 1)
    width = term.get("width")
    if type(width) is not int or not 0 < width <= 64:
        return None
    if term.get("op") == "const":
        literal = constant_bitvector(term)
        return None if literal is None else literal[0]
    args = term.get("args")
    if not isinstance(args, list) or not all(isinstance(arg, dict) for arg in args):
        return None
    operation = term.get("op")
    if operation == "ite" and len(args) == 3:
        condition = constant_flag_selector(args[0], assignments, depth=depth + 1)
        if condition is None:
            return None
        value = constant_flag_selector(args[1 if condition else 2], assignments, depth=depth + 1)
        return None if value is None else value & ((1 << width) - 1)
    if operation not in {"and", "ne"} or len(args) != 2:
        return None
    left, right = (constant_flag_selector(arg, assignments, depth=depth + 1) for arg in args)
    if left is None or right is None:
        return None
    value = left & right if operation == "and" else int(left != right)
    return value & ((1 << width) - 1)


def flag_selector_choices(term: dict[str, Any], assignments: dict[str, dict[str, Any]]) -> tuple[int, ...] | None:
    """Admit a literal or one guarded choice between two literal selectors."""
    literal = constant_flag_selector(term, assignments)
    if literal is not None:
        return (literal,)
    for _ in range(32):
        ref = term.get("ref")
        if not isinstance(ref, str):
            break
        target = assignments.get(ref)
        if target is None:
            return None
        term = target
    args = term.get("args")
    if (term.get("op") != "ite" or not isinstance(args, list) or len(args) != 3
            or not all(isinstance(arg, dict) for arg in args)):
        return None
    values = [constant_flag_selector(arg, assignments) for arg in args[1:]]
    if any(value is None for value in values):
        return None
    return tuple(value for value in values if value is not None)
