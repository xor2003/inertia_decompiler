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
