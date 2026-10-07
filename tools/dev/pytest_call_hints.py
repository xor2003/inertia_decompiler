"""Extract structured cost hints from pytest call syntax.

Layer: Tooling/gates.
Responsibility: map direct decompiler calls and pytest parameter values to
binary-symbol and function-address inventory facts without text rendering.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

_BINARY_SYMBOL_SUFFIXES = ("_EXE", "_COM", "_COD", "_BINARY")


@dataclass(frozen=True, slots=True)
class PytestCallHints:
    """Structured binary and function-address facts from one call."""

    function_addresses: tuple[int, ...] = ()
    input_symbols: tuple[str, ...] = ()


def _parameter_names(node: ast.expr) -> tuple[str, ...]:
    """Return normalized names from supported ``parametrize`` syntax."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return tuple(name.strip() for name in node.value.split(",") if name.strip())
    if isinstance(node, ast.Tuple | ast.List):
        return tuple(
            child.value
            for child in node.elts
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
        )
    return ()


def _sequence_values(node: ast.expr) -> tuple[ast.expr, ...]:
    """Return statically visible values from one literal sequence."""

    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return tuple(node.elts)
    return (node,)


def _case_values(node: ast.expr, parameter_count: int) -> tuple[ast.expr, ...]:
    """Return one parameter case's values, including ``pytest.param`` calls."""

    if isinstance(node, ast.Call):
        return tuple(node.args[:parameter_count])
    if parameter_count > 1 and isinstance(node, ast.Tuple | ast.List):
        return tuple(node.elts)
    return (node,)


def _parametrize_addresses(node: ast.Call) -> set[int]:
    """Return integer values assigned specifically to address parameters."""

    if len(node.args) < 2:
        return set()
    names = _parameter_names(node.args[0])
    address_indexes = {index for index, name in enumerate(names) if "addr" in name.lower()}
    addresses: set[int] = set()
    for case in _sequence_values(node.args[1]):
        values = _case_values(case, len(names))
        for index in address_indexes:
            if index >= len(values):
                continue
            value = values[index]
            if isinstance(value, ast.Constant) and isinstance(value.value, int) and not isinstance(value.value, bool):
                addresses.add(value.value)
    return addresses


def extract_pytest_call_hints(call_name: str, node: ast.Call) -> PytestCallHints:
    """Extract conservative direct-call and parameterized cost hints."""

    addresses: set[int] = set()
    input_symbols: set[str] = set()
    leaf_name = call_name.rsplit(".", 1)[-1].lower()
    if "decompil" in leaf_name and "addr" in leaf_name:
        for argument in node.args:
            if isinstance(argument, ast.Constant) and isinstance(argument.value, int):
                addresses.add(argument.value)
            elif isinstance(argument, ast.Name) and argument.id.upper().endswith(_BINARY_SYMBOL_SUFFIXES):
                input_symbols.add(argument.id)
    if call_name.endswith("parametrize"):
        addresses.update(_parametrize_addresses(node))
    return PytestCallHints(
        function_addresses=tuple(sorted(addresses)),
        input_symbols=tuple(sorted(input_symbols)),
    )


def concrete_function_addresses(item: pytest.Item, fallback: tuple[int, ...]) -> tuple[int, ...]:
    """Narrow static candidates using one collected node's concrete parameters."""
    from _pytest.python import CallSpec2

    call_spec = vars(item).get("callspec")
    if not isinstance(call_spec, CallSpec2):
        return fallback
    addresses = {
        value
        for name, value in call_spec.params.items()
        if "addr" in name.lower() and isinstance(value, int) and not isinstance(value, bool)
    }
    return tuple(sorted(addresses)) or fallback
