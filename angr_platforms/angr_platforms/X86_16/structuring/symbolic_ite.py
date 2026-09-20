"""Layer: Structuring.

Responsibility: preserve opaque AIL conditional-value identity at the symbolic
conversion boundary. Equal renderings do not prove equal effectful values.
Never recover calls, arguments or conditions from text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, cast

import claripy
from angr import ailment


@dataclass
class _IteSymbols:
    """Keep source objects alive and assign deterministic per-processor names."""

    by_identity: dict[int, tuple[object, str]] = field(default_factory=dict)


class _ProcessorSurface(Protocol):
    """Third-party condition map and Inertia's typed identity table."""

    _condition_mapping: dict[str, object]
    _inertia_ite_symbols_8616: _IteSymbols


class _ExpressionSurface(Protocol):
    """Third-party AIL expression width."""

    bits: int


def convert_symbolic_ite_8616(
    processor: object, condition: object, *, must_bool: bool,
) -> claripy.ast.Bool | claripy.ast.BV | None:
    """Retain opaque ITEs without conflating separate effectful expressions.

    angr names opaque ITEs by repr, which omits embedded callsite addresses.
    Reusing that name overwrites the reverse map with a different call. Preserve
    original object identity instead: absent proof, separate expressions remain
    independent. Repeated conversion of the same object reuses its symbol.
    This preserves angr's opaque-value contract, including reverse conversion.
    """
    if not isinstance(condition, ailment.Expr.ITE):
        return None
    surface = cast(_ProcessorSurface, processor)
    try:
        symbols = surface._inertia_ite_symbols_8616
    except AttributeError:
        symbols = _IteSymbols()
        surface._inertia_ite_symbols_8616 = symbols
    identity = id(condition)
    entry = symbols.by_identity.get(identity)
    if entry is None:
        name = f"inertia_ite_8616_{len(symbols.by_identity)}"
        symbols.by_identity[identity] = (condition, name)
    else:
        _source, name = entry
    surface._condition_mapping[name] = condition
    if must_bool:
        return claripy.BoolS(name, explicit_name=True)
    return claripy.BVS(name, cast(_ExpressionSurface, condition).bits, explicit_name=True)
