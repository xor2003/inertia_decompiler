"""Layer: dosunit recursive admission (staging).

Responsibility: resolve structured literal/ITE control targets with finite work,
without recursive Python evaluation, guessed branches or proof promotion.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class StaticControlReason(StrEnum):
    """Exact evidence boundary of a bounded control-target evaluation."""

    RESOLVED = "resolved"
    OPAQUE = "opaque"
    MALFORMED = "malformed"
    CYCLE = "cycle"
    NODE_LIMIT = "node_limit"
    WIDTH_LIMIT = "width_limit"
    LITERAL_LIMIT = "literal_limit"
    TARGET_LIMIT = "target_limit"
    DEADLINE = "deadline"


@dataclass(frozen=True, slots=True)
class StaticControlLimits:
    """Bound unique nodes, shifts and literal parsing before doing the work."""

    max_nodes: int = 65_536
    max_width: int = 64
    max_literal_chars: int = 256
    max_target_work: int = 1_048_576

    def __post_init__(self) -> None:
        """Reject Boolean, negative and unbounded resource declarations."""
        for value in (self.max_nodes, self.max_width, self.max_literal_chars, self.max_target_work):
            if type(value) is not int or value <= 0:
                raise ValueError("static control limits must be positive integers")


@dataclass(frozen=True, slots=True)
class StaticControlResult:
    """Targets remain diagnostic evidence unless the whole term is complete."""

    targets: frozenset[int]
    reason: StaticControlReason
    node_count: int

    @property
    def complete(self) -> bool:
        """Admit only a fully resolved finite structured control term."""
        return self.reason is StaticControlReason.RESOLVED


@dataclass(frozen=True, slots=True)
class _Value:
    """Cache a scalar separately from a possibly partial ITE target set."""

    targets: frozenset[int] = frozenset()
    scalar: tuple[int, int] | None = None
    reason: StaticControlReason = StaticControlReason.RESOLVED
    width: int | None = None


class _Stop(Exception):
    """Named resource or cyclic-graph refusal, never a swallowed defect."""

    def __init__(self, reason: StaticControlReason) -> None:
        """Keep the exact boundary for the public structured non-result."""
        self.reason = reason
        super().__init__(reason.value)


@dataclass(slots=True)
class _TargetBudget:
    """Charge target-union work before allocation, including duplicate arms."""

    remaining: int

    def charge(self, size: int) -> None:
        """Prevent deep distinct-target ITEs from accumulating quadratic storage."""
        if size > self.remaining:
            raise _Stop(StaticControlReason.TARGET_LIMIT)
        self.remaining -= size


def _children(node: dict[str, Any], limits: StaticControlLimits) -> tuple[object, ...]:
    """Select only semantic operands; an ITE guard cannot prune either arm."""
    operation = node.get("op")
    if not isinstance(operation, str):
        return ()
    width = node.get("width")
    if type(width) is int and width > limits.max_width:
        raise _Stop(StaticControlReason.WIDTH_LIMIT)
    arity = {"ite": 3, "add": 2, "sub": 2, "shl": 2, "trunc": 1, "zext": 1, "sext": 1}.get(operation)
    args = node.get("args")
    if arity is None or not isinstance(args, list) or len(args) != arity:
        return ()
    return tuple(args[1:]) if operation == "ite" else tuple(args)


def _literal(raw: object, limits: StaticControlLimits) -> int | None:
    """Bound parsing and integer size while preserving exact signed values."""
    if type(raw) is int:
        if raw.bit_length() > limits.max_literal_chars * 4:
            raise _Stop(StaticControlReason.LITERAL_LIMIT)
        return raw
    if isinstance(raw, str):
        if len(raw) > limits.max_literal_chars:
            raise _Stop(StaticControlReason.LITERAL_LIMIT)
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


def _scalar(value: int, width: int) -> _Value:
    """Materialize a width-checked unsigned bit pattern exactly once."""
    normalized = value & ((1 << width) - 1)
    return _Value(frozenset({normalized}), (normalized, width), width=width)


def _converted(operation: str, width: int, source: tuple[int, int]) -> _Value:
    """Use bitvector, rather than mathematical-integer, width semantics."""
    value, source_width = source
    if operation == "trunc" and width > source_width:
        return _Value(reason=StaticControlReason.MALFORMED)
    if operation in {"zext", "sext"} and width < source_width:
        return _Value(reason=StaticControlReason.MALFORMED)
    if operation == "sext" and value & (1 << (source_width - 1)):
        value -= 1 << source_width
    return _scalar(value, width)


def _combined(operation: str, width: int, children: tuple[_Value, ...]) -> _Value:
    """Apply only modeled scalar operations, retaining exact refusal causes."""
    for child in children:
        if child.reason is not StaticControlReason.RESOLVED:
            return _Value(reason=child.reason)
        if child.scalar is None:
            return _Value(reason=StaticControlReason.OPAQUE)
    scalars = tuple(child.scalar for child in children if child.scalar is not None)
    if operation in {"trunc", "zext", "sext"}:
        return _converted(operation, width, scalars[0])
    left, right = scalars
    if operation == "shl":
        if left[1] != width:
            return _Value(reason=StaticControlReason.MALFORMED)
        # VEX's shift count may have a different width from its value. Test
        # before shifting so adversarial literals cannot allocate huge ints.
        return _scalar(0 if right[0] >= width else left[0] << right[0], width)
    if left[1] != width or right[1] != width:
        return _Value(reason=StaticControlReason.MALFORMED)
    value = left[0] + right[0] if operation == "add" else left[0] - right[0]
    return _scalar(value, width)


def _joined(node: dict[str, Any], children: tuple[_Value, ...], targets: _TargetBudget) -> _Value:
    """Keep partial targets while refusing contradictory ITE branch widths."""
    if len(children) != 2:
        return _Value(reason=StaticControlReason.MALFORMED)
    reason = next((child.reason for child in children
                   if child.reason is not StaticControlReason.RESOLVED), StaticControlReason.RESOLVED)
    widths = {child.width for child in children if child.width is not None}
    width = node.get("width")
    if "width" in node:
        if type(width) is not int or width <= 0:
            reason = StaticControlReason.MALFORMED
        else:
            widths.add(width)
    if len(widths) > 1:
        reason = StaticControlReason.MALFORMED
    targets.charge(len(children[0].targets) + len(children[1].targets))
    inferred_width = next(iter(widths)) if len(widths) == 1 else None
    return _Value(children[0].targets | children[1].targets, reason=reason, width=inferred_width)


def _evaluate(node: dict[str, Any], operands: tuple[object, ...], memo: dict[int, _Value],
              limits: StaticControlLimits, targets: _TargetBudget) -> _Value:
    """Evaluate a postorder node after all required operands are memoized."""
    operation = node.get("op")
    if not isinstance(operation, str):
        return _Value(reason=StaticControlReason.MALFORMED)
    children = tuple(memo[id(child)] for child in operands)
    if operation == "ite":
        return _joined(node, children, targets)
    width = node.get("width")
    if type(width) is not int or width <= 0:
        return _Value(reason=StaticControlReason.MALFORMED)
    if operation == "const":
        value = _literal(node.get("value"), limits)
        return _Value(reason=StaticControlReason.MALFORMED) if value is None else _scalar(value, width)
    arity = {"add": 2, "sub": 2, "shl": 2, "trunc": 1, "zext": 1, "sext": 1}.get(operation)
    if arity is None:
        return _Value(reason=StaticControlReason.OPAQUE)
    if len(children) != arity:
        return _Value(reason=StaticControlReason.MALFORMED)
    return _combined(operation, width, children)


def resolve_static_control(term: object, *, limits: StaticControlLimits | None = None,
                           deadline: float = -1.0) -> StaticControlResult:
    """Memoize a finite term DAG under the caller's original absolute deadline.

    A negative deadline disables wall time but never the node/width limits.
    Opaque ITE arms retain known targets as diagnostics and make admission fail.
    Cycles and exhausted resources stop immediately with a typed non-result.
    """
    selected = limits if limits is not None else StaticControlLimits()
    memo: dict[int, _Value] = {}
    active: set[int] = set()
    pending: list[tuple[object, tuple[object, ...] | None]] = [(term, None)]
    count = 0
    targets = _TargetBudget(selected.max_target_work)
    try:
        while pending:
            if deadline >= 0.0 and time.monotonic() >= deadline:
                raise _Stop(StaticControlReason.DEADLINE)
            node, operands = pending.pop()
            key = id(node)
            if key in memo:
                continue
            if operands is not None:
                assert isinstance(node, dict)
                memo[key] = _evaluate(node, operands, memo, selected, targets)
                active.remove(key)
                continue
            if key in active:
                raise _Stop(StaticControlReason.CYCLE)
            if count >= selected.max_nodes:
                raise _Stop(StaticControlReason.NODE_LIMIT)
            count += 1
            if not isinstance(node, dict):
                memo[key] = _Value(reason=StaticControlReason.MALFORMED)
                continue
            operands = _children(node, selected)
            active.add(key)
            pending.append((node, operands))
            pending.extend((child, None) for child in reversed(operands))
    except _Stop as stop:
        return StaticControlResult(frozenset(), stop.reason, count)
    result = memo[id(term)]
    return StaticControlResult(result.targets, result.reason, count)
