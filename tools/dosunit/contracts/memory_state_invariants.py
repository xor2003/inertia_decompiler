"""Finite fixed-point memory invariants for relational induction.

Layer: dosunit relational state contracts.
Responsibility: project a machine state onto ordered byte facts over its scalar
components. A projection is a proposal, never evidence of reachability. Consumers
must discharge entry and continuing-state fixed-point obligations before using
the projected interior domain; final observations still require full identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from tools.dosunit.compare.real16_call_contracts import substitute_state_term
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

MAX_TEMPLATE_NODES: Final[int] = 4096
"""Bound validation work before recursively substituting a proposed template."""
MAX_TEMPLATE_DEPTH: Final[int] = 128
"""Refuse templates exceeding the recursive substitution depth budget."""
_MEMORY_OPS: Final[frozenset[str]] = frozenset(
    {"mem_input", "loadle", "loadbe", "storele", "storebe"}
)


class MemoryInvariantReason(StrEnum):
    """Typed reasons why a proposed fixed-point projection cannot be formed."""

    MISSING = "memory_invariant_state_missing"
    WIDTH = "memory_invariant_width_mismatch"
    MALFORMED = "memory_invariant_malformed"
    LIMIT = "memory_invariant_template_limit"


class MemoryInvariantRefusal(Exception):
    """Retain the exact failed invariant-admission obligation."""

    def __init__(self, reason: MemoryInvariantReason) -> None:
        """Create a refusal with a typed cause for the consuming proof report."""
        self.reason = reason
        super().__init__(reason.value)


def _scalar_children(node: dict[str, Any], bindings: dict[str, int]) -> list[dict[str, Any]]:
    """Validate one scalar template node and collect exact input widths."""
    op = node.get("op")
    width = node.get("width")
    if not isinstance(op, str) or op in _MEMORY_OPS or "ref" in node:
        raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
    if type(width) is not int or width <= 0:
        raise MemoryInvariantRefusal(MemoryInvariantReason.WIDTH)
    if op == "input":
        name = node.get("name")
        if not isinstance(name, str) or not name:
            raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
        if name in bindings and bindings[name] != width:
            raise MemoryInvariantRefusal(MemoryInvariantReason.WIDTH)
        bindings[name] = width
        return []
    if op == "const":
        if constant_bitvector(node) is None:
            raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
        return []
    args = node.get("args")
    if not isinstance(args, list) or not args or not all(isinstance(arg, dict) for arg in args):
        raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
    return args


def _template_bindings(template: dict[str, Any], width: int) -> dict[str, int]:
    """Require a bounded acyclic scalar DAG of the specified root width."""
    if not isinstance(template, dict):
        raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
    if template.get("width") != width:
        raise MemoryInvariantRefusal(MemoryInvariantReason.WIDTH)
    bindings: dict[str, int] = {}
    visiting: set[int] = set()
    visited: set[int] = set()
    stack = [(template, 0, False)]
    while stack:
        node, depth, leaving = stack.pop()
        identity = id(node)
        if leaving:
            visiting.remove(identity)
            visited.add(identity)
            continue
        if identity in visiting:
            raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
        if identity in visited:
            continue
        if depth > MAX_TEMPLATE_DEPTH or len(visited) + len(visiting) >= MAX_TEMPLATE_NODES:
            raise MemoryInvariantRefusal(MemoryInvariantReason.LIMIT)
        visiting.add(identity)
        stack.append((node, depth, True))
        stack.extend((arg, depth + 1, False) for arg in _scalar_children(node, bindings))
    return bindings


def _evaluate(template: dict[str, Any], state: MachineState, width: int) -> dict[str, Any]:
    """Bind every scalar input exactly, without inventing missing registers."""
    for name, expected in _template_bindings(template, width).items():
        if name not in state:
            raise MemoryInvariantRefusal(MemoryInvariantReason.MISSING)
        if state[name].get("width") != expected:
            raise MemoryInvariantRefusal(MemoryInvariantReason.WIDTH)
    evaluated = substitute_state_term(template, state)
    if not isinstance(evaluated, dict) or evaluated.get("width") != width:
        raise MemoryInvariantRefusal(MemoryInvariantReason.WIDTH)
    return evaluated


def _array_children(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Accept complete byte arrays, including both arms of an array merge."""
    op = node.get("op")
    if op == "mem_input":
        if node.get("addr_width") != 32 or node.get("value_width") != 8:
            raise MemoryInvariantRefusal(MemoryInvariantReason.WIDTH)
        return []
    args = node.get("args")
    if not isinstance(args, list) or len(args) != 3 or not all(isinstance(arg, dict) for arg in args):
        raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
    if op == "ite" and node.get("width") == 0 and args[0].get("width") == 1:
        return args[1:]
    if op in {"storele", "storebe"}:
        width = args[2].get("width")
        if args[1].get("width") == 32 and type(width) is int and width > 0 and width % 8 == 0:
            return args[:1]
        raise MemoryInvariantRefusal(MemoryInvariantReason.WIDTH)
    raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)


def _validate_array(memory: dict[str, Any]) -> None:
    """Refuse cyclic, oversized or unsupported memory-valued terms."""
    if not isinstance(memory, dict):
        raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
    visiting: set[int] = set()
    visited: set[int] = set()
    stack = [(memory, False)]
    while stack:
        node, leaving = stack.pop()
        identity = id(node)
        if leaving:
            visiting.remove(identity)
            visited.add(identity)
            continue
        if identity in visiting:
            raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
        if identity in visited:
            continue
        if len(visiting) + len(visited) >= MAX_TEMPLATE_NODES:
            raise MemoryInvariantRefusal(MemoryInvariantReason.LIMIT)
        visiting.add(identity)
        stack.append((node, True))
        stack.extend((child, False) for child in _array_children(node))


@dataclass(frozen=True, slots=True)
class MemoryByteFact:
    """One proposed byte store at an address derived from scalar state."""

    address: dict[str, Any]
    value: dict[str, Any]

    def __post_init__(self) -> None:
        """Admit exact address and byte widths with memory-independent templates."""
        _template_bindings(self.address, 32)
        _template_bindings(self.value, 8)


@dataclass(frozen=True, slots=True)
class MemoryInvariant:
    """Idempotent projection with ordered, alias-safe last-write semantics.

    All templates evaluate against the same original scalar components, which
    the projection preserves. Thus applying the same stores twice is idempotent
    even with conflicting facts or aliased addresses. The invariant describes
    the projection's fixed points, rather than a conjunction of all byte facts.
    """

    facts: tuple[MemoryByteFact, ...] = ()

    def __post_init__(self) -> None:
        """Require validated finite byte facts before projection is attempted."""
        if not all(isinstance(fact, MemoryByteFact) for fact in self.facts):
            raise MemoryInvariantRefusal(MemoryInvariantReason.MALFORMED)
        if len(self.facts) > MAX_TEMPLATE_NODES:
            raise MemoryInvariantRefusal(MemoryInvariantReason.LIMIT)

    @property
    def is_identity(self) -> bool:
        """Expose whether the proposal changes no memory bytes."""
        return not self.facts

    def apply(self, state: MachineState) -> MachineState:
        """Preserve all components while storing the ordered facts in memory."""
        if "memory" not in state:
            raise MemoryInvariantRefusal(MemoryInvariantReason.MISSING)
        memory = state["memory"]
        _validate_array(memory)
        for fact in self.facts:
            address = _evaluate(fact.address, state, 32)
            value = _evaluate(fact.value, state, 8)
            memory = {"op": "storele", "width": 0, "args": [memory, address, value]}
        return {**state, "memory": memory}
