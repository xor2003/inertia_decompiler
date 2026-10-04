"""Bijective memory cutpoint relations built from elementary byte transpositions.

Layer: dosunit relational state contracts.
Responsibility: describe an exact byte-level memory permutation as an ordered
tuple of two-address transpositions whose addresses are width-32 SSA templates
over scalar inputs. ``apply`` rewrites a memory term by evaluating each address
against a caller state via ``substitute_state_term``; the inverse is the same
tuple in reverse order. A relation never establishes equivalence — consumers
must still prove complete memory, register, control and flag effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from tools.dosunit.real16_call_contracts import substitute_state_term
from tools.dosunit.register_state_relations import MachineState

ADDRESS_WIDTH: Final[int] = 32
"""Every swapped byte address lives in the flat 32-bit SSA address domain."""

BYTE_WIDTH: Final[int] = 8
"""Each transposition exchanges exactly one byte per side."""

_MEMORY_OPS: Final[frozenset[str]] = frozenset(
    {"mem_input", "loadle", "loadbe", "storele", "storebe"}
)
"""Ops whose semantics read or write a memory array; forbidden inside addresses."""

_MEMORY_ROOT_OPS: Final[frozenset[str]] = frozenset({"mem_input", "storele", "storebe"})
"""Ops that may legitimately root the memory term this relation rewrites."""

_SCALAR_LEAF_OPS: Final[frozenset[str]] = frozenset({"input", "const"})
"""Leaves an address template may end at; everything else needs ``args``."""


class MemoryRelationReason(StrEnum):
    """Missing or contradictory evidence for a proposed memory relation."""

    MISSING = "memory_relation_state_missing"
    WIDTH = "memory_relation_address_width"
    MALFORMED = "memory_relation_term_malformed"


class MemoryRelationRefusal(Exception):
    """Fail closed when an attempted memory relation is not well-defined."""

    def __init__(self, reason: MemoryRelationReason) -> None:
        """Retain the typed missing relation obligation."""
        self.reason = reason
        super().__init__(reason.value)


def _address_leaf_name(node: dict[str, Any]) -> str | None:
    """Return an ``input`` leaf name, ``None`` for ``const``, or refuse malformed."""
    if node.get("op") != "input":
        return None
    name = node.get("name")
    if not isinstance(name, str) or not name:
        raise MemoryRelationRefusal(MemoryRelationReason.MALFORMED)
    return name


def _scan_address_template(term: Any) -> set[str]:  # noqa: ANN401
    """Validate a width-32 scalar-only address template; collect input names.

    Raises ``WIDTH`` when the root is not an exact width-32 term and
    ``MALFORMED`` when the term is not a dict, lacks a string ``op`` or integer
    ``width``, carries a materialized ``ref`` indirection, contains a
    memory-dependent op, or has non-dict ``args``.  Returns the set of
    ``input`` leaf names the caller state must supply.
    """
    if not isinstance(term, dict):
        raise MemoryRelationRefusal(MemoryRelationReason.MALFORMED)
    if type(term.get("width")) is not int or term["width"] != ADDRESS_WIDTH:
        raise MemoryRelationRefusal(MemoryRelationReason.WIDTH)
    names: set[str] = set()
    seen: set[int] = set()
    stack: list[dict[str, Any]] = [term]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        op = node.get("op")
        if not isinstance(op, str) or not op or "ref" in node or type(node.get("width")) is not int:
            raise MemoryRelationRefusal(MemoryRelationReason.MALFORMED)
        if op in _MEMORY_OPS:
            raise MemoryRelationRefusal(MemoryRelationReason.MALFORMED)
        if op in _SCALAR_LEAF_OPS:
            leaf = _address_leaf_name(node)
            if leaf is not None:
                names.add(leaf)
            continue
        args = node.get("args")
        if not isinstance(args, list) or not all(isinstance(arg, dict) for arg in args):
            raise MemoryRelationRefusal(MemoryRelationReason.MALFORMED)
        stack.extend(args)
    return names


@dataclass(frozen=True, slots=True)
class MemoryByteSwap:
    """One elementary transposition exchanging the bytes at two addresses.

    ``left`` and ``right`` are unevaluated width-32 SSA address templates over
    scalar ``input``/``const`` leaves.  Memory-dependent terms are refused: an
    address may never depend on the memory array being permuted.
    """

    left: dict[str, Any]
    right: dict[str, Any]

    def __post_init__(self) -> None:
        """Require exact-width scalar-only address templates on both sides."""
        _scan_address_template(self.left)
        _scan_address_template(self.right)


@dataclass(frozen=True, slots=True)
class MemoryPermutation:
    """Invertible byte-level memory relation composed of ordered transpositions.

    Swaps apply in tuple order over the evolving memory term.  Each swap loads
    both bytes from the pre-swap memory before either store, so equal or
    aliasing addresses still define a bijection with no disjointness
    assumption and no scratch-memory exclusion.  Every transposition is
    self-inverse, so the inverse relation is the same swaps in reverse order.
    """

    swaps: tuple[MemoryByteSwap, ...] = ()

    def __post_init__(self) -> None:
        """Require every element to be a validated byte swap."""
        if not all(isinstance(swap, MemoryByteSwap) for swap in self.swaps):
            raise MemoryRelationRefusal(MemoryRelationReason.MALFORMED)

    @property
    def is_identity(self) -> bool:
        """Expose whether this relation stores no transpositions at all."""
        return not self.swaps

    def inverse(self) -> MemoryPermutation:
        """Return the inverse relation: identical swaps in reverse tuple order."""
        return MemoryPermutation(tuple(reversed(self.swaps)))

    def _evaluated(
        self, swap: MemoryByteSwap, state: MachineState
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Substitute both address templates against live state, re-validated.

        Every ``input`` leaf must be bound in ``state``; after substitution the
        result is scanned again so a state term cannot smuggle memory
        dependence or a wrong width into an address.
        """
        addresses: list[dict[str, Any]] = []
        for template in (swap.left, swap.right):
            for name in _scan_address_template(template):
                if name not in state:
                    raise MemoryRelationRefusal(MemoryRelationReason.MISSING)
            evaluated = substitute_state_term(template, state)
            _scan_address_template(evaluated)
            addresses.append(evaluated)
        return addresses[0], addresses[1]

    def apply(
        self, memory: dict[str, Any], state: MachineState, *, inverse: bool = False
    ) -> dict[str, Any]:
        """Rewrite ``memory`` through these transpositions in tuple order.

        ``memory`` must be a ``mem_input`` or a ``storele``/``storebe`` chain;
        anything else refuses.  With ``inverse=True`` the swaps compose in
        reverse order, restoring the pre-relation array for every assignment
        of inputs — overlaps, duplicates and wraparound included — because each
        transposition reads both bytes before either store.  All unmentioned
        bytes are preserved by the store chain.
        """
        if not isinstance(memory, dict):
            raise MemoryRelationRefusal(MemoryRelationReason.MISSING)
        if str(memory.get("op")) not in _MEMORY_ROOT_OPS:
            raise MemoryRelationRefusal(MemoryRelationReason.MALFORMED)
        result = memory
        ordered = self.swaps[::-1] if inverse else self.swaps
        for swap in ordered:
            left, right = self._evaluated(swap, state)
            left_byte = {"op": "loadle", "width": BYTE_WIDTH, "args": [result, left]}
            right_byte = {"op": "loadle", "width": BYTE_WIDTH, "args": [result, right]}
            result = {
                "op": "storele",
                "width": 0,
                "args": [
                    {"op": "storele", "width": 0, "args": [result, left, right_byte]},
                    right,
                    left_byte,
                ],
            }
        return result


IDENTITY_MEMORY_PERMUTATION: Final[MemoryPermutation] = MemoryPermutation()
"""Immutable empty relation shared by proof contracts and default attempts."""
