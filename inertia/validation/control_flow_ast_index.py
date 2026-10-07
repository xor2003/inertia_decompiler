"""Index immutable C-AST surfaces for one control-flow validation request.

Layer: Validation.
Responsibility: Owns canonical equivalence checking and validation diagnostics
by answering repeated node, loop, guard, and subtree-presence queries without
rewalking an unchanged third-party angr C AST.

The index derives no new semantics and never mutates the AST. Callers must
discard it after the validation request; it is invalid after any AST mutation.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBreak,
    CDoWhileLoop,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CWhileLoop,
)
from inertia.pipeline.structured_ast_query_index import StructuredAstQueryIndex8616

type StructuredLoop8616 = CForLoop | CWhileLoop | CDoWhileLoop


class _TaggedAstNode8616(Protocol):
    """Third-party C-AST surface carrying optional instruction tags."""

    tags: Mapping[str, object] | None


def _ast_tags_8616(node: object) -> Mapping[str, object]:
    """Read tags at the explicit third-party C-AST boundary."""
    try:
        tags = cast(_TaggedAstNode8616, node).tags
    except AttributeError:
        return {}
    return tags if isinstance(tags, Mapping) else {}


def _instruction_address_8616(node: object) -> int | None:
    """Return one exact instruction tag when present."""
    address = _ast_tags_8616(node).get("ins_addr")
    return address if isinstance(address, int) else None


def _break_guard_condition_8616(node: object) -> object | None:
    """Return the condition from one supported break-guard shape."""
    if isinstance(node, CIfBreak):
        return cast(object, node.condition)
    if not isinstance(node, CIfElse) or node.else_node is not None:
        return None
    pairs = tuple(node.condition_and_nodes)
    if len(pairs) != 1:
        return None
    condition, body = pairs[0]
    if isinstance(body, CBreak):
        return cast(object, condition)
    if not isinstance(body, CStatements):
        return None
    statements = tuple(body.statements)
    return condition if len(statements) == 1 and isinstance(statements[0], CBreak) else None


@dataclass(frozen=True, slots=True)
class ControlFlowAstIndexStats8616:
    """Closed evidence for lazily indexed validation subtrees."""

    root_node_count: int
    subtree_query_count: int
    subtree_hit_count: int
    subtree_materialized_count: int

    @property
    def is_closed(self) -> bool:
        """Return whether every subtree query has exactly one outcome."""
        return self.subtree_query_count == self.subtree_hit_count + self.subtree_materialized_count


@dataclass(slots=True)
class ControlFlowAstIndex8616:
    """Request-owned lookup surface for final control-flow validation."""

    root_index: StructuredAstQueryIndex8616
    loops: tuple[StructuredLoop8616, ...]
    _conditions_by_jcc: dict[int, tuple[object, ...]]
    _break_guards_by_jcc: dict[int, tuple[object, ...]]
    _loops_by_jcc: dict[int, tuple[StructuredLoop8616, ...]]
    _subtree_indexes: dict[int, StructuredAstQueryIndex8616] = field(default_factory=dict)
    _subtree_addresses: dict[int, frozenset[int]] = field(default_factory=dict)
    _subtree_query_count: int = 0
    _subtree_hit_count: int = 0
    _subtree_materialized_count: int = 0

    @classmethod
    def build(
        cls,
        root: object,
        *,
        root_index: StructuredAstQueryIndex8616 | None = None,
    ) -> ControlFlowAstIndex8616:
        """Build all root-wide lookup maps in one deterministic traversal."""
        if root_index is None:
            root_index = StructuredAstQueryIndex8616.build(root)
        else:
            root_index.require_root(root)
        loops: list[StructuredLoop8616] = []
        conditions: dict[int, list[object]] = {}
        break_guards: dict[int, list[object]] = {}
        loops_by_jcc: dict[int, list[StructuredLoop8616]] = {}
        seen_conditions: set[int] = set()
        seen_break_guards: set[int] = set()
        for node in root_index.nodes:
            candidates: tuple[object, ...] = ()
            if isinstance(node, CIfBreak):
                candidates = (node.condition,)
            elif isinstance(node, CIfElse):
                candidates = tuple(condition for condition, _body in node.condition_and_nodes)
            elif isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
                loops.append(node)
                candidates = (node.condition,)
                address = _instruction_address_8616(node.condition)
                if address is not None:
                    loops_by_jcc.setdefault(address, []).append(node)
            for condition in candidates:
                marker = id(condition)
                address = _instruction_address_8616(condition)
                if address is None or marker in seen_conditions:
                    continue
                seen_conditions.add(marker)
                conditions.setdefault(address, []).append(condition)
            break_condition = _break_guard_condition_8616(node)
            break_address = _instruction_address_8616(break_condition) if break_condition is not None else None
            if break_address is not None and id(node) not in seen_break_guards:
                seen_break_guards.add(id(node))
                break_guards.setdefault(break_address, []).append(node)
        return cls(
            root_index=root_index,
            loops=tuple(loops),
            _conditions_by_jcc={key: tuple(values) for key, values in conditions.items()},
            _break_guards_by_jcc={key: tuple(values) for key, values in break_guards.items()},
            _loops_by_jcc={key: tuple(values) for key, values in loops_by_jcc.items()},
        )

    @property
    def nodes(self) -> tuple[object, ...]:
        """Return root nodes in deterministic walker order."""
        return self.root_index.nodes

    def tagged_conditions(self, jcc_addr: int) -> tuple[object, ...]:
        """Return conditions carrying ``jcc_addr``."""
        return self._conditions_by_jcc.get(jcc_addr, ())

    def break_guards(self, jcc_addr: int) -> tuple[object, ...]:
        """Return break guards carrying ``jcc_addr``."""
        return self._break_guards_by_jcc.get(jcc_addr, ())

    def loop_guards(self, jcc_addr: int) -> tuple[StructuredLoop8616, ...]:
        """Return loop headers carrying ``jcc_addr``."""
        return self._loops_by_jcc.get(jcc_addr, ())

    def subtree_nodes(self, root: object) -> tuple[object, ...]:
        """Return one lazily indexed subtree's nodes."""
        return self._subtree_index(root).nodes

    def subtree_contains_node(self, root: object, target: object) -> bool:
        """Return whether ``target`` occurs by identity under ``root``."""
        return bool(self._subtree_index(root).contains(target))

    def subtree_contains_instruction(self, root: object, target_addr: int) -> bool:
        """Return whether a subtree carries ``target_addr`` exactly."""
        index = self._subtree_index(root)
        marker = id(root)
        addresses = self._subtree_addresses.get(marker)
        if addresses is None:
            addresses = frozenset(
                address
                for node in index.nodes
                if (address := _instruction_address_8616(node)) is not None
            )
            self._subtree_addresses[marker] = addresses
        return target_addr in addresses

    def _subtree_index(self, root: object) -> StructuredAstQueryIndex8616:
        """Return or materialize one subtree index with closed accounting."""
        self._subtree_query_count += 1
        marker = id(root)
        index = self._subtree_indexes.get(marker)
        if index is not None and index.root is root:
            self._subtree_hit_count += 1
            return index
        index = StructuredAstQueryIndex8616.build(root)
        self._subtree_indexes[marker] = index
        self._subtree_materialized_count += 1
        return index

    def stats(self) -> ControlFlowAstIndexStats8616:
        """Return immutable closed-loop subtree-index evidence."""
        return ControlFlowAstIndexStats8616(
            root_node_count=len(self.root_index.nodes),
            subtree_query_count=self._subtree_query_count,
            subtree_hit_count=self._subtree_hit_count,
            subtree_materialized_count=self._subtree_materialized_count,
        )
