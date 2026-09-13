"""Build the structural half of the reusable pytest source index.

Layer: Tooling/gates.
Responsibility: collect pytest selectors and skip/xfail locations without
paying for assertion, subprocess, or evidence analysis.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, field

if __package__:
    from scripts.pytest_assertion_facts import PytestNodeFacts
else:
    from pytest_assertion_facts import PytestNodeFacts

type PytestFactsByNode = tuple[tuple[str, PytestNodeFacts], ...]


def _source_selector(node_id: str) -> str:
    """Resolve source ownership, not runtime parameter-ID validity.

    Parameter values may themselves contain ``::``. Remove the parameter
    suffix before splitting scopes so skip and assertion evidence stay with
    the test function. Pytest collection validates the concrete case ID.
    """
    source_id = node_id.partition("[")[0]
    return "::".join(part for part in source_id.split("::") if part)


@dataclass(slots=True)
class PytestFactsProvider:
    """Memoize full assertion and call facts on first consumer access."""

    loader: Callable[[], PytestFactsByNode]
    cached: PytestFactsByNode | None = None

    def get(self) -> PytestFactsByNode:
        """Return facts, memoizing the first completed source-bound load."""

        if self.cached is None:
            self.cached = self.loader()
        return self.cached


@dataclass(frozen=True, slots=True, eq=False)
class PytestSourceIndex:
    """Immutable structural index with lazily memoized test-evidence facts."""

    nodes: frozenset[str]
    skip_xfail_lines_by_node: tuple[tuple[str, tuple[int, ...]], ...]
    _facts: PytestFactsProvider = field(repr=False, compare=False)

    def has_node(self, node_id: str) -> bool:
        """Return whether a pytest node ID names an indexed source object."""

        normalized = _source_selector(node_id)
        return not normalized or normalized in self.nodes

    def skip_xfail_lines(self, node_id: str) -> tuple[int, ...]:
        """Return skip/xfail call lines within the selected pytest node."""

        normalized = _source_selector(node_id)
        return dict(self.skip_xfail_lines_by_node).get(normalized, ())

    def facts(self, node_id: str) -> PytestNodeFacts:
        """Return static facts for one normalized pytest selector."""

        normalized = "::".join(
            part.split("@", 1)[0]
            for part in _source_selector(node_id).split("::")
            if part
        )
        return dict(self._facts.get()).get(normalized, PytestNodeFacts())

    def all_facts(self) -> PytestFactsByNode:
        """Return all static facts for internal lazy-index composition."""

        return self._facts.get()

    def __eq__(self, other: object) -> bool:
        """Preserve value equality across eager and lazy fact providers."""

        if not isinstance(other, PytestSourceIndex):
            return NotImplemented
        return (
            self.nodes == other.nodes
            and self.skip_xfail_lines_by_node == other.skip_xfail_lines_by_node
            and self.all_facts() == other.all_facts()
        )

    def __hash__(self) -> int:
        """Preserve the original immutable index hash contract."""

        return hash((self.nodes, self.skip_xfail_lines_by_node, self.all_facts()))


def _dotted_attribute_name(node: ast.expr) -> str | None:
    """Return a dotted name for a simple call expression."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_attribute_name(node.value)
        return node.attr if parent is None else f"{parent}.{node.attr}"
    return None


class _PytestStructureVisitor(ast.NodeVisitor):
    """Collect selectors and skip scopes without extracting evidence facts."""

    def __init__(self, skip_calls: frozenset[str]) -> None:
        self._skip_calls = skip_calls
        self._scope: list[tuple[str, str]] = []
        self._active_selectors: list[str] = [""]
        self.nodes: set[str] = set()
        self.skip_lines: dict[str, list[int]] = {"": []}

    def _selected_function_name(self, name: str) -> str | None:
        """Return the pytest selector for a directly collectable function."""

        if not self._scope:
            return name
        if len(self._scope) == 1 and self._scope[0][0] == "class":
            return f"{self._scope[0][1]}::{name}"
        return None

    def _visit_selected_scope(
        self,
        node: ast.AST,
        *,
        kind: str,
        name: str,
        selector: str | None,
    ) -> None:
        """Visit one scope while attributing skips to every selected owner."""

        self._scope.append((kind, name))
        if selector is not None:
            self.nodes.add(selector)
            self.skip_lines[selector] = []
            self._active_selectors.append(selector)
        self.generic_visit(node)
        if selector is not None:
            self._active_selectors.pop()
        self._scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Index top-level pytest classes and their contained skips."""

        selector = node.name if not self._scope else None
        self._visit_selected_scope(node, kind="class", name=node.name, selector=selector)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Index top-level functions and direct pytest class methods."""

        self._visit_selected_scope(
            node,
            kind="function",
            name=node.name,
            selector=self._selected_function_name(node.name),
        )

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Index async functions using the same pytest selector rules."""

        self._visit_selected_scope(
            node,
            kind="function",
            name=node.name,
            selector=self._selected_function_name(node.name),
        )

    def visit_Call(self, node: ast.Call) -> None:
        """Attribute one skip/xfail call to all enclosing selectors."""

        if _dotted_attribute_name(node.func) in self._skip_calls:
            for selector in self._active_selectors:
                self.skip_lines[selector].append(node.lineno)
        self.generic_visit(node)


def build_pytest_structure_index(
    tree: ast.Module,
    skip_calls: frozenset[str],
    facts: PytestFactsProvider,
) -> PytestSourceIndex:
    """Collect selectors and skip scopes without assertion/call fact work."""

    visitor = _PytestStructureVisitor(skip_calls)
    visitor.visit(tree)
    return PytestSourceIndex(
        nodes=frozenset(visitor.nodes),
        skip_xfail_lines_by_node=tuple(
            (name, tuple(lines)) for name, lines in visitor.skip_lines.items()
        ),
        _facts=facts,
    )
