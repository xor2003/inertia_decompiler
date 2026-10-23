"""Cyclic generation atoms preserve ancestry while bounding repeated work."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import pytest

from inertia.validation.tail_validation_generation_atoms import (
    ValidationGenerationAtom8616,
    ValidationGenerationAtomBuilder8616,
    build_validation_generation_atom_8616,
)


@dataclass
class Node:
    """Minimal mutable evidence graph with shared and cyclic children."""

    payload: int = 0
    children: list[Node] = field(default_factory=list)


class CountingBuilder(ValidationGenerationAtomBuilder8616):
    """Count materialized compound inputs without changing atom semantics."""

    calls: int = 0

    def _uncached_atom(
        self, value: object,
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Count the actual uncached traversal dispatch."""
        self.calls += 1
        return super()._uncached_atom(value)


def _diamond(depth: int) -> Node:
    node = Node()
    node.children.append(node)
    for _ in range(depth):
        node = Node(children=[node, node])
    return node


def _reference_atom(
    value: Node | list[Node] | int,
    active: frozenset[int] = frozenset(),
) -> ValidationGenerationAtom8616:
    """Specify literal path-sensitive snapshots without any memoization."""
    if isinstance(value, int):
        return value
    label = f"{type(value).__module__}.{type(value).__qualname__}"
    if id(value) in active:
        return ("cycle", label, id(value))
    descendants = active | {id(value)}
    if isinstance(value, list):
        return ("sequence", label, tuple(_reference_atom(child, descendants) for child in value))
    return (
        "dataclass", label,
        (("payload", value.payload), ("children", _reference_atom(value.children, descendants))),
    )


def test_shared_cyclic_dataclass_walk_is_linear() -> None:
    root = _diamond(9)
    builder = CountingBuilder()
    atom = builder.atom(root)
    assert atom == _reference_atom(root)
    # Ten distinct dataclasses and their ten child lists, each encoded once.
    # Without contextual reuse the identical graph takes 2046 dispatches.
    assert builder.calls == 20


def test_cycle_ancestry_and_mutation_remain_exact() -> None:
    a, b = Node(1), Node(2)
    a.children.append(b)
    b.children.append(a)
    root = [a, b, a, b]
    before = build_validation_generation_atom_8616(root)
    assert before == _reference_atom(root)
    b.payload = 3
    after = build_validation_generation_atom_8616(root)
    assert before != after
    assert after == _reference_atom(root)


@pytest.mark.parametrize("seed", range(30))
def test_random_cyclic_graph_matches_literal_snapshot(seed: int) -> None:
    randomizer = random.Random(seed)
    nodes = [Node(index) for index in range(5)]
    for node in nodes:
        node.children.extend(randomizer.choices(nodes, k=2))
    assert build_validation_generation_atom_8616(nodes) == _reference_atom(nodes)


def test_context_retention_is_bounded() -> None:
    builder = ValidationGenerationAtomBuilder8616()
    roots = [_diamond(4) for _ in range(300)]
    assert builder.atom(roots) == _reference_atom(roots)
    retained_references = builder._context_references
    assert 0 < retained_references <= 4096
    # Exhausting the optimization budget must preserve complete snapshots.
    assert builder.atom(roots) == _reference_atom(roots)
    assert builder._context_references == retained_references


@pytest.mark.parametrize("dynamic", [False, True])
def test_mutated_cycle_is_observed_between_same_builder_roots(dynamic: bool) -> None:
    root = Node(1)
    root.children.append(root)
    builder = ValidationGenerationAtomBuilder8616()
    owner = Node(children=[root])
    before = builder.dynamic_field_atom(owner, "children") if dynamic else builder.atom(root)
    root.payload = 2
    after = builder.dynamic_field_atom(owner, "children") if dynamic else builder.atom(root)
    assert before != after
    assert after == _reference_atom(owner.children if dynamic else root)
