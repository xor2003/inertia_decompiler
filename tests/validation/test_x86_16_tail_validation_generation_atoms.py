"""Tests for cycle-safe tail-validation generation atom reuse."""

from __future__ import annotations

import dataclasses

import pytest

from inertia.validation.tail_validation_generation_atoms import (
    build_validation_generation_atom_8616,
)


class _SharedSurface:
    """Third-party-like semantic surface with observable field reads."""

    def __init__(self, name: str) -> None:
        self._name = name
        self.name_reads = 0

    @property
    def name(self) -> str:
        """Return the semantic name while counting normalization work."""
        self.name_reads += 1
        return self._name


def test_generation_atom_reuses_shared_cycle_free_surface() -> None:
    """One build must expand a repeated acyclic object only once."""
    shared = _SharedSurface("value")

    atom = build_validation_generation_atom_8616((shared, shared, shared))

    assert shared.name_reads == 1
    assert atom[2][0] == atom[2][1] == atom[2][2]


def test_generation_atom_preserves_path_sensitive_cycle_marker() -> None:
    """Cyclic objects must retain an ancestor-identity refusal marker."""
    cycle: list[object] = []
    cycle.append(cycle)

    atom = build_validation_generation_atom_8616(cycle)

    assert atom == (
        "sequence",
        "builtins.list",
        (("cycle", "builtins.list", id(cycle)),),
    )


def test_generation_atom_does_not_reuse_across_top_level_requests() -> None:
    """A later build must observe mutations to previously normalized evidence."""
    shared = _SharedSurface("before")
    before = build_validation_generation_atom_8616(shared)
    shared._name = "after"

    after = build_validation_generation_atom_8616(shared)

    assert before != after
    assert shared.name_reads == 2


@dataclasses.dataclass
class _InstanceFieldsRow:
    """Dataclass whose field metadata one instance can shadow."""

    a: int
    b: int


class _AliasingMeta(type):
    """Metaclass whose hash and equality alias every class using it."""

    def __eq__(cls, other: object) -> bool:
        return type(other) is _AliasingMeta

    def __hash__(cls) -> int:
        return 7


class _AliasedA(metaclass=_AliasingMeta):
    """First class sharing the aliasing metaclass."""


class _AliasedB(metaclass=_AliasingMeta):
    """Second class sharing the aliasing metaclass."""


class _NoHashMeta(type):
    """Metaclass that leaves every class using it unhashable."""

    __hash__ = None  # type: ignore[assignment]


class _NoHashClass(metaclass=_NoHashMeta):
    """Class whose metaclass makes it unusable in hashed containers."""


class _DictCollidingMeta(type):
    """Metaclass whose hash and equality collide with ``dict``."""

    def __eq__(cls, other: object) -> bool:
        return other is dict or type(other) is _DictCollidingMeta

    def __hash__(cls) -> int:
        return hash(dict)


class _DictColliding(metaclass=_DictCollidingMeta):
    """Plain object that must never be dispatched as a builtin dict."""


class _ListCollidingMeta(type):
    """Metaclass whose hash and equality collide with ``list``."""

    def __eq__(cls, other: object) -> bool:
        return other is list or type(other) is _ListCollidingMeta

    def __hash__(cls) -> int:
        return hash(list)


class _ListColliding(metaclass=_ListCollidingMeta):
    """Plain object that must never be dispatched as a builtin list."""


def test_generation_atom_reads_dataclass_fields_per_instance() -> None:
    """Instance-shadowed field metadata must not drop other instances' fields."""
    first = _InstanceFieldsRow(1, 0)
    second = _InstanceFieldsRow(2, 3)
    first.__dataclass_fields__ = {  # type: ignore[misc]
        "a": _InstanceFieldsRow.__dataclass_fields__["a"]
    }

    before = build_validation_generation_atom_8616([first, second])
    second.b = 99
    after = build_validation_generation_atom_8616([first, second])

    second_fields = before[2][1][2]
    assert ("b", 3) in second_fields
    assert before != after


def test_generation_atom_labels_stay_distinct_under_equal_classes() -> None:
    """Classes sharing metaclass hash/equality keep distinct type labels."""
    atom = build_validation_generation_atom_8616([_AliasedA(), _AliasedB()])

    assert atom[2][0][1] == f"{_AliasedA.__module__}.{_AliasedA.__qualname__}"
    assert atom[2][1][1] == f"{_AliasedB.__module__}.{_AliasedB.__qualname__}"


def test_generation_atom_unhashable_metaclass_fails_in_abc_registry() -> None:
    """An unhashable class fails inside ``isinstance``'s ABC registry."""
    with pytest.raises(TypeError, match="set element"):
        build_validation_generation_atom_8616(_NoHashClass())


def test_generation_atom_dict_colliding_metaclass_matches_original() -> None:
    """A dict-colliding metaclass still reaches only the poisoned ABC branch."""
    with pytest.raises(AttributeError, match="items"):
        build_validation_generation_atom_8616(_DictColliding())


def test_generation_atom_list_colliding_metaclass_matches_original() -> None:
    """A list-colliding metaclass still reaches only the poisoned ABC branch."""
    with pytest.raises(TypeError, match="not iterable"):
        build_validation_generation_atom_8616(_ListColliding())
