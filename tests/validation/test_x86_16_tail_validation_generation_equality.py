"""Preserve exact, work-bounded comparison of validation generation inputs."""

import multiprocessing
import resource
from dataclasses import dataclass
from typing import ClassVar

import pytest
import inertia.validation.tail_validation_generation_atoms as atoms

from inertia.validation.tail_validation_generation import (
    TailValidationSummaryInputGeneration8616 as Generation,
)


class _StatefulInt(int):
    """Demonstrate why integer subclass equality cannot be assumed pure."""

    comparisons: ClassVar[int] = 0
    __hash__ = int.__hash__

    def __eq__(self, other: object) -> bool:
        _StatefulInt.comparisons += 1
        return _StatefulInt.comparisons <= 3 and int.__eq__(self, other)


class _SelfUnequalInt(int):
    """Expose direct scalar equality that tuple identity shortcuts would skip."""

    comparisons: ClassVar[int] = 0
    __hash__ = int.__hash__

    def __eq__(self, other: object) -> bool:
        _SelfUnequalInt.comparisons += 1
        return False


@dataclass(frozen=True, slots=True)
class _NativeGeneration:
    """Keep the installed dataclass protocol as an independent field oracle."""

    function_surface: atoms.ValidationGenerationAtom8616
    codegen_evidence: tuple[tuple[str, atoms.ValidationGenerationAtom8616], ...]
    project_evidence: atoms.ValidationGenerationAtom8616


def _generation(value: object) -> Generation:
    atom = atoms.build_validation_generation_atom_8616(value)
    return Generation(atom, (), atom)


def _assert_shared_dag_contract() -> None:
    """Check pure-value comparison and key coherence under a component CPU cap."""
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    left: object = 7
    equal: object = 7
    unequal: object = 8
    for _ in range(48):
        left = (left, left)
        equal = (equal, equal)
        unequal = (unequal, unequal)
    original = _generation(left)
    equivalent = _generation(equal)
    different = _generation(unequal)
    # Exercise the existing public API first: the saved-source red must be
    # repeated native work, not the absence of the newly added atom helper.
    assert original == equivalent
    assert original != different
    assert atoms.validation_generation_atoms_equal_8616(
        original.function_surface, equivalent.function_surface
    )
    assert not atoms.validation_generation_atoms_equal_8616(
        original.function_surface, different.function_surface
    )
    assert hash(original) == hash(equivalent)
    cache = {("summary", original): "hit"}
    assert cache[("summary", equivalent)] == "hit"
    assert ("summary", different) not in cache


def test_generation_equality_bounds_shared_dag_work() -> None:
    """Repeated paths must not exhaust a bounded pure-value comparison worker."""
    child = multiprocessing.get_context("fork").Process(target=_assert_shared_dag_contract)
    child.start()
    child.join(timeout=30)
    if child.is_alive():
        child.terminate()
        child.join(timeout=5)
    assert child.exitcode == 0, "pure generation comparison exceeded component budget"


def test_generation_equality_preserves_scalar_subclass_methods() -> None:
    """Unknown scalar equality must retain native call order and result."""
    left_leaf = _StatefulInt(7)
    right_leaf = _StatefulInt(7)
    left = (left_leaf, left_leaf)
    right = (right_leaf, right_leaf)
    original = _generation((left, left))
    equivalent = _generation((right, right))
    _StatefulInt.comparisons = 0
    native = (original.function_surface,) == (equivalent.function_surface,)
    native_calls = _StatefulInt.comparisons
    _StatefulInt.comparisons = 0

    assert (original == equivalent) is native is False
    assert _StatefulInt.comparisons == native_calls == 4


@pytest.mark.parametrize("project_field", (False, True))
def test_generation_equality_preserves_shared_scalar_field_methods(project_field: bool) -> None:
    """Different generations must retain native direct-field scalar comparisons."""
    leaf = _SelfUnequalInt(7)
    fields = (None, (), leaf) if project_field else (leaf, (), None)
    native_left = _NativeGeneration(*fields)
    native_right = _NativeGeneration(*fields)
    left = Generation(*fields)
    right = Generation(*fields)
    _SelfUnequalInt.comparisons = 0
    native = native_left == native_right
    native_calls = _SelfUnequalInt.comparisons
    _SelfUnequalInt.comparisons = 0

    assert native is False and native_calls == 1
    assert (left == right) is native
    assert _SelfUnequalInt.comparisons == native_calls
    assert hash(left) == hash(right)
    assert {left: "original"}.get(right) is None


def test_generation_equality_preserves_native_same_instance_shortcut() -> None:
    """The native dataclass self comparison must not invoke scalar methods."""
    leaf = _SelfUnequalInt(7)
    generation = Generation(leaf, (), leaf)
    _SelfUnequalInt.comparisons = 0

    assert generation == generation
    assert _SelfUnequalInt.comparisons == 0


@pytest.mark.parametrize(("leaf", "expected"), ((7, True), (8, False)))
def test_generation_equality_keeps_builder_supported_depth(leaf: int, expected: bool) -> None:
    """Comparison must not introduce a lower recursion limit than the builder."""
    left: object = 7
    right: object = leaf
    for _ in range(275):
        left = [left]
        right = [right]
    left_generation = _generation(left)
    right_generation = _generation(right)

    assert (left_generation == right_generation) is expected
    assert atoms.validation_generation_atoms_equal_8616(
        left_generation.function_surface, right_generation.function_surface
    ) is expected


@pytest.mark.parametrize(
    "different",
    (
        Generation((1, 9), (("k", (3,)),), (4,)),
        Generation((1, 2), (("k", (9,)),), (4,)),
        Generation((1, 2), (("k", (3,)),), (9,)),
    ),
)
def test_generation_equality_checks_every_owned_field(different: Generation) -> None:
    """A late positional or any field mismatch must invalidate a cache key."""
    original = Generation((1, 2), (("k", (3,)),), (4,))

    assert original != different
    assert {original: "hit"}.get(different) is None


def test_generation_equality_retains_value_hash_and_class_protocols() -> None:
    """Equal independently built values share keys, without equating subclasses."""
    shared = [7]
    original = _generation((shared, shared))
    different_sharing = _generation(([7], [7]))
    assert original == different_sharing
    assert hash(original) == hash(different_sharing)
    assert {original: "hit"}[different_sharing] == "hit"

    bool_generation = Generation((True,), (), (1,))
    int_generation = Generation((1,), (), (True,))
    assert bool_generation == int_generation
    assert hash(bool_generation) == hash(int_generation)
    assert {bool_generation: "hit"}[int_generation] == "hit"

    class DerivedGeneration(Generation):
        pass

    derived = DerivedGeneration((True,), (), (1,))
    assert bool_generation.__eq__(derived) is NotImplemented
    assert bool_generation.__eq__(object()) is NotImplemented
    assert bool_generation != derived


def test_generation_equality_keeps_literal_cycles_and_request_mutations() -> None:
    """New comparison must preserve recorded cycle ids and per-request freshness."""
    cycle: list[object] = []
    cycle.append(cycle)
    other_cycle: list[object] = []
    other_cycle.append(other_cycle)
    original = _generation(cycle)
    assert original == _generation(cycle)
    assert original != _generation(other_cycle)

    mutable = {"k": [1, 2]}
    before = _generation(mutable)
    mutable["k"].append(3)
    assert before != _generation(mutable)
