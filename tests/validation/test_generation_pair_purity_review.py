"""Independent equality-protocol controls for pair-specific DAG comparison."""

from __future__ import annotations

from typing import ClassVar

import pytest

from inertia.validation.tail_validation_generation_atoms import (
    validation_generation_atoms_equal_8616,
)


class _ObservedInt(int):
    """Record native scalar comparisons without changing their result."""

    comparisons: ClassVar[list[tuple[int, int]]] = []

    def __eq__(self, other: object) -> bool:
        """Expose whether preflight improperly invokes or skips equality."""
        if not isinstance(other, int):
            return NotImplemented
        self.comparisons.append((int(self), int(other)))
        return int(self) == int(other)


@pytest.mark.parametrize("longer_left", [False, True])
def test_different_lengths_preserve_custom_prefix_comparison(longer_left: bool) -> None:
    """Native tuples compare a common prefix before checking their lengths."""
    left = (_ObservedInt(7),)
    right = (_ObservedInt(7), 9)
    if longer_left:
        left, right = right, left
    _ObservedInt.comparisons.clear()
    expected = left == right
    native_calls = tuple(_ObservedInt.comparisons)
    _ObservedInt.comparisons.clear()

    assert validation_generation_atoms_equal_8616(left, right) is expected is False
    assert tuple(_ObservedInt.comparisons) == native_calls == ((7, 7),)


class _PoisonInt(int):
    """A shared contained value whose equality must never be invoked."""

    def __eq__(self, other: object) -> bool:
        """Fail if the tuple's contained-object identity shortcut is lost."""
        raise AssertionError("identical contained objects need no equality call")


def test_identical_custom_leaf_retains_native_tuple_shortcut() -> None:
    """Different tuple roots can share the exact same custom scalar safely."""
    leaf = _PoisonInt(7)
    left = ((leaf,), (leaf,))
    right = ((leaf,), (leaf,))
    assert left == right
    assert validation_generation_atoms_equal_8616(left, right)


@pytest.mark.parametrize("custom_first", [False, True])
def test_pure_mismatch_preserves_custom_comparison_order(custom_first: bool) -> None:
    """A native early mismatch skips only custom methods after its position."""
    left = (_ObservedInt(7), 1) if custom_first else (1, _ObservedInt(7))
    right = (_ObservedInt(7), 2) if custom_first else (2, _ObservedInt(7))
    _ObservedInt.comparisons.clear()
    expected = left == right
    native_calls = tuple(_ObservedInt.comparisons)
    _ObservedInt.comparisons.clear()

    assert validation_generation_atoms_equal_8616(left, right) is expected is False
    assert tuple(_ObservedInt.comparisons) == native_calls
    assert len(native_calls) == int(custom_first)


class _UnequalTuple(tuple):
    """Distinguish root tuple-subclass equality from contained identity."""

    comparisons: ClassVar[int] = 0

    def __eq__(self, other: object) -> bool:
        """A tuple subclass may deliberately reject even self equality."""
        type(self).comparisons += 1
        return False


def test_root_tuple_subclass_preserves_its_own_equality() -> None:
    """The contained-value identity shortcut must not change root dispatch."""
    root = _UnequalTuple((1,))
    _UnequalTuple.comparisons = 0
    assert validation_generation_atoms_equal_8616(root, root) is False
    assert _UnequalTuple.comparisons == 1
