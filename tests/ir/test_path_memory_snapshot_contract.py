"""Independent path snapshots must survive all exposed memory mutation paths."""

from __future__ import annotations

import pytest

from inertia.ir.real16_path_memory8616 import PathMemory8616

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutate_copy", [False, True])
def test_copy_detaches_public_collections(mutate_copy: bool) -> None:
    """Public byte maps cannot mutate the opposite path after copying."""
    original = PathMemory8616(known={10: 1}, unknown={20})
    copied = original.copy()
    changed, unchanged = (copied, original) if mutate_copy else (original, copied)
    changed.known[10] = 2
    changed.unknown.add(21)
    assert unchanged.known == {10: 1}
    assert unchanged.unknown == {20}


def test_copy_detaches_constructor_aliases() -> None:
    """A retained constructor argument cannot overwrite a copied path's bytes."""
    known = {10: 1}
    unknown = {20}
    original = PathMemory8616(known=known, unknown=unknown)
    copied = original.copy()
    known[10] = 2
    unknown.add(21)
    assert copied.known == {10: 1}
    assert copied.unknown == {20}


def test_retained_mapping_views_observe_later_writes() -> None:
    """The mutable known-byte mapping keeps live dict-style views."""
    memory = PathMemory8616(known={10: 1})
    keys = memory.known.keys()
    items = memory.known.items()
    values = memory.known.values()
    memory.known[11] = 2
    assert set(keys) == {10, 11}
    assert set(items) == {(10, 1), (11, 2)}
    assert set(values) == {1, 2}
    assert items & {(11, 2)} == {(11, 2)}


def test_assignment_accepts_replaced_plain_known_mapping() -> None:
    """The declared mutable-mapping field can still hold a plain dictionary."""
    target = PathMemory8616()
    replacement = {1: 2}
    target.known = replacement
    source = PathMemory8616(known={3: 4}, unknown={5})
    target.assign(source)
    assert replacement == {3: 4}
    assert target.unknown == {5}
    source.known[3] = 6
    assert target.known == {3: 4}
