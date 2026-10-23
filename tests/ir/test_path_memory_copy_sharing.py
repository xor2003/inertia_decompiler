"""Persistent-root sharing controls for the path-memory overlay.

``_feasibility_call_scratch_8616`` detaches the caller's register and
memory state before speculative call authentication. Deep-copying a
thousands-byte ``known`` overlay per speculative call is the measured
CMP16 census blocker. The persistent representation must let an
independent copy share the immutable ``known`` root while every public
mutation — API or direct ``known[key] = byte`` — stays fully isolated;
``unknown`` remains an ordinary copied ``set``.
"""
import pytest

from inertia.ir.real16_path_memory8616 import (
    PathMemory8616,
    meet_path_memory_8616,
    path_memory_initial_8616,
    path_memory_tainted_8616,
    restore_path_memory_8616,
    snapshot_path_memory_8616,
)

pytestmark = pytest.mark.decompiler


def _seeded(size: int = 8) -> PathMemory8616:
    memory = path_memory_initial_8616()
    memory.apply_write(0x1000, size, bytes(range(size)))
    memory.apply_write(0x2000, 2, None)
    return memory


def test_copy_shares_known_root_copies_unknown_set() -> None:
    """O(1) known borrow, honest unknown copy."""
    memory = _seeded()
    copied = memory.copy()
    assert copied.known._root is memory.known._root
    assert copied.unknown == memory.unknown
    assert copied.unknown is not memory.unknown


def test_api_write_on_copy_never_reaches_source() -> None:
    """apply_write on the copy swaps only the copy's root."""
    memory = _seeded()
    copied = memory.copy()
    copied.apply_write(0x1000, 1, b"\xff")
    copied.apply_write(0x3000, 1, None)
    assert copied.known[0x1000] == 0xFF and memory.known[0x1000] == 0
    assert 0x3000 in copied.unknown and 0x3000 not in memory.unknown


def test_source_write_after_copy_cannot_reach_copy() -> None:
    """Source writes replace the source root; the copy keeps its borrow."""
    memory = _seeded()
    copied = memory.copy()
    memory.apply_write(0x1000, 1, b"\xaa")
    memory.apply_write(0x2000, 1, b"\xbb")
    assert copied.known[0x1000] == 0 and memory.known[0x1000] == 0xAA
    assert 0x2000 in copied.unknown and copied.unknown == {0x2000, 0x2001}


def test_copy_then_taint_leaves_source_intact() -> None:
    """Discarding a speculative copy through taint never reaches the source."""
    memory = _seeded()
    copied = memory.copy()
    copied.taint()
    assert copied.tainted and not copied.known and not copied.unknown
    assert not memory.tainted and len(memory.known) == 8
    assert memory.unknown == {0x2000, 0x2001}


def test_assign_publishes_contents_then_diverges() -> None:
    """Assign adopts contents in place; later writes stay independent."""
    source = _seeded()
    memory = path_memory_tainted_8616()
    held = memory.known
    memory.assign(source)
    assert memory == source and not memory.tainted
    assert held is memory.known and dict(held) == dict(source.known)
    memory.apply_write(0x3000, 1, b"\x01")
    assert 0x3000 not in source.known
    source.apply_write(0x3001, 1, b"\x02")
    assert 0x3001 not in memory.known


def test_meet_over_shared_inputs_never_mutates_sources() -> None:
    """Must-meet mutates only its result, never a shared input overlay."""
    first = _seeded()
    borrowed = first.copy()
    second = _seeded()
    second.apply_write(0x1000, 1, b"\x77")
    second.apply_write(0x4000, 1, b"\x09")
    result = meet_path_memory_8616((first, second))
    assert result.known.get(0x1000) is None and result.known.get(0x4000) is None
    assert 0x1000 in result.unknown and 0x4000 in result.unknown
    assert borrowed.known == dict(first.known)
    assert borrowed.unknown == first.unknown
    assert first.known[0x1000] == 0 and first.unknown == {0x2000, 0x2001}


def test_large_overlay_copy_then_single_write() -> None:
    """The CMP16 shape: a 4096-byte known map copies without cloning."""
    memory = path_memory_initial_8616()
    memory.apply_write(0x0, 4096, bytes(i & 0xFF for i in range(4096)))
    copied = memory.copy()
    assert copied.known._root is memory.known._root
    copied.apply_write(0x10, 1, b"\x00")
    assert copied.known[0x10] == 0 and memory.known[0x10] == 0x10
    assert {k: v for k, v in copied.known.items() if k != 0x10} == {
        k: v for k, v in memory.known.items() if k != 0x10
    }


def test_snapshot_roundtrip_equality_unchanged() -> None:
    """Snapshot/restore projection stays content-identical."""
    memory = _seeded()
    copied = memory.copy()
    assert copied == memory
    assert snapshot_path_memory_8616(copied) == snapshot_path_memory_8616(memory)
    restored = restore_path_memory_8616(snapshot_path_memory_8616(memory))
    assert restored == memory and restored.known == dict(memory.known)


def test_dataclasses_replace_and_copy_module_stay_isolated() -> None:
    """replace()/copy.copy produce snapshots siblings cannot corrupt."""
    import copy as copy_module
    import dataclasses

    memory = _seeded()
    replaced = dataclasses.replace(memory)
    shallow = copy_module.copy(memory)
    for sibling in (replaced, shallow):
        sibling.known[0x1000] = 0xEE
        sibling.unknown.add(0x5000)
        assert memory.known[0x1000] == 0 and 0x5000 not in memory.unknown


def test_copy_work_units_reflects_actual_copy_cost() -> None:
    """Cheap canonical share + honest unknown copy; foreign map costs len."""
    memory = _seeded()
    assert memory.copy_work_units_8616() == 2 + 8  # unknown set + constant
    foreign = PathMemory8616(known={1: 2})
    foreign.known = dict.fromkeys(range(64), 0)  # injected plain dict
    assert foreign.copy_work_units_8616() == 0 + 64 + 8


def test_producer_inventory_binds_facade_and_mixin_identities() -> None:
    """Fused-walk authentication covers inherited mixin writers too."""
    from inertia.ir.real16_persistent_bytes8616 import (
        PersistentBytes8616,
        canonical_known_root_8616,
        persistent_bytes_producers_8616,
    )

    producers = persistent_bytes_producers_8616()
    for identity in (
        persistent_bytes_producers_8616,
        canonical_known_root_8616,
        PersistentBytes8616.__setitem__,
        PersistentBytes8616.get,
        PersistentBytes8616.pop,
        PersistentBytes8616.update,
        PersistentBytes8616.setdefault,
        PersistentBytes8616.popitem,
    ):
        assert identity in producers


def test_constructor_dict_alias_cannot_reach_copy() -> None:
    """A retained constructor dict cannot write through a copied overlay."""
    known = {10: 1}
    original = PathMemory8616(known=known)
    copied = original.copy()
    known[10] = 2
    assert copied.known == {10: 1}
