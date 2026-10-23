"""Constant-time conservative address envelope on ``PersistentBytes8616``.

The canonical ``PersistentBytes8616`` facade maintains a half-open
``(low, high)`` envelope over exact-``int`` keys during the per-byte
writes it already performs, so overlap queries never pay an O(|known|)
key scan. Bounds anchor only on an observably empty root at an owned
boundary, bind to the immutable root identity, degrade to ``None`` for
unenumerated contents, and are conservative evidence — never admission.
"""

import random
import sys

import pytest
from immutables import Map as ImmutableMap

from inertia.ir.real16_persistent_bytes8616 import (
    PersistentBytes8616,
    canonical_known_root_8616,
    persistent_bytes_producers_8616,
)

pytestmark = pytest.mark.decompiler


def _seeded(*addresses: int) -> PersistentBytes8616:
    """Build a tracked facade by integer writes from the empty state."""
    facade = PersistentBytes8616()
    for index, address in enumerate(addresses):
        facade[address] = index & 0xFF
    return facade


def _assert_contains_all_int_keys(
    facade: PersistentBytes8616, envelope: tuple[int, int] | None
) -> None:
    """A reported envelope must cover every exact-int key of the map."""
    if envelope is None:
        return
    low, high = envelope
    for key in facade:
        if type(key) is int:
            assert low <= key < high, (key, envelope)


def test_envelope_api_present_and_producer_bound() -> None:
    """The query exists and the fused-walk inventory binds its identity."""
    assert callable(PersistentBytes8616.address_envelope_8616)
    assert (
        PersistentBytes8616.address_envelope_8616
        in persistent_bytes_producers_8616()
    )


def test_empty_seed_reports_none_until_int_write() -> None:
    """An empty tracked map has no endpoints; the caller owns the empty case."""
    facade = PersistentBytes8616()
    assert facade.address_envelope_8616() is None
    facade[5] = 7
    assert facade.address_envelope_8616() == (5, 6)


def test_endpoints_track_extremes() -> None:
    """Min/max writes grow the interval; interior writes keep it exact."""
    facade = _seeded(10, 3, 40)
    assert facade.address_envelope_8616() == (3, 41)
    facade[20] = 0
    assert facade.address_envelope_8616() == (3, 41)
    facade[100] = 0
    facade[-5] = 0
    assert facade.address_envelope_8616() == (-5, 101)


def test_negative_integers_are_exact_int_keys() -> None:
    """Negative byte addresses still count as exact-int keys."""
    facade = _seeded(-100, -50)
    assert facade.address_envelope_8616() == (-100, -49)


def test_interior_delete_keeps_envelope() -> None:
    """Removing a non-endpoint key leaves endpoints unchanged."""
    facade = _seeded(3, 20, 40)
    del facade[20]
    assert facade.address_envelope_8616() == (3, 41)


def test_endpoint_delete_stays_conservative() -> None:
    """Endpoint deletion may stay loose but must still cover live keys."""
    facade = _seeded(3, 20, 40)
    del facade[3]
    envelope = facade.address_envelope_8616()
    assert envelope is not None
    _assert_contains_all_int_keys(facade, envelope)
    assert envelope[1] > 40
    del facade[40]
    _assert_contains_all_int_keys(facade, facade.address_envelope_8616())


def test_delete_to_empty_reanchors() -> None:
    """Draining the map leaves an observably empty root; tracking resumes."""
    facade = _seeded(3, 40)
    del facade[3]
    del facade[40]
    assert len(facade) == 0
    _assert_contains_all_int_keys(facade, facade.address_envelope_8616())
    facade[9] = 1
    _assert_contains_all_int_keys(facade, facade.address_envelope_8616())


def test_clear_resets_envelope() -> None:
    """clear() re-anchors empty regardless of prior tracked state."""
    facade = _seeded(1, 2, 3)
    facade.clear()
    assert facade.address_envelope_8616() is None
    facade[7] = 0
    assert facade.address_envelope_8616() == (7, 8)


def test_update_pop_setdefault_popitem_stay_consistent() -> None:
    """Every inherited mutator routes through the tracked core dunders."""
    facade = PersistentBytes8616()
    facade.update({10: 1, 4: 2})
    assert facade.address_envelope_8616() == (4, 11)
    assert facade.setdefault(30, 9) == 9
    assert facade.setdefault(10, 0) == 1
    assert facade.address_envelope_8616() == (4, 31)
    assert facade.pop(4) == 2
    _assert_contains_all_int_keys(facade, facade.address_envelope_8616())
    key, _ = facade.popitem()
    assert key not in facade
    _assert_contains_all_int_keys(facade, facade.address_envelope_8616())
    remaining = 30 if key == 10 else 10
    assert facade.pop(remaining) == {10: 1, 30: 9}[remaining]
    _assert_contains_all_int_keys(facade, facade.address_envelope_8616())


def test_share_preserves_envelope_and_isolation() -> None:
    """Canonical share copies metadata; each side then diverges cleanly."""
    facade = _seeded(10, 20, 30)
    clone = facade.share_8616()
    assert clone._root is facade._root
    assert clone.address_envelope_8616() == (10, 31)
    clone[100] = 0
    assert clone.address_envelope_8616() == (10, 101)
    assert facade.address_envelope_8616() == (10, 31)
    facade[0] = 0
    assert facade.address_envelope_8616() == (0, 31)
    assert clone.address_envelope_8616() == (10, 101)
    assert dict(facade) == {0: 0, 10: 0, 20: 1, 30: 2}
    assert dict(clone) == {10: 0, 20: 1, 30: 2, 100: 0}


def test_adopt_canonical_transfers_envelope_state() -> None:
    """Adopting a canonical facade adopts its anchored-or-not verdict."""
    source = _seeded(5, 50)
    target = _seeded(1, 2)
    target.adopt_8616(source)
    assert target.address_envelope_8616() == (5, 51)
    target[0] = 0
    assert target.address_envelope_8616() == (0, 51)
    assert source.address_envelope_8616() == (5, 51)


def test_adopt_disabled_canonical_stays_unknown() -> None:
    """A source whose envelope was disabled transfers the refusal."""
    source = PersistentBytes8616()
    source["x"] = 1  # non-int key disables bounds; the store still happens
    target = _seeded(1, 2)
    target.adopt_8616(source)
    assert target.address_envelope_8616() is None
    assert dict(target) == {"x": 1}


def test_foreign_construction_never_scans() -> None:
    """Nonempty foreign or native roots report unknown bounds, no scan."""
    assert PersistentBytes8616({1: 2}).address_envelope_8616() is None
    assert (
        PersistentBytes8616(ImmutableMap({1: 2})).address_envelope_8616()
        is None
    )
    # An observably empty folded root anchors regardless of provenance.
    for empty in ({}, ImmutableMap(), PersistentBytes8616()):
        facade = PersistentBytes8616(empty)
        assert facade.address_envelope_8616() is None
        facade[3] = 0
        assert facade.address_envelope_8616() == (3, 4)


def test_adopt_foreign_never_scans() -> None:
    """Foreign adopt folds without enumeration: empty anchors, else None."""
    target = _seeded(1, 2)
    target.adopt_8616({7: 7, 9: 9})
    assert target.address_envelope_8616() is None
    target.adopt_8616({})
    assert target.address_envelope_8616() is None
    target[4] = 0
    assert target.address_envelope_8616() == (4, 5)


def test_external_root_replacement_invalidates() -> None:
    """A swapped _root — even a genuine Map — must not trust stale bounds."""
    facade = _seeded(1, 2, 3)
    facade._root = ImmutableMap({100: 0, 900: 1})
    assert facade.address_envelope_8616() is None
    facade[200] = 0  # contents were never enumerated: still unknown
    assert facade.address_envelope_8616() is None
    facade._root = ImmutableMap()  # observably empty at the next write
    assert facade.address_envelope_8616() is None
    facade[8] = 0
    assert facade.address_envelope_8616() == (8, 9)


def test_malformed_key_disables_envelope_keeps_mapping() -> None:
    """A non-int key stores like dict but disables the envelope."""
    facade = _seeded(1, 2)
    facade["x"] = 9
    assert facade["x"] == 9 and len(facade) == 3
    assert facade.address_envelope_8616() is None
    facade[3] = 0  # the root was never re-enumerated: stays unknown
    assert facade.address_envelope_8616() is None
    assert dict(facade) == {1: 0, 2: 1, "x": 9, 3: 0}


def test_bool_key_is_not_an_exact_int() -> None:
    """bool keys store fine but disable the envelope like dict would."""
    facade = _seeded(1)
    facade[True] = 0
    assert facade.address_envelope_8616() is None
    assert True in facade and facade[True] == 0


def test_failed_mutations_leave_root_and_bounds_consistent() -> None:
    """Raising writes/deletes change neither the root nor the envelope."""
    facade = _seeded(4, 9)
    root_before = facade._root
    with pytest.raises(KeyError):
        del facade[999]
    with pytest.raises(TypeError):
        facade[[]] = 0
    with pytest.raises(KeyError):
        facade.pop(999)
    assert facade._root is root_before
    assert facade.address_envelope_8616() == (4, 10)
    assert dict(facade) == {4: 0, 9: 1}


def test_mapping_semantics_unchanged() -> None:
    """len/eq/contains/live views behave exactly like the dict contract."""
    facade = _seeded(1, 2, 3)
    view = facade.keys()
    facade[10] = 0
    assert len(facade) == 4 and facade == dict(facade)
    assert 10 in view and set(view) == {1, 2, 3, 10}
    assert facade == {1: 0, 2: 1, 3: 2, 10: 0}
    assert facade != {1: 0}


def test_canonical_admission_contract_unchanged() -> None:
    """canonical_known_root_8616 still authenticates only type and root."""
    facade = _seeded(1)
    assert canonical_known_root_8616(facade)
    assert not canonical_known_root_8616({1: 0})


def test_no_iteration_on_tracked_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """O(1) proof: envelope, share, adopt, set and del never iterate.

    Patching every iteration surface of the facade to raise would break
    any scan-based implementation; all tracked paths must still succeed.
    """
    facade = _seeded(*range(64))
    source = _seeded(*range(128))

    def _no_iteration(*args: object, **kwargs: object) -> None:
        raise AssertionError("envelope path iterated the map")

    for name in ("__iter__", "items", "keys", "values"):
        monkeypatch.setattr(PersistentBytes8616, name, _no_iteration)

    assert facade.address_envelope_8616() == (0, 64)
    clone = facade.share_8616()
    clone[200] = 0
    del facade[0]
    facade[70] = 1
    target = PersistentBytes8616()
    target.adopt_8616(source)
    assert target.address_envelope_8616() == (0, 128)


def test_no_c_level_scan_on_query() -> None:
    """The query executes zero inner calls — profile-verified, no timing."""
    facade = _seeded(*range(256))
    calls: list[str] = []
    recording = True
    previous_profiler = sys.getprofile()

    def _profiler(frame, event, arg) -> None:
        if not recording:
            return
        if event == "call":
            calls.append(frame.f_code.co_name)
        elif event == "c_call":
            calls.append(getattr(arg, "__qualname__", repr(arg)))

    sys.setprofile(_profiler)
    try:
        assert facade.address_envelope_8616() == (0, 256)
    finally:
        recording = False
        sys.setprofile(previous_profiler)
    assert calls == ["address_envelope_8616"], calls


def test_no_c_level_scan_on_mutations() -> None:
    """Maintained writes perform no iter/next enumeration of the root."""
    facade = _seeded(*range(256))
    calls: list[str] = []
    recording = True
    previous_profiler = sys.getprofile()

    def _profiler(frame, event, arg) -> None:
        if not recording:
            return
        if event == "call":
            calls.append(frame.f_code.co_name)
        elif event == "c_call":
            calls.append(getattr(arg, "__qualname__", repr(arg)))

    sys.setprofile(_profiler)
    try:
        facade[300] = 0
        del facade[300]
        facade.share_8616()
        PersistentBytes8616().adopt_8616(facade)
    finally:
        recording = False
        sys.setprofile(previous_profiler)
    forbidden = {"iter", "next", "Map.__iter__", "keys", "items", "values"}
    assert not forbidden.intersection(calls), calls
    # Each mutation does a bounded amount of Python-level work regardless
    # of the 256-entry map — a scan would show O(n) interpreter frames.
    assert len(calls) < 24, calls


def test_deterministic_mutation_sequence_envelope_covers_keys() -> None:
    """Property: every actual int key stays inside each reported envelope.

    A seeded pseudo-random mix of every mutator keeps the facade equal to
    a reference dict while asserting the conservative-envelope invariant
    after every single step.
    """
    rng = random.Random(8616)
    facade = PersistentBytes8616()
    reference: dict[object, object] = {}
    live_keys = list(range(-20, 200))
    for step in range(400):
        op = rng.randrange(7)
        if op == 0 and reference:
            key = rng.choice(list(reference))
            del facade[key]
            del reference[key]
        elif op == 1 and reference:
            key = rng.choice(list(reference))
            assert facade.pop(key) == reference.pop(key)
        elif op == 2:
            key = rng.choice(live_keys)
            assert facade.setdefault(key, 0) == reference.setdefault(key, 0)
        elif op == 3:
            batch = {rng.choice(live_keys): step for _ in range(4)}
            facade.update(batch)
            reference.update(batch)
        elif op == 4:
            facade.clear()
            reference.clear()
        elif op == 5 and reference:
            key, _ = facade.popitem()
            reference.pop(key)
        else:
            key = rng.choice(live_keys)
            facade[key] = step
            reference[key] = step
        assert dict(facade) == reference, (step, op)
        _assert_contains_all_int_keys(
            facade, facade.address_envelope_8616()
        )
    assert len(facade) == len(reference)
