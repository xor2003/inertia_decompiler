"""Written-address envelope fast path at the code/write guard boundary.

``_feasibility_code_unmodified_8616`` decides "no written byte touches
protected code" per path. A conservative written-byte envelope provably
disjoint from the protected-union envelope must skip the merge and both
membership lanes with the identical ``True`` verdict — without paying an
O(|known|) scan on a large canonical known-byte map. Intersecting,
unbounded, oversized or foreign inputs keep the original exact lanes.
"""

import sys
import time
from contextlib import contextmanager
from itertools import combinations
from types import SimpleNamespace
from typing import cast

import pytest
from immutables import Map as ImmutableMap

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.real16_persistent_bytes8616 import (
    PersistentBytes8616,
    persistent_bytes_producers_8616,
)
from inertia.ir.real16_scratch_protection import (
    CallerIntervalSelectionStatus8616,
    ScratchCallerRange8616,
    select_caller_intervals_8616,
)
from inertia.ir.segment_call_preservation import (
    segment_call_dependency_traversal_scope_8616,
)

pytestmark = pytest.mark.decompiler

#: Required integration witness: a 4094-byte canonical known map plus two
#: unknown writes checked against 121 protected spans under a caller range.
_WITNESS_KNOWN_START = 9024
_WITNESS_KNOWN_COUNT = 4094
_WITNESS_UNKNOWN = frozenset({11522, 11523})
_CALLER_RANGE = ScratchCallerRange8616(7149, 7714)


def _ctx(
    spans: set[tuple[int, int]] | list[tuple[int, int]],
    limit: int = 100000,
    deadline: float | None = None,
) -> owner._PathCensusContext8616:
    """Provide the exact resource fields this private guard consumes."""
    return cast(
        owner._PathCensusContext8616,
        SimpleNamespace(
            manifest=spans,
            work_units=0,
            accounted_work_units=0,
            work_limit=limit,
            deadline=time.monotonic() + 30 if deadline is None else deadline,
        ),
    )


def _memory(
    known: dict[int, int] | PersistentBytes8616 | None = None,
    unknown: set[int] | None = None,
) -> PathMemory8616:
    return PathMemory8616(known or {}, unknown or set())


def _check(ctx, memory, caller_range=None):
    with segment_call_dependency_traversal_scope_8616():
        return owner._feasibility_code_unmodified_8616(
            ctx, memory, caller_range=caller_range
        )


def _witness_spans() -> set[tuple[int, int]]:
    """121 in-range subspans plus the complete caller-range span."""
    spans = {(_CALLER_RANGE.start + 4 * index, 2) for index in range(120)}
    spans.add((_CALLER_RANGE.start, _CALLER_RANGE.end - _CALLER_RANGE.start))
    return spans


def _witness_memory(
    known_extra: set[int] | None = None,
    unknown: set[int] | None = None,
) -> PathMemory8616:
    """4094 tracked known bytes via update(), then the shared overlay."""
    facade = PersistentBytes8616()
    facade.update(
        {
            address: index & 0xFF
            for index, address in enumerate(
                range(_WITNESS_KNOWN_START, _WITNESS_KNOWN_START + _WITNESS_KNOWN_COUNT + 2)
            )
            if address not in _WITNESS_UNKNOWN
        }
    )
    for address in known_extra or ():
        facade[address] = 0
    return PathMemory8616(
        facade, _WITNESS_UNKNOWN if unknown is None else unknown
    )


@contextmanager
def _py_start_counts():
    """Count PY_START events per code object without replacing producers."""
    counts: dict[object, int] = {}
    monitoring = sys.monitoring

    def record(code, _offset) -> None:
        counts[code] = counts.get(code, 0) + 1

    tool_id = None
    for candidate in (
        monitoring.PROFILER_ID,
        monitoring.OPTIMIZER_ID,
        4,
        5,
        monitoring.DEBUGGER_ID,
        monitoring.COVERAGE_ID,
    ):
        try:
            monitoring.use_tool_id(candidate, "written_envelope_review")
        except ValueError:
            continue
        tool_id = candidate
        break
    assert tool_id is not None, "no free sys.monitoring tool id"
    monitoring.register_callback(tool_id, monitoring.events.PY_START, record)
    monitoring.set_events(tool_id, monitoring.events.PY_START)
    try:
        yield counts
    finally:
        monitoring.set_events(tool_id, 0)
        monitoring.register_callback(
            tool_id, monitoring.events.PY_START, None
        )
        monitoring.free_tool_id(tool_id)


def _facade_call_count(counts: dict[object, int], name: str) -> int:
    """Instrumented entries of one facade method by code identity."""
    return counts.get(getattr(PersistentBytes8616, name).__code__, 0)


def test_witness_disjoint_fast_path_never_enumerates_known_map() -> None:
    """4094 known bytes + 2 unknown vs 121 spans: verdict True, zero scans.

    sys.monitoring proves the disjoint path consulted only the maintained
    envelope — no facade iteration, per-key lookup or membership call ran.
    Producer identities stay bound to the unmodified functions throughout.
    """
    ctx = _ctx(_witness_spans())
    memory = _witness_memory()
    producers_before = persistent_bytes_producers_8616()
    with _py_start_counts() as counts:
        result = _check(ctx, memory, caller_range=_CALLER_RANGE)
    assert result is True
    # The maintained-envelope query ran exactly once: the fast path was
    # really taken, not silently replaced by a skipped guard.
    assert _facade_call_count(counts, "address_envelope_8616") == 1
    for name in (
        "__iter__", "items", "keys", "values",
        "__getitem__", "__contains__", "get",
        "pop", "popitem", "setdefault",
    ):
        assert _facade_call_count(counts, name) == 0, name
    # O(1) length checks are the only permitted facade work; a scan would
    # fire per-key interpreter frames instead.
    assert _facade_call_count(counts, "__len__") <= 4
    producers_after = persistent_bytes_producers_8616()
    assert len(producers_after) == len(producers_before)
    assert all(
        before is after
        for before, after in zip(producers_before, producers_after, strict=True)
    )


def test_witness_overlapping_unknown_write_refuses() -> None:
    """One unknown byte inside the caller envelope keeps the exact lane."""
    ctx = _ctx(_witness_spans())
    memory = _witness_memory(unknown={4865, 7150})
    assert _check(ctx, memory, caller_range=_CALLER_RANGE) is False


def test_witness_overlapping_known_write_refuses() -> None:
    """A tracked known byte inside the union refuses identically."""
    ctx = _ctx(_witness_spans())
    memory = _witness_memory(known_extra={7200})
    assert _check(ctx, memory, caller_range=_CALLER_RANGE) is False


def test_witness_root_replacement_invalidates_stale_bounds() -> None:
    """A swapped known root must not certify on the old maintained bounds."""
    ctx = _ctx(_witness_spans())
    memory = _witness_memory()
    memory.known._root = ImmutableMap({7150: 0})
    assert _check(ctx, memory, caller_range=_CALLER_RANGE) is False

    ctx = _ctx(_witness_spans())
    memory = _witness_memory()
    memory.known._root = ImmutableMap({100: 0})
    assert _check(ctx, memory, caller_range=_CALLER_RANGE) is True


def test_manifest_span_operator_mutation_cannot_stale_certify() -> None:
    """A foreign span whose unpacking mutates known keeps the exact verdict."""
    memory = _witness_memory()

    class _MutatingSpan:
        def __iter__(self):
            memory.known[7150] = 0  # operator mutates the ledger mid-walk
            return iter((200, 0))

    spans = _witness_spans()
    spans.add(_MutatingSpan())
    ctx = _ctx(spans)
    assert _check(ctx, memory, caller_range=_CALLER_RANGE) is False


@pytest.mark.parametrize("size", [0, -4])
@pytest.mark.parametrize("selected_caller", [False, True])
def test_nonpositive_extent_operator_cannot_stale_certify(size: int, selected_caller: bool) -> None:
    """Even a discarded foreign extent can write code during its comparison."""
    memory = _witness_memory()

    class MutatingExtent(int):
        def __gt__(self, other: int) -> bool:
            memory.known[7150] = 0
            return int.__gt__(self, other)

    spans = _witness_spans() | {(200, MutatingExtent(size))}
    assert _check(
        _ctx(spans), memory,
        caller_range=_CALLER_RANGE if selected_caller else None,
    ) is False
    assert memory.known[7150] == 0


@pytest.mark.parametrize(
    "extra",
    [
        ((200, 0),),
        ((300, -4),),
        ((7149, 0),),
        ((7149, -565),),
        ((7149, True),),
    ],
)
def test_foreign_manifest_coordinates_keep_exact_verdict(extra) -> None:
    """Zero/negative/bool extents and foreign coords never stale-certify."""
    spans = _witness_spans() | set(extra)
    ctx = _ctx(spans)
    memory = _witness_memory()
    expected = not any(
        start <= address < start + size
        for start, size in spans
        if type(start) is int and type(size) is int
        for address in set(memory.known) | memory.unknown
    )
    assert _check(ctx, memory, caller_range=_CALLER_RANGE) is expected


def test_caller_range_selected_envelope_covers_kept_intervals() -> None:
    """Selection publishes an envelope covering every kept interval."""
    ctx = _ctx(set())
    spans = {(0x1000 + i, 1) for i in range(20)} | {(0x1000, 100), (0x2000, 4)}
    selected = select_caller_intervals_8616(
        ctx, spans, ScratchCallerRange8616(0x1000, 0x1064),
        owner._census_work_exceeded_8616,
    )
    assert selected.status is CallerIntervalSelectionStatus8616.SELECTED
    assert selected.envelope is not None
    low, high = selected.envelope
    for base, end in selected.intervals or ():
        assert low <= base and end <= high
    assert (low, high) == (0x1000, 0x2004)


def test_disjoint_envelope_returns_true_under_scan_bound() -> None:
    """A far-away write stays True while paying no merge or lane units."""
    spans = [(100 + 3 * i, 2) for i in range(30)]
    ctx = _ctx(spans)
    memory = _memory({0xFFFF0: 7}, {0xFFFF1})
    assert _check(ctx, memory) is True
    # scan(2) + input walk(30) only; merge(30)+sizes(30)+lane stay below.
    assert ctx.work_units <= len(spans) + 8


def test_intersecting_envelope_keeps_exact_lane_and_verdict() -> None:
    """Envelope overlap must still run the original per-byte lane."""
    spans = [(100 + 3 * i, 2) for i in range(30)]
    ctx = _ctx(spans)
    memory = _memory({101: 0})  # inside span (100, 2)
    assert _check(ctx, memory) is False


def test_disjoint_below_and_touching_endpoints() -> None:
    """A written envelope ending exactly at the low bound is disjoint."""
    spans = [(100 + 3 * i, 2) for i in range(30)]
    ctx = _ctx(spans)
    assert _check(ctx, _memory({98: 0}, {99})) is True


def test_high_side_disjoint() -> None:
    """A written envelope starting at the union high bound is disjoint."""
    spans = [(100 + 3 * i, 2) for i in range(30)]  # envelope [100, 189)
    ctx = _ctx(spans)
    assert _check(ctx, _memory(unknown={189, 190})) is True


def test_disjoint_envelope_with_caller_range() -> None:
    """caller_range path returns True early on a disjoint ledger."""
    spans = {(0x1000, 100)} | {(0x1000 + i, 1) for i in range(10)}
    ctx = _ctx(spans)
    result = _check(
        ctx, _memory(unknown={0x9000}),
        caller_range=ScratchCallerRange8616(0x1000, 0x1064),
    )
    assert result is True


def test_caller_range_intersecting_still_exact() -> None:
    """Selected envelope overlap keeps the exact verdicts."""
    spans = {(0x1000, 100)} | {(0x1000 + i, 1) for i in range(10)}
    ctx = _ctx(spans)
    result = _check(
        ctx, _memory(unknown={0x1010}),
        caller_range=ScratchCallerRange8616(0x1000, 0x1064),
    )
    assert result is False


def test_empty_memory_stays_true() -> None:
    """Empty ledgers never pay the written-envelope scan."""
    ctx = _ctx([(10, 3), (10, 3), (12, 3), (15, 2), (20, 1)])
    assert _check(ctx, _memory()) is True


def test_oversized_ledger_takes_original_path() -> None:
    """A written ledger at the half-manifest bound runs the original path."""
    spans = [(10, 3), (12, 3), (15, 2), (20, 1)]  # manifest 4
    ctx = _ctx(spans)
    memory = _memory(dict.fromkeys((30, 31), 0), set())  # 2*2 < 4 is False
    assert _check(ctx, memory) is True


def test_malformed_written_key_falls_back_exact() -> None:
    """Non-int addresses disable the envelope but keep the exact verdict."""
    spans = [(100 + 3 * i, 2) for i in range(30)]
    ctx = _ctx(spans)
    memory = _memory({"x": 0, 101: 0})
    # "x" is not int -> envelope disabled -> exact sparse lane still runs.
    try:
        result = _check(ctx, memory)
    except TypeError:
        result = "typeerror"
    assert result in (False, "typeerror")


def test_bool_address_not_treated_as_int() -> None:
    """bool keys skip the int-only envelope; verdict stays exact."""
    spans = [(100 + 3 * i, 2) for i in range(30)]
    ctx = _ctx(spans)
    memory = _memory({True: 0})  # True == 1, outside code either way
    assert _check(ctx, memory) is True


def test_differential_verdicts_match_exhaustive_membership() -> None:
    """Guard verdict equals brute-force protected-byte membership."""
    protected_spans = [
        (10, 3), (25, 5), (40, 2), (100, 30), (200, 1), (50, 4), (60, 8)
    ]
    writes = list(range(0, 260, 7)) + list(range(5, 260, 11))
    for combo in combinations(writes[:24], 2):
        known = {combo[0]: 0}
        unknown = {combo[1]}
        memory = _memory(known, unknown)
        expected = not any(
            start <= addr < start + size
            for addr in combo
            for start, size in protected_spans
        )
        ctx = _ctx(list(protected_spans))
        assert _check(ctx, memory) is expected, (combo, expected)


def test_no_mutation_and_no_result_sharing() -> None:
    """Inputs stay unmodified and every call rebuilds its evidence."""
    spans = [(100 + 3 * i, 2) for i in range(10)]
    ctx = _ctx(spans)
    memory = _memory({0xFFFF0: 1})
    before = list(spans)
    assert _check(ctx, memory) is True
    assert ctx.manifest == before
    known_snapshot = dict(memory.known)
    assert set(memory.unknown) == set() and dict(memory.known) == known_snapshot


def test_exhausted_work_budget_refuses() -> None:
    """The charged written scan still refuses on the existing cap."""
    spans = [(100 + 3 * i, 2) for i in range(30)]
    ctx = _ctx(spans, limit=1)
    assert _check(ctx, _memory({0xFFFF0: 0}, {0xFFFF1})) is False
    assert ctx.work_units >= 1


def test_expired_deadline_refuses() -> None:
    """An already-expired deadline refuses before any envelope work."""
    ctx = _ctx(_witness_spans(), deadline=time.monotonic() - 1)
    assert _check(ctx, _witness_memory(), caller_range=_CALLER_RANGE) is False
