"""Detached native prefix selections preserve whole-block proof boundaries."""
import time
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import real16_invocation_domain as domain
from inertia.ir import vex_import as vex
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from tests.ir.test_native_import_surface_cache import _world


@pytest.fixture
def native_world() -> tuple[object, ExactFunctionRangeBoundary8616]:
    """Build two native blocks through the canonical registered lifter."""
    apply_x86_16_bootstrap()
    project, boundary, _calls, _request = _world(bytes.fromhex('b83412eb02909089d0c3'))
    assert len(boundary.blocks) == 2
    return project, boundary


def _select(project: object, boundary: ExactFunctionRangeBoundary8616,
            selected: frozenset[int] | None = None,
            terminal: tuple[int, int] | None = None) -> cache.NativeCensusBlockSelection8616 | None:
    return cache._request_native_census_blocks_8616(
        project, boundary, vex._census_raw_native_blocks_8616,
        selected_blocks=selected,
        producers=(domain._census_reimport_8616, *vex._census_finishing_producers_8616(),
                   *vex._native_import_producers_8616()),
        terminal=terminal,
    )


def _prefix_len(block: object, stop: int) -> int:
    """Count rows an exact cutoff consumes, mirroring the census helper."""
    return sum(1 for row in block.instrs if row.addr <= stop)


def test_cold_prefix_never_copies_unrequested_rows(native_world, monkeypatch):
    """The first prefix query must not clone unused blocks or terminal suffixes."""
    project, boundary = native_world
    head = boundary.addr
    copied_blocks = []
    original = cache.deepcopy

    def observe(value, memo=None):
        rows = value.values() if isinstance(value, dict) else value
        if isinstance(rows, (tuple, list)) or isinstance(value, dict):
            copied_blocks.extend(block for block in rows if isinstance(block, IRBlock))
        return original(value, memo)

    monkeypatch.setattr(cache, 'deepcopy', observe)
    with cache.native_import_request_8616():
        prefix = _select(project, boundary, selected=frozenset({head}), terminal=(head, head))
        assert prefix is not None and prefix.prefix_rows == ((head, head),)
        assert copied_blocks
        assert all(block.addr == head for block in copied_blocks)
        assert all(row.addr <= head for block in copied_blocks for row in block.instrs)
        prefix_work = prefix.work_units
        object.__setattr__(prefix.blocks[head].instrs[0], 'op', 'CORRUPTED_PREFIX')
        full = _select(project, boundary)
        assert full is not None and full.prefix_rows == ()
        assert full.source_binding is not None and prefix.source_binding is not None
        assert full.source_binding.key is prefix.source_binding.key
        assert set(full.blocks) == boundary.block_addrs_set
        assert full.blocks[head].instrs[0].op != 'CORRUPTED_PREFIX'
        assert len(full.blocks[head].instrs) > len(prefix.blocks[head].instrs)
        assert full.work_units > prefix_work


def test_terminal_prefix_copy_detaches_only_consumed_rows(native_world):
    """A valid cutoff returns only prefix rows; every row stays detached."""
    project, boundary = native_world
    head = boundary.addr
    with cache.native_import_request_8616():
        full = _select(project, boundary)
        stop = head
        expected = _prefix_len(full.blocks[head], stop)
        assert 0 < expected < len(full.blocks[head].instrs)
        prefixed = _select(project, boundary, terminal=(head, stop))
        assert prefixed is not None
        assert prefixed.prefix_rows == ((head, stop),)
        full_block = full.blocks[head]
        prefix_block = prefixed.blocks[head]
        assert len(prefix_block.instrs) == expected
        assert all(row.addr <= stop for row in prefix_block.instrs)
        assert prefix_block.addr == full_block.addr
        assert prefix_block.refusals == full_block.refusals
        assert prefix_block.successor_addrs == full_block.successor_addrs
        assert all(row is not other for row, other in
                   zip(prefix_block.instrs, full_block.instrs[:expected], strict=True))
        # Detached-row isolation: mutating the returned copy cannot poison
        # the cached projection or a later selection.
        object.__setattr__(prefix_block.instrs[0], "addr", -1)
        again = _select(project, boundary, terminal=(head, stop))
        assert again is not None and again.blocks[head].instrs[0].addr == stop


def test_terminal_charge_reflects_actual_copy(native_world):
    """Only the eliminated suffix copy may disappear from the charge."""
    project, boundary = native_world
    head = boundary.addr
    with cache.native_import_request_8616():
        full = _select(project, boundary)
        stop = head
        suffix = len(full.blocks[head].instrs) - _prefix_len(full.blocks[head], stop)
        assert suffix > 0
        hit_full = _select(project, boundary)
        hit_prefix = _select(project, boundary, terminal=(head, stop))
        assert hit_prefix is not None and hit_full is not None
        assert hit_full.work_units - hit_prefix.work_units == suffix


@pytest.mark.parametrize("bad", [
    "head", ("head",), ("head", "x"), ("x", 0), ("other", 0), ("head", -1), ("head", "last"),
])
def test_invalid_terminal_falls_back_to_full_copy(native_world, bad):
    """Missing, mistyped, out-of-selection or degenerate cutoffs never truncate."""
    project, boundary = native_world
    head = boundary.addr
    with cache.native_import_request_8616():
        seeded = _select(project, boundary)
        rows = seeded.blocks[head].instrs
        resolved = tuple(
            rows[-1].addr if item == "last"
            else head if item == "head"
            else head + 0x8000 if item == "other"
            else item
            for item in bad
        )
        selected = _select(project, boundary, terminal=resolved)
        assert selected is not None
        assert selected.prefix_rows == ()
        assert len(selected.blocks[head].instrs) == len(rows)


def test_stop_at_last_row_is_degenerate_full_copy(native_world):
    """A cutoff at the final consumed row leaves nothing to eliminate."""
    project, boundary = native_world
    head = boundary.addr
    with cache.native_import_request_8616():
        seeded = _select(project, boundary)
        last = seeded.blocks[head].instrs[-1].addr
        selected = _select(project, boundary, terminal=(head, last))
        assert selected is not None and selected.prefix_rows == ()
        assert len(selected.blocks[head].instrs) == len(seeded.blocks[head].instrs)


def test_prefix_block_binds_cutoff_but_never_whole(native_world):
    """A prefix copy binds exactly the consumed rows; a whole bind refuses."""
    project, boundary = native_world
    head = boundary.addr
    with cache.native_import_request_8616():
        full = _select(project, boundary)
        stop = head
        prefixed = _select(project, boundary, terminal=(head, stop))
        artifact = full.blocks[head]
        native = prefixed.blocks[head]
        assert domain._native_block_bound_8616(native, artifact, stop_after=stop)
        assert not domain._native_block_bound_8616(native, artifact)


def test_full_and_foreign_selections_stay_whole(native_world):
    """Selections without a terminal keep every row, including after one."""
    project, boundary = native_world
    head = boundary.addr
    with cache.native_import_request_8616():
        seeded = _select(project, boundary)
        _select(project, boundary, terminal=(head, head))
        ordinary = _select(project, boundary)
        partial = _select(project, boundary, selected=frozenset({head}))
        assert ordinary is not None and ordinary.prefix_rows == ()
        assert len(ordinary.blocks[head].instrs) == len(seeded.blocks[head].instrs)
        assert partial is not None and partial.prefix_rows == ()
        assert len(partial.blocks[head].instrs) == len(seeded.blocks[head].instrs)


def test_source_change_never_returns_stale_prefix_rows(native_world):
    """A changed operand byte must refuse or re-derive — never stale rows."""
    project, boundary = native_world
    head = boundary.addr
    with cache.native_import_request_8616():
        first = _select(project, boundary)
        project.loader.memory.store(head + 1, b"\x90")
        second = _select(project, boundary, terminal=(head, head))
        # Production declines a mid-session byte change outright; a terminal
        # request must observe the identical refusal — never a stale copy.
        assert second is None or (
            second.source_binding is not None
            and second.source_binding.key != first.source_binding.key
        )


def test_suffix_calls_are_not_native_bound():
    first = IRInstr("CJMP", None, (), addr=10)
    before = IRInstr("CALL", None, (), addr=11)
    terminal = IRInstr("CALL", None, (), addr=12)
    suffix = IRInstr("CALL", None, (), addr=13)
    artifact = IRBlock(10, (first, before, terminal, suffix))
    native = IRBlock(10, (first, before, terminal))
    calls = domain._feasibility_call_rows_8616(
        {10: artifact}, {10: native}, frozenset({10}), 12,
        prefix_blocks=frozenset({10}),
    )
    assert id(before) in calls
    assert id(suffix) not in calls


@pytest.mark.parametrize("cached", [True, False])
def test_full_selection_clears_old_prefix_metadata(monkeypatch, cached):
    project = object()
    boundary = SimpleNamespace(project=project, addr=10)
    full = IRBlock(10, (IRInstr("CJMP", None, (), addr=10), IRInstr("STORE", None, (), addr=11)))
    ctx = SimpleNamespace(project=project, deadline=time.monotonic()+5,
        work_units=0, accounted_work_units=0, work_limit=20000,
        prefix_capture_requested=False, prefix_native_entries={(10, 10): (boundary, 10)})
    if cached:
        monkeypatch.setattr(cache, "_request_native_census_blocks_8616",
                            lambda *_a, **_k: cache.NativeCensusBlockSelection8616({10: full}, 0))
    else:
        monkeypatch.setattr(domain, "_census_reimport_8616", lambda *_a: None)
        monkeypatch.setattr(domain, "_uncached_native_effect_blocks_8616", lambda *_a: {10: full})
    result = domain._native_effect_blocks_8616(ctx, boundary)
    assert result == {10: full}
    assert (10, 10) not in ctx.prefix_native_entries
    corrupt = replace(full, instrs=(full.instrs[0], IRInstr("CALL", None, (), addr=11)))
    prefixes = frozenset(block for function, block in ctx.prefix_native_entries if function == 10)
    calls = domain._feasibility_call_rows_8616(
        {10: corrupt}, result, frozenset({10}), 10, prefix_blocks=prefixes,
    )
    assert calls == {}, "the full native map must reject changed suffix effects"


def test_prefix_upgrade_repeated_store_requires_whole_block(monkeypatch):
    """A REP consumer upgrades to a detached full block before binding."""
    row = IRInstr("STORE", None, (), addr=10)
    suffix = IRInstr("CALL", None, (), addr=11)
    full = IRBlock(10, (row, suffix))
    artifact = IRFunctionArtifact(10, (full,))
    boundary = SimpleNamespace(addr=10)
    ctx = SimpleNamespace(native_blocks={10: {10: IRBlock(10, (row,))}},
        prefix_native_entries={(10, 10): (boundary, 10)})
    def select(current, bound, *, selected_blocks):
        assert current is ctx and bound is boundary and selected_blocks == frozenset({10})
        domain._record_native_prefix_selection_8616(ctx, boundary, {10: full}, ())
        return {10: deepcopy(full)}
    monkeypatch.setattr(domain, "_native_effect_blocks_8616", select)
    result, failure = domain._repeated_store_native_8616(ctx, artifact, full)
    assert failure is None and domain._native_block_bound_8616(result, full)
    assert result is not full
    assert ctx.native_blocks[10][10] is result
    assert not ctx.prefix_native_entries


@pytest.mark.parametrize("missing", [True, False])
def test_repeated_store_upgrade_cannot_authorize_missing_or_refused_rows(monkeypatch, missing):
    """A failed/missing full import cannot substitute the earlier prefix."""
    prefix = IRBlock(10, (IRInstr("STORE", None, (), addr=10),))
    full = replace(prefix, instrs=(*prefix.instrs, IRInstr("CALL", None, (), addr=11)))
    artifact = IRFunctionArtifact(10, (full,))
    ctx = SimpleNamespace(native_blocks={10: {10: prefix}},
        prefix_native_entries={(10, 10): (SimpleNamespace(addr=10), 10)})
    outcome = {} if missing else domain.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    monkeypatch.setattr(domain, "_native_effect_blocks_8616", lambda *_a, **_k: outcome)
    result, failure = domain._repeated_store_native_8616(ctx, artifact, full)
    assert result is None
    assert failure is None if missing else failure is outcome
    assert not domain._native_block_bound_8616(result, full)


def test_cutoff_metadata_retains_unselected_and_other_function_entries():
    """Refreshing one selected block cannot erase another block's obligation."""
    boundary = SimpleNamespace(addr=10)
    ctx = SimpleNamespace(prefix_native_entries={(10, 10): (boundary, 10),
        (10, 20): (boundary, 20), (30, 10): (boundary, 10)})
    domain._record_native_prefix_selection_8616(ctx, boundary, {10: IRBlock(10)}, ())
    assert set(ctx.prefix_native_entries) == {(10, 20), (30, 10)}
