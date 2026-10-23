"""Extending a private native projection must not re-copy already owned full blocks."""
from collections.abc import Callable

import pytest

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import vex_import as vex
from inertia.ir.core import IRBlock
from tests.ir.test_native_census_projection import _select
from tests.ir.test_native_census_projection import native_world as native_world
from tests.ir.test_native_prefix_copy import _select as _select_prefix


def _observe_deepcopy(
    copied: list[frozenset[int]],
) -> Callable[..., dict[int, IRBlock]]:
    """Record the block addresses inside each private/consumer copy call."""
    clone = cache.deepcopy

    def observe(value: dict[int, IRBlock], memo: dict[int, object] | None = None) -> dict[int, IRBlock]:
        copied.append(frozenset(value))
        return clone(value, memo)

    return observe


def test_growing_inventory_only_copies_new_private_blocks(
    native_world: tuple[object, ExactFunctionRangeBoundary8616],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Growth to the full inventory copies only the missing tail privately."""
    project, boundary = native_world
    copied: list[frozenset[int]] = []
    with cache.native_import_request_8616():
        first = _select(project, boundary, frozenset({boundary.addr}))
        assert first is not None
        monkeypatch.setattr(cache, 'deepcopy', _observe_deepcopy(copied))
        full = _select(project, boundary)
    assert full is not None
    assert set(full.blocks) == boundary.block_addrs_set
    assert copied[0] == boundary.block_addrs_set - {boundary.addr}
    assert copied[1] == boundary.block_addrs_set
    assert full.blocks[boundary.addr] is not first.blocks[boundary.addr]


def test_growth_keeps_old_consumers_detached(
    native_world: tuple[object, ExactFunctionRangeBoundary8616],
) -> None:
    """Mutating an earlier returned copy cannot poison the grown projection."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        first = _select(project, boundary, frozenset({boundary.addr}))
        assert first is not None
        old_addr = first.blocks[boundary.addr].instrs[0].addr
        object.__setattr__(first.blocks[boundary.addr].instrs[0], 'addr', -1)
        full = _select(project, boundary)
        assert full is not None
        assert full.blocks[boundary.addr].instrs[0].addr == old_addr


def test_prefix_projection_growth_recopies_only_the_truncated_block(
    native_world: tuple[object, ExactFunctionRangeBoundary8616],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stored truncated prefix can never satisfy the later full request."""
    project, boundary = native_world
    head = boundary.addr
    copied: list[frozenset[int]] = []
    with cache.native_import_request_8616():
        prefix = _select_prefix(project, boundary, terminal=(head, head))
        assert prefix is not None and prefix.prefix_rows == ((head, head),)
        monkeypatch.setattr(cache, 'deepcopy', _observe_deepcopy(copied))
        full = _select(project, boundary)
    assert full is not None and full.prefix_rows == ()
    assert set(full.blocks) == boundary.block_addrs_set
    # The truncated head is re-copied fresh; the already-private full tail
    # block is donated instead of being detached a second time.
    assert copied[0] == frozenset({head})
    assert copied[1] == boundary.block_addrs_set
    assert len(full.blocks[head].instrs) > len(prefix.blocks[head].instrs)


def test_alternating_partial_selections_keep_unaffected_private_blocks(
    native_world: tuple[object, ExactFunctionRangeBoundary8616],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Moving the selection never discards an already-private block."""
    project, boundary = native_world
    head = boundary.addr
    tail = next(iter(boundary.block_addrs_set - {head}))
    copied: list[frozenset[int]] = []
    with cache.native_import_request_8616():
        assert _select(project, boundary, frozenset({head})) is not None
        assert _select(project, boundary, frozenset({tail})) is not None
        monkeypatch.setattr(cache, 'deepcopy', _observe_deepcopy(copied))
        again = _select(project, boundary, frozenset({head}))
    assert again is not None and set(again.blocks) == {head}
    assert copied == [frozenset({head})]


def test_changed_producer_discards_donated_private_blocks(
    native_world: tuple[object, ExactFunctionRangeBoundary8616],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replaced lift producer re-copies every selected row; nothing donated."""
    project, boundary = native_world
    copied: list[frozenset[int]] = []
    original = vex._block_to_ir

    def replaced(*args: object, **kwargs: object) -> object:
        return original(*args, **kwargs)

    with cache.native_import_request_8616():
        first = _select(project, boundary, frozenset({boundary.addr}))
        assert first is not None and first.source_binding is not None
        monkeypatch.setattr(vex, '_block_to_ir', replaced)
        monkeypatch.setattr(cache, 'deepcopy', _observe_deepcopy(copied))
        second = _select(project, boundary)
    assert second is not None and second.source_binding is not None
    assert second.source_binding.key != first.source_binding.key
    assert copied[0] == boundary.block_addrs_set
    assert copied[1] == boundary.block_addrs_set


def test_byte_store_never_donates_stale_private_rows(
    native_world: tuple[object, ExactFunctionRangeBoundary8616],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mid-session byte change refuses or re-copies the whole selection."""
    project, boundary = native_world
    copied: list[frozenset[int]] = []
    with cache.native_import_request_8616():
        first = _select(project, boundary, frozenset({boundary.addr}))
        assert first is not None and first.source_binding is not None
        monkeypatch.setattr(cache, 'deepcopy', _observe_deepcopy(copied))
        project.loader.memory.store(boundary.addr, b"\x90")
        second = _select(project, boundary)
    assert second is None or (
        second.source_binding is not None
        and second.source_binding.key != first.source_binding.key
        and copied[0] == boundary.block_addrs_set
    )


def test_growth_accounts_for_copy_savings_and_new_index_work(
    native_world: tuple[object, ExactFunctionRangeBoundary8616],
) -> None:
    """Real copy savings also pay for retained and selected inventory walks."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        first = _select(project, boundary, frozenset({boundary.addr}))
        grown = _select(project, boundary)
    with cache.native_import_request_8616():
        cold = _select(project, boundary)
    assert first is not None and grown is not None and cold is not None
    # The eliminated private copy saves the block plus its rows; the retained
    # projection and selected-inventory scans are still billed.
    saved = len(first.blocks[boundary.addr].instrs) - len(grown.blocks)
    assert cold.work_units - grown.work_units == saved
