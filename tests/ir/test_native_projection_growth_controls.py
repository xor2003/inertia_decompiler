"""Parent review: projection growth must preserve source and prefix obligations."""
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import real16_invocation_domain as domain
from inertia.ir import vex_import as vex
from inertia.ir.core import IRBlock
from tests.ir.test_native_census_projection import _select
from tests.ir.test_native_census_projection import native_world as native_world


def select_prefix(project, boundary):
    return cache._request_native_census_blocks_8616(
        project, boundary, vex._census_raw_native_blocks_8616,
        selected_blocks=frozenset({boundary.addr}),
        terminal=(boundary.addr, boundary.addr),
        producers=(domain._census_reimport_8616, *vex._census_finishing_producers_8616(),
                   *vex._native_import_producers_8616()),
    )


def test_partial_head_then_tail_cannot_claim_full_head(native_world):
    project, boundary = native_world
    with cache.native_import_request_8616():
        first = select_prefix(project, boundary)
        assert first is not None and first.prefix_rows
        short_count = len(first.blocks[boundary.addr].instrs)
        tail = _select(project, boundary, boundary.block_addrs_set - {boundary.addr})
        assert tail is not None and not tail.prefix_rows
        full = _select(project, boundary)
        assert full is not None and not full.prefix_rows
        assert len(full.blocks[boundary.addr].instrs) > short_count
        raw = vex._census_raw_native_blocks_8616(project, boundary)
        assert raw is not None
        for block in raw:
            assert domain._native_block_equal_8616(full.blocks[block.addr], block, 0)


def test_changed_bytes_in_previously_retained_block_refuse(native_world):
    project, boundary = native_world
    with cache.native_import_request_8616():
        first = _select(project, boundary, frozenset({boundary.addr}))
        assert first is not None
        project.loader.memory.store(boundary.addr + 1, bytes.fromhex('7856'))
        full = _select(project, boundary)
        assert full is None


def test_growth_does_not_share_values_with_prior_consumer(native_world):
    project, boundary = native_world
    with cache.native_import_request_8616():
        first = _select(project, boundary, frozenset({boundary.addr}))
        assert first is not None
        full = _select(project, boundary)
        assert full is not None
        row = first.blocks[boundary.addr].instrs[0]
        original = full.blocks[boundary.addr].instrs[0].addr
        object.__setattr__(row, 'addr', -1)
        assert full.blocks[boundary.addr].instrs[0].addr == original
        again = _select(project, boundary)
        assert again is not None
        assert again.blocks[boundary.addr].instrs[0].addr == original


def test_partial_upgrade_keeps_complete_inventory(native_world):
    project, boundary = native_world
    with cache.native_import_request_8616():
        first = cache._request_native_census_blocks_8616(
            project, boundary, vex._census_raw_native_blocks_8616,
            terminal=(boundary.addr, boundary.addr),
            producers=(domain._census_reimport_8616, *vex._census_finishing_producers_8616(),
                       *vex._native_import_producers_8616()),
        )
        assert first is not None and first.prefix_rows
        updated = _select(project, boundary, frozenset({boundary.addr}))
        assert updated is not None and not updated.prefix_rows
        session = cache._ACTIVE.get()
        assert session is not None
        projections = [r.census for r in session.records.values() if r.census is not None]
        assert len(projections) == 1
        assert projections[0].complete_inventory
        assert set(projections[0].blocks) == boundary.block_addrs_set


def test_growth_drops_addresses_absent_from_fresh_inventory():
    old = {addr: IRBlock(addr=addr, instrs=()) for addr in range(cache._MAX_BLOCKS)}
    fresh = {addr: IRBlock(addr=addr, instrs=())
             for addr in range(cache._MAX_BLOCKS, 2 * cache._MAX_BLOCKS)}
    retained = cache._CensusProjection(('source',), (), old, True, ())
    result, markers, *_ = cache._grow_census_projection_8616(retained, retained.key, fresh, fresh, ())
    assert set(result) == set(fresh)
    assert len(result) == cache._MAX_BLOCKS
    assert not markers
