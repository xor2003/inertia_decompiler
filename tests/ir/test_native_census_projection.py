"""Actual byte-bound raw census projections detach every consumed IR row."""
import pytest

from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import real16_invocation_domain as domain
from inertia.ir import vex_import as vex
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRValue
from tests.ir.test_native_import_surface_cache import _world


@pytest.fixture
def native_world() -> tuple[object, ExactFunctionRangeBoundary8616]:
    """Build two native blocks through the canonical registered lifter."""
    apply_x86_16_bootstrap()
    project, boundary, _calls, _request = _world(bytes.fromhex('b83412eb02909089d0c3'))
    assert len(boundary.blocks) == 2
    return project, boundary


def _select(project: object, boundary: ExactFunctionRangeBoundary8616,
            selected: frozenset[int] | None = None) -> cache.NativeCensusBlockSelection8616 | None:
    return cache._request_native_census_blocks_8616(
        project, boundary, vex._census_raw_native_blocks_8616,
        selected_blocks=selected,
        producers=(domain._census_reimport_8616, *vex._census_finishing_producers_8616(),
                   *vex._native_import_producers_8616()),
    )


def _current_authorities() -> tuple[object, ...]:
    """Resolve the live producers rather than replaying old retained identities."""
    return (
        vex._census_raw_native_blocks_8616, domain._census_reimport_8616,
        *vex._census_finishing_producers_8616(), *vex._native_import_producers_8616(),
    )


def test_source_binding_survives_session_without_sharing_returned_rows(native_world):
    """An old immutable source key remains independent of consumed IR mutation."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        selected = _select(project, boundary)
        assert selected is not None and selected.source_binding is not None
        binding = selected.source_binding
        assert binding.project is project and binding.boundary is boundary
        assert binding.pinned
        object.__setattr__(selected.blocks[boundary.addr].instrs[0], "addr", -1)
        selected.blocks.clear()
    assert cache.native_census_source_current_8616(binding, producers=_current_authorities())


def test_conditional_raw_selection_never_grants_prefix_replay_authority(native_world):
    """Conditional rows may be copied, but cannot authenticate a cached path proof."""
    from tests.ir.test_native_import_surface_cache import _conditional_boundary

    project, boundary = native_world
    conditional = _conditional_boundary(boundary)
    with cache.native_import_request_8616():
        first = _select(project, conditional)
        second = _select(project, conditional)
        assert first is not None and second is not None
        assert first.source_binding is None and second.source_binding is None
        assert first.blocks is not second.blocks
        assert second.work_units < first.work_units


@pytest.mark.parametrize("authority", ["native", "configuration", "producer"])
def test_retained_source_binding_rejects_current_authority_changes(native_world, authority, monkeypatch):
    """Updating current authorities must never authenticate an older source key."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        selected = _select(project, boundary)
        assert selected is not None and selected.source_binding is not None
        binding = selected.source_binding
    if authority == "native":
        project.loader.memory.store(boundary.addr, b"\x90")
    elif authority == "configuration":
        project.selfmodifying_code = True
    else:
        original = vex._block_to_ir

        def replaced(*args, **kwargs):
            return original(*args, **kwargs)

        monkeypatch.setattr(vex, "_block_to_ir", replaced)
    assert not cache.native_census_source_current_8616(binding, producers=_current_authorities())


def test_source_binding_rejects_deadline_expiring_during_key_check(native_world, monkeypatch):
    """A successful source read cannot publish freshness after its deadline."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        selected = _select(project, boundary)
        assert selected is not None and selected.source_binding is not None
        binding = selected.source_binding
    expired = False
    original = cache._source_key_8616

    def key_then_expire(*args):
        nonlocal expired
        result = original(*args)
        expired = True
        return result

    monkeypatch.setattr(cache, "_source_key_8616", key_then_expire)
    monkeypatch.setattr(cache, "direct_evidence_deadline_expired_8616", lambda current: expired)
    assert not cache.native_census_source_current_8616(binding, producers=_current_authorities())


def test_actual_raw_rows_equal_guarded_full_import(native_world: tuple[object, ExactFunctionRangeBoundary8616]) -> None:
    """Guarded finishing cannot change the raw native instruction rows."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        raw = vex._census_raw_native_blocks_8616(project, boundary)
        full = domain.real16_native_census_import_8616(project, boundary)
    assert raw is not None and full is not None
    assert len(raw) == len(full.blocks)
    assert all(domain._native_block_equal_8616(left, right, 0)
               for left, right in zip(raw, full.blocks, strict=True))


def test_returned_rows_and_consumed_artifact_cannot_poison_private_projection(native_world: tuple[object, ExactFunctionRangeBoundary8616]) -> None:
    """Deliberate consumed row/value mutation remains detached from cache."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        first = _select(project, boundary)
        assert first is not None
        consumed = IRFunctionArtifact(function_addr=boundary.addr, blocks=tuple(first.blocks.values()))
        block = consumed.blocks[0]
        row = block.instrs[0]
        row_addr = row.addr
        value_row, value_arg, value = next(
            (i, j, arg) for i, instruction in enumerate(block.instrs)
            for j, arg in enumerate(instruction.args) if isinstance(arg, IRValue))
        old_const = value.const
        object.__setattr__(value, 'const', -1)
        object.__setattr__(row, 'addr', -1)
        object.__setattr__(block, 'addr', -1)
        first.blocks.clear()
        second = _select(project, boundary)
        assert second is not None
        assert second.blocks[boundary.addr].addr == boundary.addr
        assert second.blocks[boundary.addr].instrs[0].addr == row_addr
        assert second.blocks[boundary.addr].instrs[0] is not row
        later_value = second.blocks[boundary.addr].instrs[value_row].args[value_arg]
        assert isinstance(later_value, IRValue) and later_value is not value
        assert later_value.const == old_const


def test_selected_prefix_reuses_only_requested_detached_blocks(native_world: tuple[object, ExactFunctionRangeBoundary8616]) -> None:
    """A later selection clones and charges only the requested block."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        full = _select(project, boundary)
        assert full is not None and set(full.blocks) == boundary.block_addrs_set
        selected = _select(project, boundary, frozenset({boundary.addr}))
        assert selected is not None and set(selected.blocks) == {boundary.addr}
        assert selected.blocks[boundary.addr] is not full.blocks[boundary.addr]
        assert selected.work_units == 1 + len(selected.blocks[boundary.addr].instrs)
        assert full.work_units > selected.work_units


def test_changed_raw_producer_executes_after_cached_projection(native_world: tuple[object, ExactFunctionRangeBoundary8616],
                                                              monkeypatch: pytest.MonkeyPatch) -> None:
    """A replaced converter must run on the next otherwise eligible hit."""
    project, boundary = native_world
    calls = []
    original = vex._block_to_ir

    def counted(block: object, *, return_terminal: bool = False,
                indirect_terminal_pending: bool = False) -> tuple[
        IRBlock, vex.VexConditionTransportStats8616, vex.TerminalJumpEvidence8616 | None,
    ]:
        calls.append(block)
        return original(block, return_terminal=return_terminal,
                        indirect_terminal_pending=indirect_terminal_pending)

    with cache.native_import_request_8616():
        first = _select(project, boundary)
        assert first is not None
        monkeypatch.setattr(vex, '_block_to_ir', counted)
        second = _select(project, boundary)
        assert second is not None
        assert len(calls) == len(boundary.blocks)
        assert all(domain._native_block_equal_8616(first.blocks[addr], second.blocks[addr], 0)
                   for addr in first.blocks)
        third = _select(project, boundary)
        assert third is not None
        assert len(calls) == len(boundary.blocks)


def test_foreign_finish_equality_is_never_executed(native_world: tuple[object, ExactFunctionRangeBoundary8616],
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    """Foreign equality/callback cannot impersonate a canonical producer."""
    project, boundary = native_world

    class ForeignFinish:
        """A callable whose equality must never establish source authority."""

        def __eq__(self, other: object) -> bool:
            raise AssertionError('foreign producer equality executed')

        def __call__(self, *args: object, **kwargs: object) -> IRFunctionArtifact:
            raise AssertionError('foreign producer callback executed')

    with cache.native_import_request_8616():
        assert _select(project, boundary) is not None
        monkeypatch.setattr(vex, '_finalize_x86_16_ir_artifact_8616', ForeignFinish())
        assert _select(project, boundary) is None


def test_return_copy_expiry_cannot_publish_projection(native_world: tuple[object, ExactFunctionRangeBoundary8616],
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    """Expiry during returned-row copying must refuse the retained projection."""
    project, boundary = native_world
    expired = False
    original = cache.deepcopy

    def copy_then_expire(value: object, memo=None) -> object:
        nonlocal expired
        result = original(value, memo)
        expired = True
        return result

    def reached(current: object) -> bool:
        return expired

    with cache.native_import_request_8616():
        assert _select(project, boundary) is not None
        monkeypatch.setattr(cache, 'direct_evidence_deadline_expired_8616', reached)
        monkeypatch.setattr(cache, 'deepcopy', copy_then_expire)
        assert _select(project, boundary) is None


def test_selected_copy_uses_detached_typed_memo(native_world, monkeypatch):
    """Avoid generic reconstruction while preserving ordinary copy equality."""
    project, boundary = native_world
    original = cache.deepcopy
    copies = []

    def checked_copy(value, memo=None):
        assert memo is not None
        for block in value.values():
            assert id(block) in memo and memo[id(block)] is not block
        result = original(value, memo)
        assert result == original(value)
        copies.append(tuple(value))
        return result

    with cache.native_import_request_8616():
        assert _select(project, boundary) is not None
        monkeypatch.setattr(cache, 'deepcopy', checked_copy)
        selected = _select(project, boundary, frozenset({boundary.addr}))
        assert selected is not None
        assert selected.work_units == 1 + len(selected.blocks[boundary.addr].instrs)
    assert copies == [(boundary.addr,)]


@pytest.mark.parametrize('authority', ['native', 'configuration', 'producer'])
def test_actual_freshness_rejects_stale_selection(native_world: tuple[object, ExactFunctionRangeBoundary8616],
                                                authority: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real source/configuration/finishing changes reject retained projection."""
    project, boundary = native_world
    with cache.native_import_request_8616():
        assert _select(project, boundary) is not None
        if authority == 'native':
            project.loader.memory.store(boundary.addr, b'\x90')
        elif authority == 'configuration':
            project.selfmodifying_code = True
        else:
            original = vex._finalize_x86_16_ir_artifact_8616
            def replaced(*args: object, **kwargs: object) -> IRFunctionArtifact:
                return original(*args, **kwargs)
            monkeypatch.setattr(vex, '_finalize_x86_16_ir_artifact_8616', replaced)
        assert _select(project, boundary) is None
