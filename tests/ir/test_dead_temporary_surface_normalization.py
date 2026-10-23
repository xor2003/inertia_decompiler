"""Deletion admission must preserve byte coordinates and capture dependencies."""

from dataclasses import replace

import pytest

from inertia.ir.condition_ir import ConditionSource
from inertia.ir.condition_lift_capture import ConditionLiftCaptureSession8616
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from inertia.ir.dead_temporary_normalization import DeadTemporaryNormalizationStatus8616
from inertia.ir.dead_temporary_surface_normalization import normalize_dead_temporary_surface_8616

pytestmark = pytest.mark.decompiler


def _block() -> IRBlock:
    first = IRInstr("MOV", IRValue(MemSpace.TMP, size=2, source_tmp=1),
                    (IRValue(MemSpace.CONST, const=1, size=2),), size=2, addr=100)
    dead = replace(first, dst=IRValue(MemSpace.TMP, size=2, source_tmp=2))
    write = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                    (IRValue(MemSpace.CONST, const=3, size=2),), size=2, addr=101)
    return IRBlock(100, (first, dead, write), successor_addrs=(102,))


def test_first_row_anchor_preserves_native_instruction_inventory() -> None:
    block = _block()
    result = normalize_dead_temporary_surface_8616(
        (block,), ConditionLiftCaptureSession8616({}, {}), (), {},
    )
    kept = result.blocks[0]
    assert len(kept.instrs) == 2
    assert kept.instrs[0] is block.instrs[0]
    assert kept.instrs[1] is block.instrs[2]
    assert kept.successor_addrs == block.successor_addrs
    assert {row.addr for row in kept.instrs} == {row.addr for row in block.instrs}
    assert result.to_summary() == {
        "dead_temporary_raw_fact_count": 3,
        "dead_temporary_normalized_fact_count": 2,
        "dead_temporary_classified_fact_count": 1,
        "dead_temporary_materialized_count": 1,
        "dead_temporary_failure_count": 0,
    }


def test_captured_register_pin_keeps_otherwise_dead_equation() -> None:
    block = _block()
    captured = IRValue(MemSpace.REG, name="ax", source_tmp=2, size=2)
    source = ConditionSource("cmp", lhs=captured, block_addr=100, addr=100)
    result = normalize_dead_temporary_surface_8616(
        (block,), ConditionLiftCaptureSession8616({}, {102: source}), (), {},
    )
    assert result.blocks[0].instrs == block.instrs
    assert all(left is right for left, right in zip(result.blocks[0].instrs, block.instrs, strict=True))
    assert result.to_summary()["dead_temporary_materialized_count"] == 0


def test_foreign_capture_never_authorizes_deletion() -> None:
    block = _block()
    source = ConditionSource("cmp", block_addr=999, addr=999)
    result = normalize_dead_temporary_surface_8616(
        (block,), ConditionLiftCaptureSession8616({}, {102: source}), (), {},
    )
    assert result.blocks[0] is block
    assert result.results[0].status is DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE
    assert result.to_summary()["dead_temporary_materialized_count"] == 0


def test_missing_instruction_coordinate_keeps_original_block() -> None:
    original = _block()
    block = replace(original, instrs=(replace(original.instrs[0], addr=None), *original.instrs[1:]))
    result = normalize_dead_temporary_surface_8616(
        (block,), ConditionLiftCaptureSession8616({}, {}), (), {},
    )
    assert result.blocks[0] is block
    assert result.results[0].status is DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE


def _selection_block() -> IRBlock:
    """Keep distinct SSA dependencies for both arms and a captured guard."""
    def tmp(number: int) -> IRValue:
        return IRValue(MemSpace.TMP, size=1, source_tmp=number)

    def constant(number: int) -> IRValue:
        return IRValue(MemSpace.CONST, size=1, const=number)

    rows = tuple(IRInstr("MOV", tmp(number), (constant(value),), size=1, addr=100)
                 for number, value in enumerate((0, 0, 42, 19)))
    return IRBlock(100, (*rows,
        IRInstr("SELECT8", tmp(4), (tmp(1), tmp(2), tmp(3)), size=1, addr=100),
        IRInstr("MOV", IRValue(MemSpace.REG, name="al", size=1), (tmp(4),), size=1, addr=101),
    ))


@pytest.mark.parametrize("capture_unselected", [False, True])
def test_proven_selection_preserves_external_arm_roots(capture_unselected: bool) -> None:
    """Only dependencies unneeded by both execution and captures may disappear."""
    block = _selection_block()
    capture = ConditionLiftCaptureSession8616({}, {})
    if capture_unselected:
        source = ConditionSource("cmp", lhs=block.instrs[2].dst, block_addr=100, addr=100)
        capture = ConditionLiftCaptureSession8616({}, {102: source})
    result = normalize_dead_temporary_surface_8616((block,), capture, (), {})
    kept = result.blocks[0]
    selection = next(row for row in kept.instrs if row.dst.source_tmp == 4)
    assert selection.op == "MOV"
    assert selection.args[0].source_tmp == 3
    assert any(row.dst.source_tmp == 2 for row in kept.instrs) is capture_unselected
    assert {row.addr for row in kept.instrs} == {100, 101}
    summary = result.to_summary()
    assert summary["select_raw_fact_count"] == 1
    assert summary["select_materialized_count"] == 1
    assert summary["select_failure_count"] == 0


def test_unowned_capture_refuses_selection_rewrite() -> None:
    block = _selection_block()
    capture = ConditionLiftCaptureSession8616({}, {
        102: ConditionSource("cmp", block_addr=999, addr=999),
    })
    result = normalize_dead_temporary_surface_8616((block,), capture, (), {})
    assert result.blocks[0] is block
    assert result.results[0].status is DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE


def test_native_census_cache_rechecks_changed_dependency_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
    from inertia.ir import dead_temporary_normalization as normalization
    from inertia.ir import native_import_surface_cache as cache
    from inertia.ir import vex_import as vex
    from tests.ir.test_native_import_surface_cache import _world

    apply_x86_16_bootstrap()
    project, boundary, _calls, _request = _world(bytes.fromhex("b83412eb02909089d0c3"))
    original = normalization._value_children
    visits = []

    def changed(value: IRValue) -> tuple[object, ...] | None:
        visits.append(value)
        return original(value)

    with cache.native_import_request_8616():
        first = vex._import_x86_16_function_surface_8616(project, boundary)
        assert first.dead_temporary_normalization is not None
        monkeypatch.setattr(normalization, "_value_children", changed)
        second = vex._import_x86_16_function_surface_8616(project, boundary)
        assert visits
        assert second.dead_temporary_normalization is not None
        assert second.dead_temporary_normalization.to_summary() == first.dead_temporary_normalization.to_summary()


@pytest.mark.parametrize("origin_values", [
    (100.0, 0, False, False),
    (100, True, False, False),
    (100, 0, 1, False),
    (100, 0, False, 1),
])
def test_malformed_origin_never_authorizes_deletion(origin_values: tuple[object, ...]) -> None:
    from inertia.ir.dead_temporary_normalization import normalize_dead_temporaries_8616
    from inertia.ir.instruction_origin import IRInstructionOrigin8616

    block_addr, statement, next_mark, instruction_mark = origin_values
    origin = IRInstructionOrigin8616(block_addr, statement, is_block_next=next_mark,
                                    is_instruction_mark=instruction_mark)
    row = replace(_block().instrs[0], origin=origin)
    block = IRBlock(100, (row,))
    result = normalize_dead_temporaries_8616(block)
    assert result.status is DeadTemporaryNormalizationStatus8616.UNKNOWN_REFUSE
    assert result.block is block


def test_warm_vex_cache_preserves_normalization_capture_inputs() -> None:
    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
    from inertia.ir import vex_import as vex
    from tests.ir.test_native_import_surface_cache import _world

    apply_x86_16_bootstrap()
    project, boundary, _calls, _request = _world(bytes.fromhex("a10010c3"))
    project.factory.default_engine.clear_cache()
    fresh = vex._lift_x86_16_function_surface_8616(project, boundary)
    warm = vex._lift_x86_16_function_surface_8616(project, boundary)
    assert fresh.captured_accesses
    assert len(warm.captured_accesses) == len(fresh.captured_accesses)
    assert fresh.dead_temporary_normalization is not None
    assert warm.dead_temporary_normalization is not None
    assert warm.dead_temporary_normalization.to_summary() == fresh.dead_temporary_normalization.to_summary()
