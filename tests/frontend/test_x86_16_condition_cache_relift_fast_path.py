from types import SimpleNamespace

from inertia.ir.condition_cache_relift import (
    ConditionCacheReliftFailureReason8616,
    ConditionReliftBlock8616,
    relift_function_condition_cache_8616,
)
from pytest import MonkeyPatch


def _project_with_loads(loads: list[tuple[int, int]]) -> SimpleNamespace:
    def load(address: int, size: int) -> bytes:
        loads.append((address, size))
        return bytes(size)

    return SimpleNamespace(
        arch=object(),
        loader=SimpleNamespace(memory=SimpleNamespace(load=load)),
    )


def test_exact_relift_skips_work_without_condition_owners(
    monkeypatch: MonkeyPatch,
) -> None:
    from inertia.ir import condition_cache_relift as relift

    loaded: list[tuple[int, int]] = []
    lifted: list[int] = []
    blocks = (
        ConditionReliftBlock8616(0x2100, 2),
        ConditionReliftBlock8616(0x2110, 3),
    )
    monkeypatch.setattr(
        relift,
        "_direct_lift_8616",
        lambda _data, address, _arch: lifted.append(address),
    )

    artifact = relift_function_condition_cache_8616(
        _project_with_loads(loaded),
        blocks,
        frozenset(),
    )

    assert artifact is not None and artifact.stats.complete
    assert artifact.conditions_by_block == ((0x2100, ()), (0x2110, ()))
    assert artifact.pending_sources_by_addr == ()
    assert artifact.failures == ()
    assert loaded == []
    assert lifted == []


def test_empty_owner_fast_path_retains_invalid_range_refusal(
    monkeypatch: MonkeyPatch,
) -> None:
    from inertia.ir import condition_cache_relift as relift

    loaded: list[tuple[int, int]] = []
    lifted: list[int] = []
    monkeypatch.setattr(
        relift,
        "_direct_lift_8616",
        lambda _data, address, _arch: lifted.append(address),
    )

    artifact = relift_function_condition_cache_8616(
        _project_with_loads(loaded),
        (ConditionReliftBlock8616(0x2200, 0),),
        frozenset(),
    )

    assert artifact is not None and not artifact.stats.complete
    assert artifact.stats.failure_count == 1
    assert artifact.failures[0].reason is ConditionCacheReliftFailureReason8616.INVALID_BLOCK_RANGE
    assert loaded == []
    assert lifted == []
