from __future__ import annotations

import inertia.lowering.segmented_global_loads as global_loads


def test_direct_global_pair_prefilter_refuses_non_binary_node(monkeypatch) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("impossible pair candidate reached the expensive matcher")

    monkeypatch.setattr(
        global_loads,
        "_materialize_direct_ref_load_pair_expr_8616",
        fail_if_called,
    )

    result = global_loads._materialize_direct_global_load_pair_expr_8616(
        object(),
        object(),
        {},
        {},
        global_loads.SegmentedGlobalLoadStats8616(),
    )

    assert result is None
