from __future__ import annotations

from types import SimpleNamespace

import inertia.lowering.segmented_global_loads as segmented_global_loads


def test_dword_update_admission_rejects_missing_evidence_before_ast_walk(monkeypatch):
    def _unexpected_ast_walk(_root: object):
        raise AssertionError("missing dword evidence must not trigger a C-AST walk")

    monkeypatch.setattr(segmented_global_loads, "_iter_c_nodes_deep_8616", _unexpected_ast_walk)

    assert segmented_global_loads._materialized_sidecar_free_dword_update_refs_8616(SimpleNamespace(), []) == ()


def test_direct_global_binary_evidence_is_collected_once_per_function_surface(monkeypatch):
    project = SimpleNamespace()
    function = SimpleNamespace(
        addr=0x1000,
        size=4,
        blocks=(SimpleNamespace(addr=0x1000, size=4),),
    )
    calls = {"loads": 0, "stores": 0}

    def _loads(_project: object | None, _function: object):
        calls["loads"] += 1
        return ()

    def _stores(_project: object | None, _function: object):
        calls["stores"] += 1
        return ()

    monkeypatch.setattr(
        segmented_global_loads,
        "_recover_direct_segmented_global_load_evidence_uncached_8616",
        _loads,
    )
    monkeypatch.setattr(
        segmented_global_loads,
        "_recover_direct_segmented_global_store_evidence_uncached_8616",
        _stores,
    )

    for _ in range(2):
        assert segmented_global_loads.recover_direct_segmented_global_load_evidence_8616(project, function) == ()
        assert segmented_global_loads.recover_direct_segmented_global_store_evidence_8616(project, function) == ()
    assert calls == {"loads": 1, "stores": 1}

    function.blocks = (SimpleNamespace(addr=0x1000, size=6),)
    assert segmented_global_loads.recover_direct_segmented_global_load_evidence_8616(project, function) == ()
    assert segmented_global_loads.recover_direct_segmented_global_store_evidence_8616(project, function) == ()
    assert calls == {"loads": 2, "stores": 2}
