"""Ordering regressions for the segmented-global Lowering coordinator."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
import inertia.lowering.segment_global_materialization as materialization


def _stub_unrelated_materializers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep query-session tests scoped to the two indexed consumers."""
    for name in (
        "materialize_compare_register_global_carriers_8616",
        "materialize_indexed_segmented_global_loads_8616",
        "materialize_direct_global_symbol_stores_8616",
        "materialize_dos_interrupt_aggregate_globals_8616",
        "apply_segmented_load_widening_8616",
    ):
        monkeypatch.setattr(materialization, name, lambda *_args, **_kwargs: False)


def test_runtime_segment_projection_runs_after_typed_materializers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    state = {"indexed": False, "widened": False}

    def record(name: str, *, changed: bool = False) -> Any:
        def run(*_args: object, **_kwargs: object) -> bool:
            calls.append(name)
            return changed

        return run

    def indexed(*_args: object, **_kwargs: object) -> bool:
        calls.append("indexed")
        state["indexed"] = True
        return True

    def widening(*_args: object, **_kwargs: object) -> bool:
        calls.append("widening")
        assert state["indexed"] is True
        state["widened"] = True
        return True

    def runtime(*_args: object, **_kwargs: object) -> bool:
        calls.append("runtime")
        assert state == {"indexed": True, "widened": True}
        return True

    monkeypatch.setattr(materialization, "materialize_named_segmented_global_loads_8616", record("named"))
    monkeypatch.setattr(materialization, "materialize_compare_register_global_carriers_8616", record("compare"))
    monkeypatch.setattr(materialization, "materialize_indexed_segmented_global_loads_8616", indexed)
    monkeypatch.setattr(materialization, "materialize_direct_global_symbol_stores_8616", record("direct"))
    monkeypatch.setattr(materialization, "materialize_dos_interrupt_aggregate_globals_8616", record("dos"))
    monkeypatch.setattr(materialization, "apply_segmented_load_widening_8616", widening)
    monkeypatch.setattr(materialization, "apply_runtime_segment_lowering_8616", runtime)
    monkeypatch.setattr(materialization, "reconcile_recorded_cod_global_storage_identities_8616", record("reconcile"))

    result = materialization.run_segment_global_materialization_8616(
        SimpleNamespace(_inertia_c_target="portable-flat"),
        SimpleNamespace(cfunc=SimpleNamespace(statements=object())),
        synthetic_globals=None,
        include_runtime_segment=True,
    )

    assert calls == ["named", "compare", "indexed", "direct", "dos", "widening", "runtime", "named", "reconcile"]
    assert result.indexed_global_changed is True
    assert result.segmented_load_widening_changed is True
    assert result.runtime_segment_changed is True
    assert result.changed is True
    assert result.query_stats is not None
    assert result.query_stats.request_count == 0


def test_reuses_current_ast_query_index_until_a_materializer_changes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = object()
    indexes: list[object] = []
    _stub_unrelated_materializers(monkeypatch)

    monkeypatch.setattr(
        materialization,
        "materialize_named_segmented_global_loads_8616",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        materialization,
        "materialize_logical_word_memory_copies_8616",
        lambda *_args, query_session=None, **_kwargs: (
            indexes.append(query_session.current()) or SimpleNamespace(changed=False)
        ),
    )
    monkeypatch.setattr(
        materialization,
        "materialize_direct_global_register_updates_8616",
        lambda *_args, query_session=None, **_kwargs: indexes.append(query_session.current()) or False,
    )

    result = materialization.run_segment_global_materialization_8616(
        SimpleNamespace(_inertia_c_target="portable-flat"),
        SimpleNamespace(cfunc=SimpleNamespace(statements=root)),
        synthetic_globals=None,
    )

    assert indexes[0] is indexes[1]
    assert result.query_stats is not None
    assert result.query_stats.request_count == 2
    assert result.query_stats.build_count == 1
    assert result.query_stats.hit_count == 1
    assert result.query_stats.invalidation_count == 0


def test_invalidates_ast_query_index_after_rhs_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = object()
    indexes: list[object] = []
    _stub_unrelated_materializers(monkeypatch)

    def change_logical_rhs(
        *_args: object,
        query_session: Any,
        **_kwargs: object,
    ) -> SimpleNamespace:
        indexes.append(query_session.current())
        query_session.record_mutation(True)
        return SimpleNamespace(changed=True)

    monkeypatch.setattr(
        materialization,
        "materialize_named_segmented_global_loads_8616",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        materialization,
        "materialize_logical_word_memory_copies_8616",
        change_logical_rhs,
    )
    monkeypatch.setattr(
        materialization,
        "materialize_direct_global_register_updates_8616",
        lambda *_args, query_session=None, **_kwargs: indexes.append(query_session.current()) or False,
    )

    result = materialization.run_segment_global_materialization_8616(
        SimpleNamespace(_inertia_c_target="portable-flat"),
        SimpleNamespace(cfunc=SimpleNamespace(statements=root)),
        synthetic_globals=None,
    )

    assert indexes[0] is not indexes[1]
    assert result.query_stats is not None
    assert result.query_stats.request_count == 2
    assert result.query_stats.build_count == 2
    assert result.query_stats.hit_count == 0
    assert result.query_stats.invalidation_count == 1
