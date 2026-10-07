"""Tests for regenerated CLI segment-lowering orchestration."""

from __future__ import annotations

from types import SimpleNamespace

from inertia.cli import cli_decompilation


def test_runtime_segment_replay_always_replays_named_global_identities(monkeypatch) -> None:
    """A pre-existing runtime helper still needs Lowering-owned identity replay."""
    calls: list[str] = []
    project = SimpleNamespace(_inertia_c_target="portable-flat")
    codegen = SimpleNamespace(project=project)

    monkeypatch.setattr(
        cli_decompilation,
        "apply_runtime_segment_lowering_8616",
        lambda *_args, **_kwargs: calls.append("runtime") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_named_segmented_global_lowering_after_regen_8616",
        lambda _codegen: calls.append("named") or True,
    )

    assert cli_decompilation._replay_runtime_segment_lowering_after_regen_8616(codegen) is True
    assert calls == ["runtime", "named"]


def test_final_codegen_projection_replay_uses_bound_lowering_owner() -> None:
    """Late CLI cleanup delegates exact state replay back to Lowering."""
    calls: list[object] = []

    def replayer(candidate_codegen: object) -> bool:
        calls.append(candidate_codegen)
        return True

    codegen = SimpleNamespace(_inertia_final_codegen_projection_replayer_8616=replayer)

    assert cli_decompilation._replay_final_codegen_projections_after_regen_8616(codegen) is True
    assert calls == [codegen]


def test_final_typed_interfaces_run_before_lowering_projection_replay(monkeypatch) -> None:
    """Typed interface mutation cannot be the last writer of the rendered AST."""
    calls: list[str] = []
    codegen = SimpleNamespace()

    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_typed_call_interfaces_before_render_8616",
        lambda _codegen: calls.append("typed-interfaces") or True,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_final_codegen_projections_after_regen_8616",
        lambda _codegen: calls.append("lowering-projections") or False,
    )

    assert cli_decompilation._finalize_typed_interfaces_and_projections_before_render_8616(codegen) is True
    assert calls == ["typed-interfaces", "lowering-projections"]


def test_regenerated_noncall_cleanup_finishes_with_lowering_projection_replay(monkeypatch) -> None:
    """Final cleanup cannot remain the last writer of a regenerated AST."""
    calls: list[str] = []
    codegen = SimpleNamespace(project=object())

    monkeypatch.setattr(
        cli_decompilation,
        "_stabilize_regenerated_noncall_ast_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_simplify_structured_expressions_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_call_return_selector_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_runtime_segment_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "finalize_shared_call_occurrences_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_recover_canonical_for_loops_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "finalize_late_ast_cleanup_8616",
        lambda _project, _codegen: calls.append("cleanup") or SimpleNamespace(changed=False),
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_final_codegen_projections_after_regen_8616",
        lambda _codegen: calls.append("lowering-projections") or True,
    )

    assert cli_decompilation._finalize_regenerated_noncall_ast_8616(codegen) is True
    assert calls == ["cleanup", "lowering-projections"]
