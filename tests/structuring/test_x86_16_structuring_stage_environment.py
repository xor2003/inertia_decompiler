from __future__ import annotations

from types import SimpleNamespace

import inertia.structuring.decompiler_structuring_stage as stage


def test_typed_switch_replacement_prepares_artifacts_without_leaking_environment(monkeypatch) -> None:
    forced: list[bool] = []
    monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_REPLACEMENT", "1")
    monkeypatch.delenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", raising=False)
    monkeypatch.setattr(stage, "prepare_typed_edge_switch_artifacts_8616", lambda _codegen, *, force=False: forced.append(force))
    monkeypatch.setattr(
        stage._codegen,
        "replace_typed_edge_switch_ast_8616",
        lambda _codegen: SimpleNamespace(changed=False),
    )
    codegen = SimpleNamespace(project=None, cfunc=None)

    assert stage.apply_typed_edge_switch_ast_replacement_if_enabled_8616(codegen) is False
    assert forced == [True]
    assert "INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS" not in stage.os.environ
