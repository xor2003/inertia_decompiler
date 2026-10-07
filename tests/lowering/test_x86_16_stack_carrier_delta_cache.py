from __future__ import annotations

from types import SimpleNamespace

import inertia.lowering.real_mode_linear as real_mode_linear


def test_vvar_carrier_delta_cache_tracks_structuring_root(monkeypatch) -> None:
    first_root = object()
    second_root = object()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(statements=first_root))
    built_for: list[object] = []

    def build(actual_codegen: object) -> dict[int, int]:
        root = actual_codegen.cfunc.statements
        built_for.append(root)
        return {7: len(built_for)}

    monkeypatch.setattr(real_mode_linear, "_build_vvar_carrier_delta_map_8616", build)

    first = real_mode_linear._ensure_vvar_carrier_delta_map_8616(codegen)
    replay = real_mode_linear._ensure_vvar_carrier_delta_map_8616(codegen)
    codegen.cfunc.statements = second_root
    replaced = real_mode_linear._ensure_vvar_carrier_delta_map_8616(codegen)

    assert replay is first
    assert replaced == {7: 2}
    assert built_for == [first_root, second_root]
