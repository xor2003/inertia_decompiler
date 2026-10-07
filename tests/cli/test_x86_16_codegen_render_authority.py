from __future__ import annotations

from types import SimpleNamespace

from inertia.pipeline.render_authority import CodegenRenderAuthority8616

import inertia.cli.cli_decompilation as cli_decompilation


def test_forced_regeneration_honors_proven_full_function_render_override(monkeypatch) -> None:
    """A proven full-function render must not be replaced by raw stale AST text."""
    proven_text = "void f(void)\n{\n    __x86_16_stos(2);\n}\n"

    class _RawCFunc:
        functy = None

        def c_repr(self) -> str:
            raise AssertionError("raw C AST rendering must not bypass the authoritative override")

    codegen = SimpleNamespace(
        text="void f(void) { vvar_1 = tmp_2; }\n",
        cfunc=_RawCFunc(),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        render_text=lambda _cfunc: proven_text,
        regenerate_text=lambda: None,
        _inertia_force_codegen_regeneration_8616=True,
        _inertia_codegen_render_authority_8616=(
            CodegenRenderAuthority8616.PROVEN_FULL_FUNCTION_OVERRIDE
        ),
    )

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_typed_call_interfaces_before_render_8616",
        lambda _codegen: False,
    )

    rendered, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert rendered == proven_text
    assert codegen.text == proven_text
