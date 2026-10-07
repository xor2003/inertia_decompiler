from __future__ import annotations

from types import SimpleNamespace

from inertia.structuring.string_codegen_override import apply_x86_16_string_codegen_override
from inertia.lowering.string_instruction_lowering import (
    StringInstructionCoverage8616,
    StringIntrinsicArtifact,
    StringIntrinsicRecord,
)


def test_string_codegen_override_replaces_render_text_with_normal_path_c():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, name="memset_like"),
        render_text=lambda _cfunc: "old text",
        _inertia_string_intrinsic_artifact=StringIntrinsicArtifact(
            coverage=StringInstructionCoverage8616.EXACT_FUNCTION,
            records=(
                StringIntrinsicRecord(
                    index=0,
                    family="memset_class",
                    record_indexes=(0,),
                    width=2,
                    direction_mode="forward",
                    repeat_kind="rep",
                ),
            )
        ),
    )

    changed = apply_x86_16_string_codegen_override(None, codegen)

    assert changed is True
    rendered = codegen.render_text(codegen.cfunc)
    assert "void memset_like(void)" in rendered
    assert "__x86_16_stos(2);" in rendered
    assert "__x86_16_string_state" not in rendered


def test_string_codegen_override_refuses_partial_function_artifact():
    """One proved string instruction cannot replace unrelated function effects."""
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, name="mixed_effects"),
        render_text=lambda _cfunc: "void mixed_effects(void) { output_port(); }",
        _inertia_string_intrinsic_artifact=StringIntrinsicArtifact(
            records=(
                StringIntrinsicRecord(
                    index=0,
                    family="memset_class",
                    record_indexes=(0,),
                    width=4,
                    direction_mode="forward",
                    repeat_kind="rep",
                ),
            )
        ),
    )

    changed = apply_x86_16_string_codegen_override(None, codegen)

    assert changed is False
    assert codegen.render_text(codegen.cfunc) == "void mixed_effects(void) { output_port(); }"
