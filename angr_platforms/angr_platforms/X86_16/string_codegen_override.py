"""Layer: Helper boundary.

Responsibility: attach a codegen-boundary render override for fully proven string intrinsic artifacts.
Forbidden: repairing arbitrary generated C or inferring semantics from rendered output text.
Dynamic attribute boundary: getattr/setattr use here is limited to third-party
angr/codegen compatibility objects and optional diagnostic metadata.
"""

from __future__ import annotations

import typing

from .pipeline.render_authority import CodegenRenderAuthority8616
from .string_instruction_lowering import (
    StringInstructionCoverage8616,
    StringIntrinsicArtifact,
    render_x86_16_string_intrinsic_c,
)

__all__ = ["apply_x86_16_string_codegen_override", "render_complete_string_function_8616"]


def render_complete_string_function_8616(name: str, artifact: StringIntrinsicArtifact) -> str | None:
    """Admit whole-body rendering only under the shared typed coverage contract.

    Diagnostic intrinsic rendering alone does not authorize replacing a function.
    CLI fallbacks and normal codegen must consume this same admission decision.
    """
    if (
        artifact.coverage is not StringInstructionCoverage8616.EXACT_FUNCTION
        or artifact.refusals
        or not artifact.records
    ):
        return None
    return render_x86_16_string_intrinsic_c(name, artifact)


def _render_override_text(codegen: object) -> str | None:
    """Return proven string-intrinsic replacement text for a codegen object.

    Dynamic attribute boundary: codegen/cfunc are third-party angr/codegen
    compatibility objects that intentionally carry optional diagnostic metadata.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    artifact = getattr(codegen, "_inertia_string_intrinsic_artifact", None)
    if not isinstance(artifact, StringIntrinsicArtifact):
        return None
    name = getattr(cfunc, "name", None) or f"sub_{getattr(cfunc, 'addr', 0):x}"
    return render_complete_string_function_8616(name, artifact)


def apply_x86_16_string_codegen_override(project: object, codegen: object) -> bool:
    """Install the string-intrinsic render override when the artifact is proven.

    Dynamic attribute boundary: codegen is a third-party angr/codegen
    compatibility object whose render hook is patched at this helper boundary.
    """
    rendered = _render_override_text(codegen)
    if rendered is None:
        return False
    if getattr(codegen, "_inertia_string_codegen_override_text", None) == rendered:
        return False
    original = getattr(codegen, "render_text", None)
    if not callable(original):
        return False

    def _render_text_override(_cfunc: object) -> str:
        return rendered

    typing.cast(typing.Any, codegen)._inertia_original_render_text = original
    typing.cast(typing.Any, codegen)._inertia_string_codegen_override_text = rendered
    typing.cast(typing.Any, codegen)._inertia_codegen_render_authority_8616 = (
        CodegenRenderAuthority8616.PROVEN_FULL_FUNCTION_OVERRIDE
    )
    typing.cast(typing.Any, codegen).render_text = _render_text_override
    return True
