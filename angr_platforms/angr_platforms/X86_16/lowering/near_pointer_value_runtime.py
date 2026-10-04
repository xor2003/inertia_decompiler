"""Render single-evaluation conversion of proven near argument offsets.

Layer: Types/Lowering.
Responsibility: encode the existing target-specific native-near or guest-view
pointer representation, preserving word narrowing and null for runtime offsets.
The caller still owns pointer classification, source provenance and segment
binding. Rendering this helper grants none of those semantic proofs.
"""

from __future__ import annotations

from enum import StrEnum


class NearPointerArgumentHelper8616(StrEnum):
    """Owned runtime conversion, not a binary function-name classification."""

    SINGLE_EVALUATION = "NEAR_ARG_PTR"


def render_near_pointer_argument_runtime_8616(target: str) -> str:
    """Render a C89-compatible DOS or C99 portable single-evaluation helper.

    Each argument is narrowed exactly once at the boundary. Repeated reads of
    the helper's ordinary parameters are safe even if the original AST contains
    calls or volatile reads. Portable inline avoids unused-function warnings in
    functions that do not consume the helper; DOS C does not require inline.
    """
    if target == "msc-dos":
        declaration = "static void near *"
    elif target == "portable-flat":
        declaration = "static inline void *"
    else:
        raise ValueError(f"Unsupported near-argument target: {target!r}")
    return (
        "#ifndef INERTIA_NEAR_ARG_PTR_DEFINED\n"
        "#define INERTIA_NEAR_ARG_PTR_DEFINED\n"
        f"{declaration} inertia_near_arg_ptr(uint16_t segment, uint16_t offset)\n"
        "{\n"
        "    (void)segment;\n"
        "    return NEAR_PTR(segment, offset);\n"
        "}\n"
        f"#define {NearPointerArgumentHelper8616.SINGLE_EVALUATION.value}(seg, off) "
        "inertia_near_arg_ptr((uint16_t)(seg), (uint16_t)(off))\n"
        "#endif\n"
    )
