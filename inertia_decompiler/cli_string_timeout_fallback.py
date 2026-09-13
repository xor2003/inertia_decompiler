"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr_platforms.X86_16.string_codegen_override import render_complete_string_function_8616
from angr_platforms.X86_16.string_instruction_artifact import (
    build_x86_16_string_instruction_artifact_from_linear_range,
)
from angr_platforms.X86_16.string_instruction_lowering import (
    build_x86_16_string_intrinsic_artifact,
)

__all__ = ["StringTimeoutFallback", "try_render_x86_16_string_timeout_fallback"]


class _ProjectArchLike(Protocol):
    """Architecture identity at the third-party project boundary."""

    name: str | None


class _ProjectLike(Protocol):
    """Minimal project surface needed before requesting typed string evidence."""

    arch: _ProjectArchLike | None


@dataclass(frozen=True, slots=True)
class StringTimeoutFallback:
    """Rendered string-instruction timeout fallback for one function."""

    family: str
    c_text: str


def try_render_x86_16_string_timeout_fallback(
    project: object, *, start: int, end: int, name: str
) -> StringTimeoutFallback | None:
    """Render a bounded x86-16 string-instruction fallback when applicable."""
    try:
        arch = cast(_ProjectLike, project).arch
    except AttributeError:
        return None
    if arch is None or arch.name != "86_16":
        return None
    artifact = build_x86_16_string_instruction_artifact_from_linear_range(project, start=start, end=end)
    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    rendered = render_complete_string_function_8616(name, lowered)
    if rendered is None:
        return None
    family = ",".join(item.family for item in lowered.records)
    return StringTimeoutFallback(family=family or "string_intrinsic", c_text=rendered)
