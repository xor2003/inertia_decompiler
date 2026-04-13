from __future__ import annotations

from dataclasses import dataclass

from angr_platforms.X86_16.string_instruction_artifact import (
    build_x86_16_string_instruction_artifact_from_linear_range,
)
from angr_platforms.X86_16.string_instruction_lowering import (
    build_x86_16_string_intrinsic_artifact,
    render_x86_16_string_intrinsic_c,
)

__all__ = ["StringTimeoutFallback", "try_render_x86_16_string_timeout_fallback"]


@dataclass(frozen=True, slots=True)
class StringTimeoutFallback:
    family: str
    c_text: str


def try_render_x86_16_string_timeout_fallback(project, *, start: int, end: int, name: str) -> StringTimeoutFallback | None:
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return None
    artifact = build_x86_16_string_instruction_artifact_from_linear_range(project, start=start, end=end)
    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    rendered = render_x86_16_string_intrinsic_c(name, lowered)
    if rendered is None:
        return None
    family = ",".join(item.family for item in lowered.records)
    return StringTimeoutFallback(family=family or "string_intrinsic", c_text=rendered)
