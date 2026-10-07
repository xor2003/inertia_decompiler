"""Layer: Recovery metadata.

Responsibility: normalize recovered callee labels for comparison and reporting.
Forbidden: treating names as semantic proof or synthesizing missing callees.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import re

__all__ = ["normalize_callee_name_8616"]


_CALLEE_NAMESPACE_RE_8616 = re.compile(r"^::0x[0-9a-fA-F]+::(?P<name>[A-Za-z_]\w*)$")


def normalize_callee_name_8616(name: str | None) -> str | None:
    """Return a comparison/reporting label without treating it as proof."""
    if not isinstance(name, str):
        return None
    normalized = name.strip()
    if not normalized:
        return None
    if normalized.endswith("()"):
        normalized = normalized[:-2].rstrip()
    match = _CALLEE_NAMESPACE_RE_8616.fullmatch(normalized)
    if match is not None:
        return match.group("name")
    return normalized
