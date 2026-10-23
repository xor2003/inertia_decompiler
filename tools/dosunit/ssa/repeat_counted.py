"""Layer: dosunit SSA repeat semantics.

Responsibility: exact flat32 count/index effects of completed MOVS/STOS.
Memory contents remain owned by the existing repeat summary.
"""
from __future__ import annotations

from tools.dosunit.contracts.ssa import SsaExpr


def counted_repeat_outputs(
    before: dict[str, SsaExpr], after: dict[str, SsaExpr], *, family: str, width: int,
) -> None:
    """Apply modular index arithmetic using the VEX direction step."""
    count = before["ecx"]
    extent = SsaExpr("mul", 32, (count, SsaExpr("const", 32, value=width)))
    delta = SsaExpr("mul", 32, (extent, before["d"]))
    after["ecx"] = SsaExpr("const", 32, value=0)
    for name in (("esi", "edi") if family == "movs" else ("edi",)):
        after[name] = SsaExpr("add", 32, (before[name], delta))
