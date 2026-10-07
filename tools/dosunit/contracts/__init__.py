"""Pure machine-independent SSA/proof data contracts.

Layer: dosunit contracts.
Responsibility: expose immutable expression and lowering-refusal data without
importing lowering, composition or solver implementations.
"""

from __future__ import annotations

from .ssa import LowerFailure, SsaExpr, SsaExprKey

__all__ = ["LowerFailure", "SsaExpr", "SsaExprKey"]
