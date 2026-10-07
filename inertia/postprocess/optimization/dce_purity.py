"""Define the pure structured-C operators shared by cleanup DCE passes.

Layer: Rewrite/Postprocess cleanup.
Responsibility: provide one typed operator vocabulary for expressions whose
evaluation has no call, memory-write, or address side effect. This module does
not infer liveness or authorize deletion; DCE consumers must prove that
separately and must refuse unknown operators.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

PURE_LOCAL_BINARY_OPS_8616: frozenset[str] = frozenset(
    {
        "Add",
        "And",
        "CmpEQ",
        "CmpGE",
        "CmpGT",
        "CmpLE",
        "CmpLT",
        "CmpNE",
        "Mul",
        "Mull",
        "Or",
        "Sar",
        "Shl",
        "Shr",
        "Sub",
        "Xor",
    }
)

PURE_LOCAL_UNARY_OPS_8616: frozenset[str] = frozenset(
    {
        "BitNot",
        "BitwiseNeg",
        "BitwiseNegate",
        "LogicalNot",
        "Neg",
        "Not",
    }
)

__all__ = [
    "PURE_LOCAL_BINARY_OPS_8616",
    "PURE_LOCAL_UNARY_OPS_8616",
]
