"""Typed value-domain aliases and constructors for IR values.

Layer: IR.
Responsibility: owns typed Value aliases and constructors.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .core import IRValue, MemSpace

__all__ = ["IRValue", "MemSpace", "build_value_ir_8616"]


def build_value_ir_8616(
    *,
    space: MemSpace,
    name: str | None = None,
    offset: int = 0,
    const: int | None = None,
    size: int = 0,
    version: int | None = None,
    expr: tuple[str, ...] | None = None,
) -> IRValue:
    """Build a typed IR value without adding alias, widening, or lowering facts."""
    return IRValue(
        space=space,
        name=name,
        offset=offset,
        const=const,
        size=size,
        version=version,
        expr=expr,
    )
