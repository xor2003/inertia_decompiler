"""Typed flag and condition semantic helpers.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.
This module exposes flag condition helpers without owning cleanup or lowering.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.ir.condition_ir import (
    build_condition_ir_8616,
    condition_compare_symbol_8616,
    is_condition_compare_family_8616,
    is_signed_condition_8616,
    is_unsigned_condition_8616,
)

from .alu_semantics import build_compare_condition_8616

__all__ = [
    "build_compare_condition_8616",
    "build_condition_ir_8616",
    "condition_compare_symbol_8616",
    "is_condition_compare_family_8616",
    "is_signed_condition_8616",
    "is_unsigned_condition_8616",
]
