# cython: language_level=3, infer_types=True
"""Typed memory and callsite effect semantic exports.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.
This module exposes effect summaries without owning materialization or cleanup.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import cython

from inertia.semantics.callsite_summary import CallsiteSummary8616, summarize_x86_16_callsite
from inertia.semantics.function_effect_summary import FunctionEffectSummary, summarize_x86_16_function_effects

__all__ = [
    "CallsiteSummary8616",
    "FunctionEffectSummary",
    "summarize_x86_16_callsite",
    "summarize_x86_16_function_effects",
]
