# cython: language_level=3, infer_types=True
"""Instruction semantics and their typed contracts.

Layer: Semantics.
Responsibility: house instruction-effect helpers and semantic evidence contracts.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import cython
