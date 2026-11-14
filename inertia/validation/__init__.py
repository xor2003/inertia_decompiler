# cython: language_level=3, infer_types=True
"""Validation-layer package exports.

Layer: Validation.
Responsibility: owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations
import cython
