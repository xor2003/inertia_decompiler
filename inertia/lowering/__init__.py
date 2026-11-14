# cython: language_level=3, infer_types=True
"""Types/lowering package exports.

Layer: Types/Lowering.
Responsibility: owns exports for typed lowering helpers and contracts.
Consumes alias, widening, and typed facts to materialize stack/global/object C
representations.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import cython
