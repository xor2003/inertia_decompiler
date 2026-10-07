"""Compatibility exports for final simplification cleanup.

Layer: Rewrite/Postprocess cleanup.
Responsibility: preserve package-level simplification imports while the root
decompiler_postprocess_simplify module owns cleanup behavior and exports.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from inertia.postprocess.decompiler_postprocess_simplify import *  # noqa: F403
