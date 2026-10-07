"""Rewrite/postprocess cleanup package exports.

Layer: Rewrite/Postprocess cleanup.
Responsibility: owns exports for cleanup-only postprocess helpers.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations
