"""Cleanup optimization helpers.

Layer: Rewrite/Postprocess cleanup.
Responsibility: package existing cleanup helpers for ordinary and installed imports.
Consumes already-proven facts; does not recover new semantics.

Package ownership contract (canonical inertia/postprocess/optimization package):
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from
rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations
