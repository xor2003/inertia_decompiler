"""Compatibility exports for cleanup-stage postprocess passes.

Layer: Rewrite/Postprocess cleanup.
Responsibility: re-export legacy cleanup helpers without owning semantic proof.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
