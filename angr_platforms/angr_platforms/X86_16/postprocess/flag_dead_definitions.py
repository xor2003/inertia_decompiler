"""Compatibility entry for previously proven unread FLAGS cleanup.

Layer: Rewrite/Postprocess cleanup.
Responsibility: delegate the historical unread-definition API to its Lowering
owner. Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
Cycle liveness must run after typed condition materialization in Structuring,
not be introduced as semantic recovery by a late Rewrite pass.
"""

from __future__ import annotations

from ..lowering.packed_flags_liveness import prune_unread_flag_definitions_8616

__all__ = ["prune_unread_flag_definitions_8616"]
