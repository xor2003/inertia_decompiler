"""Compatibility imports for function-scoped logical-memory capture.

Layer: Semantics compatibility boundary.
Responsibility: preserve the historical evidence-cache import surface while IR
owns logical-memory capture contracts and context-local transport.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.

New capture or resolution behavior belongs in ``ir/logical_memory_capture.py``
or ``ir/logical_memory_resolution.py``. Do not add process-global caches or
semantic reconstruction here; consumers should migrate to typed IR artifacts.
"""

from __future__ import annotations

from inertia.ir.logical_memory_capture import (
    IRLogicalMemoryCaptureCollection8616,
    IRLogicalMemoryCaptureRecord8616,
    collect_accesses_for_function,
    get_current_function_addr,
    record_access,
)

AccessRecord8616: type[IRLogicalMemoryCaptureRecord8616] = IRLogicalMemoryCaptureRecord8616
EvidenceCollection8616: type[IRLogicalMemoryCaptureCollection8616] = (
    IRLogicalMemoryCaptureCollection8616
)

__all__ = [
    "AccessRecord8616",
    "EvidenceCollection8616",
    "collect_accesses_for_function",
    "get_current_function_addr",
    "record_access",
]
