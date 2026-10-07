"""Retain proven wide predicate storage across deferred call capture.

Layer: Types/Lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Responsibility: carry immutable call and stack binding evidence for Validation.
This contract does not prove CFG polarity or permit late semantic recovery.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from .wide_call_output_assignment_ast import _call_target_matches_8616

WIDE_CALL_BINDING_TAG_8616: str = "inertia_wide_call_binding_8616"


@dataclass(frozen=True, slots=True)
class WideCallBinding8616:
    """Exact typed decision inputs and their accepted C storage projection."""

    condition_keys: tuple[tuple[object, ...], ...]
    callsite_addr: int
    callee_identity: int | str
    stack_bp_offset: int
    temporary_id: int | None = None


def wide_call_identity_8616(call: CFunctionCall) -> int | str | None:
    """Keep checked binary identity stable across naming and slice rebasing."""
    original_target = call.tags.get("inertia_target_addr_8616")
    if original_target is not None:
        if type(original_target) is not int:
            return None
        return original_target if _call_target_matches_8616(call, original_target, call.codegen.project) else None
    if call.callee_func is not None:
        return int(call.callee_func.addr)
    return call.callee_target if isinstance(call.callee_target, str) else None
