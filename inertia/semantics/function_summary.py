# cython: language_level=3, infer_types=True
"""Layer: Recovery metadata.

Responsibility: summarize recovered function-level callsite and typed-IR signals.
Forbidden: source/COD-backed recovery, output repair, or validation acceptance.
Dynamic attribute boundary: getattr use here is limited to third-party angr
project/function objects and their optional metadata dictionaries.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from types import SimpleNamespace

from .callsite_summary import summarize_x86_16_callsite
import dataclasses
import builtins

__all__ = ["FunctionSummary8616", "summarize_x86_16_function"]


@dataclasses.dataclass(frozen=True, )
class FunctionSummary8616:
    """Function-level summary of recovered 86:16 decompiler evidence."""

    function_addr: cython.longlong
    direct_call_count: cython.longlong
    callsite_kinds: object
    typed_ir_condition_kinds: object
    typed_ir_register_clobbers: object
    typed_ir_address_spaces: object
    typed_ir_stable_address_spaces: object
    frame_slot_count: int | None


def summarize_x86_16_function(project: object, function: object) -> FunctionSummary8616 | None:
    """Summarize angr function metadata for 86:16 diagnostics.

    Dynamic attribute boundary: project/function are third-party angr objects
    whose architecture, callsite, address, and info fields are optional across
    supported angr versions.
    """
    info: object
    summary: object
    callsite_addr: object
    if project is None or function is None:
        return None
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return None

    callsite_kinds: list[str] = []
    for callsite_addr in tuple(sorted(tuple(getattr(function, "get_call_sites", list)() or ()))):
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is None or not isinstance(summary.kind, str):
            continue
        callsite_kinds.append(summary.kind)

    info = getattr(function, "info", None)
    vex_ir_summary = info.get("x86_16_vex_ir_summary", {}) if isinstance(info, dict) else {}
    condition_counts = vex_ir_summary.get("condition_counts", {}) if isinstance(vex_ir_summary, dict) else {}
    register_clobbers = vex_ir_summary.get("register_clobbers", {}) if isinstance(vex_ir_summary, dict) else {}
    address_space_counts = vex_ir_summary.get("address_space_counts", {}) if isinstance(vex_ir_summary, dict) else {}
    stable_address_space_counts = (
        vex_ir_summary.get("stable_address_space_counts", {}) if isinstance(vex_ir_summary, dict) else {}
    )
    frame_slot_count = vex_ir_summary.get("frame_slot_count") if isinstance(vex_ir_summary, dict) else None
    typed_ir_condition_kinds = tuple(sorted(str(key) for key in iter(condition_counts)))
    typed_ir_register_clobbers = tuple(
        sorted(str(key) for key, count in builtins.iter(register_clobbers.items()) if isinstance(count, int) and count > 0)
    )
    typed_ir_address_spaces = tuple(
        sorted(str(key) for key, count in builtins.iter(address_space_counts.items()) if isinstance(count, int) and count > 0)
    )
    typed_ir_stable_address_spaces = tuple(
        sorted(str(key) for key, count in builtins.iter(stable_address_space_counts.items()) if isinstance(count, int) and count > 0)
    )
    return FunctionSummary8616(
        function_addr=int(function.addr),
        direct_call_count=len(callsite_kinds),
        callsite_kinds=tuple(sorted(callsite_kinds)),
        typed_ir_condition_kinds=typed_ir_condition_kinds,
        typed_ir_register_clobbers=typed_ir_register_clobbers,
        typed_ir_address_spaces=typed_ir_address_spaces,
        typed_ir_stable_address_spaces=typed_ir_stable_address_spaces,
        frame_slot_count=frame_slot_count if isinstance(frame_slot_count, int) else None,
    )
