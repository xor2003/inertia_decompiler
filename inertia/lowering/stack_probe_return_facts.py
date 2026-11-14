# cython: language_level=3, infer_types=True
"""Build lowering-owned stack-probe return facts from callsite summaries.

Layer: Types/Lowering.
Responsibility: consumes alias, widening, and typed facts to identify helper
returns that carry stable stack addresses.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import cython

import typing
from dataclasses import dataclass
from typing import Any

from inertia.semantics.callsite_summary import CallsiteSummary8616
import dataclasses

CarrierKey8616 = typing.TypeAliasType("CarrierKey8616", tuple[str, str | int])

__all__ = [
    "CarrierKey8616",
    "TypedStackProbeReturnFact8616",
    "build_typed_stack_probe_return_facts_8616",
]


@dataclasses.dataclass(frozen=True, )
class TypedStackProbeReturnFact8616:
    """Lowering-owned proof that a stack-probe call returns an SS stack address."""

    call_node_id: cython.longlong
    segment_space: object
    width: cython.longlong
    carrier_keys: tuple[CarrierKey8616, ...] = ()


@cython.ccall
def _dynamic_codegen_attr_8616(obj: object, name: object, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic codegen boundary: read optional metadata attached by angr codegen passes."""
    return getattr(obj, name, default)


@cython.ccall
def _stack_probe_summary_fact_8616(
    call_node_id: cython.longlong, summary: CallsiteSummary8616
) -> TypedStackProbeReturnFact8616 | None:
    """Project one callsite summary into a stack-probe return fact, or refuse."""
    if not summary.stack_probe_helper:
        return None
    if summary.helper_return_state != "stack_address":
        return None
    address_kind = summary.helper_return_address_kind
    if address_kind in {None, "none"}:
        address_kind = "stack"
    if address_kind != "stack":
        return None
    if summary.helper_return_space != "ss":
        return None
    width = summary.helper_return_width
    if not isinstance(width, int) or width <= 0:
        return None
    return TypedStackProbeReturnFact8616(
        call_node_id=call_node_id,
        segment_space="ss",
        width=width,
        carrier_keys=(),
    )


@cython.ccall
def build_typed_stack_probe_return_facts_8616(codegen: object) -> object:
    """Build lowering-owned stack-probe facts from typed callsite summaries."""
    fact: object
    call_node_id: object
    summary: object
    summary_map = _dynamic_codegen_attr_8616(codegen, "_inertia_callsite_summaries", None)
    facts: dict[cython.longlong, TypedStackProbeReturnFact8616] = {}
    if isinstance(summary_map, dict):
        for call_node_id, summary in summary_map.items():
            if not isinstance(call_node_id, int):
                continue
            if not isinstance(summary, CallsiteSummary8616):
                continue
            fact = _stack_probe_summary_fact_8616(call_node_id, summary)
            if fact is not None:
                facts[call_node_id] = fact

    typing.cast(typing.Any, codegen)._inertia_typed_stack_probe_return_facts = facts
    return facts
