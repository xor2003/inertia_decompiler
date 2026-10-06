"""Layer: IR (frontend condition IR provenance).

Responsibility: attach complete decoded conditional-control bytes before facts
enter frontend caches. This owner never resolves CS or invents CFG targets.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""
from __future__ import annotations

from dataclasses import replace
from enum import StrEnum

from ..relative_control_edge import DecodedRelativeEdge, decode_relative_edge
from .condition_ir import ConditionFailure, ConditionIR


class RelativeConditionReason(StrEnum):
    """Explicit refusal when a retained raw edge belongs to different bytes."""

    SOURCE = "relative_condition_source_mismatch"


def attach_relative_condition_edge(condition: ConditionIR, head: int,
                                   encoding: bytes) -> ConditionIR | ConditionFailure:
    """Retain exact conditional bytes without granting concrete target evidence.

    Unsupported encodings leave an existing guard unchanged and contribute no
    relative-edge proof. An already retained edge must match the current source;
    its opaque provenance label is preserved without interpreting it.
    """
    retained = condition.relative_edge
    source = retained.source if retained is not None else None
    decoded = decode_relative_edge(head, encoding, source=source)
    if retained is not None and retained != decoded:
        return ConditionFailure(RelativeConditionReason.SOURCE, source=condition.source,
                                detail="retained relative edge differs from current instruction bytes")
    if not isinstance(decoded, DecodedRelativeEdge) or not decoded.is_conditional:
        return condition
    if condition.src_insn != head:
        return ConditionFailure(RelativeConditionReason.SOURCE, source=condition.source,
                                detail="condition instruction does not own the decoded relative edge")
    return replace(condition, relative_edge=decoded)
