"""Typed provenance for CFG-materialized composite conditions.

Layer: Structuring.
Responsibility: retain the exact ordered JCC identities consumed when typed
ConditionIR facts are combined into one structured logical expression.

Validation may consume this identity but must not reconstruct missing branch
semantics from it. Rewrite and postprocess must preserve it when replacing the
expression; they must not create it.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.structured_tags import copy_structured_tags_8616

CONDITION_CHAIN_PROVENANCE_TAG_8616: str = (
    "inertia_structuring_condition_chain_provenance_8616"
)


@dataclass(frozen=True, slots=True)
class ConditionChainProvenance8616:
    """Exact JCC identities consumed into one structured condition chain."""

    jcc_addrs: tuple[int, ...]


class _TaggedConditionExpression8616(Protocol):
    """Third-party C expression tag boundary used by Structuring."""

    tags: object


def bind_condition_chain_provenance_8616(
    expression: object,
    conditions: tuple[ConditionIR, ...],
) -> ConditionChainProvenance8616 | None:
    """Attach complete, unique JCC provenance to one materialized expression."""
    jcc_addrs = tuple(
        dict.fromkeys(
            condition.src_insn
            for condition in conditions
            if isinstance(condition.src_insn, int)
        )
    )
    if len(jcc_addrs) != len(conditions) or not jcc_addrs:
        return None
    provenance = ConditionChainProvenance8616(jcc_addrs)
    surface = cast(_TaggedConditionExpression8616, expression)
    try:
        tags = copy_structured_tags_8616(surface.tags) or {}
    except AttributeError:
        return None
    tags[CONDITION_CHAIN_PROVENANCE_TAG_8616] = provenance
    surface.tags = tags
    return provenance


def condition_chain_provenance_8616(
    expression: object,
) -> ConditionChainProvenance8616 | None:
    """Read valid composite-condition provenance from a C expression."""
    surface = cast(_TaggedConditionExpression8616, expression)
    try:
        tags = surface.tags
    except AttributeError:
        return None
    if not isinstance(tags, Mapping):
        return None
    provenance = tags.get(CONDITION_CHAIN_PROVENANCE_TAG_8616)
    return (
        provenance
        if isinstance(provenance, ConditionChainProvenance8616)
        else None
    )


__all__ = [
    "CONDITION_CHAIN_PROVENANCE_TAG_8616",
    "ConditionChainProvenance8616",
    "bind_condition_chain_provenance_8616",
    "condition_chain_provenance_8616",
]
