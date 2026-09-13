"""Bind block-origin loop guards to authoritative terminal branch identities.

Layer: Structuring.
Responsibility: transport identity from an already-materialized JCC guard when
angr retained its block-start tag rather than the terminal instruction tag.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here. Never infer identity from rendered comparisons or variable names.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from ..ir.condition_ir import ConditionIR


class _TaggedCondition8616(Protocol):
    """Dynamic angr condition tag boundary."""

    tags: dict[str, object]


def is_owned_loop_continuation_8616(condition: object) -> bool:
    """Identify a complete Structuring-owned polarity contract for replay guards."""
    try:
        tags = cast(_TaggedCondition8616, condition).tags
    except AttributeError:
        return False
    key = tags.get("inertia_typed_loop_condition_key_8616")
    return (
        isinstance(key, tuple)
        and all(isinstance(address, int) for address in key)
        and key == (tags.get("ins_addr"), tags.get("vex_block_addr"))
        and tags.get("inertia_typed_loop_condition_bound_8616") is True
        and tags.get("inertia_typed_loop_continuation_edge_8616") in ("taken", "fallthrough")
    )


def loop_condition_keys_8616(
    condition: object,
    tagged_keys: frozenset[tuple[int, int]],
    conditions_by_key: Mapping[tuple[int, int], Sequence[ConditionIR]],
    successors: Mapping[int, tuple[int, ...]],
) -> frozenset[tuple[int, int]]:
    """Prefer exact keys; admit a unique CFG-proven block-origin JCC bridge."""
    exact = tagged_keys.intersection(conditions_by_key)
    if exact:
        return exact
    try:
        tags = cast(_TaggedCondition8616, condition).tags
    except AttributeError:
        return frozenset()
    block = tags.get("vex_block_addr")
    marked_block_origin = (
        isinstance(block, int)
        and tags.get("ins_addr") == block
        and tags.get("inertia_jcc_materialized_8616") is True
    )
    if not marked_block_origin:
        return frozenset()
    candidates = [
        (key, fact)
        for key, facts in conditions_by_key.items()
        if key[1] == block
        for fact in facts
    ]
    if len(candidates) != 1:
        return frozenset()
    key, fact = candidates[0]
    targets = (fact.taken_target, fact.fallthrough_target)
    cfg_targets = successors.get(key[1], ())
    complete_branch = (
        all(isinstance(target, int) for target in targets)
        and targets[0] != targets[1]
        and len(cfg_targets) == len(targets)
        and set(cfg_targets) == set(targets)
    )
    return frozenset((key,)) if complete_branch else frozenset()
