"""Layer: Frontend/angr compatibility.

Responsibility: preserve captured load values across native AIL memory effects.
Byte-resolved real-mode stores may alias earlier reads within one instruction;
an instruction address is not evidence that reloading memory is safe.
Forbidden: variable recovery, guessed non-aliasing, or rendered-C repair.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass

from angr.ailment.block import Block
from angr.ailment.expression import Expression, Tmp
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.code_location import AILCodeLocation
from angr.utils.ssa import has_load_expr


@dataclass(frozen=True, slots=True)
class LoadPropagationStats8616:
    """Account for native load candidates and consumed ordering refusals."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    refused_count: int


def _has_memory_barrier_8616(block: Block, temporary: Tmp, use_index: int) -> bool:
    """Require an exact preceding definition and no intervening memory effect."""
    for statement in reversed(block.statements[:use_index]):
        if isinstance(statement, (Store, SideEffectStatement)):
            return True
        is_definition = (
            isinstance(statement, Assignment) and isinstance(statement.dst, Tmp)
            and statement.dst.tmp_idx == temporary.tmp_idx
        )
        if is_definition:
            return False
    # A stale or absent definition cannot justify moving a captured load.
    return True


def refuse_reordered_loads_8616(
    blocks: Mapping[tuple[int, int | None], Block],
    replacements: MutableMapping[AILCodeLocation, MutableMapping[Expression, Expression]],
) -> LoadPropagationStats8616:
    """Filter load-bearing temporary substitutions in block and function models.

    Refusal keeps the original temporary definition/use intact. It does not
    assert alias independence for distinct-looking addresses, nor collapse the
    independently resolved byte accesses required for 16-bit offset wrapping.
    """
    inspected = refused = missing = 0
    for location, entries in replacements.items():
        block = blocks.get((location.block_addr, location.block_idx))
        for old, new in tuple(entries.items()):
            if not isinstance(old, Tmp) or not has_load_expr(Assignment(None, old, new)):
                continue
            inspected += 1
            use_index = location.stmt_idx
            valid_location = block is not None and use_index is not None and 0 <= use_index < len(block.statements)
            if not valid_location:
                missing += 1
                del entries[old]
                refused += 1
                continue
            assert block is not None and use_index is not None
            if _has_memory_barrier_8616(block, old, use_index):
                del entries[old]
                refused += 1
    classified = inspected - missing
    return LoadPropagationStats8616(inspected, inspected, classified, classified, missing, refused)
