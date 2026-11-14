# cython: language_level=3, infer_types=True
"""Layer: Frontend/angr compatibility.

Responsibility: preserve captured load values across native AIL memory effects.
Byte-resolved real-mode stores may alias earlier reads within one instruction;
an instruction address is not evidence that reloading memory is safe.
Forbidden: variable recovery, guessed non-aliasing, or rendered-C repair.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass

from angr.ailment.block import Block
from angr.ailment.expression import Expression, Load, Tmp
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.code_location import AILCodeLocation
from angr.utils.ssa import AILBlacklistExprTypeWalker
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class LoadPropagationStats8616:
    """Account for native load candidates and consumed ordering refusals."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    refused_count: cython.longlong


@cython.ccall
def _has_memory_barrier_8616(block: Block, temporary: Tmp, use_index: cython.longlong) -> cython.bint:
    """Stop at the nearest definition or barrier without copying block prefixes."""
    statements = block.statements
    for index in range(use_index - 1, -1, -1):
        statement = statements[index]
        if isinstance(statement, (Store, SideEffectStatement)):
            return True
        is_definition = (
            isinstance(statement, Assignment) and isinstance(statement.dst, Tmp)
            and operator.eq(statement.dst.tmp_idx, temporary.tmp_idx)
        )
        if is_definition:
            return False
    return True


@cython.ccall
def refuse_reordered_loads_8616(
    blocks: Mapping[tuple[cython.longlong, int | None], Block],
    replacements: MutableMapping[AILCodeLocation, MutableMapping[Expression, Expression]],
) -> LoadPropagationStats8616:
    """Filter load-bearing temporary substitutions in block and function models.

    Refusal keeps the original temporary definition/use intact. It does not
    assert alias independence for distinct-looking addresses, nor collapse the
    independently resolved byte accesses required for 16-bit offset wrapping.

    ``has_load_expr`` classification of the replacement expression is keyed by
    object identity and reused only within this invocation, so mutation of an
    expression between invocations is always re-observed. Only ``new`` is
    walked: ``old`` is already proven a ``Tmp`` leaf, so this matches walking
    ``Assignment(None, old, new)`` exactly (``walk_expression`` is the upstream
    expression entrypoint, as used by ``has_ite_expr``).
    """
    block: object
    cached: object
    use_index: object
    entries: object
    location: object
    new: object
    old: object
    inspected = refused = missing = 0
    walker = AILBlacklistExprTypeWalker((Load,))
    load_verdicts: dict[cython.longlong, tuple[Expression, cython.bint]] = {}
    for location, entries in replacements.items():
        block = blocks.get((location.block_addr, location.block_idx))
        for old, new in tuple(entries.items()):
            if not isinstance(old, Tmp):
                continue
            cached = load_verdicts.get(id(new))
            if cached is not None and cached[0] is new:
                has_load = cached[1]
            else:
                # This walker only classifies Load: no context-dependent vvar
                # predicate is enabled. Reset the accumulated verdict per root.
                walker.has_blacklisted_exprs = False
                walker.walk_expression(new)
                has_load = walker.has_blacklisted_exprs
                load_verdicts[id(new)] = (new, has_load)
            if not has_load:
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
