# cython: language_level=3, infer_types=True
"""Prove overlap-prefix edges through already canonicalized suffix owners.

Layer: IR.
Responsibility: preserve CFG ownership when one recovered block overlaps several
later blocks. The retained prefix must reach the first suffix, every intermediate
suffix must reach the next, and the final branch must retain the original edges.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping

from .core import IRBlock, IRInstr
import operator


def proven_suffix_owner_chain_8616(
    source: IRBlock,
    retained: object,
    owner_addrs: object,
    original_blocks: Mapping[cython.longlong, IRBlock],
    canonical_blocks: Mapping[cython.longlong, IRBlock],
) -> cython.bint:
    """Require an exact straight-line suffix chain before reconnecting a prefix."""
    first_owner: object
    owner: object
    index: object
    if not owner_addrs or not retained:
        return False
    first_owner = original_blocks.get(owner_addrs[0])
    if first_owner is None or operator.ne(first_owner.successor_addrs, source.successor_addrs):
        return False
    if any(instruction.addr is None or instruction.addr >= first_owner.addr for instruction in iter(retained)):
        return False
    owners = tuple(canonical_blocks.get(address) for address in iter(owner_addrs))
    for index, owner in enumerate(owners):
        if owner is None:
            return False
        expected = (
            (owner_addrs[index + 1],)
            if index + 1 < len(owners)
            else source.successor_addrs
        )
        if operator.ne(owner.successor_addrs, expected):
            return False
    return True
