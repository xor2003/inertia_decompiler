"""Conservatively compare escaped ranges in a 16-bit stack coordinate.

Layer: IR.
Responsibility: reject preservation when typed stack ranges overlap or lack
comparable coordinates. This consumes address evidence; it does not infer Alias
identity, private lifetime, or permission to delete a store.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .core import AddressStatus, IRAddress, MemSpace

_STACK_OFFSET_MODULUS = 1 << 16


def stack_ranges_may_overlap_8616(address: IRAddress, escaped: IRAddress) -> bool:
    """Return false only for proved disjoint spaces or comparable byte ranges.

    Different BP/SP bases cannot establish disjointness without normalization.
    Circular distance preserves the 16-bit offset wrap, including negative BP
    displacements. Unknown width, coordinate, or provenance refuses separation.
    """
    if MemSpace.UNKNOWN in {address.space, escaped.space}:
        return True
    if address.space is not escaped.space:
        return False
    if address.status is not AddressStatus.STABLE or escaped.status is not AddressStatus.STABLE:
        return True
    if not address.base or address.base != escaped.base:
        return True
    if address.base_values != escaped.base_values:
        return True
    if address.size <= 0 or escaped.size <= 0:
        return True
    forward_distance = (escaped.offset - address.offset) % _STACK_OFFSET_MODULUS
    backward_distance = (address.offset - escaped.offset) % _STACK_OFFSET_MODULUS
    return forward_distance < address.size or backward_distance < escaped.size
