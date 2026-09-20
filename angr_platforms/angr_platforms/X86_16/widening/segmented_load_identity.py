"""Retain typed storage identity on materialized segmented-load expressions.

Layer: Widening.
Responsibility: define the exact segmented scalar identity that Widening joins
and Types/Lowering attaches to materialized C helper expressions.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence. Untagged expressions remain unknown.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from ..ir.core import (
    SEGMENTED_LOAD_ADDRESS_TAG_8616,
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)

__all__ = [
    "SegmentedLoadIdentity8616",
    "segmented_load_identity_8616",
    "segmented_load_tags_8616",
]

_SEGMENTED_LOAD_IDENTITY_TAG_8616 = "inertia_x86_16_segmented_load_identity"


@dataclass(frozen=True, slots=True)
class SegmentedLoadIdentity8616:
    """Exact segmented scalar storage represented by one C load expression."""

    space: MemSpace
    offset: int
    width: int
    region: int | None

    def __post_init__(self) -> None:
        """Reject malformed owned identities at the widening boundary."""
        if self.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}:
            raise ValueError("segmented load identity requires DS, ES, or SS")
        if not 0 <= self.offset <= 0xFFFF:
            raise ValueError("segmented load offset must fit 16 bits")
        if self.width <= 0:
            raise ValueError("segmented load width must be positive")
        if self.region is not None and self.region < 0:
            raise ValueError("segmented load region must be nonnegative")


def segmented_load_tags_8616(
    identity: SegmentedLoadIdentity8616,
    *,
    existing: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return C-node tags carrying one exact widening-owned identity."""
    if not isinstance(identity, SegmentedLoadIdentity8616):
        raise TypeError("identity must be SegmentedLoadIdentity8616")
    tags = dict(existing or {})
    tags[_SEGMENTED_LOAD_IDENTITY_TAG_8616] = identity
    return tags


def segmented_load_identity_8616(
    node: object,
) -> SegmentedLoadIdentity8616 | None:
    """Return an exact tagged identity without parsing the helper expression."""
    if not isinstance(node, CFunctionCall) or not isinstance(node.tags, dict):
        return None
    address = node.tags.get(SEGMENTED_LOAD_ADDRESS_TAG_8616)
    if isinstance(address, IRAddress) and (address.base or address.base_values):
        return None
    identity = node.tags.get(_SEGMENTED_LOAD_IDENTITY_TAG_8616)
    if isinstance(identity, SegmentedLoadIdentity8616):
        return identity
    if not isinstance(address, IRAddress):
        return None
    proven_address = address.status is AddressStatus.STABLE and address.segment_origin is SegmentOrigin.PROVEN
    supported_scalar = address.space in {MemSpace.DS, MemSpace.ES, MemSpace.SS} and 0 <= address.offset <= 0xFFFF and address.size > 0
    if proven_address and supported_scalar:
        return SegmentedLoadIdentity8616(
            space=address.space,
            offset=address.offset,
            width=address.size,
            region=None,
        )
    return None
