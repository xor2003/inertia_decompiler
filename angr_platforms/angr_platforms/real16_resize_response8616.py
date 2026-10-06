"""Single-owner contract for the declared DOS tail-resize service response.

Layer: Frontend/runtime package surface — shared service contract.
Responsibility: own exactly once the declared INT 21h / AH=4Ah tail-block
resize contract that two consumers project: the dosunit canonical
``program_resize_call`` owner and the invocation census's declared-service
revalidation. This module is pure data plus one pure function — it imports
nothing beyond the standard library and the sibling version owner for the
shared INT 21h vector constant, and must stay importable without
initializing angr or the ``X86_16`` platform package. Nothing here asserts
an installed DOS: the constants name the declared native single-tail-MCB
contract shape and the function computes the caller-declared response for
one admitted call. Other blocks and nonterminal chains require allocator
state this contract does not declare and return a typed refusal.

"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from angr_platforms.real16_version_response8616 import INT21_VERSION_VECTOR_8616

__all__ = [
    "INT21_RESIZE_FUNCTION_8616",
    "INT21_RESIZE_VECTOR_8616",
    "RESIZE_CONVENTIONAL_END_8616",
    "RESIZE_MCB_BYTES_8616",
    "RESIZE_NATIVE_PROCESS_ID_8616",
    "RESIZE_NATIVE_PSP_SEGMENT_8616",
    "RESIZE_NATIVE_SIGNATURE_8616",
    "ResizeRefusal8616",
    "ResizeResponse8616",
    "resize_metadata_error_8616",
    "resize_response_8616",
]

# INT 21h is the DOS service vector this declared contract binds — the
# constant projects the shared version owner's architectural name once.
INT21_RESIZE_VECTOR_8616: int = INT21_VERSION_VECTOR_8616

# AH=4Ah is Resize Memory Block (SETBLOCK). AL carries no selector: every
# proven AL value is admitted and AX returns unchanged on success.
INT21_RESIZE_FUNCTION_8616: int = 0x4A

# The declared native profile models exactly one first/final Kvikdos MCB
# (16 bytes) ahead of the loader PSP at segment 0x100, below the
# conventional-memory ceiling at paragraph 0xA000.
RESIZE_MCB_BYTES_8616: int = 16
RESIZE_NATIVE_PSP_SEGMENT_8616: int = 0x100
RESIZE_NATIVE_PROCESS_ID_8616: int = 0x192
RESIZE_NATIVE_SIGNATURE_8616: bytes = b"\xb2KV1KPR0G"
RESIZE_CONVENTIONAL_END_8616: int = 0xA000


def _resize_word_8616(value: int, field: str) -> None:
    """Reject truncated or Boolean machine-word declarations."""
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{field} must be a 16-bit integer")


def resize_metadata_error_8616(mcb: bytes, maximum: int) -> bool:
    """Check the native first/final MCB invariants, before any update.

    A complete 16-byte MCB must carry the declared signature, process id,
    zeroed reserved bytes, a size within the declared ``maximum`` and a
    valid ``M``/``Z`` marker. The function reads only; it never normalizes
    or repairs a corrupted declaration.
    """
    return (
        len(mcb) != RESIZE_MCB_BYTES_8616
        or mcb[7:] != RESIZE_NATIVE_SIGNATURE_8616
        or int.from_bytes(mcb[1:3], "little") != RESIZE_NATIVE_PROCESS_ID_8616
        or mcb[5:7] != b"\0\0"
        or int.from_bytes(mcb[3:5], "little") > maximum
        or mcb[0] not in (ord("Z"), ord("M"))
    )


class ResizeRefusal8616(StrEnum):
    """Missing environment state, distinct from a modeled DOS error result."""

    OTHER_BLOCK = "resize_other_block_undeclared"
    CHAIN = "resize_nonterminal_chain_undeclared"


@dataclass(frozen=True, slots=True)
class ResizeResponse8616:
    """Complete low-register response and replacement MCB, staged before commit."""

    ax: int
    bx: int
    carry: bool
    metadata: bytes


def resize_response_8616(
    *,
    block_segment: int,
    maximum: int,
    segment: int,
    paragraphs: int,
    ax: int,
    metadata: bytes,
) -> ResizeResponse8616 | ResizeRefusal8616:
    """Stage native final-block resize or an exact DOS error without mutation.

    ``block_segment`` is the declared tail-block owner segment and
    ``maximum`` its declared capacity in paragraphs. ``segment``/``paragraphs``
    are the proven ES/BX inputs and ``ax`` the proven full AX input whose
    high byte must be AH=4Ah. ``metadata`` carries every current MCB byte —
    complete bytes are the caller's obligation; this function reads them,
    never supplies them. Corrupt-but-complete metadata answers the
    documented DOS error 7 (destroyed MCBs) with CF set and metadata
    unchanged; a request beyond ``maximum`` answers error 8 with BX=maximum.
    Only the size word at bytes 3..5 ever changes. OTHER_BLOCK and CHAIN
    are typed refusals, never DOS error results.
    """
    for field, value in (("ES", segment), ("BX", paragraphs), ("AX", ax)):
        _resize_word_8616(value, field)
    _resize_word_8616(block_segment, "resize block segment")
    _resize_word_8616(maximum, "resize maximum")
    if ax >> 8 != INT21_RESIZE_FUNCTION_8616:
        raise ValueError("resize requires INT21/AH4A")
    if len(metadata) != RESIZE_MCB_BYTES_8616:
        raise ValueError("resize requires every current MCB byte")
    if segment != block_segment:
        return ResizeRefusal8616.OTHER_BLOCK
    if resize_metadata_error_8616(metadata, maximum):
        return ResizeResponse8616(7, paragraphs, True, metadata)
    if metadata[0] != ord("Z"):
        return ResizeRefusal8616.CHAIN
    if paragraphs > maximum:
        return ResizeResponse8616(8, maximum, True, metadata)
    changed = metadata[:3] + paragraphs.to_bytes(2, "little") + metadata[5:]
    return ResizeResponse8616(ax, paragraphs, False, changed)
