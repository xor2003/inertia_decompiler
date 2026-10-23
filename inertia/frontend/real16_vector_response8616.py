"""Single-owner response contract for declared get/set-vector effects.

Layer: Frontend.
Responsibility: own once the pure INT 21h AH=35h / AH=25h effect arithmetic —
a live four-byte IVT slot projected into ``es``/``bx`` for get, and ``ds``/``dx``
encoded into four slot bytes for set, with an unchanged dispatch-slot rewrite
admitted and a changed dispatch slot refused. This module performs effect
computation only: the caller must authenticate the declared environment, the
live DOS dispatch entry, and the interrupt frame; no value here admits a call
site, proves a native handler body, or grants policy authority. Pure data and
one pure function — stdlib only, importable without angr or Unicorn.

Forbidden: dispatch/arena/frame guards (owned by the runtime), IVT layout
policy (owned by the memory model), and any effect beyond ``es``/``bx`` and
the four exact slot bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "DOS_DISPATCH_SLOT_8616",
    "INT21_GET_VECTOR_8616",
    "INT21_SET_VECTOR_8616",
    "IVT_SLOT_BYTES_8616",
    "VectorResponseEffect8616",
    "VectorResponseRefusal8616",
    "vector_response_8616",
]

INT21_GET_VECTOR_8616: int = 0x35
INT21_SET_VECTOR_8616: int = 0x25
DOS_DISPATCH_SLOT_8616: int = 0x21
IVT_SLOT_BYTES_8616: int = 4


class VectorResponseRefusal8616(StrEnum):
    """Typed result when a vector response cannot be computed.

    ``DOS_UPDATE`` keeps the exact runtime refusal value: installing a
    different dispatch pointer requires handler execution the contract never
    models. ``FUNCTION_UNSUPPORTED`` types every undeclared or malformed
    selector so no ABI is guessed.
    """

    DOS_UPDATE = "dos_vector_update_requires_handler_execution"
    FUNCTION_UNSUPPORTED = "vector_function_not_declared"


@dataclass(frozen=True, slots=True)
class VectorResponseEffect8616:
    """Computed get/set-vector effects, without callsite admission authority.

    ``es``/``bx`` carry the AH=35h register result and are ``None`` for
    AH=25h, which writes no registers; ``slot_after`` carries the exact four
    bytes to commit for AH=25h and is ``None`` for AH=35h, which writes no
    memory. Flags, frame bytes, IP, and all other registers are outside the
    granted effect set.
    """

    function: int
    number: int
    es: int | None
    bx: int | None
    slot_after: bytes | None


def _word_8616(value: object) -> bool:
    """Return whether ``value`` is a strict 16-bit word, bool excluded."""
    return type(value) is int and 0 <= value <= 0xFFFF


def vector_response_8616(
    *,
    function: int,
    number: int,
    slot_before: bytes,
    ds: int | None = None,
    dx: int | None = None,
) -> VectorResponseEffect8616 | VectorResponseRefusal8616:
    """Compute an AH=35h/AH=25h response over one live IVT slot.

    ``slot_before`` is the exact live four bytes at ``number * 4``. AH=35h
    projects the slot into ``es``/``bx`` in offset-then-segment order with no
    memory effect. AH=25h encodes ``ds``/``dx`` into ``slot_after``; for the
    dispatch slot a changed pointer refuses ``DOS_UPDATE`` while rewriting the
    identical pointer stays admitted because DOS dispatch is unchanged. Every
    other function, out-of-range or bool selector, malformed slot length, or
    missing/out-of-word ``ds``/``dx`` refuses typed rather than guessing.
    """
    valid_selectors = (
        type(function) is int
        and function in (INT21_GET_VECTOR_8616, INT21_SET_VECTOR_8616)
        and type(number) is int
        and 0 <= number <= 0xFF
    )
    if (
        not valid_selectors
        or not isinstance(slot_before, bytes)
        or len(slot_before) != IVT_SLOT_BYTES_8616
    ):
        return VectorResponseRefusal8616.FUNCTION_UNSUPPORTED
    if function == INT21_GET_VECTOR_8616:
        return VectorResponseEffect8616(
            function=function,
            number=number,
            es=int.from_bytes(slot_before[2:], "little"),
            bx=int.from_bytes(slot_before[:2], "little"),
            slot_after=None,
        )
    if ds is None or dx is None or not _word_8616(ds) or not _word_8616(dx):
        return VectorResponseRefusal8616.FUNCTION_UNSUPPORTED
    slot_after = dx.to_bytes(2, "little") + ds.to_bytes(2, "little")
    if number == DOS_DISPATCH_SLOT_8616 and slot_after != slot_before:
        return VectorResponseRefusal8616.DOS_UPDATE
    return VectorResponseEffect8616(
        function=function, number=number, es=None, bx=None, slot_after=slot_after
    )
