# cython: language_level=3, infer_types=True
"""Authenticated selector geometry for every native instruction fetch.

Layer: frontend x86_16.
Responsibility: validate the complete encoded instruction against the incoming
CS window and conservative A20 limits. Source/native byte identity is an
independent required binding supplied by the caller, never inferred here.
"""
from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from .control_transfer_geometry import _fetch_fits
import dataclasses


class FetchVerdict8616(StrEnum):
    """A fetch extent either fits its authenticated selector or refuses."""
    CLOSED = "closed"
    REFUSED = "refused"


@dataclasses.dataclass(frozen=True, )
class InstructionFetchCheck8616:
    """One instruction's extent checked under its incoming numeric CS."""
    addr: cython.longlong
    size: cython.longlong
    cs: int | None
    verdict: FetchVerdict8616
    detail: object


@cython.ccall
def check_instruction_fetch_8616(
    addr: cython.longlong, encoded: object, known_cs: int | None,
) -> InstructionFetchCheck8616:
    """Refuse missing bytes, unknown CS, crossing its window or A20 ambiguity."""
    detail: object
    size = 0 if encoded is None else len(encoded)
    if type(known_cs) is not int or not 0 <= known_cs <= 0xFFFF:
        detail = "cs_unbound"
    else:
        detail = _fetch_fits(addr, size, known_cs << 4)
    return InstructionFetchCheck8616(
        addr, size, known_cs,
        FetchVerdict8616.CLOSED if detail is None else FetchVerdict8616.REFUSED,
        "instruction_fetch_bound" if detail is None else detail,
    )
