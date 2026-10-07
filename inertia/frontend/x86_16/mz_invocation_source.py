"""Derive invocation entry and relocated code from immutable MZ source.

Layer: Frontend.
Responsibility: project the authoritative MZ parser and relocation owner into
source-bound entry, stack and module facts. A caller supplies only serialized
bytes and a declared load paragraph; no callback or supplied boot fields can
authenticate these facts. Environment, execution paths and proof scope remain
separate obligations for consumers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .mz_load_source import MzExe, parse_mz, relocate_mz_load_module

_WORD_LIMIT: int = 0xFFFF
_REAL_MODE_LIMIT: int = 0x100000


@dataclass(frozen=True, slots=True)
class MzBootCoordinates8616:
    """Header coordinates projected under one explicitly declared load paragraph."""

    entry_segment: int
    entry_offset: int
    stack_segment: int
    stack_offset: int


def mz_boot_coordinates_8616(exe: MzExe, load_segment: int) -> MzBootCoordinates8616:
    """Project a parsed source header without reparsing or relocating its image.

    The caller owns the source-to-parser provenance. These coordinate facts
    alone do not authenticate a program, invocation path or environment.
    """
    if type(exe) is not MzExe:
        raise TypeError("MZ boot coordinates require the owned parsed source header")
    if type(load_segment) is not int or not 0 <= load_segment <= _WORD_LIMIT:
        raise ValueError("MZ invocation load segment must be a 16-bit paragraph")
    entry_segment = load_segment + exe.entry_cs
    stack_segment = load_segment + exe.stack_ss
    if entry_segment > _WORD_LIMIT or stack_segment > _WORD_LIMIT:
        raise ValueError("header CS/SS addition wraps the 16-bit segment space")
    return MzBootCoordinates8616(entry_segment, exe.entry_ip, stack_segment, exe.stack_sp)


@dataclass(frozen=True, slots=True)
class MzInvocationSource8616:
    """Source-derived load projection, never an unconditional call proof.

    ``complete`` reparses the retained source and checks every projected field
    so direct construction, replacement or mutation cannot authenticate an
    invented entry or relocated module. The load paragraph is an explicit
    invocation declaration, not inferred universal DOS behavior.
    """

    source: bytes
    load_segment: int
    module: bytes
    entry_segment: int
    entry_offset: int
    stack_segment: int
    stack_offset: int
    minalloc: int
    maxalloc: int

    @property
    def complete(self) -> bool:
        """Require exact agreement with a fresh source-derived projection."""
        if type(self) is not MzInvocationSource8616:
            return False
        try:
            derived = mz_invocation_source_8616(self.source, self.load_segment)
        except (TypeError, ValueError):
            return False
        return self == derived and all(type(value) is int for value in (
            self.entry_segment, self.entry_offset, self.stack_segment,
            self.stack_offset, self.minalloc, self.maxalloc,
        )) and type(self.module) is bytes

    @property
    def file_sha256(self) -> str:
        """Fingerprint the exact serialized source, including trailing bytes."""
        return hashlib.sha256(self.source).hexdigest()

    @property
    def module_base(self) -> int:
        """Return the physical load-module base for this declared invocation."""
        return self.load_segment * 16

    @property
    def entry_linear(self) -> int:
        """Return the header-derived physical entry under the declared load."""
        return self.entry_segment * 16 + self.entry_offset


def mz_invocation_source_8616(source: bytes, load_segment: int) -> MzInvocationSource8616:
    """Derive a checked entry/module projection from source and load paragraph.

    This function deliberately does not validate a program arena, services,
    initial registers or root-to-callsite execution. Its consumer must prove
    those applicable obligations and preserve invocation-local assumptions.
    """
    if type(source) is not bytes or not source:
        raise TypeError("MZ invocation requires immutable serialized source bytes")
    if type(load_segment) is not int or not 0 <= load_segment <= _WORD_LIMIT:
        raise ValueError("MZ invocation load segment must be a 16-bit paragraph")
    exe = parse_mz(source)
    module = relocate_mz_load_module(exe, load_segment)
    coordinates = mz_boot_coordinates_8616(exe, load_segment)
    entry_in_module = exe.entry_cs * 16 + exe.entry_ip
    if entry_in_module >= len(module):
        raise ValueError("MZ invocation entry must lie in source-backed module bytes")
    if load_segment * 16 + len(module) + exe.minalloc * 16 > _REAL_MODE_LIMIT:
        raise ValueError("MZ invocation image and minimum allocation exceed real-mode memory")
    return MzInvocationSource8616(
        source, load_segment, module, coordinates.entry_segment, coordinates.entry_offset,
        coordinates.stack_segment, coordinates.stack_offset, exe.minalloc, exe.maxalloc,
    )
