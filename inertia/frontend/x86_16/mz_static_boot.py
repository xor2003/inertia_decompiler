# cython: language_level=3, infer_types=True
"""Static-header MZ boot input for source-authenticated invocation proofs.

Layer: Frontend.
Responsibility: project retained MZ source bytes plus the loader's declared
load paragraph into a typed boot-shaped input carrying only header facts the
input can itself authenticate — the load module, the initial CS:IP, the
initial SS:SP — and explicitly no environment. A static input is not a
declared ``ProgramBoot``: it exposes no ``environment`` field, so the
declared-evidence owner refuses it as malformed and no layer can confuse
header-authenticated state with a caller-declared register file. The domain
owner consumes this object through a separate typed evidence surface whose
register seed contains only CS/SS/SP; every other register stays unknown and
path effects depending on them refuse. It knows no dosunit replay backend,
simulation, solver, typed edge, or success verdict.
"""

from __future__ import annotations
import typing
import cython

import hashlib
from dataclasses import dataclass

from .mz_invocation_source import mz_invocation_source_8616
from .mz_load_source import parse_mz
import dataclasses
import operator

__all__ = [
    "MzStaticBoot8616",
    "MzStaticBootImage8616",
    "MzStaticBootPoint8616",
    "MzStaticBootRange8616",
    "mz_static_boot_8616",
    "recompute_mz_static_boot_8616",
]


@dataclasses.dataclass(frozen=True, )
class MzStaticBootPoint8616:
    """Typed segmented point projected from the MZ header.

    ``linear`` is the segment base plus offset; the constructor asserts a
    20-bit real-mode range.
    """

    segment: cython.longlong
    offset: cython.longlong

    def linear(self) -> cython.longlong:
        """Return the 20-bit linear address of ``segment:offset``."""
        linear = self.segment * 16 + self.offset
        if not 0 <= linear < 0x100000:
            raise ValueError("real16 static boot requires 20-bit linear addresses")
        return linear


@dataclasses.dataclass(frozen=True, )
class MzStaticBootRange8616:
    """Typed linear byte range projected onto the loaded module."""

    address: cython.longlong
    size: cython.longlong

    def contains(self, address: cython.longlong, size: cython.longlong = 1) -> cython.bint:
        """Return whether ``[address, address+size)`` lies inside this range."""
        return (
            size >= 0
            and self.address <= address
            and address + size <= self.address + self.size
        )


@dataclasses.dataclass(frozen=True, )
class MzStaticBootImage8616:
    """Declared image surface for a static-header boot input.

    ``chunks`` carry the relocated load module exactly as mapped by the DOS
    MZ loader; ``load_segment`` is the paragraph the loader actually placed
    the module at; the digests fingerprint the source bytes, the relocated
    module and the relocation records so mutation cannot silently change the
    retained image. ``code_scope`` states how ``code_ranges`` was derived —
    ``"whole_image"`` means the constructor synthesized the whole-module
    range, ``"declared"`` means the caller supplied explicit spans.
    """

    chunks: object
    code_ranges: object
    load_segment: cython.longlong
    file_sha256: object
    image_sha256: object
    reloc_sha256: object
    code_scope: object


@dataclasses.dataclass(frozen=True, )
class MzStaticBoot8616:
    """Static-header invocation input projected from retained MZ bytes.

    ``source`` is the exact MZ byte stream the consumer loaded; ``entry`` and
    ``stack`` carry only the header-authenticated initial CS:IP and SS:SP;
    ``image`` binds the relocated module, load paragraph and fingerprint
    digests. ``boot_sha256`` is a stable digest of every typed field, so an
    equal object has equal fields. There is intentionally no ``environment``:
    the sole authenticated register facts are the header CS:IP/SS:SP, and no
    other register may acquire a value through this input.
    """

    source: object
    entry: MzStaticBootPoint8616
    stack: MzStaticBootPoint8616
    image: MzStaticBootImage8616
    boot_sha256: object

    @property
    def complete(self) -> cython.bint:
        """Return whether re-deriving this input reproduces it exactly.

        The recompute consumes only ``source``, ``load_segment`` and the
        caller-declared code ranges, so ``False`` means at least one typed
        field was forged after construction.
        """
        try:
            return operator.eq(recompute_mz_static_boot_8616(self), self)
        except (TypeError, ValueError):
            return False


@cython.ccall
def _static_identity_8616(
    entry_linear: cython.longlong,
    stack_linear: cython.longlong,
    image: MzStaticBootImage8616,
) -> object:
    """Compute the stable digest of one static-header input's typed fields."""
    address: object
    bound: object
    chunk: object
    tag: object
    value: object
    digest = hashlib.sha256()
    digest.update(b"static")
    for value in (entry_linear, stack_linear, image.load_segment):
        digest.update(value.to_bytes(4, "big"))
    for tag in (
        image.file_sha256,
        image.image_sha256,
        image.reloc_sha256,
        image.code_scope,
    ):
        digest.update(tag.encode("utf-8"))
    for bound in image.code_ranges:
        digest.update(bound.address.to_bytes(4, "big"))
        digest.update(bound.size.to_bytes(4, "big"))
    for address, chunk in image.chunks:
        digest.update(address.to_bytes(4, "big"))
        digest.update(chunk)
    return digest.hexdigest()


def mz_static_boot_8616(
    source: object,
    load_segment: cython.longlong,
    *,
    code_ranges: object = (),
) -> MzStaticBoot8616:
    """Construct one static-header input from source bytes and load paragraph.

    ``source`` must be a nonempty MZ byte stream; it is reparsed and
    relocated by the shared MZ source owner, and the ``load_segment`` claim
    relocates every stored word exactly as the DOS loader did. The header's
    CS:IP/SS:SP become the only seed facts — no environment, PSP, DS/ES or
    flag state is invented. ``code_ranges`` scopes native fetches; when
    omitted, the whole module is declared in scope.
    """
    bound: object
    reloc_offset: object
    reloc_segment: object
    if not isinstance(load_segment, int) or not 0 <= load_segment <= 0xFFFF:
        raise TypeError("real16 static boot requires a declared load paragraph")
    projection = mz_invocation_source_8616(source, load_segment)
    if not projection.complete:
        raise TypeError("real16 static boot projection is not complete")
    exe = parse_mz(projection.source)
    module_base = projection.module_base
    module_end = module_base + len(projection.module)
    if code_ranges:
        if not all(type(bound) is MzStaticBootRange8616 for bound in iter(code_ranges)):
            raise TypeError("real16 static code ranges must be typed bounds")
        for bound in code_ranges:
            if bound.size < 0 or bound.address < module_base or bound.address + bound.size > module_end:
                raise ValueError("static code range must lie inside the loaded module")
        ranges = tuple(code_ranges)
        scope = "declared"
    else:
        ranges = (MzStaticBootRange8616(module_base, len(projection.module)),)
        scope = "whole_image"
    reloc_digest = hashlib.sha256()
    for reloc_offset, reloc_segment in exe.relocations:
        reloc_digest.update(reloc_offset.to_bytes(2, "little"))
        reloc_digest.update(reloc_segment.to_bytes(2, "little"))
    image = MzStaticBootImage8616(
        chunks=((module_base, projection.module),),
        code_ranges=ranges,
        load_segment=load_segment,
        file_sha256=projection.file_sha256,
        image_sha256=hashlib.sha256(
            module_base.to_bytes(4, "little")
            + len(projection.module).to_bytes(4, "little")
            + projection.module
        ).hexdigest(),
        reloc_sha256=reloc_digest.hexdigest(),
        code_scope=scope,
    )
    entry = MzStaticBootPoint8616(
        projection.entry_segment, projection.entry_offset
    )
    stack = MzStaticBootPoint8616(
        projection.stack_segment, projection.stack_offset
    )
    return MzStaticBoot8616(
        source=projection.source,
        entry=entry,
        stack=stack,
        image=image,
        boot_sha256=_static_identity_8616(
            projection.entry_linear,
            projection.stack_segment * 16 + projection.stack_offset,
            image,
        ),
    )


@cython.ccall
def recompute_mz_static_boot_8616(boot: object) -> MzStaticBoot8616:
    """Reconstruct the static input from its retained source bytes.

    The result must equal ``boot`` for admission: the digest binds entry,
    stack, image fingerprints, code scope and chunks, so equality proves
    every typed field is reproducible from source plus the load-paragraph
    claim alone.
    """
    if type(boot) is not MzStaticBoot8616:
        raise TypeError("real16 static boot recomputation requires a static input")
    declared = (
        boot.image.code_ranges
        if boot.image.code_scope == "declared"
        else ()
    )
    return mz_static_boot_8616(
        boot.source, boot.image.load_segment, code_ranges=declared
    )
