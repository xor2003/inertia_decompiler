"""Layer: test support.
Responsibility: own replay capture contracts fixture contracts and evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.runtime.flat32_memory_permissions import PAGE_SIZE
from tools.dosunit.runtime.flat32_replay_model import (
    RETURN_TRAP,
    ReplayImage,
    ReplayVector,
)
from tools.dosunit.runtime.real16_replay_model import (
    VECTOR_SEGMENTS,
    Real16Image,
    Real16Vector,
    SegOffset,
)


class WindowRole(StrEnum):
    """How an admitted capture window feeds the emitted runtime vector."""

    BELOW = "below"
    """Caller stack bytes below the pushed return slot; emitted as a patch."""
    RETURN_SLOT = "return_slot"
    """The pushed return address; the replay frame owns it, so it is
    disclosed through ``replaced_cells`` and never re-seeded."""
    ABOVE = "above"
    """Caller bytes above the pushed slot; emitted as a patch and, on
    flat32, an explicit VECTOR scratch mapping above the harness stack."""


class WindowAdmissionKind(StrEnum):
    """Typed outcome of admitting one declared capture window."""

    ADMITTED = "admitted"
    """Observed bytes carry declared byte-extent provenance."""
    MISSING_SNAPSHOT_WINDOW = "missing_snapshot_window"
    """The declared window was not echoed by the capture result or
    returned no usable bytes; nothing may be fabricated in its place."""
    OBSERVATION_UNMAPPED = "observation_unmapped"
    """The observation itself is a typed non-result (no mapped bytes)."""
    PADDING_ONLY_PROVENANCE = "padding_only_provenance"
    """Captured bytes sit outside every declared byte extent; only page
    rounding mapped them, so they are padding, not reusable state."""
    OBSERVATION_COORDINATE_MISMATCH = "observation_coordinate_mismatch"
    """Echoed physical coordinates differ from the requested byte window."""
    NON_STACK_SEGMENT = "non_stack_segment"
    """This fixture only emits captured SS-relative windows."""
    FRAME_INCONSISTENT = "frame_inconsistent"
    """Captured stack registers do not match the declared caller frame;
    the declared windows describe a different frame than the one run."""


@dataclass(frozen=True, slots=True)
class CaptureWindow:
    """One upfront-declared bounded observation window and its role.

    ``address`` is a 16-bit segment offset for real16 windows (paired with
    ``segment``, or the check's declared stack segment when ``segment`` is
    ``None``) and a flat linear address for flat32 windows.
    """

    name: str
    address: int
    size: int
    role: WindowRole
    segment: int | None = None


@dataclass(frozen=True, slots=True)
class DeclaredExtent:
    """One byte-exact declared provenance extent in linear addresses.

    ``kind`` labels where the declaration came from (``image``, ``bss``,
    ``patch``, ``caller_frame``, ``return_trap``, ``declared_segment``,
    ``file_region``, ``vector_scratch`` or ``stack_frame``); ``address`` and
    ``size`` are the exact declared bytes, never a rounded page.
    """

    kind: str
    address: int
    size: int


@dataclass(frozen=True, slots=True)
class WindowEvidence:
    """Admission record for one declared capture window.

    ``address`` echoes the declared spec coordinate, ``linear`` the
    resolved physical address the extent check ran on, ``origins`` the
    page-grant origin evidence the capture API reported (flat32 only;
    recorded as corroboration, never accepted as byte-extent proof), and
    ``data`` the captured bytes when admitted.
    """

    name: str
    address: int
    size: int
    linear: int
    role: WindowRole
    admission: WindowAdmissionKind
    provenance: str = ""
    origins: tuple[str, ...] = ()
    data: bytes = b""
    detail: str = ""


@dataclass(frozen=True, slots=True)
class WindowCheck:
    """Admission outcome for the whole declared window set.

    ``refusal`` is ``None`` when every window admitted; otherwise it is the
    first typed failure in declared order and ``detail`` explains it.
    """

    windows: tuple[WindowEvidence, ...]
    refusal: WindowAdmissionKind | None
    detail: str = ""


def extent_provenance(
    extents: tuple[DeclaredExtent, ...], address: int, size: int
) -> str | None:
    """Kind label when one declared extent fully covers the byte range.

    A single extent must cover the entire range; stitching coverage across
    distinct declarations is not admitted, so a padding tail can never ride
    a neighbour's provenance. Returns ``None`` for padding-only ranges.
    """
    for extent in extents:
        if extent.address <= address and address + size <= extent.address + extent.size:
            return extent.kind
    return None


def real16_declared_extents(
    image: Real16Image, vector: Real16Vector
) -> tuple[DeclaredExtent, ...]:
    """Byte-exact declared extents for one real16 capture contract.

    Mirrors the guest's declared memory model: loaded image chunks and BSS,
    declared memory patches, the caller-frame slot, the return trap, and
    every declared segment's addressable band (the real16 stack-frame
    extent). More specific declarations precede segment bands so overlapped
    ranges report their tighter provenance.
    """
    extents: list[DeclaredExtent] = [
        *(DeclaredExtent("image", address, len(data)) for address, data in image.chunks),
        *(
            DeclaredExtent("patch", patch.linear(), len(data))
            for patch, data in vector.memory
        ),
    ]
    if image.bss_size:
        extents.append(
            DeclaredExtent("bss", image.chunks[0][0] + image.image_size, image.bss_size)
        )
    segments = dict(vector.segments)
    frame_base = SegOffset(segments.get("ss", 0), dict(vector.registers)["sp"]).linear()
    extents.append(DeclaredExtent("caller_frame", frame_base, len(vector.frame.push_bytes())))
    extents.append(DeclaredExtent("return_trap", vector.frame.target.linear(), 1))
    bases = {patch.segment for patch, _ in vector.memory}
    bases.update(observation.segment for observation, _ in vector.observations)
    bases.update(segments.get(name, 0) for name in VECTOR_SEGMENTS)
    for base in sorted(bases):
        extents.append(DeclaredExtent("declared_segment", base * 16, 0x10000))
    return tuple(extents)


def flat32_declared_extents(
    image: ReplayImage, vector: ReplayVector
) -> tuple[DeclaredExtent, ...]:
    """Byte-exact declared extents for one flat32 capture contract.

    Mirrors the guest's declared memory model: loaded image chunks, the
    file's declared permission regions, declared byte patches, declared
    VECTOR scratch regions, the harness stack window below declared ESP
    plus its pushed trap dword, and the return-trap byte. Page grants are
    deliberately absent: they are rounded mappings, not declared bytes.
    """
    extents: list[DeclaredExtent] = [
        *(DeclaredExtent("image", address, len(data)) for address, data in image.chunks),
        *(
            DeclaredExtent("file_region", region.address, region.size)
            for region in image.declared
        ),
        *(
            DeclaredExtent("patch", address, len(data))
            for address, data in vector.memory
        ),
        *(
            DeclaredExtent("vector_scratch", region.address, region.size)
            for region in vector.mappings
        ),
    ]
    esp = dict(vector.registers)["esp"]
    extents.append(DeclaredExtent("stack_frame", esp - PAGE_SIZE, PAGE_SIZE + 4))
    extents.append(DeclaredExtent("return_trap", RETURN_TRAP, 1))
    return tuple(extents)
