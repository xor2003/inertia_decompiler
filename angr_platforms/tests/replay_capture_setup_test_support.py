"""Layer: test support.
Responsibility: own replay capture setup fixture contracts and evidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from replay_capture_contracts_test_support import (
    CaptureWindow,
    DeclaredExtent,
    WindowRole,
    flat32_declared_extents,
    real16_declared_extents,
)
from replay_capture_fixture_test_support import (
    F32_CALLEE,
    F32_ESP,
    F32_TEXT,
    INSTRUCTION_LIMIT,
    R16_CALLEE,
    R16_LOAD,
    R16_SP,
    R16_SS,
    R16_TRAP_OFF,
    TRACE_CAP,
    flat32_code_bytes,
    flat32_data_bytes,
    flat32_pe_image,
    real16_image_bytes,
    real16_load_image,
)

from tools.dosunit.flat32_replay_model import (
    Flat32CaptureResult,
    ReplayImage,
    ReplayVector,
)
from tools.dosunit.real16_replay_model import (
    Real16CaptureResult,
    Real16Image,
    Real16Vector,
    SegOffset,
)

R16_CAPTURE_WINDOWS: tuple[CaptureWindow, ...] = (
    CaptureWindow("below", R16_SP - 2 - 16, 16, WindowRole.BELOW),
    CaptureWindow("return_slot", R16_SP - 2, 2, WindowRole.RETURN_SLOT),
    CaptureWindow("above", R16_SP, 32, WindowRole.ABOVE),
)


F32_CAPTURE_WINDOWS: tuple[CaptureWindow, ...] = (
    CaptureWindow("below", F32_ESP - 4 - 16, 16, WindowRole.BELOW),
    CaptureWindow("return_slot", F32_ESP - 4, 4, WindowRole.RETURN_SLOT),
    CaptureWindow("above", F32_ESP, 4, WindowRole.ABOVE),
)


@dataclass(frozen=True, slots=True)
class Real16CaptureFixture:
    """The declared real16 capture contract plus its provenance extents."""

    image: Real16Image
    entry: SegOffset
    vector: Real16Vector
    boundary: SegOffset
    extents: tuple[DeclaredExtent, ...]


@dataclass(frozen=True, slots=True)
class Flat32CaptureFixture:
    """The declared flat32 capture contract plus its provenance extents."""

    image: ReplayImage
    entry: int
    vector: ReplayVector
    boundary: int
    extents: tuple[DeclaredExtent, ...]


def real16_capture_vector() -> Real16Vector:
    """The real16 caller contract with the bounded windows declared upfront."""
    from tools.dosunit.real16_replay_model import (
        CallerFrame,
        FrameKind,
        Real16Vector,
        SegOffset,
    )

    return Real16Vector(
        registers=(("flags", 0x0002), ("sp", R16_SP)),
        segments=(("ds", R16_LOAD), ("es", R16_LOAD), ("ss", R16_SS)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(R16_LOAD, R16_TRAP_OFF)),
        observations=tuple(
            (SegOffset(R16_SS, spec.address), spec.size)
            for spec in R16_CAPTURE_WINDOWS
        ),
    )


def flat32_capture_vector() -> ReplayVector:
    """The flat32 caller contract with the bounded windows declared upfront."""
    from tools.dosunit.flat32_replay_model import MemoryRange, ReplayVector

    return ReplayVector(
        (("esp", F32_ESP),),
        observations=tuple(
            MemoryRange(spec.address, spec.size) for spec in F32_CAPTURE_WINDOWS
        ),
    )


def real16_capture_fixture(image: Real16Image | None = None) -> Real16CaptureFixture:
    """Assemble the real16 capture fixture: image, contract and extents."""
    from tools.dosunit.real16_replay_model import SegOffset

    resolved = image if image is not None else real16_load_image(real16_image_bytes(mutated=False))
    vector = real16_capture_vector()
    return Real16CaptureFixture(
        image=resolved,
        entry=SegOffset(R16_LOAD, 0),
        vector=vector,
        boundary=SegOffset(R16_LOAD, R16_CALLEE),
        extents=real16_declared_extents(resolved, vector),
    )


def flat32_capture_fixture(image: ReplayImage | None = None) -> Flat32CaptureFixture:
    """Assemble the flat32 capture fixture: image, contract and extents."""
    resolved = image if image is not None else flat32_pe_image(
        flat32_code_bytes(mutated=False), flat32_data_bytes()
    )
    vector = flat32_capture_vector()
    return Flat32CaptureFixture(
        image=resolved,
        entry=F32_TEXT,
        vector=vector,
        boundary=F32_CALLEE,
        extents=flat32_declared_extents(resolved, vector),
    )


def capture_real16(
    image: Real16Image, entry: SegOffset, boundary: SegOffset, vector: Real16Vector
) -> Real16CaptureResult:
    """Snapshot real segmented state at ``boundary`` via the real API."""
    from tools.dosunit.real16_replay import capture

    return capture(
        image, entry, vector, boundary,
        instruction_limit=INSTRUCTION_LIMIT, trace_limit=TRACE_CAP,
    )


def capture_flat32(
    image: ReplayImage, entry: int, boundary: int, vector: ReplayVector
) -> Flat32CaptureResult:
    """Snapshot flat i386 state at ``boundary`` via the real API."""
    from tools.dosunit.flat32_replay import capture

    return capture(
        image, entry, vector, boundary,
        instruction_limit=INSTRUCTION_LIMIT, trace_limit=TRACE_CAP,
    )
