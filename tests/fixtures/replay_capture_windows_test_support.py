"""Layer: test support.
Responsibility: own replay capture windows fixture contracts and evidence.
"""
from __future__ import annotations

from collections.abc import Callable

from tests.fixtures.replay_capture_contracts_test_support import (
    CaptureWindow,
    DeclaredExtent,
    WindowAdmissionKind,
    WindowCheck,
    WindowEvidence,
    extent_provenance,
)

from tools.dosunit.runtime.flat32_replay_model import (
    Flat32CaptureResult,
    MemoryObservation,
    ObservationStatus,
)
from tools.dosunit.runtime.real16_replay_model import (
    Real16CaptureObservation,
    Real16CaptureResult,
)
from tools.dosunit.runtime.replay_capture_model import CaptureObservationStatus


def _finish_check(rows: list[WindowEvidence]) -> WindowCheck:
    """Resolve the declared-order first refusal, if any."""
    for row in rows:
        if row.admission is not WindowAdmissionKind.ADMITTED:
            return WindowCheck(tuple(rows), row.admission, row.detail)
    return WindowCheck(tuple(rows), None)


def _frame_refusal(
    windows: tuple[CaptureWindow, ...],
    resolver: Callable[[CaptureWindow], int],
    detail: str,
) -> WindowCheck:
    """Refuse every declared window when the captured frame disagrees."""
    rows = [
        WindowEvidence(
            spec.name,
            spec.address,
            spec.size,
            resolver(spec),
            spec.role,
            WindowAdmissionKind.FRAME_INCONSISTENT,
            detail=detail,
        )
        for spec in windows
    ]
    return WindowCheck(tuple(rows), WindowAdmissionKind.FRAME_INCONSISTENT, detail)


def _r16_evidence(
    spec: CaptureWindow,
    observation: Real16CaptureObservation | None,
    linear: int,
    extents: tuple[DeclaredExtent, ...],
) -> WindowEvidence:
    """Admit one real16 window only with declared byte-extent provenance."""
    base = {
        "name": spec.name,
        "address": spec.address,
        "size": spec.size,
        "linear": linear,
        "role": spec.role,
    }
    if observation is None:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.MISSING_SNAPSHOT_WINDOW,
            detail="declared window absent from capture observations",
        )
    if observation.linear != linear:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.OBSERVATION_COORDINATE_MISMATCH,
            detail="observation physical address differs from requested window",
        )
    if observation.status is not CaptureObservationStatus.CAPTURED:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.OBSERVATION_UNMAPPED,
            detail=f"observation status {observation.status.value}",
        )
    if len(observation.data) != observation.size:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.MISSING_SNAPSHOT_WINDOW,
            detail="observation returned fewer bytes than the declared window",
        )
    provenance = extent_provenance(extents, observation.linear, observation.size)
    if provenance is None:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.PADDING_ONLY_PROVENANCE,
            detail="captured bytes have no declared image, region or stack extent",
        )
    return WindowEvidence(
        **base,
        admission=WindowAdmissionKind.ADMITTED,
        provenance=provenance,
        data=observation.data,
    )


def real16_window_check(
    capture: Real16CaptureResult,
    extents: tuple[DeclaredExtent, ...],
    windows: tuple[CaptureWindow, ...],
    *,
    stack_segment: int,
    declared_sp: int | None,
    stack_only: bool = False,
) -> WindowCheck:
    """Admit declared real16 capture windows with byte-exact provenance.

    ``stack_only`` refuses explicit non-SS windows for the SS-only emitter.
    ``declared_sp`` binds the expected callee-entry SP; when it is ``None``
    the frame-consistency check is skipped for windows that do not describe
    a stack frame (unit controls only). A capture whose SS:SP disagrees
    with the declared caller frame refuses every stack window instead of
    guessing a different frame from post-capture registers.
    """
    if declared_sp is not None:
        registers = dict(capture.registers)
        captured_sp = registers.get("sp")
        captured_ss = registers.get("ss")
        if captured_sp != declared_sp - 2 or captured_ss != stack_segment:
            detail = (
                f"captured ss:sp {captured_ss!r}:{captured_sp!r} does not match "
                f"the declared frame {stack_segment:#06x}:{declared_sp - 2:#06x}"
            )
            return _frame_refusal(
                windows,
                lambda spec: (spec.segment if spec.segment is not None else stack_segment) * 16
                + spec.address,
                detail,
            )
    observed = {
        (obs.request.segment, obs.request.offset, obs.size): obs
        for obs in capture.observations
    }
    rows: list[WindowEvidence] = []
    for spec in windows:
        segment = spec.segment if spec.segment is not None else stack_segment
        if stack_only and segment != stack_segment:
            rows.append(WindowEvidence(
                spec.name, spec.address, spec.size, segment * 16 + spec.address,
                spec.role, WindowAdmissionKind.NON_STACK_SEGMENT,
                detail="SS-only fixture cannot emit a different segment's bytes",
            ))
            continue
        observation = observed.get((segment, spec.address, spec.size))
        rows.append(_r16_evidence(spec, observation, segment * 16 + spec.address, extents))
    return _finish_check(rows)


def _f32_evidence(
    spec: CaptureWindow,
    observation: MemoryObservation | None,
    extents: tuple[DeclaredExtent, ...],
) -> WindowEvidence:
    """Admit one flat32 window only with declared byte-extent provenance."""
    base = {
        "name": spec.name,
        "address": spec.address,
        "size": spec.size,
        "linear": spec.address,
        "role": spec.role,
    }
    if observation is None:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.MISSING_SNAPSHOT_WINDOW,
            detail="declared window absent from capture observations",
        )
    origins = tuple(sorted({origin.value for origin in observation.origins}))
    if observation.status is not ObservationStatus.CAPTURED:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.OBSERVATION_UNMAPPED,
            origins=origins,
            detail=f"observation status {observation.status.value}",
        )
    if len(observation.data) != observation.size:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.MISSING_SNAPSHOT_WINDOW,
            origins=origins,
            detail="observation returned fewer bytes than the declared window",
        )
    provenance = extent_provenance(extents, observation.address, observation.size)
    if provenance is None:
        return WindowEvidence(
            **base,
            admission=WindowAdmissionKind.PADDING_ONLY_PROVENANCE,
            origins=origins,
            detail="page-grant coverage only; no declared byte extent backs these bytes",
        )
    return WindowEvidence(
        **base,
        admission=WindowAdmissionKind.ADMITTED,
        provenance=provenance,
        origins=origins,
        data=observation.data,
    )


def flat32_window_check(
    capture: Flat32CaptureResult,
    extents: tuple[DeclaredExtent, ...],
    windows: tuple[CaptureWindow, ...],
    *,
    declared_esp: int | None,
) -> WindowCheck:
    """Admit declared flat32 capture windows with byte-exact provenance.

    ``declared_esp`` binds the expected callee-entry ESP (a near32 call
    pushes four bytes); ``None`` skips the frame-consistency check for
    non-frame windows (unit controls only). Page-grant origins are recorded
    as corroborating evidence and are never accepted as byte-extent proof.
    """
    if declared_esp is not None:
        captured_esp = dict(capture.registers).get("esp")
        if captured_esp != declared_esp - 4:
            detail = (
                f"captured esp {captured_esp!r} does not match the declared "
                f"frame esp {declared_esp - 4:#x}"
            )
            return _frame_refusal(windows, lambda spec: spec.address, detail)
    observed = {(obs.address, obs.size): obs for obs in capture.observations}
    rows = [
        _f32_evidence(spec, observed.get((spec.address, spec.size)), extents)
        for spec in windows
    ]
    return _finish_check(rows)
