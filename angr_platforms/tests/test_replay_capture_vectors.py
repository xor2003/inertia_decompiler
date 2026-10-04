"""Focused controls for the staged M6 replay-vector rewire.

Layer: tests.
Responsibility: prove the runtime vectors come from the production guarded
capture APIs (replay's own guarded loop, never a
second emulator), that declared-window admission keeps byte-extent
provenance, that padding-only, missing and unmapped observations refuse
explicitly, that a CPUID caller prefix refuses through both architectures'
real capture APIs, and that the cohort stays deterministic with complete
typed accounting. No proof status is claimed anywhere; agreement is
execution evidence only.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest
import replay_capture_test_support as conv
import replay_capture_test_support as m6


def test_capture_uses_current_production_modules() -> None:
    """Fixture capture delegates to production APIs without copied overlays."""
    import tools.dosunit.flat32_replay as flat32_replay
    import tools.dosunit.real16_replay as real16_replay
    repository = Path.cwd().resolve()
    for module in (real16_replay, flat32_replay):
        assert Path(module.__file__).resolve().parent == repository / "tools/dosunit"



def test_fixture_mutation_is_exactly_one_opcode_byte() -> None:
    """Both fixtures mutate exactly the loop-body add opcode byte."""
    original = m6.real16_image_bytes(mutated=False)
    mutant = m6.real16_image_bytes(mutated=True)
    diffs = [i for i, pair in enumerate(zip(original, mutant, strict=True)) if pair[0] != pair[1]]
    assert diffs == [m6._R16_MUT_OFFSET]
    assert original[m6._R16_MUT_OFFSET] == 0x03 and mutant[m6._R16_MUT_OFFSET] == 0x2B
    f32_orig, f32_mut = m6.flat32_code_bytes(mutated=False), m6.flat32_code_bytes(mutated=True)
    f32_diffs = [i for i, pair in enumerate(zip(f32_orig, f32_mut, strict=True)) if pair[0] != pair[1]]
    assert f32_diffs == [m6._F32_MUT_OFFSET]


def test_real16_capture_is_actual_executed_state() -> None:
    """The runtime vector's registers must come from executing the caller."""
    fixture = m6.real16_capture_fixture()
    capture = m6.capture_real16(fixture.image, fixture.entry, fixture.boundary, fixture.vector)
    assert capture.status is m6.CaptureStatus.CAPTURED
    assert capture.execution_status is None  # capture-local stop, no replay outcome
    regs = dict(capture.registers)
    assert regs["bx"] == m6.R16_ARRAY and regs["cx"] == 4
    assert regs["sp"] == m6.R16_SP - 2  # the call pushed its return address
    assert capture.fetch_trace[-1] == m6.R16_LOAD * 16 + m6.R16_CALLEE
    assert capture.fetch_trace[-2] == m6.R16_LOAD * 16 + 0x06  # the call site
    assert capture.trap_linear == m6.R16_LOAD * 16 + m6.R16_TRAP_OFF
    observations = {
        (obs.request.segment, obs.request.offset): obs for obs in capture.observations
    }
    slot = observations[(m6.R16_SS, m6.R16_SP - 2)]
    assert int.from_bytes(slot.data, "little") == 0x0009  # real return address


def test_unreached_capture_boundary_is_typed_not_fabricated() -> None:
    """Unreached and out-of-scope boundaries stay typed non-results."""
    from tools.dosunit.real16_replay_model import SegOffset

    fixture = m6.real16_capture_fixture()
    unreached = m6.capture_real16(
        fixture.image, fixture.entry,
        SegOffset(m6.R16_LOAD, m6.R16_SPIN), fixture.vector,
    )
    assert unreached.status is m6.CaptureStatus.RETURNED_BEFORE_BOUNDARY
    assert unreached.execution_status is not None
    assert unreached.execution_status.value == "returned"
    invalid = m6.capture_real16(
        fixture.image, fixture.entry,
        SegOffset(m6.R16_LOAD, 0x6000), fixture.vector,
    )
    assert invalid.status is m6.CaptureStatus.BOUNDARY_INVALID
    rng = random.Random(int(m6.SEED, 16))
    vectors, provenance = m6.emit_real16(unreached, fixture.extents, rng)
    assert all(v["id"] != "r16-rt-00" for v in vectors)
    refusal = provenance["r16-rt-00"]["refusal"]
    assert refusal["status"] == "returned_before_boundary"
    assert refusal["execution_status"] == "returned"


def test_cpuid_prefix_refuses_through_real_capture_apis() -> None:
    """A CPUID caller prefix must refuse on both tracks via the real API."""
    image16 = bytearray(m6.real16_image_bytes(mutated=False))
    image16[0:2] = b"\x0f\xa2"  # cpuid as the first executed prefix instruction
    fixture16 = m6.real16_capture_fixture(image=m6.real16_load_image(bytes(image16)))
    result16 = m6.capture_real16(
        fixture16.image, fixture16.entry, fixture16.boundary, fixture16.vector
    )
    assert result16.status is m6.CaptureStatus.EXECUTION_REFUSED
    assert result16.execution_status is not None
    assert result16.execution_status.value == "unsupported"
    assert result16.detail == "undeclared_machine_input"

    code = bytearray(m6.flat32_code_bytes(mutated=False))
    code[0:2] = b"\x0f\xa2"
    fixture32 = m6.flat32_capture_fixture(
        image=m6.flat32_pe_image(bytes(code), m6.flat32_data_bytes())
    )
    result32 = m6.capture_flat32(
        fixture32.image, fixture32.entry, fixture32.boundary, fixture32.vector
    )
    assert result32.status is m6.CaptureStatus.EXECUTION_REFUSED
    assert result32.execution_status is not None
    assert result32.execution_status.value == "unsupported"
    assert result32.detail == "undeclared_machine_input"


def test_padding_only_observation_origin_is_rejected() -> None:
    """Page-grant coverage without byte-extent provenance refuses admission.

    Mirrors the reviewed limit: a VECTOR declaration of [0x30000,0x30004)
    grants the whole page, so an observation of [0x30010,0x30014) captures
    zeros with VECTOR origin — configured mapped memory, not declared bytes.
    """
    from tools.dosunit.flat32_memory_permissions import (
        DeclaredAccess,
        DeclaredRegion,
        MappingOrigin,
    )
    from tools.dosunit.flat32_replay_model import MemoryRange, ReplayVector

    fixture = m6.flat32_capture_fixture()
    probe = ReplayVector(
        (("esp", m6.F32_ESP),),
        observations=(MemoryRange(0x30010, 4),),
        mappings=(
            DeclaredRegion(0x30000, 4, DeclaredAccess.READ | DeclaredAccess.WRITE,
                           MappingOrigin.VECTOR),
        ),
    )
    result = m6.capture_flat32(fixture.image, fixture.entry, fixture.boundary, probe)
    assert result.status is m6.CaptureStatus.CAPTURED
    observation = result.observations[0]
    assert observation.status.value == "captured"
    assert observation.origins == (MappingOrigin.VECTOR,)
    extents = m6.flat32_declared_extents(fixture.image, probe)
    windows = (conv.CaptureWindow("probe", 0x30010, 4, conv.WindowRole.ABOVE),)
    check = conv.flat32_window_check(result, extents, windows, declared_esp=m6.F32_ESP)
    assert check.refusal is conv.WindowAdmissionKind.PADDING_ONLY_PROVENANCE
    assert check.windows[0].origins == ("vector",)
    rng = random.Random(int(m6.SEED, 16) + 1)
    vectors, provenance = m6.emit_flat32(result, extents, rng, windows=windows)
    assert all(v["id"] != "f32-rt-00" for v in vectors)
    refusal = provenance["f32-rt-00"]["refusal"]
    assert refusal["status"] == "captured"
    assert refusal["window_refusal"] == "padding_only_provenance"


def test_missing_or_unmapped_window_is_rejected() -> None:
    """Absent echo and unmapped observations are typed refusals."""
    from tools.dosunit.flat32_replay_model import MemoryRange, ReplayVector
    from tools.dosunit.real16_replay_model import Real16CaptureResult

    fixture16 = m6.real16_capture_fixture()
    capture = m6.capture_real16(
        fixture16.image, fixture16.entry, fixture16.boundary, fixture16.vector
    )
    assert capture.status is m6.CaptureStatus.CAPTURED
    # Dropping one echoed observation must refuse, not fabricate the window.
    shortened = Real16CaptureResult(
        capture.status, capture.entry, capture.boundary, capture.execution_status,
        capture.registers, capture.observations[:2], capture.writes, capture.events,
        capture.instructions, capture.fetch_trace, capture.trap_linear,
        capture.detail, capture.flags_mask,
    )
    check = m6.real16_window_check(
        shortened, fixture16.extents, m6.R16_CAPTURE_WINDOWS,
        stack_segment=m6.R16_SS, declared_sp=m6.R16_SP,
    )
    assert check.refusal is conv.WindowAdmissionKind.MISSING_SNAPSHOT_WINDOW
    rng = random.Random(int(m6.SEED, 16))
    vectors, provenance = m6.emit_real16(shortened, fixture16.extents, rng)
    assert all(v["id"] != "r16-rt-00" for v in vectors)
    assert provenance["r16-rt-00"]["refusal"]["window_refusal"] == "missing_snapshot_window"

    # A real-API unmapped observation stays a typed non-result.
    fixture32 = m6.flat32_capture_fixture()
    probe = ReplayVector(
        (("esp", m6.F32_ESP),),
        observations=(MemoryRange(0x800000, 4),),
    )
    result = m6.capture_flat32(fixture32.image, fixture32.entry, fixture32.boundary, probe)
    assert result.status is m6.CaptureStatus.CAPTURED
    assert result.observations[0].status.value == "unmapped"
    windows = (conv.CaptureWindow("probe", 0x800000, 4, conv.WindowRole.ABOVE),)
    check32 = conv.flat32_window_check(
        result, m6.flat32_declared_extents(fixture32.image, probe),
        windows, declared_esp=m6.F32_ESP,
    )
    assert check32.refusal is conv.WindowAdmissionKind.OBSERVATION_UNMAPPED


def test_real16_padding_only_origin_is_rejected() -> None:
    """A forged observation outside every declared extent refuses (real16)."""
    from tools.dosunit.real16_replay_model import (
        Real16CaptureObservation,
        Real16CaptureResult,
        SegOffset,
    )
    from tools.dosunit.replay_capture_model import CaptureObservationStatus

    fixture = m6.real16_capture_fixture()
    capture = m6.capture_real16(
        fixture.image, fixture.entry, fixture.boundary, fixture.vector
    )
    assert capture.status is m6.CaptureStatus.CAPTURED
    bogus = Real16CaptureObservation(
        SegOffset(0x9000, 0x10), 4, 0x90010,
        CaptureObservationStatus.CAPTURED, b"\x00" * 4,
    )
    padded = Real16CaptureResult(
        capture.status, capture.entry, capture.boundary, capture.execution_status,
        capture.registers, (*capture.observations, bogus), capture.writes,
        capture.events, capture.instructions, capture.fetch_trace,
        capture.trap_linear, capture.detail, capture.flags_mask,
    )
    windows = (conv.CaptureWindow("probe", 0x10, 4, conv.WindowRole.BELOW, segment=0x9000),)
    check = m6.real16_window_check(
        padded, fixture.extents, windows, stack_segment=0x9000, declared_sp=None,
    )
    assert check.refusal is conv.WindowAdmissionKind.PADDING_ONLY_PROVENANCE


def test_emission_is_deterministic_under_fixed_seed() -> None:
    """Same seed produces identical cohorts; sentinel stays a declared input."""
    fixture = m6.real16_capture_fixture()
    capture = m6.capture_real16(
        fixture.image, fixture.entry, fixture.boundary, fixture.vector
    )
    first, _ = m6.emit_real16(capture, fixture.extents, random.Random(int(m6.SEED, 16)))
    second, _ = m6.emit_real16(capture, fixture.extents, random.Random(int(m6.SEED, 16)))
    assert first == second
    assert [v["id"] for v in first] == [v["id"] for v in second]
    sentinel_rows = [v for v in first if v["id"] != "r16-edge-cpuid"]
    assert all(v["registers"]["dx"] != "0xdead" for v in sentinel_rows)










@pytest.mark.parametrize("architecture", ["real16", "flat32"])
def test_inconsistent_capture_frame_refuses_emission(architecture: str) -> None:
    """Forged captured stack coordinates cannot seed a reusable runtime vector."""
    from dataclasses import replace

    if architecture == "real16":
        fixture = m6.real16_capture_fixture()
        captured = m6.capture_real16(fixture.image, fixture.entry, fixture.boundary, fixture.vector)
        registers = tuple((name, value + 2 if name == "sp" else value)
                          for name, value in captured.registers)
        forged = replace(captured, registers=registers)
        check = m6.real16_window_check(forged, fixture.extents, m6.R16_CAPTURE_WINDOWS,
                                      stack_segment=m6.R16_SS, declared_sp=m6.R16_SP)
        vectors, provenance = m6.emit_real16(forged, fixture.extents, random.Random(int(m6.SEED, 16)))
        runtime_id = "r16-rt-00"
    else:
        fixture = m6.flat32_capture_fixture()
        captured = m6.capture_flat32(fixture.image, fixture.entry, fixture.boundary, fixture.vector)
        registers = tuple((name, value + 4 if name == "esp" else value)
                          for name, value in captured.registers)
        forged = replace(captured, registers=registers)
        check = m6.flat32_window_check(forged, fixture.extents, m6.F32_CAPTURE_WINDOWS,
                                      declared_esp=m6.F32_ESP)
        vectors, provenance = m6.emit_flat32(forged, fixture.extents, random.Random(int(m6.SEED, 16)))
        runtime_id = "f32-rt-00"
    assert check.refusal is conv.WindowAdmissionKind.FRAME_INCONSISTENT
    assert all(vector["id"] != runtime_id for vector in vectors)
    assert provenance[runtime_id]["refusal"]["window_refusal"] == "frame_inconsistent"


def test_real16_observation_coordinates_must_match_requested_window() -> None:
    """A different valid extent cannot lend provenance to requested coordinates."""
    from dataclasses import replace

    fixture = m6.real16_capture_fixture()
    captured = m6.capture_real16(fixture.image, fixture.entry, fixture.boundary, fixture.vector)
    original = captured.observations[0]
    # Both coordinates lie inside declared SS memory; only exact binding can
    # reject this. Changing request would merely exercise missing-window refusal.
    redirected = replace(original, linear=original.linear + 0x100, data=b"\xa5" * original.size)
    forged = replace(captured, observations=(redirected, *captured.observations[1:]))
    check = m6.real16_window_check(forged, fixture.extents, m6.R16_CAPTURE_WINDOWS,
                                  stack_segment=m6.R16_SS, declared_sp=m6.R16_SP)
    assert check.refusal is not None, check
    vectors, provenance = m6.emit_real16(forged, fixture.extents, random.Random(int(m6.SEED, 16)))
    assert all(vector["id"] != "r16-rt-00" for vector in vectors)
    assert provenance["r16-rt-00"]["refusal"]["window_refusal"] == "observation_coordinate_mismatch"


def test_real16_emission_refuses_non_stack_segment_window() -> None:
    """This SS-only fixture must not reseed a valid DS observation under SS."""
    from dataclasses import replace

    from tools.dosunit.real16_replay_model import SegOffset

    fixture = m6.real16_capture_fixture()
    vector = replace(fixture.vector, observations=((SegOffset(m6.R16_LOAD, m6.R16_ARRAY), 2),))
    captured = m6.capture_real16(fixture.image, fixture.entry, fixture.boundary, vector)
    assert captured.observations[0].data == b"\x05\x00"
    windows = (conv.CaptureWindow("data", m6.R16_ARRAY, 2, conv.WindowRole.BELOW, segment=m6.R16_LOAD),)
    vectors, provenance = m6.emit_real16(captured, fixture.extents, random.Random(int(m6.SEED, 16)), windows=windows)
    assert all(row["id"] != "r16-rt-00" for row in vectors)
    assert provenance["r16-rt-00"]["refusal"]["window_refusal"] == "non_stack_segment"
