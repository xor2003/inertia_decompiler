"""Focused M5 returning-service tests: declared DOS/BIOS queries in symbolic traces.

Layer: Tests.
Responsibility: prove the bounded symbolic terminal comparator admits the
declared ``INT 21h/AH=30h AL=00`` version query and ``INT 10h/AH=0Fh`` video
query as returning services — ordered observable events, exact fallthrough
continuation, live IVT authentication, low-half register effects and complete
preservation — while unsupported selectors, missing policies, redirected or
program-owned vectors and divergent event histories refuse or counterexample.
Every case builds actual MZ bytes; no service is emulated — a declared policy
is a visible environment premise, never real DOS/BIOS proof.

These cases run actual native lifting and the public symbolic trace verifier.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

import tools.dosunit.compare.symbolic_terminal as ST
from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment
from tools.dosunit.runtime.real16_program_memory import InitialMemoryRegion
from tools.dosunit.runtime.real16_program_model import ProgramEventKind
from tools.dosunit.runtime.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.runtime.real16_program_version import VersionPolicy, version_event_data
from tools.dosunit.runtime.real16_program_video import (
    VideoQueryPolicy,
    video_query_event_data,
)
from tools.dosunit.runtime.real16_replay_model import SegOffset

VERSION_POLICY = VersionPolicy(3, 30, 0x42, 0x123456)
VIDEO_ENTRY = SegOffset(0xF000, 0x0000)
DOS_ENTRY = SegOffset(0xF000, 0x0100)
VIDEO_POLICY = VideoQueryPolicy(mode=3, columns=80, page=2, entry=VIDEO_ENTRY)

# mov ax,0x3000 ; int 21h ; mov ax,0x4C00 ; int 21h
QUERY_THEN_EXIT = bytes.fromhex("b80030cd21b8004ccd21")
# mov ax,0x0F00 ; int 10h ; mov ax,0x4C00 ; int 21h
VIDEO_THEN_EXIT = bytes.fromhex("b8000fcd10b8004ccd21")
TERMINATE = bytes.fromhex("b8004ccd21")


def mz(code: bytes, *, entry_ip: int = 0, stack_sp: int = 0x1000) -> bytes:
    """Build a real MZ executable whose load module is exactly ``code``."""
    header = bytearray(64)
    size = len(header) + len(code)
    header[:2] = b"MZ"
    for offset, value in ((2, size % 512), (4, (size + 511) // 512), (8, 4),
                          (12, 0x400), (16, stack_sp), (20, entry_ip), (24, 0x1C)):
        header[offset:offset + 2] = value.to_bytes(2, "little")
    return bytes(header) + code


def dos_environment() -> ProgramEnvironment:
    """The declared DOS arena and register file used by every real16 lane."""
    arena = bytearray(b"\xA5" * 0x2000)
    arena[:2] = b"\xCD\x20"
    arena[2:4] = (0x1200).to_bytes(2, "little")
    arena[0x200] = 3
    values = tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
    return ProgramEnvironment(0x1000, bytes(arena), (*values, ("eflags", 2)), 0, 0)


def version_environment(*, vector: bool = True) -> ProgramEnvironment:
    """Declared arena plus the version policy and an authenticated IVT."""
    env = dos_environment()
    ivt = bytearray(1024)
    ivt[0x84:0x88] = vector_bytes(DOS_ENTRY)
    updates: dict[str, object] = {
        "version_policy": VERSION_POLICY,
        "extra_memory": (InitialMemoryRegion(SegOffset(0, 0), bytes(ivt)),),
    }
    if vector:
        updates["vector_policy"] = VectorPolicy(DOS_ENTRY)
    return replace(env, **updates)


def video_environment() -> ProgramEnvironment:
    """Declared arena with version and video policies over one full IVT image."""
    env = version_environment()
    ivt = bytearray(env.extra_memory[0].data)
    ivt[0x40:0x44] = vector_bytes(VIDEO_ENTRY)
    return replace(
        env,
        extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(ivt)),),
        video_policy=VIDEO_POLICY,
    )


def compare_mz(
    oracle: bytes, candidate: bytes, environment: ProgramEnvironment
) -> ST.TerminalComparison:
    """Compare two real16 programs under one shared declared environment."""
    return ST.compare_symbolic_terminals(
        mz(oracle), environment, mz(candidate), environment
    )


def test_version_query_continues_to_terminal_and_records_event() -> None:
    """The declared query returns, applies its effects and reaches AH=4C."""
    environment = version_environment()
    trace = ST.trace_real16_terminal(mz(QUERY_THEN_EXIT), environment)
    assert trace.site is not None and trace.fault is None
    assert len(trace.blocks) == 2
    assert len(trace.service_events) == 1
    event = trace.service_events[0]
    assert event.kind is ProgramEventKind.DOS_VERSION
    assert event.vector == 0x21 and event.function == 0x30
    assert event.data == version_event_data(VERSION_POLICY)
    # CD 21 sits at code offset 3 (0x1010:0003 linear 0x10103); the receipt's
    # next_target is the exact fallthrough, not the interrupt core.
    assert event.address == 0x10103
    assert trace.blocks[0].next_target == 0x10105


def test_identical_version_programs_proved_equivalent() -> None:
    """Original/original under the declared version environment proves."""
    result = compare_mz(QUERY_THEN_EXIT, QUERY_THEN_EXIT, version_environment())
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_returning_service_report_schema_retains_events() -> None:
    """Public lane projection preserves typed event fields and rejects unknown kinds."""
    from tools.dosunit.reporting.symbolic_terminal_cli import terminal_document

    result = compare_mz(QUERY_THEN_EXIT, QUERY_THEN_EXIT, version_environment())
    report = terminal_document(result)
    schema_path = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas/dosunit.symbolic_terminal_compare.v1.schema.json"
    schema = json.loads(schema_path.read_text())
    lane_schema = {"$defs": schema["$defs"], "$ref": "#/$defs/lane"}
    oracle = report["oracle"]
    assert isinstance(oracle, dict)
    assert oracle["service_events"][0]["kind"] == "dos_version"
    jsonschema.validate(oracle, lane_schema)
    oracle["service_events"][0]["kind"] = "invented_service"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(oracle, lane_schema)


def test_equivalent_register_setup_proved() -> None:
    """Different flag-preserving setup at equal INT offsets proves equivalent."""
    oracle = bytes.fromhex("b8003090cd21b8004ccd21")  # mov ax,3000h; nop
    alternate = bytes.fromhex("b000b430cd21b8004ccd21")  # mov al,0; mov ah,30h
    result = compare_mz(oracle, alternate, version_environment())
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_flag_changing_setup_remains_observable() -> None:
    """Equal AX alone cannot hide changed flags or residual interrupt frames."""
    alternate = bytes.fromhex("33c0b430cd21b8004ccd21")
    result = compare_mz(QUERY_THEN_EXIT, alternate, version_environment())
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "flags" in result.diverged


def test_identical_video_programs_proved_equivalent() -> None:
    """Original/original under the declared video environment proves."""
    result = compare_mz(VIDEO_THEN_EXIT, VIDEO_THEN_EXIT, video_environment())
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_video_query_records_ordered_event() -> None:
    """The declared INT10 receipt is retained before the terminal outcome."""
    environment = video_environment()
    trace = ST.trace_real16_terminal(mz(VIDEO_THEN_EXIT), environment)
    assert trace.site is not None and len(trace.service_events) == 1
    event = trace.service_events[0]
    assert event.kind is ProgramEventKind.BIOS_VIDEO_QUERY
    assert event.vector == 0x10 and event.function == 0x0F
    assert event.data == video_query_event_data(VIDEO_POLICY)


def test_reordered_service_events_counterexample() -> None:
    """Version-then-video versus video-then-version diverges observably."""
    environment = video_environment()
    both_ordered = bytes.fromhex("b80030cd21b8000fcd10b8004ccd21")
    reordered = bytes.fromhex("b8000fcd10b80030cd21b8004ccd21")
    result = compare_mz(both_ordered, reordered, environment)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "service_events" in result.diverged


def test_extra_version_query_counterexample() -> None:
    """An extra declared query cannot disappear from the observables."""
    environment = version_environment()
    repeated = bytes.fromhex("b80030cd21b80030cd21b8004ccd21")
    result = compare_mz(QUERY_THEN_EXIT, repeated, environment)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "service_events" in result.diverged


def test_returned_version_bytes_are_observable() -> None:
    """Storing the answered AX versus CX is a real counterexample."""
    environment = version_environment()
    # mov ax,0x3000 ; int 21h ; mov [0x200],ax ; exit — stores the answer.
    store_ax = bytes.fromhex("b80030cd21a30002b8004ccd21")
    store_cx = bytes.fromhex("b80030cd21890e0002b8004ccd21")
    result = compare_mz(store_ax, store_cx, environment)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE


def test_upper_half_preserved_across_version_query() -> None:
    """EAX's high half must survive the declared query untouched."""
    environment = version_environment()
    # mov eax,0xDEAD3000 ; int 21h ; mov [0x200],eax ; exit.
    # Six NOPs match the length of the candidate's EAX reload, keeping the
    # terminal return IP (an observable residual stack write) identical.
    oracle = bytes.fromhex("66b80030addecd2190909090909066a30002b8004ccd21")
    # Same query, then rebuild eax = 0xDEAD1E03 before the store: equivalent
    # only when the query replaced AX with (minor<<8)|major = 0x1E03 and left
    # the high half 0xDEAD alone.
    rebuilt = bytes.fromhex("66b80030addecd2166b8031eadde66a30002b8004ccd21")
    result = compare_mz(oracle, rebuilt, environment)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_native_transfer_metadata_cannot_hide_service() -> None:
    """Native INT bytes refute a forged Boring receipt and erased event."""
    trace = ST.trace_real16_terminal(mz(QUERY_THEN_EXIT), version_environment())
    assert ST.verify_terminal_trace(trace) is None
    counts = replace(
        trace.counters,
        raw_fact_count=trace.counters.raw_fact_count - 1,
        normalized_fact_count=trace.counters.normalized_fact_count - 1,
        classified_fact_count=trace.counters.classified_fact_count - 1,
        materialized_count=trace.counters.materialized_count - 1,
    )
    forged = replace(
        trace, service_events=(), counters=counts,
        blocks=(replace(trace.blocks[0], jumpkind="Ijk_Boring"), *trace.blocks[1:]),
    )
    refusal = ST.verify_terminal_trace(forged)
    assert refusal is not None and refusal.kind is ST.TerminalRefusalKind.STALE_EVIDENCE


@pytest.mark.parametrize("forge_entry", [False, True])
def test_initial_service_block_cannot_be_removed(forge_entry: bool) -> None:
    """Dropping the entry query cannot replace the source-declared entry."""
    trace = ST.trace_real16_terminal(mz(QUERY_THEN_EXIT), version_environment())
    counts = replace(
        trace.counters,
        raw_fact_count=trace.counters.raw_fact_count - 2,
        normalized_fact_count=trace.counters.normalized_fact_count - 2,
        classified_fact_count=trace.counters.classified_fact_count - 2,
        materialized_count=trace.counters.materialized_count - 1,
    )
    forged = replace(
        trace, service_events=(), counters=counts, blocks=trace.blocks[1:],
        entry=trace.blocks[1].address if forge_entry else trace.entry,
    )
    refusal = ST.verify_terminal_trace(forged)
    assert refusal is not None and refusal.kind is ST.TerminalRefusalKind.STALE_EVIDENCE


def test_wrong_version_selector_refuses() -> None:
    """AH=30h with AL != 00 is an undeclared service, never emulated."""
    environment = version_environment()
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_real16_terminal(mz(bytes.fromhex("b80130cd21")), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_SERVICE


def test_unsupported_dos_selector_refuses() -> None:
    """AH=09h is outside the declared contract even with a version policy."""
    environment = version_environment()
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_real16_terminal(mz(bytes.fromhex("b409cd21")), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_SERVICE


def test_missing_version_policy_refuses() -> None:
    """The same query bytes refuse when the environment declares no policy."""
    environment = version_environment()
    environment = replace(environment, version_policy=None)
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_real16_terminal(mz(QUERY_THEN_EXIT), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_SERVICE


def test_missing_video_policy_refuses() -> None:
    """INT 10h refuses when the environment declares no video policy."""
    environment = video_environment()
    environment = replace(environment, video_policy=None)
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_real16_terminal(mz(VIDEO_THEN_EXIT), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_SERVICE


def test_ivt_coverage_without_policy_refuses() -> None:
    """Declared IVT bytes cannot be silently ignored without a vector policy."""
    environment = version_environment(vector=False)
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_real16_terminal(mz(TERMINATE), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT


def test_redirected_dos_vector_refuses() -> None:
    """Live IVT bytes not matching the declared entry refuse as redirected."""
    environment = version_environment()
    environment = replace(environment, vector_policy=VectorPolicy(SegOffset(0xF000, 0x0200)))
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_real16_terminal(mz(TERMINATE), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT


def test_program_owned_dos_entry_refuses() -> None:
    """A declared entry inside the program arena is not an external service."""
    environment = version_environment()
    environment = replace(environment, vector_policy=VectorPolicy(SegOffset(0x1010, 0)))
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_real16_terminal(mz(TERMINATE), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT


def test_terminal_and_fault_regressions_hold() -> None:
    """A plain AH=4C lane still proves and a divide error still faults."""
    environment = dos_environment()
    result = compare_mz(TERMINATE, TERMINATE, environment)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    # mov cx,0 ; div cx ; exit — the admitted #DE fault outcome.
    faulting = bytes.fromhex("b90000f6f1b8004ccd21")
    trace = ST.trace_real16_terminal(mz(faulting), environment)
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
