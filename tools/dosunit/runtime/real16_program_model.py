"""Shared outcomes and observations for initialized integer programs.

Layer: dosunit concrete execution contracts.
Responsibility: retain process termination, external events and declared output
projections independently of function returns and symbolic proof verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.runtime.real16_program_device_info import device_info_receipt_complete
from tools.dosunit.runtime.real16_program_file_receipts import FilePositions, FileReceipt, file_state_complete
from tools.dosunit.runtime.real16_program_output import OutputAccepted, output_stream_bytes
from tools.dosunit.runtime.real16_program_resize import resize_receipt_complete
from tools.dosunit.runtime.real16_program_vectors import vector_receipt_complete
from tools.dosunit.runtime.real16_program_version import version_receipt_complete
from tools.dosunit.runtime.real16_program_video import video_query_receipt_complete
from tools.dosunit.runtime.real16_program_video_state import video_state_receipt_complete
from tools.dosunit.runtime.real16_replay_model import LinearRange


class ProgramStatus(StrEnum):
    """Observed program outcome; incomplete execution never establishes equality."""

    TERMINATED = "terminated"
    FAULTED = "faulted"
    UNSUPPORTED = "unsupported"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNAVAILABLE = "unavailable"


class ProgramEventKind(StrEnum):
    """Typed service or refusal recorded by the independent executor."""

    DOS_EXIT = "dos_exit"
    PE_EXIT = "pe_exit"
    OUTPUT_WRITE = "output_write"
    DOS_VERSION = "dos_version"
    DOS_RESIZE = "dos_resize"
    DOS_VECTOR = "dos_vector"
    DOS_DEVICE_INFO = "dos_device_info"
    BIOS_VIDEO_QUERY = "bios_video_query"
    BIOS_VIDEO_STATE = "bios_video_state"
    CPU_FAULT = "cpu_fault"
    UNSUPPORTED_INSTRUCTION = "unsupported_instruction"
    CONTROL_ESCAPE = "control_escape"
    UNDECLARED_ACCESS = "undeclared_access"
    CODE_WRITE = "code_write"
    READ_ONLY_WRITE = "read_only_write"


class ProgramAgreement(StrEnum):
    """Agreement on executed vectors, never an all-input equivalence proof."""

    AGREED = "agreed"
    MISMATCHED = "mismatched"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class ProgramObservation:
    """One named output range; names declare the cross-program correspondence."""

    name: str
    region: LinearRange

    def __post_init__(self) -> None:
        """Require a nonempty output identity independent of its address."""
        if not self.name:
            raise ValueError("program observation requires a name")


@dataclass(frozen=True, slots=True)
class ProgramEvent:
    """External event payload plus its diagnostic instruction address."""

    kind: ProgramEventKind
    address: int
    data: bytes


@dataclass(frozen=True, slots=True)
class ProgramResult:
    """Complete captured state with independent outcome and output denominator.

    Registers and writes retain diagnostics. Terminated-process agreement
    observes the exit/event trace and every named output, not ephemeral register
    allocation after a process stops. No supported file/device service is hidden.
    """

    status: ProgramStatus
    exit_code: int | None
    registers: tuple[tuple[str, int], ...]
    observations: tuple[tuple[str, bytes], ...]
    requested_observations: tuple[tuple[str, int], ...]
    writes: tuple[tuple[int, bytes], ...]
    events: tuple[ProgramEvent, ...]
    instructions: int
    boot_identity: str
    environment_identity: str
    detail: str = ""
    requested_streams: tuple[int, ...] = ()
    requested_input_files: FilePositions = ()
    input_file_positions: FilePositions = ()
    file_receipts: tuple[FileReceipt, ...] = ()


def compare_programs(oracle: ProgramResult, candidate: ProgramResult) -> ProgramAgreement:
    """Compare complete termination under the same declared initial environment.

    Equal faults and truncated/refused executions remain incomplete. Output
    labels may bind different physical ranges, but their complete size/name
    denominator must match and every requested byte must have been collected.
    """
    if oracle.environment_identity != candidate.environment_identity:
        return ProgramAgreement.INCOMPLETE
    oracle_complete = _complete_outcome(oracle)
    candidate_complete = _complete_outcome(candidate)
    if not oracle_complete or not candidate_complete:
        return ProgramAgreement.INCOMPLETE
    if oracle.status is not candidate.status:
        return ProgramAgreement.MISMATCHED
    if oracle.status is ProgramStatus.FAULTED:
        return ProgramAgreement.INCOMPLETE
    if oracle.requested_observations != candidate.requested_observations:
        return ProgramAgreement.INCOMPLETE
    if oracle.requested_streams != candidate.requested_streams:
        return ProgramAgreement.INCOMPLETE
    if oracle.requested_input_files != candidate.requested_input_files:
        return ProgramAgreement.INCOMPLETE
    oracle_events = _external_outputs(oracle)
    candidate_events = _external_outputs(candidate)
    if (oracle.exit_code, oracle.observations, oracle_events, oracle.input_file_positions,
            _service_receipts(oracle)) != (
        candidate.exit_code, candidate.observations, candidate_events, candidate.input_file_positions,
        _service_receipts(candidate)):
        return ProgramAgreement.MISMATCHED
    return ProgramAgreement.AGREED


def _complete_outcome(result: ProgramResult) -> bool:
    """Admit concrete process termination or a captured CPU fault, never truncation."""
    if result.status is ProgramStatus.TERMINATED:
        return file_state_complete(result.requested_input_files, result.input_file_positions, result.file_receipts) and _complete_outputs(result)
    if result.status is ProgramStatus.FAULTED and len(result.events) == 1:
        event = result.events[0]
        return event.kind is ProgramEventKind.CPU_FAULT and len(event.data) == 4 and result.exit_code is None
    return False


def _complete_outputs(result: ProgramResult) -> bool:
    """Check the independent output denominator and mandatory architecture-specific exit receipt."""
    requested = dict(result.requested_observations)
    observed = dict(result.observations)
    if len(requested) != len(result.requested_observations) or len(observed) != len(result.observations):
        return False
    if requested.keys() != observed.keys() or result.exit_code is None:
        return False
    if any(size <= 0 or len(observed[name]) != size for name, size in requested.items()):
        return False
    if type(result.exit_code) is not int or not result.events:
        return False
    if result.events[-1].kind is ProgramEventKind.PE_EXIT and any(
        event.kind in (ProgramEventKind.DOS_RESIZE, ProgramEventKind.DOS_VECTOR,
                       ProgramEventKind.DOS_DEVICE_INFO, ProgramEventKind.BIOS_VIDEO_QUERY, ProgramEventKind.BIOS_VIDEO_STATE)
        for event in result.events[:-1]
    ):
        return False
    if len(set(result.requested_streams)) != len(result.requested_streams):
        return False
    if any(type(handle) is not int or handle not in (1, 2) for handle in result.requested_streams):
        return False
    if any(not _complete_service_event(write, result.requested_streams) for write in result.events[:-1]):
        return False
    return _complete_exit(result.events[-1], result.exit_code)


def _complete_service_event(event: ProgramEvent, requested_streams: tuple[int, ...]) -> bool:
    """Admit a stream write or a complete declared DOS service receipt."""
    if event.kind is ProgramEventKind.OUTPUT_WRITE:
        return bool(event.data) and len(event.data) <= 0x10000 and event.data[0] in requested_streams
    if event.kind is ProgramEventKind.DOS_RESIZE:
        return resize_receipt_complete(event.data)
    if event.kind is ProgramEventKind.DOS_VECTOR:
        return vector_receipt_complete(event.data)
    if event.kind is ProgramEventKind.DOS_DEVICE_INFO:
        return device_info_receipt_complete(event.data)
    if event.kind is ProgramEventKind.BIOS_VIDEO_QUERY:
        return video_query_receipt_complete(event.data)
    if event.kind is ProgramEventKind.BIOS_VIDEO_STATE:
        return video_state_receipt_complete(event.data)
    return event.kind is ProgramEventKind.DOS_VERSION and version_receipt_complete(event.data)


def _complete_exit(event: ProgramEvent, exit_code: int) -> bool:
    """Require the architecture-specific complete terminal receipt and width."""
    if event.kind is ProgramEventKind.DOS_EXIT:
        return 0 <= exit_code <= 255 and event.data == bytes((0x21, 0x4C, exit_code))
    if event.kind is ProgramEventKind.PE_EXIT:
        return 0 <= exit_code <= 0xFFFFFFFF and event.data == exit_code.to_bytes(4, "little")
    return False


def _external_outputs(result: ProgramResult) -> tuple[tuple[int, bytes], ...]:
    """Compare separate declared streams independently of write chunk boundaries.

    The opt-in environment models stdout and stderr as independent byte streams;
    their relative interleaving is outside this contract. Exit is compared by
    the caller after complete event admission, so intermediate writes cannot
    erase, replace or conceal the mandatory final termination receipt.
    """
    writes = (OutputAccepted(event.data[0], event.data[1:], len(event.data) - 1, False)
              for event in result.events[:-1] if event.kind is ProgramEventKind.OUTPUT_WRITE)
    streams = output_stream_bytes(writes)
    return tuple((handle, streams.get(handle, b"")) for handle in sorted(result.requested_streams))


def _service_receipts(result: ProgramResult) -> tuple[bytes, ...]:
    """Return declared DOS service payloads in emission order.

    Answered services are observable declared-environment interactions: two
    programs under one identity always see identical response bytes, but a
    different query count is a real behavioral difference and must compare
    as such rather than being silently dropped from the agreement input.
    """
    return tuple(event.data for event in result.events
                 if event.kind in (ProgramEventKind.DOS_VERSION, ProgramEventKind.DOS_RESIZE,
                                   ProgramEventKind.DOS_VECTOR, ProgramEventKind.DOS_DEVICE_INFO,
                                   ProgramEventKind.BIOS_VIDEO_QUERY, ProgramEventKind.BIOS_VIDEO_STATE))
