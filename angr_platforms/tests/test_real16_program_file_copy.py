"""Combined declared file-input/output-stream scenario for initialized MZ replay.

M6 integration controls: actual initialized MZ binaries exercise the opt-in
preopened immutable file input services (INT21 AH=42 seek, AH=3F read) and the
declared output stream (INT21 AH=40) under a single explicit synthetic
environment, then terminate through DOS AH=4C. Equivalence and corruption
verdicts come from real Unicorn replay: actual stream bytes, file cursors and
receipts are checked, never fabricated or reduced to mock status. No actual
file opens, devices or DOS internals are inferred; behavior comes only from
the exact machine instructions below and the declared manifest contract.

"""

from dataclasses import replace

import pytest
from test_real16_program_replay import environment, mz

from tools.dosunit.real16_program_boot import program_from_mz_bytes
from tools.dosunit.real16_program_file_receipts import FileOperation, FileReceipt
from tools.dosunit.real16_program_manifest import ProgramManifest, parse_program_manifest
from tools.dosunit.real16_program_model import (
    ProgramAgreement,
    ProgramEventKind,
    ProgramResult,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.real16_program_replay import replay_program

# Declared input contract: one preopened immutable file on handle 5. The four
# byte "HEAD" prefix is never read; AH=42 seeks past it and AH=3F serves only
# the payload, so the read bytes can be checked against the exact snapshot.
INPUT_HANDLE = 5
INPUT_DATA = b"HEADABCD"
EXPECTED_PAYLOAD = b"ABCD"
OUTPUT_HANDLE = 1
SERVICE_CAP = 32

# PSP segment 0x1000 gives the arena linear base 0x10000; DS=PSP at entry, so
# the read/write destinations are plain DS:DX offsets into the declared arena.
ARENA_BASE = 0x10000
ORACLE_BUFFER_OFFSET = 0x0200
CANDIDATE_BUFFER_OFFSET = 0x0210

# Instruction encodings (hand-derived 16-bit machine code, disassembly-verified):
#   bb0500  mov bx,5         31c9    xor cx,cx        ba0400  mov dx,4
#   b80042  mov ax,0x4200    cd21    int 0x21         ; AH=42 AL=0 seek BEGIN+4
#   baXXXX  mov dx,off       b9YY00  mov cx,count     b43f    mov ah,0x3f
#   cd21    int 0x21                                   ; AH=3F read DS:DX<-file
#   bb0100  mov bx,1         baXXXX  mov dx,off       b9YY00  mov cx,count
#   b440    mov ah,0x40      cd21    int 0x21         ; AH=40 write DS:DX->stdout
#   c606130245  mov byte ptr ds:[0x213],0x45          ; corrupt one buffered byte
#   b8ZZ4c  mov ax,0x4cZZ    cd21    int 0x21         ; AH=4C exit with code ZZ
_SEEK_PAST_HEADER = "bb050031c9ba0400b80042cd21"
_EXIT0 = "b8004ccd21"

# Oracle: one seek, one 4-byte read into DS:0x200, one 4-byte write, exit 0.
ORACLE_COPY = (
    _SEEK_PAST_HEADER
    + "ba0002b90400b43fcd21"
    + "bb0100ba0002b90400b440cd21"
    + _EXIT0
)

# Equivalent candidate: same copy at a distinct buffer DS:0x210 with the read
# and write split into 2-byte chunks. Final cursors, streams and the named
# observation match; only call-chunk boundaries differ.
SPLIT_COPY = (
    _SEEK_PAST_HEADER
    + "ba1002b90200b43fcd21"
    + "ba1202b90200b43fcd21"
    + "bb0100ba1002b90200b440cd21"
    + "bb0100ba1202b90200b440cd21"
    + _EXIT0
)

# Corruptions of the split candidate: each changes exactly one compared facet.
# Output byte: buffered 'D' becomes 'E' before the writes (stream+observation).
CHANGED_OUTPUT_BYTE = (
    _SEEK_PAST_HEADER
    + "ba1002b90200b43fcd21"
    + "ba1202b90200b43fcd21"
    + "c606130245"
    + "bb0100ba1002b90200b440cd21"
    + "bb0100ba1202b90200b440cd21"
    + _EXIT0
)
# Destination: identical copy relocated to DS:0x218; the declared candidate
# observation at 0x10210 keeps its initial bytes (observation-only mismatch).
MOVED_DESTINATION = (
    _SEEK_PAST_HEADER
    + "ba1802b90200b43fcd21"
    + "ba1a02b90200b43fcd21"
    + "bb0100ba1802b90200b440cd21"
    + "bb0100ba1a02b90200b440cd21"
    + _EXIT0
)
# Write source: reads still fill the observed buffer but the writes emit the
# untouched arena bytes at DS:0x218 (stream-only mismatch).
MOVED_WRITE_SOURCE = (
    _SEEK_PAST_HEADER
    + "ba1002b90200b43fcd21"
    + "ba1202b90200b43fcd21"
    + "bb0100ba1802b90200b440cd21"
    + "bb0100ba1a02b90200b440cd21"
    + _EXIT0
)
# Exit code: identical copy terminating with code 5 instead of 0.
CHANGED_EXIT = (
    _SEEK_PAST_HEADER
    + "ba1002b90200b43fcd21"
    + "ba1202b90200b43fcd21"
    + "bb0100ba1002b90200b440cd21"
    + "bb0100ba1202b90200b440cd21"
    + "b8054ccd21"
)

# Refused-service probes under the same declared environment.
# Read from an undeclared input handle after a successful seek.
UNKNOWN_READ_HANDLE = _SEEK_PAST_HEADER + "bb0600" + "ba0002b90400b43fcd21" + _EXIT0
# Read from handle 1: a declared output stream is never an input file.
READ_ON_OUTPUT_HANDLE = _SEEK_PAST_HEADER + "bb0100" + "ba0002b90400b43fcd21" + _EXIT0
# Write to handle 5: a declared input file is never an output stream.
WRITE_ON_INPUT_HANDLE = (
    _SEEK_PAST_HEADER
    + "ba0002b90400b43fcd21"
    + "bb0500ba0002b90400b440cd21"
    + _EXIT0
)
# Seek origin mode 3 is outside the declared BEGIN/CURRENT/END domain.
UNKNOWN_SEEK_ORIGIN = _SEEK_PAST_HEADER.replace("b80042", "b80342") + _EXIT0
# AH=09 is an undeclared DOS service entirely.
UNKNOWN_SERVICE = "b409cd21" + _EXIT0


def combined_manifest(
    *,
    declare_input: bool = True,
    declare_output: bool = True,
    input_entries: list[dict[str, object]] | None = None,
    service_cap: int = SERVICE_CAP,
) -> ProgramManifest:
    """Build the shared explicit environment with both service policies declared."""
    base = environment()
    declared = {
        "psp_segment": base.psp_segment,
        "allocation_hex": base.allocation.hex(),
        "registers": dict(base.registers),
        "fs": 0,
        "gs": 0,
    }
    if declare_input:
        files = [{"handle": INPUT_HANDLE, "bytes": INPUT_DATA.hex(), "cursor": 0}]
        if input_entries is not None:
            files = input_entries
        declared["input_files"] = {
            "files": files,
            "max_call_bytes": service_cap,
            "max_total_bytes": service_cap,
        }
    if declare_output:
        declared["output_streams"] = {
            "handles": [OUTPUT_HANDLE],
            "max_call_bytes": service_cap,
            "max_total_bytes": service_cap,
        }
    return parse_program_manifest({
        "schema": "dosunit.real16_program_environment.v1",
        "environment": declared,
        "observations": [{
            "name": "buffer",
            "size": len(EXPECTED_PAYLOAD),
            "oracle_address": ARENA_BASE + ORACLE_BUFFER_OFFSET,
            "candidate_address": ARENA_BASE + CANDIDATE_BUFFER_OFFSET,
        }],
    })


def run_oracle(manifest: ProgramManifest, code: str) -> ProgramResult:
    """Replay one binary with the oracle-side observation binding."""
    boot = program_from_mz_bytes(mz(bytes.fromhex(code)), manifest.environment)
    return replay_program(boot, observations=manifest.oracle_observations, instruction_limit=100)


def run_candidate(manifest: ProgramManifest, code: str) -> ProgramResult:
    """Replay one binary with the candidate-side observation binding."""
    boot = program_from_mz_bytes(mz(bytes.fromhex(code)), manifest.environment)
    return replay_program(boot, observations=manifest.candidate_observations, instruction_limit=100)


def test_identical_programs_are_deterministic_and_agree_across_fresh_runs() -> None:
    """Two fresh boots of the same bytes produce fully equal concrete results."""
    first = run_oracle(combined_manifest(), ORACLE_COPY)
    second = run_oracle(combined_manifest(), ORACLE_COPY)
    assert first.status is second.status is ProgramStatus.TERMINATED
    assert first == second
    assert first.boot_identity == second.boot_identity
    assert first.environment_identity == second.environment_identity
    assert compare_programs(first, second) is ProgramAgreement.AGREED


def test_copy_scenario_reports_actual_stream_cursor_and_receipts() -> None:
    """The combined run retains real output bytes, cursor transitions and exit."""
    result = run_oracle(combined_manifest(), ORACLE_COPY)
    assert result.status is ProgramStatus.TERMINATED
    assert result.exit_code == 0
    assert result.observations == (("buffer", EXPECTED_PAYLOAD),)
    assert result.writes == ((ARENA_BASE + ORACLE_BUFFER_OFFSET, EXPECTED_PAYLOAD),
                             (0x110FA, bytes.fromhex("290010104600")))
    assert result.requested_input_files == ((INPUT_HANDLE, 0),)
    assert result.input_file_positions == ((INPUT_HANDLE, len(INPUT_DATA)),)
    assert result.requested_streams == (OUTPUT_HANDLE,)
    assert result.file_receipts == (
        FileReceipt(FileOperation.SEEK, INPUT_HANDLE, 0, len(INPUT_DATA) - len(EXPECTED_PAYLOAD)),
        FileReceipt(FileOperation.READ, INPUT_HANDLE, len(INPUT_DATA) - len(EXPECTED_PAYLOAD),
                    len(INPUT_DATA), EXPECTED_PAYLOAD),
    )
    assert len(result.events) == 2
    write_event, exit_event = result.events
    assert write_event.kind is ProgramEventKind.OUTPUT_WRITE
    assert write_event.data == bytes((OUTPUT_HANDLE,)) + EXPECTED_PAYLOAD
    assert exit_event.kind is ProgramEventKind.DOS_EXIT
    assert exit_event.data == bytes((0x21, 0x4C, 0))


def test_equivalent_chunked_program_agrees_across_distinct_buffers() -> None:
    """Different instruction chunking and a different buffer still agree."""
    manifest = combined_manifest()
    oracle = run_oracle(manifest, ORACLE_COPY)
    candidate = run_candidate(manifest, SPLIT_COPY)
    assert candidate.status is ProgramStatus.TERMINATED
    assert oracle.boot_identity != candidate.boot_identity
    assert oracle.environment_identity == candidate.environment_identity
    # Three receipts instead of two: chunking is diagnostic, never compared.
    assert len(candidate.file_receipts) == len(oracle.file_receipts) + 1
    assert oracle.input_file_positions == candidate.input_file_positions
    assert oracle.observations == candidate.observations == (("buffer", EXPECTED_PAYLOAD),)
    assert compare_programs(oracle, candidate) is ProgramAgreement.AGREED


@pytest.mark.parametrize(
    "code",
    [CHANGED_OUTPUT_BYTE, MOVED_DESTINATION, MOVED_WRITE_SOURCE, CHANGED_EXIT, ORACLE_COPY],
)
def test_corrupted_or_relocated_programs_mismatch(code: str) -> None:
    """Changed bytes, destination, exit code or buffer binding never agree."""
    manifest = combined_manifest()
    oracle = run_oracle(manifest, ORACLE_COPY)
    candidate = run_candidate(manifest, code)
    assert candidate.status is ProgramStatus.TERMINATED
    assert compare_programs(oracle, candidate) is ProgramAgreement.MISMATCHED


@pytest.mark.parametrize(
    "code",
    [UNKNOWN_READ_HANDLE, READ_ON_OUTPUT_HANDLE, WRITE_ON_INPUT_HANDLE,
     UNKNOWN_SEEK_ORIGIN, UNKNOWN_SERVICE],
)
def test_refused_service_uses_stay_incomplete_under_the_same_environment(code: str) -> None:
    """Undeclared handles, origins and services refuse; refusals never agree."""
    manifest = combined_manifest()
    oracle = run_oracle(manifest, ORACLE_COPY)
    refused = run_oracle(manifest, code)
    assert refused.status is ProgramStatus.UNSUPPORTED
    assert compare_programs(refused, run_oracle(manifest, code)) is ProgramAgreement.INCOMPLETE
    assert compare_programs(oracle, refused) is ProgramAgreement.INCOMPLETE


@pytest.mark.parametrize(
    "declare_input,declare_output,input_entries",
    [
        (False, True, None),   # input service omitted: seek/read are undeclared
        (True, False, None),   # output service omitted: the write is undeclared
        (False, False, None),  # termination-only environment
        (True, True, []),      # declared-but-empty input policy refuses handle 5
    ],
)
def test_omitted_or_empty_service_policies_stay_incomplete(
    declare_input: bool, declare_output: bool, input_entries: list[dict[str, object]] | None
) -> None:
    """Without the declared policy the same program has no admitted service."""
    refused = run_oracle(
        combined_manifest(declare_input=declare_input, declare_output=declare_output,
                          input_entries=input_entries),
        ORACLE_COPY,
    )
    assert refused.status is ProgramStatus.UNSUPPORTED
    assert compare_programs(refused, refused) is ProgramAgreement.INCOMPLETE
    oracle = run_oracle(combined_manifest(), ORACLE_COPY)
    assert compare_programs(oracle, refused) is ProgramAgreement.INCOMPLETE


def test_missing_output_policy_still_reports_the_completed_input_receipts() -> None:
    """A refused write does not erase honest seek/read evidence already taken."""
    refused = run_oracle(combined_manifest(declare_output=False), ORACLE_COPY)
    assert refused.status is ProgramStatus.UNSUPPORTED
    assert refused.file_receipts == (
        FileReceipt(FileOperation.SEEK, INPUT_HANDLE, 0, 4),
        FileReceipt(FileOperation.READ, INPUT_HANDLE, 4, len(INPUT_DATA), EXPECTED_PAYLOAD),
    )
    assert refused.input_file_positions == ((INPUT_HANDLE, len(INPUT_DATA)),)


def test_combined_projection_tampering_cannot_pass_or_hide_state() -> None:
    """Incomplete file/stream/exit projections stay INCOMPLETE; hiding a stream
    write or a cursor transition is a real MISMATCH, not silent agreement."""
    complete = run_oracle(combined_manifest(), ORACLE_COPY)
    assert compare_programs(complete, complete) is ProgramAgreement.AGREED
    for broken in (
        replace(complete, file_receipts=()),
        replace(complete, input_file_positions=()),
        replace(complete, input_file_positions=((INPUT_HANDLE, 7),)),
        replace(complete, observations=()),
        replace(complete, events=complete.events[:1]),  # no termination receipt
        replace(complete, exit_code=None),
    ):
        assert compare_programs(complete, broken) is ProgramAgreement.INCOMPLETE
    hidden_write = replace(complete, events=complete.events[1:])
    assert compare_programs(complete, hidden_write) is ProgramAgreement.MISMATCHED
    moved_cursor = replace(
        complete,
        input_file_positions=((INPUT_HANDLE, 3),),
        file_receipts=(FileReceipt(FileOperation.SEEK, INPUT_HANDLE, 0, 3),),
    )
    assert compare_programs(complete, moved_cursor) is ProgramAgreement.MISMATCHED


def test_declared_snapshots_stay_immutable_and_guest_writes_stay_isolated() -> None:
    """The declared file/arena snapshots never change; file bytes reach only
    the declared destination and the skipped prefix never enters the arena."""
    manifest = combined_manifest()
    env = manifest.environment
    allocation_before = env.allocation
    declared_file = env.input_policy.files[0]
    result = run_oracle(manifest, ORACLE_COPY)
    assert env.allocation == allocation_before
    assert (declared_file.handle, declared_file.data, declared_file.cursor) == (
        INPUT_HANDLE, INPUT_DATA, 0)
    assert result.writes == ((ARENA_BASE + ORACLE_BUFFER_OFFSET, EXPECTED_PAYLOAD),
                             (0x110FA, bytes.fromhex("290010104600")))
    assert INPUT_DATA[:4] != EXPECTED_PAYLOAD
    assert EXPECTED_PAYLOAD not in env.allocation


def test_input_and_output_budgets_remain_independent_in_one_execution() -> None:
    """Reading four bytes must not consume the separate four-byte output cap."""
    manifest = combined_manifest(service_cap=len(EXPECTED_PAYLOAD))
    original = run_oracle(manifest, ORACLE_COPY)
    candidate = run_candidate(manifest, SPLIT_COPY)
    assert original.status is candidate.status is ProgramStatus.TERMINATED
    assert original.input_file_positions == candidate.input_file_positions == ((INPUT_HANDLE, 8),)
    assert original.observations == candidate.observations == (("buffer", EXPECTED_PAYLOAD),)
    assert compare_programs(original, candidate) is ProgramAgreement.AGREED
