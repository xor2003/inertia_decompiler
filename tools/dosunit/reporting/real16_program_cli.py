"""Public initialized-MZ program differential execution command.

Layer: dosunit CLI/execution reporting.
Responsibility: snapshot and validate declared inputs, execute both initialized
programs independently, and publish concrete outcomes without symbolic promotion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.dosunit.contracts.model import DosUnitError, write_json
from tools.dosunit.reporting.real16_program_input_manifest import input_policy_document
from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_program_device_info import device_info_policy_document
from tools.dosunit.runtime.real16_program_interrupts import INTERRUPT_ENTRY_MODEL, VIDEO_INTERRUPT_ENTRY_MODEL
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramResult, compare_programs
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_program_resize import resize_policy_document
from tools.dosunit.runtime.real16_program_rom import rom_document
from tools.dosunit.runtime.real16_program_vectors import vector_policy_document
from tools.dosunit.runtime.real16_program_version import version_policy_document
from tools.dosunit.runtime.real16_program_video import video_policy_document
from tools.dosunit.runtime.real16_program_video_state import video_state_document


def add_program16_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register initialized-program replay as a distinct execution lane."""
    parser = subparsers.add_parser("replay-program16", help="Compare initialized MZ execution; concrete evidence only")
    parser.add_argument("--oracle-exe", required=True, type=Path)
    parser.add_argument("--candidate-exe", required=True, type=Path)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--instruction-limit", type=int, default=100000)
    parser.add_argument("--out", required=True, type=Path)
    parser.set_defaults(func=cmd_replay_program16)


def _read(path: Path) -> bytes:
    """Read an immutable input snapshot and preserve any filesystem cause."""
    try:
        return path.read_bytes()
    except OSError as error:
        raise DosUnitError(f"program replay cannot read {path}: {error}") from error


def _result_document(result: ProgramResult) -> dict[str, object]:
    """Serialize typed execution evidence, including the output denominator."""
    return {
        "status": result.status.value, "exit_code": result.exit_code,
        "registers": dict(result.registers),
        "observations": [{"name": name, "bytes": data.hex()} for name, data in result.observations],
        "requested_observations": [{"name": name, "size": size} for name, size in result.requested_observations],
        "writes": [{"address": address, "bytes": data.hex()} for address, data in result.writes],
        "events": [{"kind": event.kind.value, "address": event.address, "bytes": event.data.hex()}
                   for event in result.events],
        "requested_streams": list(result.requested_streams),
        "requested_input_files": [{"handle": handle, "cursor": cursor} for handle, cursor in result.requested_input_files],
        "input_file_positions": [{"handle": handle, "cursor": cursor} for handle, cursor in result.input_file_positions],
        "file_receipts": [{"operation": receipt.operation.value, "handle": receipt.handle,
                           "before": receipt.before, "after": receipt.after, "bytes": receipt.payload.hex()}
                          for receipt in result.file_receipts],
        "instructions": result.instructions, "boot_identity": result.boot_identity,
        "environment_identity": result.environment_identity, "detail": result.detail,
    }


def cmd_replay_program16(args: argparse.Namespace) -> int:
    """Return agreement/mismatch/incomplete as exit0/1/2 after stable snapshots."""
    if args.instruction_limit <= 0:
        raise DosUnitError("program instruction limit must be positive")
    environment_path: Path = args.environment
    environment_bytes = _read(environment_path)
    try:
        manifest = parse_program_manifest(json.loads(environment_bytes))
    except (ValueError, UnicodeDecodeError) as error:
        raise DosUnitError(f"invalid program environment {environment_path}: {error}") from error
    paths: tuple[Path, Path] = (args.oracle_exe, args.candidate_exe)
    snapshots = tuple(_read(path) for path in paths)
    try:
        boots = (
            program_from_mz_bytes(snapshots[0], manifest.environment, code_ranges=manifest.oracle_code_ranges),
            program_from_mz_bytes(snapshots[1], manifest.environment, code_ranges=manifest.candidate_code_ranges),
        )
        left = replay_program(boots[0], observations=manifest.oracle_observations,
                              instruction_limit=args.instruction_limit)
        right = replay_program(boots[1], observations=manifest.candidate_observations,
                               instruction_limit=args.instruction_limit)
    except ValueError as error:
        raise DosUnitError(f"program boot/execution contract: {error}") from error
    agreement = compare_programs(left, right)
    all_inputs = ((paths[0], snapshots[0]), (paths[1], snapshots[1]), (environment_path, environment_bytes))
    if any(hashlib.sha256(_read(path)).digest() != hashlib.sha256(data).digest() for path, data in all_inputs):
        raise DosUnitError("program input changed during execution")
    document = {
        "schema": "dosunit.real16_program_replay.v1", "agreement": agreement.value,
        "proof_status": "not_established_by_execution",
        "contract": {
            "entry_and_stack": "MZ header; no synthetic caller frame",
            "interrupt_entry": (VIDEO_INTERRUPT_ENTRY_MODEL if (manifest.environment.video_policy is not None
                                    or manifest.environment.video_state_policy is not None)
                                else INTERRUPT_ENTRY_MODEL),
            "initial_memory": "complete caller-declared pre-load allocation, optional allocator metadata and disjoint extra RAM",
            "read_only_rom": rom_document(manifest.environment.rom),
            "services": {
                "termination": "INT21/AH4C",
                "dos_version": version_policy_document(manifest.environment.version_policy),
                "dos_resize": resize_policy_document(manifest.environment.resize_policy),
                "dos_vectors": vector_policy_document(manifest.environment.vector_policy),
                "dos_device_info": device_info_policy_document(manifest.environment.device_info_policy),
                "bios_video": video_policy_document(manifest.environment.video_policy),
                "bios_video_state": video_state_document(manifest.environment.video_state_policy),
                "input_files": input_policy_document(manifest.environment.input_policy),
                "output_streams": None if manifest.environment.output_policy is None else {
                    "handles": sorted(manifest.environment.output_policy.handles),
                    "max_call_bytes": manifest.environment.output_policy.per_call_bytes,
                    "max_total_bytes": manifest.environment.output_policy.aggregate_bytes,
                    "scope": "declared successful independent byte streams; no file/redirection semantics",
                },
            },
            "observations": "exit, declared version/resize/vector/device receipts, independent output streams, final input-file cursors and complete named memory ranges",
            "registers_and_writes": "captured machine diagnostics",
            "scope": "one declared initialized state; independent Unicorn real16 execution",
        },
        "inputs": [{"path": str(path), "sha256": hashlib.sha256(data).hexdigest()} for path, data in all_inputs],
        "oracle": _result_document(left), "candidate": _result_document(right),
    }
    try:
        write_json(args.out, document)
    except OSError as error:
        raise DosUnitError(f"program replay cannot write {args.out}: {error}") from error
    return {ProgramAgreement.AGREED: 0, ProgramAgreement.MISMATCHED: 1, ProgramAgreement.INCOMPLETE: 2}[agreement]
