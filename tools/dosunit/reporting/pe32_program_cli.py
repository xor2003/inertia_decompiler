"""Public initialized PE32 differential execution with immutable input snapshots.

Layer: dosunit CLI/execution reporting.
Responsibility: load actual PE entry state, run independent initialized guests
and publish concrete agreement separately from SSA/Z3 proof verdicts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.dosunit.contracts.model import DosUnitError, write_json
from tools.dosunit.reporting.real16_program_cli import _read, _result_document
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, compare_programs


def add_pe_program_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the distinct PE32 process lane without changing ELF replay."""
    parser = subparsers.add_parser("replay-program32", help="Compare initialized PE32 execution; concrete evidence only")
    parser.add_argument("--oracle-exe", required=True, type=Path)
    parser.add_argument("--candidate-exe", required=True, type=Path)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--instruction-limit", type=int, default=100000)
    parser.add_argument("--out", required=True, type=Path)
    parser.set_defaults(func=cmd_replay_pe_program)


def cmd_replay_pe_program(args: argparse.Namespace) -> int:
    """Return exit0/1/2 for declared execution agreement/mismatch/incompleteness."""
    if type(args.instruction_limit) is not int or args.instruction_limit <= 0:
        raise DosUnitError("PE program instruction limit must be a positive integer")
    # This optional process lane must not make ordinary dosunit startup load
    # angr/Unicorn or require the initialized PE backend before command use.
    try:
        from tools.dosunit.reporting.pe32_program_manifest import parse_pe_program_manifest
        from tools.dosunit.runtime.pe32_program_boot import pe_program_from_bytes
        from tools.dosunit.runtime.pe32_program_replay import replay_pe_program, validate_pe_observations
    except ImportError as error:
        raise DosUnitError(f"initialized PE32 execution backend unavailable: {error}") from error
    environment_path: Path = args.environment
    environment_bytes = _read(environment_path)
    try:
        manifest = parse_pe_program_manifest(json.loads(environment_bytes))
    except (ValueError, UnicodeDecodeError) as error:
        raise DosUnitError(f"invalid PE program environment {environment_path}: {error}") from error
    paths: tuple[Path, Path] = (args.oracle_exe, args.candidate_exe)
    snapshots = tuple(_read(path) for path in paths)
    try:
        boots = tuple(pe_program_from_bytes(data, manifest.environment) for data in snapshots)
        validate_pe_observations(boots[0], manifest.oracle_observations)
        validate_pe_observations(boots[1], manifest.candidate_observations)
        left = replay_pe_program(boots[0], observations=manifest.oracle_observations,
                                 instruction_limit=args.instruction_limit)
        right = replay_pe_program(boots[1], observations=manifest.candidate_observations,
                                  instruction_limit=args.instruction_limit)
    except ValueError as error:
        raise DosUnitError(f"PE program boot/execution contract: {error}") from error
    agreement = compare_programs(left, right)
    inputs = ((paths[0], snapshots[0]), (paths[1], snapshots[1]), (environment_path, environment_bytes))
    if any(hashlib.sha256(_read(path)).digest() != hashlib.sha256(data).digest() for path, data in inputs):
        raise DosUnitError("PE program input changed during execution")
    report = {
        "schema": "dosunit.pe32_program_replay.v1", "agreement": agreement.value,
        "proof_status": "not_established_by_execution",
        "contract": {
            "entry": "loaded PE AddressOfEntryPoint; no synthetic caller frame or return trap",
            "initial_memory": "PE loader bytes and exact caller-declared initialized data allocations",
            "services": "explicit stdcall-shaped terminal gateway; full u32 exit argument",
            "segments": "flat zero selectors; FS/GS memory accesses and segment writes unsupported",
            "startup": "imports/TLS/delay-imports/CLR/load-config initialization unsupported",
            "scope": "one declared initial state; independent Unicorn PE32 integer execution",
        },
        "inputs": [{"path": str(path), "sha256": hashlib.sha256(data).hexdigest()} for path, data in inputs],
        "oracle": _result_document(left), "candidate": _result_document(right),
    }
    try:
        write_json(args.out, report)
    except OSError as error:
        raise DosUnitError(f"PE program replay cannot write {args.out}: {error}") from error
    return {ProgramAgreement.AGREED: 0, ProgramAgreement.MISMATCHED: 1, ProgramAgreement.INCOMPLETE: 2}[agreement]
