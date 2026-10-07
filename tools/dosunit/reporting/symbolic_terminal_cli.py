"""Layer: dosunit symbolic-proof CLI and reporting.

Responsibility: compare declared terminal transitions from immutable binary
snapshots, retain every proof premise and keep execution status independent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from tools.dosunit.contracts.model import DosUnitError, write_json
from tools.dosunit.contracts.proof_contracts import Architecture, ProofStatus
from tools.dosunit.reporting.real16_program_cli import _read

if TYPE_CHECKING:
    from tools.dosunit.compare.symbolic_terminal import ImportedServiceEvent, TerminalComparison, TerminalLaneResult
    from tools.dosunit.compare.symbolic_terminal_real16_services import TerminalServiceEvent
    from tools.dosunit.runtime.pe32_program_boot import PeProgramEnvironment
    from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment


def add_terminal_parsers(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register symbolic terminal commands without loading the proof backend."""
    for suffix, architecture in (("16", Architecture.REAL16), ("32", Architecture.FLAT32)):
        parser = subparsers.add_parser(
            f"compare-terminal{suffix}", help="Compare bounded symbolic terminal effects; explicit premises",
            description=(
                "Compare bounded native terminal paths under declared environment premises. "
                "Real16 supports declared DOS version and BIOS video queries; PE32 supports "
                "declared no-argument DWORD import services through actual IAT routes. "
                "Ordered events remain observable; unsupported services refuse. Equality is conditional."
            ),
        )
        parser.add_argument("--oracle-exe", required=True, type=Path)
        parser.add_argument("--candidate-exe", required=True, type=Path)
        parser.add_argument("--environment", required=True, type=Path)
        parser.add_argument("--solver-timeout-ms", type=int)
        parser.add_argument("--out", required=True, type=Path)
        parser.set_defaults(func=cmd_compare_terminal, terminal_architecture=architecture)


def _environment(data: bytes, architecture: Architecture) -> ProgramEnvironment | PeProgramEnvironment:
    """Read the existing environment format without discarding output contracts."""
    from tools.dosunit.reporting.pe32_program_manifest import parse_pe_program_manifest
    from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest

    try:
        document = json.loads(data)
        if architecture is Architecture.REAL16:
            mz = parse_program_manifest(document)
            if mz.oracle_observations or mz.candidate_observations or mz.oracle_code_ranges or mz.candidate_code_ranges:
                raise ValueError("terminal proof requires whole-image scope without named replay projections")
            return mz.environment
        pe = parse_pe_program_manifest(document)
        if pe.oracle_observations or pe.candidate_observations:
            raise ValueError("terminal proof requires whole-state scope without named replay projections")
        return pe.environment
    except (ValueError, UnicodeDecodeError) as error:
        raise DosUnitError(f"invalid terminal environment: {error}") from error


def _service_event_document(event: TerminalServiceEvent | ImportedServiceEvent) -> dict[str, object]:
    """Serialize either typed service receipt without losing its observable identity."""
    from tools.dosunit.compare.symbolic_terminal import ImportedServiceEvent

    if isinstance(event, ImportedServiceEvent):
        return {"kind": "pe32_import", "service": event.service, "slot": event.slot,
                "site": event.site, "sequence": event.sequence}
    return {"kind": event.kind.value, "address": event.address, "vector": event.vector,
            "function": event.function, "data": event.data.hex()}


def _lane_document(lane: TerminalLaneResult) -> dict[str, object]:
    """Retain native identity or the exact typed intake refusal for each lane."""
    if lane.refusal is not None:
        return {"refusal": lane.refusal.kind.value, "detail": lane.refusal.detail}
    trace = lane.trace
    assert trace is not None
    return {
        "outcome": trace.outcome.value,
        "fault": None if trace.fault is None else {
            "kind": trace.fault.kind.value,
            "vector": trace.fault.vector,
            "site_address": trace.fault.site_address,
            "encoding": trace.fault.encoding.hex(),
            "reason": trace.fault.reason.value,
        },
        "source_sha256": trace.source_sha256,
        "boot_identity": trace.boot_identity,
        "environment_identity": trace.environment_identity,
        "native_limits": {
            "max_blocks": trace.decode_limits.max_blocks,
            "max_block_bytes": trace.decode_limits.max_block_bytes,
            "max_instructions": trace.decode_limits.max_instructions,
        },
        "entry": trace.entry,
        "site": None if trace.site is None else {
            "address": trace.site.address, "encoding": trace.site.encoding.hex(), "target": trace.site.target,
        },
        "service_events": [_service_event_document(event) for event in trace.service_events],
        "blocks": [
            {"address": block.address, "size": block.size, "sha256": block.sha256,
             "jumpkind": block.jumpkind, "instructions": block.instructions, "next_target": block.next_target}
            for block in trace.blocks
        ],
    }


def _proof_status(result: TerminalComparison) -> ProofStatus:
    """Translate the typed terminal verdict without discarding its premises."""
    from tools.dosunit.compare.symbolic_terminal import TerminalComparisonStatus

    statuses = {
        TerminalComparisonStatus.EQUIVALENT: ProofStatus.CONDITIONAL,
        TerminalComparisonStatus.COUNTEREXAMPLE: ProofStatus.COUNTEREXAMPLE,
    }
    return statuses.get(result.status, ProofStatus.UNKNOWN)


def terminal_document(result: TerminalComparison) -> dict[str, object]:
    """Project equality as conditional, never as replay or unconditional proof."""
    domain = result.environment_model()
    counters = result.counters
    return {
        "schema": "dosunit.symbolic_terminal_compare.v1",
        "status": _proof_status(result).value,
        "terminal_status": result.status.value,
        "execution_status": "not_run",
        "architecture": result.architecture.value if result.architecture is not None else None,
        "service": result.service.value if result.service is not None else None,
        "environment_identity": result.environment_identity,
        "detail": result.detail,
        "assumptions": [dict(item) for item in result.assumptions],
        "domain": {"instruction_memory": domain.instruction_memory.value,
                   "external_effects": domain.external_effects.value,
                   "faults": domain.faults.value, "initial_data": domain.initial_data.value},
        "counters": {"raw_fact_count": counters.raw_fact_count,
                     "normalized_fact_count": counters.normalized_fact_count,
                     "classified_fact_count": counters.classified_fact_count,
                     "materialized_count": counters.materialized_count,
                     "failure_count": counters.failure_count},
        "diverged": list(result.diverged), "model": dict(result.model),
        "solver_time_ms": result.solver_time_ms,
        "oracle": _lane_document(result.oracle), "candidate": _lane_document(result.candidate),
    }


def cmd_compare_terminal(args: argparse.Namespace) -> int:
    """Publish conditional/counterexample/unknown as exit 0/1/2 after freshness checks."""
    from tools.dosunit.compare.symbolic_terminal import TerminalLimits, compare_symbolic_terminals

    limits = TerminalLimits()
    requested: int | None = args.solver_timeout_ms
    if requested is not None:
        if not 0 <= requested <= limits.solver_timeout_ms:
            raise DosUnitError(f"terminal solver timeout must be between 0 and {limits.solver_timeout_ms} ms")
        limits = TerminalLimits(solver_timeout_ms=requested)
    environment_bytes = _read(args.environment)
    environment = _environment(environment_bytes, args.terminal_architecture)
    paths: tuple[Path, Path] = (args.oracle_exe, args.candidate_exe)
    snapshots = (_read(paths[0]), _read(paths[1]))
    result = compare_symbolic_terminals(snapshots[0], environment, snapshots[1], environment, limits=limits)
    inputs = ((paths[0], snapshots[0]), (paths[1], snapshots[1]), (args.environment, environment_bytes))
    if any(_read(path) != data for path, data in inputs):
        raise DosUnitError("terminal input changed during comparison")
    document = terminal_document(result)
    document["inputs"] = [{"path": str(path), "sha256": hashlib.sha256(data).hexdigest()} for path, data in inputs]
    try:
        write_json(args.out, document)
    except OSError as error:
        raise DosUnitError(f"cannot write terminal report {args.out}: {error}") from error
    return {ProofStatus.CONDITIONAL: 0, ProofStatus.COUNTEREXAMPLE: 1}.get(_proof_status(result), 2)
