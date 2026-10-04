"""Checked initialized-program environment and output declarations.

Layer: dosunit CLI contracts.
Responsibility: parse the entire declared arena/register/output selection before
binary reads or guest execution, without inventing startup or service state.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.dosunit.real16_program_boot import ProgramEnvironment
from tools.dosunit.real16_program_device_info import parse_device_info_policy
from tools.dosunit.real16_program_input_manifest import parse_input_policy
from tools.dosunit.real16_program_memory import parse_memory_regions
from tools.dosunit.real16_program_model import ProgramObservation
from tools.dosunit.real16_program_output import OutputPolicy
from tools.dosunit.real16_program_resize import parse_resize_policy
from tools.dosunit.real16_program_rom import parse_rom
from tools.dosunit.real16_program_vectors import parse_vector_policy
from tools.dosunit.real16_program_version import parse_version_policy
from tools.dosunit.real16_program_video import parse_video_policy
from tools.dosunit.real16_program_video_state import parse_video_state_policy
from tools.dosunit.real16_replay_model import LinearRange


@dataclass(frozen=True, slots=True)
class ProgramManifest:
    """One shared concrete environment and named per-side output projections."""

    environment: ProgramEnvironment
    oracle_observations: tuple[ProgramObservation, ...]
    candidate_observations: tuple[ProgramObservation, ...]
    oracle_code_ranges: tuple[LinearRange, ...]
    candidate_code_ranges: tuple[LinearRange, ...]


def _integer(value: object, name: str) -> int:
    """Read exact nonnegative integers or explicitly written hexadecimal values."""
    if type(value) is int:
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as error:
            raise ValueError(f"{name}: invalid integer") from error
    else:
        raise ValueError(f"{name}: expected an integer")
    if parsed < 0:
        raise ValueError(f"{name}: negative integer")
    return parsed


def _object(value: object, name: str) -> dict[str, object]:
    """Require a named JSON object with string keys."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name}: expected an object")
    return value


def _ranges(value: object, name: str) -> tuple[LinearRange, ...]:
    """Read explicitly declared physical code ranges, if present."""
    if not isinstance(value, list):
        raise ValueError(f"{name}: expected a list")
    ranges: list[LinearRange] = []
    for raw in value:
        item = _object(raw, name)
        ranges.append(LinearRange(_integer(item.get("address"), name), _integer(item.get("size"), name)))
    return tuple(ranges)


def _observations(
    value: object, environment: ProgramEnvironment,
) -> tuple[tuple[ProgramObservation, ...], tuple[ProgramObservation, ...]]:
    """Check both output denominators against the same declared byte coverage."""
    if not isinstance(value, list):
        raise ValueError("observations: expected a list")
    left: list[ProgramObservation] = []
    right: list[ProgramObservation] = []
    names: set[str] = set()
    arena = environment.memory_layout()
    for raw in value:
        item = _object(raw, "observation")
        name = item.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("observation names must be nonempty and unique")
        names.add(name)
        size = _integer(item.get("size"), "observation size")
        for side, target in (("oracle", left), ("candidate", right)):
            region = LinearRange(_integer(item.get(f"{side}_address"), f"{side} observation"), size)
            if not arena.contains(region.address, region.size):
                raise ValueError("observation must lie inside the declared initial arena")
            target.append(ProgramObservation(name, region))
    return tuple(left), tuple(right)


def _output_policy(value: object) -> OutputPolicy | None:
    """Require an explicit successful byte-stream contract and positive caps."""
    if value is None:
        return None
    item = _object(value, "output_streams")
    if set(item) != {"handles", "max_call_bytes", "max_total_bytes"}:
        raise ValueError("output_streams requires handles and both byte budgets")
    handles = item["handles"]
    if not isinstance(handles, list):
        raise ValueError("output_streams handles must be a list")
    if len(handles) != len({_integer(handle, "output handle") for handle in handles}):
        raise ValueError("output handles must be unique")
    return OutputPolicy(
        frozenset(_integer(handle, "output handle") for handle in handles),
        _integer(item["max_call_bytes"], "output per-call budget"),
        _integer(item["max_total_bytes"], "output total budget"),
    )


def parse_program_manifest(document: object) -> ProgramManifest:
    """Fully validate the environment and projections before any execution."""
    root = _object(document, "program manifest")
    if root.get("schema") != "dosunit.real16_program_environment.v1":
        raise ValueError("unsupported initialized-program manifest schema")
    declared = _object(root.get("environment"), "environment")
    allocation_hex = declared.get("allocation_hex")
    if not isinstance(allocation_hex, str):
        raise ValueError("allocation_hex must explicitly supply every initial byte")
    try:
        allocation = bytes.fromhex(allocation_hex)
    except ValueError as error:
        raise ValueError("allocation_hex contains invalid hexadecimal bytes") from error
    registers = _object(declared.get("registers"), "registers")
    environment = ProgramEnvironment(
        _integer(declared.get("psp_segment"), "PSP"), allocation,
        tuple((name, _integer(value, name)) for name, value in sorted(registers.items())),
        _integer(declared.get("fs"), "FS"), _integer(declared.get("gs"), "GS"),
        _output_policy(declared.get("output_streams")),
        parse_input_policy(declared.get("input_files")),
        parse_version_policy(declared.get("dos_version")),
        parse_resize_policy(declared.get("dos_resize")),
        parse_memory_regions(declared.get("extra_memory", [])),
        parse_vector_policy(declared.get("dos_vectors")),
        parse_device_info_policy(declared.get("dos_device_info")),
        parse_video_policy(declared.get("bios_video")),
        parse_video_state_policy(declared.get("bios_video_state")),
        parse_rom(declared.get("rom")),
    )
    if dict(environment.registers)["eflags"] & 2 == 0:
        raise ValueError("EFLAGS must retain architectural bit1")
    left, right = _observations(root.get("observations", []), environment)
    return ProgramManifest(environment, left, right,
                           _ranges(root.get("oracle_code_ranges", []), "oracle code ranges"),
                           _ranges(root.get("candidate_code_ranges", []), "candidate code ranges"))
