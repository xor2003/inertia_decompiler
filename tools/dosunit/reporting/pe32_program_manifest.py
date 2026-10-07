"""Checked initialized PE32 environment and complete named output denominator.

Layer: dosunit CLI contracts.
Responsibility: validate fully declared registers, initialized data allocations
and terminal gateway before loading either binary or starting either guest.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.dosunit.reporting.flat32_replay_cli import _u32
from tools.dosunit.runtime.flat32_memory_permissions import MAX_MAPPED_BYTES, MAX_PAGE_CLAIMS, DeclaredAccess
from tools.dosunit.runtime.flat32_replay_model import MemoryRange
from tools.dosunit.runtime.pe32_import_service import (
    MAX_IMPORT_BINDINGS,
    ImportResultKind,
    PeImportResult,
    PeImportService,
    ServiceFlagsPolicy,
)
from tools.dosunit.runtime.pe32_program_boot import PeProgramEnvironment, PeProgramMemory
from tools.dosunit.runtime.pe32_program_replay import PeProgramObservation


@dataclass(frozen=True, slots=True)
class PeProgramManifest:
    """Shared exact initial environment with paired named memory outputs."""

    environment: PeProgramEnvironment
    oracle_observations: tuple[PeProgramObservation, ...]
    candidate_observations: tuple[PeProgramObservation, ...]


def _object(value: object, name: str) -> dict[str, object]:
    """Require an explicit object with string keys at the JSON boundary."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name}: expected an object")
    return value


def _allocation(value: object) -> PeProgramMemory:
    """Read complete initial bytes and explicit nonexecutable access flags."""
    item = _object(value, "memory")
    if set(item) != {"address", "bytes", "access"}:
        raise ValueError("PE memory requires address, complete bytes and access")
    raw = item["bytes"]
    if not isinstance(raw, str):
        raise ValueError("PE memory bytes must be hexadecimal")
    if len(raw) > 2 * MAX_MAPPED_BYTES:
        raise ValueError("PE initial memory hexadecimal byte budget exceeded")
    try:
        data = bytes.fromhex(raw)
    except ValueError as error:
        raise ValueError("PE memory contains invalid hexadecimal bytes") from error
    access_names = item["access"]
    if not isinstance(access_names, list):
        raise ValueError("PE memory access requires a list")
    flags = {"read": DeclaredAccess.READ, "write": DeclaredAccess.WRITE}
    access = DeclaredAccess.NONE
    for name in access_names:
        if not isinstance(name, str) or name not in flags:
            raise ValueError("PE memory grants only explicit read/write access")
        access |= flags[name]
    return PeProgramMemory(_u32(item["address"], "memory address"), data, access)


def _outputs(value: object) -> tuple[tuple[PeProgramObservation, ...], tuple[PeProgramObservation, ...]]:
    """Validate both sides' complete names and sizes before guest execution."""
    if not isinstance(value, list):
        raise ValueError("PE observations require a list")
    if len(value) > MAX_PAGE_CLAIMS:
        raise ValueError("PE output count budget exceeded")
    left: list[PeProgramObservation] = []
    right: list[PeProgramObservation] = []
    names: set[str] = set()
    for raw in value:
        item = _object(raw, "observation")
        if set(item) != {"name", "size", "oracle_address", "candidate_address"}:
            raise ValueError("PE observation requires name, size and both addresses")
        name = item.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("PE observation names must be nonempty and unique")
        names.add(name)
        size = _u32(item.get("size"), "observation size")
        left.append(PeProgramObservation(name, MemoryRange(_u32(item.get("oracle_address"), "oracle output"), size)))
        right.append(PeProgramObservation(name, MemoryRange(_u32(item.get("candidate_address"), "candidate output"), size)))
    if sum(item.region.size for item in left) > MAX_MAPPED_BYTES:
        raise ValueError("PE output byte budget exceeded")
    return tuple(left), tuple(right)


def _service_result(value: object) -> PeImportResult:
    """Parse one declared DWORD response shape without inventing defaults."""
    item = _object(value, "service result")
    if item.get("kind") == "declared_dword":
        if set(item) != {"kind", "value"}:
            raise ValueError("declared dword results require exactly kind and value")
        return PeImportResult(ImportResultKind.DECLARED_DWORD, _u32(item["value"], "service result"))
    if item.get("kind") == "shared_opaque":
        if set(item) != {"kind"}:
            raise ValueError("opaque results declare no concrete value")
        return PeImportResult(ImportResultKind.SHARED_OPAQUE)
    raise ValueError("service result kind must be declared_dword or shared_opaque")


def _service(value: object) -> PeImportService:
    """Parse one fully declared returning-service contract."""
    item = _object(value, "service")
    if set(item) != {"dll", "name", "address", "result", "volatile", "flags"}:
        raise ValueError("PE service requires dll, name, address, result, volatile and flags")
    volatile = item["volatile"]
    if (
        not isinstance(volatile, list)
        or len(volatile) > 2
        or not all(isinstance(register, str) for register in volatile)
    ):
        raise ValueError("PE service volatile requires a bounded string list")
    dll, name = item["dll"], item["name"]
    if not isinstance(dll, str) or not isinstance(name, str):
        raise ValueError("PE service dll and name must be strings")
    flags = item["flags"]
    if not isinstance(flags, str):
        raise ValueError("PE service flags must be preserved or opaque")
    try:
        flag_policy = ServiceFlagsPolicy(flags)
    except ValueError as error:
        raise ValueError("PE service flags must be preserved or opaque") from error
    return PeImportService(
        dll, name, _u32(item["address"], "service address"),
        _service_result(item["result"]), tuple(volatile), flag_policy,
    )


def _services(value: object) -> tuple[PeImportService, ...]:
    """Parse the optional declared import-service set within its budget."""
    if not isinstance(value, list) or len(value) > MAX_IMPORT_BINDINGS:
        raise ValueError("PE service count exceeds the intake budget")
    return tuple(_service(item) for item in value)


def parse_pe_program_manifest(document: object) -> PeProgramManifest:
    """Parse all required initialized-state fields without inventing defaults."""
    root = _object(document, "PE program manifest")
    if set(root) - {"schema", "environment", "observations"}:
        raise ValueError("PE program manifest contains undeclared fields")
    if root.get("schema") != "dosunit.pe32_program_environment.v1":
        raise ValueError("unsupported PE program environment schema")
    declared = _object(root.get("environment"), "environment")
    if not {"registers", "memory", "exit_address"} <= set(declared) or set(declared) - {
        "registers", "memory", "exit_address", "services",
    }:
        raise ValueError("PE environment requires complete registers, memory and exit_address")
    registers = _object(declared["registers"], "registers")
    memory = declared["memory"]
    if not isinstance(memory, list):
        raise ValueError("PE environment memory requires a list")
    if len(memory) > MAX_PAGE_CLAIMS:
        raise ValueError("PE initial memory count budget exceeded")
    encoded = [_object(item, "memory").get("bytes") for item in memory]
    if sum(len(value) for value in encoded if isinstance(value, str)) > 2 * MAX_MAPPED_BYTES:
        raise ValueError("PE initial memory byte budget exceeded")
    environment = PeProgramEnvironment(
        tuple((name, _u32(value, name)) for name, value in sorted(registers.items())),
        tuple(_allocation(item) for item in memory), _u32(declared["exit_address"], "exit_address"),
        _services(declared.get("services", [])),
    )
    left, right = _outputs(root.get("observations", []))
    return PeProgramManifest(environment, left, right)
