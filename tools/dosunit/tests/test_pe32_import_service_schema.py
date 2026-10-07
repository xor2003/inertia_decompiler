"""Pure JSON schema controls for declared PE services and terminal receipts."""

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator


def _schema_directory() -> Path:
    """Use the repository schemas, with an explicit private-stage override."""
    override = os.environ.get("SERVICE_SCHEMA_DIR")
    if override is not None:
        return Path(override)
    for directory in Path(__file__).resolve().parents:
        schemas = directory / "tools/dosunit/schemas"
        if schemas.is_dir():
            return schemas
    raise RuntimeError("repository tools/dosunit/schemas directory not found")


SCHEMAS = _schema_directory()


def _schema(name: str) -> Draft202012Validator:
    """Load and validate the selected schema before exercising its contract."""
    schema = json.loads((SCHEMAS / f"dosunit.{name}.v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _service() -> dict[str, Any]:
    """Return one complete declaration using the public JSON representation."""
    return {"dll": "KERNEL32.DLL", "name": "GetTickCount", "address": "0x71000000",
            "result": {"kind": "declared_dword", "value": 4294967295},
            "volatile": ["ecx", "edx"], "flags": "opaque"}


def _environment(services: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Construct a complete initialized environment with explicit services."""
    return {"schema": "dosunit.pe32_program_environment.v1", "environment": {
        "registers": dict.fromkeys(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"), 0),
        "memory": [], "exit_address": 0, "services": services,
    }}


@pytest.mark.parametrize("result", [
    {"kind": "declared_dword", "value": 0},
    {"kind": "declared_dword", "value": 4294967295},
    {"kind": "declared_dword", "value": "4294967295"},
    {"kind": "declared_dword", "value": "0xFFFFFFFF"},
    {"kind": "shared_opaque"},
])
def test_declared_service_shapes(result: dict[str, Any]) -> None:
    """Admit both exact DWORD declarations and value-free opaque responses."""
    service = _service()
    service["result"] = result
    _schema("pe32_program_environment").validate(_environment([service]))


@pytest.mark.parametrize("change", [
    {"result": {"kind": "shared_opaque", "value": None}},
    {"result": {"kind": "shared_opaque", "value": 1}},
    {"result": {"kind": "declared_dword"}},
    {"result": {"kind": "declared_dword", "value": -1}},
    {"result": {"kind": "declared_dword", "value": 4294967296}},
    {"result": {"kind": "declared_dword", "value": "4294967296"}},
    {"result": {"kind": "declared_dword", "value": "0x100000000"}},
    {"result": {"kind": "declared_dword", "value": True}},
    {"dll": "bad/path.dll"}, {"dll": "x" * 125 + ".dll"},
    {"dll": "kernel32.dll\n"}, {"name": "é"}, {"name": "x" * 129},
    {"name": ""}, {"name": "Get Tick Count"},
    {"volatile": ["eax"]}, {"volatile": ["ecx"] * 3},
    {"flags": "guessed"}, {"address": False}, {"address": "0x100000000"},
    {"unexpected": 1},
])
def test_malformed_services_refuse(change: dict[str, Any]) -> None:
    """Reject malformed declarations without silently supplying missing fields."""
    service = _service() | change
    assert not _schema("pe32_program_environment").is_valid(_environment([service]))


def test_service_count_and_omission() -> None:
    """Bound service count and distinguish omitted services from explicit null."""
    validator = _schema("pe32_program_environment")
    validator.validate(_environment([]))
    validator.validate(_environment([_service() for _ in range(16)]))
    assert not validator.is_valid(_environment([_service() for _ in range(17)]))
    assert not validator.is_valid(_environment(None))
    omitted = _environment([])
    del omitted["environment"]["services"]
    validator.validate(omitted)


def test_case_sensitive_symbol_and_duplicate_volatile_are_preserved_by_schema() -> None:
    """Validation preserves export case and leaves canonicalization to intake."""
    document = _environment([_service() | {"name": "gEtTickCount", "volatile": ["ecx", "ecx"]}])
    original = deepcopy(document)
    _schema("pe32_program_environment").validate(document)
    assert document == original


REAL16 = {"kind": "dos_version", "address": 4096, "vector": 33, "function": 48, "data": "cd21"}
PE32 = {"kind": "pe32_import", "service": "kernel32.dll!GetTickCount", "slot": 0x402060,
        "site": 0x401000, "sequence": 0}


def _report(event: dict[str, Any]) -> dict[str, Any]:
    """Build a complete unproved report without importing the native pipeline."""
    return {"schema": "dosunit.symbolic_terminal_compare.v1", "status": "unknown",
            "terminal_status": "unknown", "execution_status": "not_run", "architecture": "flat32",
            "service": None, "assumptions": [],
            "domain": {"instruction_memory": "immutable", "external_effects": "not_established",
                       "faults": "refused", "initial_data": "shared_unconstrained"},
            "counters": dict.fromkeys(("raw_fact_count", "normalized_fact_count", "classified_fact_count",
                                       "materialized_count", "failure_count"), 0),
            "oracle": {"service_events": [event]}, "candidate": {},
            "inputs": [{"path": "fixture", "sha256": "0" * 64}] * 3}


@pytest.mark.parametrize("event", [REAL16, REAL16 | {"kind": "bios_video_query", "vector": 16, "function": 15}, PE32])
def test_terminal_event_variants(event: dict[str, Any]) -> None:
    """Admit real16 service records and distinct PE import records."""
    _schema("symbolic_terminal_compare").validate(_report(event))


@pytest.mark.parametrize("event", [
    PE32 | {"address": 1}, REAL16 | {"slot": 1}, PE32 | {"kind": "dos_version"},
    PE32 | {"sequence": -1}, PE32 | {"slot": 4294967296}, PE32 | {"site": True},
    PE32 | {"service": "kernel32.dll!"}, PE32 | {"service": "KERNEL32.DLL!GetTickCount"},
    {key: value for key, value in PE32.items() if key != "sequence"},
])
def test_mixed_or_malformed_terminal_events_refuse(event: dict[str, Any]) -> None:
    """Reject mixed variant fields, missing identities and invalid addresses."""
    assert not _schema("symbolic_terminal_compare").is_valid(_report(event))


@pytest.mark.parametrize("limits,valid", [
    ({"max_blocks": 16, "max_block_bytes": 256, "max_instructions": 128}, True),
    ({"max_blocks": 0, "max_block_bytes": 256, "max_instructions": 128}, False),
    ({"max_blocks": 16}, False),
    ({"max_blocks": True, "max_block_bytes": 256, "max_instructions": 128}, False),
    ({"max_blocks": 16, "max_block_bytes": 256, "max_instructions": 128, "extra": 1}, False),
])
def test_native_limit_receipt(limits: dict[str, int], valid: bool) -> None:
    """Require a complete positive integer budget whenever limits are emitted."""
    document = _report(REAL16)
    document["oracle"]["native_limits"] = limits
    assert _schema("symbolic_terminal_compare").is_valid(document) is valid


def test_existing_real16_event_schema_is_unchanged() -> None:
    """Keep the real16 service-event contract exact across the PE extension."""
    expected = {
        "type": "object",
        "required": ["kind", "address", "vector", "function", "data"],
        "properties": {
            "kind": {"enum": ["dos_version", "bios_video_query"]},
            "address": {"type": "integer", "minimum": 0},
            "vector": {"enum": [16, 33]},
            "function": {"enum": [15, 48]},
            "data": {"type": "string", "pattern": "^(?:[0-9a-f]{2})+$"},
        },
        "additionalProperties": False,
    }
    changed = json.loads((SCHEMAS / "dosunit.symbolic_terminal_compare.v1.schema.json").read_text())
    assert changed["$defs"]["lane"]["properties"]["service_events"]["items"]["oneOf"][0] == expected
