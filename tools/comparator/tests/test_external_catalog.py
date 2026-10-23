"""External ABI catalogs are explicit, bounded and source-bound."""

import hashlib
import json
from pathlib import Path

import pytest

from tools.comparator.external_catalog import load_external_catalog

pytestmark = pytest.mark.ssa_z3


def catalog(tmp_path: Path, imports: list) -> Path:
    path = tmp_path / "external.json"
    path.write_text(json.dumps({"schema": "dosunit.flat32_external_calls.v1", "functions": {"root": imports}}))
    return path


def test_explicit_contract_and_hash(tmp_path: Path) -> None:
    path = catalog(tmp_path, [{"dll": "KERNEL32.dll", "name": "HeapAlloc", "argument_count": 3, "cleanup": "callee"}])
    contracts, binding = load_external_catalog(path, "matched-cfg")
    assert contracts["root"][0].argument_count == 3
    assert contracts["root"][0].dll == "kernel32.dll"
    assert binding["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("field,value", [("argument_count", True), ("cleanup", "guess"), ("name", ""), ("purity", True)])
def test_invalid_contract_refused(tmp_path: Path, field: str, value: object) -> None:
    item = {"dll": "kernel32.dll", "name": "HeapAlloc", "argument_count": 3, "cleanup": "callee", field: value}
    with pytest.raises(ValueError):
        load_external_catalog(catalog(tmp_path, [item]), "matched-cfg")


def test_duplicate_identity_refused(tmp_path: Path) -> None:
    item = {"dll": "kernel32.dll", "name": "HeapAlloc", "argument_count": 3, "cleanup": "callee"}
    with pytest.raises(ValueError, match="duplicate"):
        load_external_catalog(catalog(tmp_path, [item, item]), "matched-cfg")


def test_unsupported_mode_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="matched-cfg"):
        load_external_catalog(tmp_path / "absent.json", "auto")


@pytest.mark.parametrize("preserve", [True, False])
def test_explicit_iat_preservation_roundtrip(tmp_path: Path, preserve: bool) -> None:
    path = catalog(tmp_path, [{"dll": "kernel32.dll", "name": "HeapAlloc", "argument_count": 3,
                              "cleanup": "callee", "preserve_import_bindings": preserve}])
    contracts, _ = load_external_catalog(path, "matched-cfg")
    assert contracts["root"][0].declared_fields()["preserve_import_bindings"] is preserve


@pytest.mark.parametrize("memory_access", ["none", "arbitrary", "guess"])
def test_explicit_memory_access_roundtrip(tmp_path: Path, memory_access: str) -> None:
    path = catalog(tmp_path, [{"dll": "kernel32.dll", "name": "Example", "argument_count": 0,
                              "cleanup": "callee", "memory_access": memory_access}])
    if memory_access == "guess":
        with pytest.raises(ValueError):
            load_external_catalog(path, "matched-cfg")
    else:
        contracts, _ = load_external_catalog(path, "matched-cfg")
        assert contracts["root"][0].declared_fields()["memory_access"] == memory_access


def test_return_region_catalog_retains_explicit_footprint(tmp_path: Path) -> None:
    """The catalog binds region size to an argument without inferring API behavior."""
    path = catalog(tmp_path, [{"dll": "kernel32.dll", "name": "HeapAlloc", "argument_count": 3,
                              "cleanup": "callee", "memory_access": "returned_region", "write_size_argument": 2}])
    contracts, _ = load_external_catalog(path, "matched-cfg")
    fields = contracts["root"][0].declared_fields()
    assert fields["write_size_argument"] == 2
    assert fields["memory_access"] == "returned_region"
    assert fields["freshness_assumed"] is False


def test_argument_region_catalog_retains_fixed_footprint(tmp_path: Path) -> None:
    """Output-only arguments require an explicit pointer index and byte count."""
    path = catalog(tmp_path, [{"dll": "kernel32.dll", "name": "ExampleOut", "argument_count": 1,
                              "cleanup": "callee", "memory_access": "argument_region",
                              "write_address_argument": 0, "write_size_bytes": 16}])
    contracts, binding = load_external_catalog(path, "matched-cfg")
    fields = contracts["root"][0].declared_fields()
    assert fields["write_address_argument"] == 0
    assert fields["write_size_bytes"] == 16
    assert fields["dependencies"] == ["external_history", "ordered_arguments"]
    assert binding["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
