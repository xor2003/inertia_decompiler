"""Source-bound MZ loading and live declaration freshness controls."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from inertia.cli.mz_static_intake import MzStaticIntakeRequest8616
from inertia.cli.project_loading import _build_project, _build_project_cached, declared_input_path_8616
from inertia.frontend.x86_16.load_dos_mz import DOSMZ


@pytest.fixture
def declared_files(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    """Build a tiny plain MZ and an explicit whole-program input."""
    header = bytearray(64)
    header[:2] = b"MZ"
    for offset, value in ((2, 65), (4, 1), (8, 4), (12, 0xFFFF), (16, 0xFF00), (24, 0x1C)):
        header[offset:offset + 2] = value.to_bytes(2, "little")
    source = bytes(header) + b"\xc3"
    binary = tmp_path / "PROGRAM.EXE"
    binary.write_bytes(source)
    registers = dict.fromkeys(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"), 0)
    registers.update(esp=0xFF00, eflags=0x202)
    document: dict[str, object] = {
        "schema": "inertia.real16_declared_input.v1",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "program": {
            "schema": "dosunit.real16_program_environment.v1",
            "environment": {"psp_segment": 0x1000, "allocation_hex": bytes(0x10000).hex(),
                            "registers": registers, "fs": 0, "gs": 0},
        },
        "services": [],
    }
    declaration = tmp_path / "input.json"
    declaration.write_text(json.dumps(document))
    return binary, declaration, document


def test_declared_project_retains_exact_boot_and_deferred_authority(declared_files):
    binary, declaration, _ = declared_files
    project = _build_project(binary, force_blob=False, base_addr=0x1010,
                             entry_point=0x10100, real16_declared_input=declaration)
    assert isinstance(project.loader.main_object, DOSMZ)
    assert project.entry == 0x10100
    assert declared_input_path_8616(project) == declaration.resolve()
    request = project._inertia_mz_static_invocation_request_8616
    assert isinstance(request, MzStaticIntakeRequest8616)
    assert request.source == binary.read_bytes()
    assert request.declared_boot.source == request.source
    assert request.declared_boot_recompute(request.declared_boot) == request.declared_boot
    assert request.declared_services == ()


@pytest.mark.parametrize("force_blob,base,entry", [(True, 0x1010, 0x10100),
                                                  (False, 0x10101, 0x10100),
                                                  (False, 0x1010, 0x10101)])
def test_conflicting_load_never_falls_back(declared_files, force_blob, base, entry):
    binary, declaration, _ = declared_files
    with pytest.raises(ValueError):
        _build_project(binary, force_blob=force_blob, base_addr=base,
                       entry_point=entry, real16_declared_input=declaration)


def test_changed_source_refuses_before_project_construction(declared_files, monkeypatch):
    binary, declaration, _ = declared_files
    binary.write_bytes(binary.read_bytes()[:-1] + b"\x90")

    def forbid(*args, **kwargs):
        pytest.fail("a foreign source must refuse before angr construction")

    monkeypatch.setattr("inertia.cli.real16_declared_project.angr.Project", forbid)
    with pytest.raises(ValueError, match="source"):
        _build_project(binary, force_blob=False, base_addr=0x1010,
                       entry_point=0x10100, real16_declared_input=declaration)


def test_live_declaration_rebuilds_after_same_path_input_change(declared_files):
    binary, declaration, document = declared_files
    first = _build_project_cached(str(binary), force_blob=False, base_addr=0x1010,
                                  entry_point=0x10100, real16_declared_input=declaration)
    document["program"]["environment"]["registers"]["eax"] = 0x12345678
    declaration.write_text(json.dumps(document))
    second = _build_project_cached(str(binary), force_blob=False, base_addr=0x1010,
                                   entry_point=0x10100, real16_declared_input=declaration)
    assert first is not second
    original = first._inertia_mz_static_invocation_request_8616.declared_boot
    updated = second._inertia_mz_static_invocation_request_8616.declared_boot
    assert original.boot_sha256 != updated.boot_sha256
    assert dict(updated.environment.registers)["eax"] == 0x12345678


def test_low_linear_loader_base_is_preserved_on_isolated_rebuild(declared_files):
    binary, declaration, document = declared_files
    document["program"]["environment"]["psp_segment"] = 0x100
    declaration.write_text(json.dumps(document))
    first = _build_project(binary, force_blob=False, base_addr=0x110,
                           entry_point=0x1100, real16_declared_input=declaration)
    second = _build_project_cached(str(binary), force_blob=False,
                                   base_addr=first.loader.main_object.linked_base,
                                   entry_point=first.entry,
                                   real16_declared_input=declared_input_path_8616(first))
    assert first is not second
    assert second.entry == first.entry == 0x1100
    assert second.loader.main_object.mz_load_segment == 0x110


def test_extended_executable_stub_is_not_admitted_as_real16(declared_files):
    binary, declaration, document = declared_files
    source = bytearray(binary.read_bytes())
    source[0x3C:0x40] = (0x40).to_bytes(4, "little")
    source[0x40:] = b"PE\0\0"
    binary.write_bytes(source)
    document["source_sha256"] = hashlib.sha256(source).hexdigest()
    declaration.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="plain DOS MZ"):
        _build_project(binary, force_blob=False, base_addr=0x1010,
                       entry_point=0x10100, real16_declared_input=declaration)
