"""Explicit native application entries load without proving unsupported startup."""
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.cli.mz_static_intake import MzStaticIntakeStatus8616
from inertia.cli.real16_declared_project import build_declared_project_8616
from inertia.ir.declared_entry_pipeline import prepare_declared_entry_pipeline_8616
from inertia.ir.entry_domain_call_preservation import _real16_invocation_source_8616
from inertia.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes

pytestmark = pytest.mark.decompiler


@pytest.fixture
def loaded_entry(native_scope, tmp_path, monkeypatch):
    _old_project, link, scope, _proof = native_scope
    boot = scope.boot
    registers = dict(boot.environment.registers)
    registers["eflags"] = 2
    environment = replace(boot.environment, registers=tuple(registers.items()))
    spec = replace(link.admission.spec, environment_sha256=declared_environment_digest_8616(environment))
    document = {
        'schema': 'inertia.real16_declared_input.v1',
        'source_sha256': hashlib.sha256(boot.source).hexdigest(),
        'program': {'schema': 'dosunit.real16_program_environment.v1', 'environment': {
            'psp_segment': environment.psp_segment, 'allocation_hex': environment.allocation.hex(),
            'registers': dict(environment.registers), 'fs': environment.fs, 'gs': environment.gs,
            'dos_version': {'major': 5, 'minor': 0, 'oem': 0, 'serial24': 0},
            'dos_vectors': {'dos_entry': {'segment': 0xF000, 'offset': 0xF100}},
            'extra_memory': [{'segment': 0, 'offset': 0, 'data_hex': environment.extra_memory[0].data.hex()}],
        }},
        'services': [], 'function_entries': [spec.to_dict()],
    }
    binary = tmp_path / 'entry.exe'
    binary.write_bytes(boot.source)
    declaration = tmp_path / 'entry.json'
    declaration.write_text(json.dumps(document))

    def forbid_startup(*args, **kwargs):
        pytest.fail('explicit entry intake must not traverse startup inventory')

    monkeypatch.setattr('inertia.cli.mz_static_intake.build_invocation_inventory_8616', forbid_startup)
    project = build_declared_project_8616(binary, declaration, force_blob=False,
                                         base_addr=boot.image.load_segment, entry_point=boot.entry.linear())
    return project, spec


def test_loader_installs_declared_extent_only_and_initial_pipeline(loaded_entry):
    project, spec = loaded_entry
    request = project._inertia_mz_static_invocation_request_8616
    assert len(request.function_entries) == 1
    receipt = request.install(project)
    assert receipt.status is MzStaticIntakeStatus8616.DECLARED_ENTRIES_INSTALLED
    assert receipt.installed and receipt.inventory is None
    source = _real16_invocation_source_8616(project)
    assert source.function_entries == request.function_entries
    assert project.loader.memory.load(project.entry, 2) == b'\x0f\x0b'
    assert all(row.entry_addr == spec.range_start for row in source.callsite_index.caller_censuses)
    entry = prepare_declared_entry_pipeline_8616(project, SimpleNamespace(), spec.range_start)
    assert entry is not None
    assert entry.admission == request.function_entries[0]
    assert entry.scope.kind.value == 'declared_function_entry'


@pytest.mark.parametrize('mutation', ['revoke', 'replace', 'native', 'environment', 'source'])
def test_installed_source_reauthenticates_mutable_request(loaded_entry, mutation):
    project, spec = loaded_entry
    request = project._inertia_mz_static_invocation_request_8616
    assert request.install(project).installed
    source = _real16_invocation_source_8616(project)
    if mutation == 'revoke':
        request.function_entries = ()
    elif mutation == 'replace':
        entry = request.function_entries[0]
        request.function_entries = (replace(entry, spec=replace(entry.spec, entry_offset=0x21)),)
    elif mutation == 'native':
        project.loader.memory.store(spec.range_start, b'\x90')
    elif mutation == 'environment':
        request.declared_boot = program_from_mz_bytes(
            request.source, replace(request.declared_boot.environment, fs=1),
        )
    else:
        request.source = request.source[:-1] + b'\x90'
    assert not request.validate_installed_source_8616(project, source)
    assert project._inertia_real16_invocation_source_8616 is None
