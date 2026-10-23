"""Freeze declared requests independently of child result and companion files."""
import hashlib
import json

import pytest

from tests.cli.test_real16_declared_entry_loading import loaded_entry as loaded_entry
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tools.compiler_toolchain import conditional_case_request as owner
from tools.compiler_toolchain.compiler_profile import FrozenCompilerContext

pytestmark = pytest.mark.decompiler


@pytest.fixture
def request_args(loaded_entry, monkeypatch):
    project, _ = loaded_entry
    context = FrozenCompilerContext('test', 'small', '/test', '/evidence', 'a'*64, 'b'*64)
    monkeypatch.setattr(FrozenCompilerContext, 'resolve', lambda self: None)
    return {'binary_path': project.loader.main_object.binary,
            'declaration_path': project._inertia_real16_declared_input_path_8616,
            'compiler_context': context, 'observations': b'{"expected_exit_code":255}'}


def _request(arguments):
    from pathlib import Path
    return owner.prepare_conditional_case_request(**{**arguments, 'binary_path': Path(arguments['binary_path'])})


def test_native_request_freezes_explicit_entry_project_and_exact_documents(request_args):
    result = _request(request_args)
    assert result.status is owner.ConditionalCaseRequestStatus.READY
    prepared = result.prepared
    assert prepared is not None and prepared.inputs_current()
    contract = prepared.contract
    document = json.loads(prepared.declaration_path.read_bytes())
    spec = document['function_entries'][0]
    assert contract.entry.address == (spec['entry_segment'] << 4) + spec['entry_offset']
    assert json.loads(contract.declarations[0][1]) == spec
    assert contract.observations == request_args['observations']
    assert contract.compiler_context is request_args['compiler_context']
    assert contract.mapped_base == prepared.project.loader.main_object.mapped_base
    assert all(target.name == target.emitted_name for target in contract.selected)
    assert contract.image_sha256 == hashlib.sha256(prepared.binary_path.read_bytes()).hexdigest()


@pytest.mark.parametrize('damage', ['binary', 'declaration'])
def test_later_input_mutation_invalidates_prepared_request(request_args, damage):
    prepared = _request(request_args).prepared
    assert prepared is not None
    path = prepared.binary_path if damage == 'binary' else prepared.declaration_path
    path.write_bytes(path.read_bytes() + b' ')
    assert not prepared.inputs_current()


def test_environment_only_request_preserves_ordinary_route(request_args):
    path = request_args['declaration_path']
    doc = json.loads(path.read_bytes())
    del doc['function_entries']
    path.write_text(json.dumps(doc))
    assert _request(request_args).status is owner.ConditionalCaseRequestStatus.NO_FUNCTION_ENTRY


def test_multiple_explicit_roots_are_refused(request_args, loaded_entry):
    project, _ = loaded_entry
    path = request_args['declaration_path']
    doc = json.loads(path.read_bytes())
    second = dict(doc['function_entries'][0])
    second['entry_offset'] += 1
    second['range_start'] += 1
    second['native_sha256'] = hashlib.sha256(bytes(project.loader.memory.load(
        second['range_start'], second['range_end']-second['range_start']))).hexdigest()
    doc['function_entries'].append(second)
    path.write_text(json.dumps(doc))
    assert _request(request_args).status is owner.ConditionalCaseRequestStatus.MULTIPLE_ROOTS


def test_changed_declaration_during_project_load_refuses(request_args, monkeypatch):
    original = owner._build_project

    def changing(*args, **kwargs):
        project = original(*args, **kwargs)
        path = request_args['declaration_path']
        path.write_bytes(path.read_bytes() + b' ')
        return project

    monkeypatch.setattr(owner, '_build_project', changing)
    assert _request(request_args).status is owner.ConditionalCaseRequestStatus.INPUT_CHANGED
