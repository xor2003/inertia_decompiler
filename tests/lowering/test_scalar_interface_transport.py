"""Preserve exact accepted C scalar kind across JSON evidence encoding."""
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeLong, SimTypeShort

from inertia.lowering.authoritative_function_prototypes import publish_authoritative_function_prototype_8616
from inertia.lowering.scalar_interface_transport import (
    _scalar,
    attach_scalar_interface_8616,
    scalar_interface_for_result_8616,
    scalar_interface_from_record_8616,
)
from tests.lowering.test_x86_16_callsite_prototype_declarations import _Codegen

pytestmark = pytest.mark.decompiler


def _world(tmp_path, result_type=SimTypeInt):
    project = _Codegen().project
    binary = tmp_path / 'source.bin'
    binary.write_bytes(b'\xc3')
    argument = SimTypeShort(True).with_arch(project.arch)
    prototype = SimTypeFunction((argument,), result_type(True).with_arch(project.arch)).with_arch(project.arch)
    function = SimpleNamespace(addr=0x2000, size=1, prototype=prototype,
                               prototype_source=PrototypeSource.CCA_DECOMPILER, info={})
    function.block_addrs_set = {function.addr}
    function.get_block_size = lambda addr: function.size
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda **_: function))
    project.loader = SimpleNamespace(main_object=SimpleNamespace(binary=str(binary), mapped_base=0),
                                     memory=SimpleNamespace(load=lambda addr, size: binary.read_bytes()))
    publish_authoritative_function_prototype_8616(project, function.addr, prototype,
                                                  source=PrototypeSource.CCA_DECOMPILER)
    function.project = project
    return project, function, binary


@pytest.mark.parametrize('kind', [SimTypeInt, SimTypeLong, SimTypeShort])
def test_scalar_kind_roundtrip(tmp_path, kind):
    project, function, _ = _world(tmp_path, kind)
    receipt = scalar_interface_for_result_8616(project, function.addr, 'accepted-payload')
    assert receipt is not None
    restored = scalar_interface_from_record_8616(json.loads(json.dumps(receipt.to_record())))
    assert restored == receipt
    assert restored.result == _scalar(kind(True).with_arch(project.arch))
    attach_scalar_interface_8616(project, restored)


def test_changed_native_source_refuses(tmp_path):
    project, function, binary = _world(tmp_path)
    receipt = scalar_interface_for_result_8616(project, function.addr, 'accepted-payload')
    assert receipt is not None
    binary.write_bytes(b'\xcc')
    with pytest.raises(ValueError, match='stale'):
        attach_scalar_interface_8616(project, receipt)


def test_kind_width_conflict_refuses(tmp_path):
    project, function, _ = _world(tmp_path)
    receipt = scalar_interface_for_result_8616(project, function.addr, 'accepted-payload')
    assert receipt is not None
    malformed = replace(receipt, result=replace(receipt.result, width=1))
    with pytest.raises(ValueError, match='kind/width'):
        attach_scalar_interface_8616(project, malformed)


def test_sparse_native_extent_covers_last_block(tmp_path):
    project, function, binary = _world(tmp_path)
    binary.write_bytes(b"\xc3" + b"\x90" * 15 + b"\xc3")
    function.block_addrs_set = {function.addr, function.addr + 16}
    receipt = scalar_interface_for_result_8616(project, function.addr, 'accepted-payload')
    assert receipt is not None and receipt.native_size == 17
    project.loader.memory.load = lambda addr, size: b"\xc3" + b"\x90" * 15 + b"\xcc"
    with pytest.raises(ValueError, match='stale'):
        attach_scalar_interface_8616(project, receipt)
