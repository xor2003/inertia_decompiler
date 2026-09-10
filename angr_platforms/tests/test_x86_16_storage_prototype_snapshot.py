"""Accepted storage contracts must survive authoritative prototype replay."""

from types import SimpleNamespace

import pytest
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    publish_authoritative_function_prototype_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_prototype_application import (
    apply_accepted_function_storage_prototype_8616,
)
from test_x86_16_interprocedural_storage_prototype_application import _Codegen, _contract, _publish, _slot


@pytest.mark.parametrize("already_applied", [False, True])
def test_storage_prototype_application_refreshes_replay_snapshot(already_applied):
    arch = Arch86_16()
    scalar = SimTypeFunction([], SimTypeShort(False)).with_arch(arch)
    function = SimpleNamespace(addr=0x2000, prototype=scalar, is_prototype_guessed=False)
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **kwargs: function)))
    _publish(project, _contract(outputs=(
        _slot(StorageTrialRole8616.RETURN, 0, 2, StorageTrialSignedness8616.NOT_APPLICABLE,
              StorageTrialValueClass8616.POINTER, register="ax"),
    )))
    codegen = _Codegen(project)
    codegen.cfunc = SimpleNamespace(addr=0x2000, arg_list=[], functy=scalar)
    if already_applied:
        apply_accepted_function_storage_prototype_8616(project, codegen)
    publish_authoritative_function_prototype_8616(
        project, 0x2000, scalar, source=PrototypeSource.CCA_DECOMPILER,
    )

    apply_accepted_function_storage_prototype_8616(project, codegen)

    assert isinstance(codegen.cfunc.functy.returnty, SimTypePointer)
    snapshot = authoritative_function_prototype_8616(project, function, argument_count=0)
    assert snapshot is not None
    assert isinstance(snapshot.returnty, SimTypePointer)
    assert snapshot == codegen.cfunc.functy
