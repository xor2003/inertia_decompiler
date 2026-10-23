"""Call declarations must consume available authoritative callee signedness."""
from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeShort

from inertia.lowering.authoritative_function_prototypes import publish_authoritative_function_prototype_8616
from inertia.lowering.callsite_prototype_declarations import _prototype_decl_8616
from inertia.lowering.interprocedural_storage_contracts import (
    CallsiteStorageBinding8616,
    CallsiteStorageTrials8616,
    FunctionStorageResolution8616,
    FunctionStorageTrials8616,
    ProgramStorageResolution8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
    StorageTrialVerdict8616,
)
from tests.lowering.test_x86_16_callsite_prototype_declarations import _Codegen, _summary
from tests.lowering.test_x86_16_interprocedural_storage_prototype_application import _contract, _slot

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("with_storage", [False, True, "liveout", "pointer", "wide-return"])
@pytest.mark.parametrize("result_type, expected", [(SimTypeShort(False), "unsigned short"), (SimTypeInt(True), "int")])
def test_signed_callee_snapshot_controls_scalar_declaration(result_type, expected, with_storage) -> None:
    """A word-sized physical caller summary must not overwrite signed callee inputs."""
    codegen = _Codegen()
    unsigned = SimTypeShort(False).with_arch(codegen.project.arch)
    signed = SimTypeShort(True).with_arch(codegen.project.arch)
    prototype = SimTypeFunction((signed, signed), result_type.with_arch(codegen.project.arch)).with_arch(codegen.project.arch)
    callee = SimpleNamespace(addr=0x2000, name='combine', prototype=prototype,
                             prototype_source=PrototypeSource.CCA_DECOMPILER, info={})
    codegen.project.kb = SimpleNamespace(functions=SimpleNamespace(
        function=lambda *, addr, create=False: callee if addr == callee.addr else None,
    ))
    publish_authoritative_function_prototype_8616(
        codegen.project, callee.addr, prototype, source=PrototypeSource.CCA_DECOMPILER,
    )
    call = CFunctionCall('combine', None, [CConstant(1, unsigned, codegen=codegen),
                                         CConstant(2, unsigned, codegen=codegen)], codegen=codegen)
    if with_storage:
        contract = _contract(inputs=tuple(_slot(
            StorageTrialRole8616.INPUT,index,2,StorageTrialSignedness8616.UNSIGNED,
            StorageTrialValueClass8616.POINTER if with_storage == "pointer" else StorageTrialValueClass8616.VALUE,offset=4+index*2,
        ) for index in range(2)))
        if with_storage == "liveout":
            contract = replace(contract, outputs=(_slot(
                StorageTrialRole8616.LIVE_OUT,0,2,StorageTrialSignedness8616.UNKNOWN,
                StorageTrialValueClass8616.UNKNOWN,register="sp",
            ),))
        elif with_storage == "wide-return":
            contract = replace(contract, outputs=(_slot(
                StorageTrialRole8616.RETURN,0,4,StorageTrialSignedness8616.UNSIGNED,
                StorageTrialValueClass8616.VALUE,register="eax",
            ),))
        contract = replace(contract,callsites=(CallsiteStorageBinding8616(0x1000,0x1010,(),(),4),))
        from inertia.lowering.interprocedural_storage_transaction import apply_program_storage_resolution_8616
        stats = StorageTrialStats8616(1,1,1,1)
        trials = FunctionStorageTrials8616(0x2000,True,(0x1010,),(
            CallsiteStorageTrials8616(0x1000,0x2000,0x1010,stack_delta=4),
        ))
        resolution = ProgramStorageResolution8616((trials,),(
            FunctionStorageResolution8616(0x2000,StorageTrialVerdict8616.ACCEPTED,contract,(),stats),
        ),((0x2000,),),(1,),stats)
        assert apply_program_storage_resolution_8616(codegen.project,resolution)
    result = _prototype_decl_8616(codegen.project, codegen, call, _summary(0x1010), 'unsigned short')
    if with_storage == "pointer":
        assert result is not None and result.count("*") == 2
        assert result.startswith("unsigned short ")
    elif with_storage == "wide-return":
        assert result is None
    else:
        assert result == f'{expected} combine(short a0, short a1);'


def test_transported_scalar_interface_does_not_require_callee_function(tmp_path):
    """A caller-only CFG still consumes the independently accepted callee receipt."""
    from inertia.lowering.scalar_interface_transport import (
        attach_scalar_interface_8616,
        scalar_interface_for_result_8616,
    )
    from tests.lowering.test_scalar_interface_transport import _world
    project, function, _ = _world(tmp_path)
    receipt = scalar_interface_for_result_8616(project, function.addr, 'typed fixture')
    assert receipt is not None
    attach_scalar_interface_8616(project, receipt)
    project.kb.functions.function = lambda **kwargs: None
    codegen = _Codegen()
    codegen.project = project
    word = SimTypeShort(False).with_arch(project.arch)
    call = CFunctionCall('combine', None, [CConstant(1,word,codegen=codegen)],codegen=codegen)
    assert _prototype_decl_8616(project,codegen,call,_summary(0x1010,arg_count=1),'unsigned short') == 'int combine(short a0);'
