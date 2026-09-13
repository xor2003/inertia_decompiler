from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.lowering.callsite_prototype_declarations import (
    materialize_callsite_prototype_declarations_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
    StorageTrial8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
    StorageUseEvidence8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_solver import (
    resolve_program_storage_trials_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_transaction import (
    accepted_callsite_storage_binding_8616,
    accepted_stack_input_layout_8616,
    apply_program_storage_resolution_8616,
)
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    reconcile_exact_stack_argument_prototype_8616,
)


class _Codegen:
    def __init__(self, project: object) -> None:
        self.project = project
        self.cfunc: object | None = None
        self._next_index = 0
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}
        self._inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616] = {}
        self._inertia_callsite_prototype_decls: tuple[str, ...] = ()

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _stack_identity(offset: int) -> StorageIdentity8616:
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.STACK,
        width=2,
        address=IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=offset,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )


def _input_trial(
    *,
    logical_index: int,
    callsite_addr: int,
    signedness: StorageTrialSignedness8616,
    value_class: StorageTrialValueClass8616,
) -> StorageTrial8616:
    source_register = ("ax", "bx")[logical_index]
    source = StorageIdentity8616(
        kind=StorageIdentityKind8616.REGISTER,
        width=2,
        register=source_register,
    )
    return StorageTrial8616(
        callee_addr=0x2000,
        caller_addr=0x1000,
        callsite_addr=callsite_addr,
        role=StorageTrialRole8616.INPUT,
        logical_index=logical_index,
        piece_index=0,
        piece_count=1,
        storage=_stack_identity(4 + 2 * logical_index),
        reaching_definition=StorageReachingDefinition8616(
            value=IRValue(
                space=MemSpace.REG,
                name=source_register,
                size=2,
                version=logical_index + 1,
            ),
            block_addr=0x1000,
            instr_index=logical_index,
            instr_addr=callsite_addr - 4 + logical_index,
            source_storage=source,
        ),
        use=StorageUseEvidence8616(
            block_addr=0x1000,
            instr_index=logical_index + 2,
            instr_addr=callsite_addr,
            callsite_addr=callsite_addr,
        ),
        signedness=signedness,
        value_class=value_class,
    )


def _publish_two_argument_contract(project: object, callsite_addr: int = 0x1010) -> None:
    arguments = (
        _input_trial(
            logical_index=0,
            callsite_addr=callsite_addr,
            signedness=StorageTrialSignedness8616.SIGNED,
            value_class=StorageTrialValueClass8616.VALUE,
        ),
        _input_trial(
            logical_index=1,
            callsite_addr=callsite_addr,
            signedness=StorageTrialSignedness8616.UNSIGNED,
            value_class=StorageTrialValueClass8616.POINTER,
        ),
    )
    trials = FunctionStorageTrials8616(
        function_addr=0x2000,
        caller_census_complete=True,
        expected_callsite_addrs=(callsite_addr,),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=0x1000,
                callee_addr=0x2000,
                callsite_addr=callsite_addr,
                arguments=arguments,
                stack_delta=4,
            ),
        ),
    )
    resolution = resolve_program_storage_trials_8616((trials,))
    assert resolution.stats.complete is True
    assert apply_program_storage_resolution_8616(project, resolution) is True


def _summary(callsite_addr: int) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=0x2000,
        return_addr=callsite_addr + 3,
        kind="direct_near",
        arg_count=2,
        arg_widths=(4, 4),
        stack_cleanup=8,
        return_register=None,
        return_used=False,
    )


def _call_codegen(project: object, callsite_addr: int) -> _Codegen:
    codegen = _Codegen(project)
    short_type = SimTypeShort(False).with_arch(project.arch)
    call = CFunctionCall(
        "typed_target",
        None,
        [
            CConstant(1, short_type, codegen=codegen),
            CConstant(2, short_type, codegen=codegen),
        ],
        tags={"ins_addr": callsite_addr},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(callsite_addr)}
    return codegen


def test_declaration_consumes_proof_bearing_contract_types() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    _publish_two_argument_contract(project)
    codegen = _call_codegen(project, 0x1010)

    changed = materialize_callsite_prototype_declarations_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_prototype_decls == (
        "int typed_target(short a0, void *a1);",
    )
    binding = accepted_callsite_storage_binding_8616(project, 0x2000, 0x1010)
    assert binding is not None
    assert tuple(trial.reaching_definition.value.name for trial in binding.arguments) == (
        "ax",
        "bx",
    )


def test_declaration_refuses_callsite_missing_from_accepted_transaction() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    _publish_two_argument_contract(project)
    codegen = _call_codegen(project, 0x1020)

    changed = materialize_callsite_prototype_declarations_8616(project, codegen)

    assert changed is False
    assert codegen._inertia_callsite_prototype_decls == ()


def test_declaration_does_not_fallback_past_published_typed_refusal() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    trials = FunctionStorageTrials8616(
        function_addr=0x2000,
        caller_census_complete=False,
        expected_callsite_addrs=(0x1010,),
        callsites=(
            CallsiteStorageTrials8616(
                caller_addr=0x1000,
                callee_addr=0x2000,
                callsite_addr=0x1010,
                stack_delta=0,
            ),
        ),
    )
    resolution = resolve_program_storage_trials_8616((trials,))
    assert apply_program_storage_resolution_8616(project, resolution)
    codegen = _call_codegen(project, 0x1010)

    changed = materialize_callsite_prototype_declarations_8616(project, codegen)

    assert changed is False
    assert codegen._inertia_callsite_prototype_decls == ()


def test_callee_prototype_consumes_same_accepted_stack_layout() -> None:
    arch = Arch86_16()
    guessed_wide = SimTypeLong(False).with_arch(arch)
    prototype = SimTypeFunction(
        [guessed_wide, guessed_wide],
        SimTypeShort(False),
        arg_names=("left", "right"),
    ).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    functions = SimpleNamespace(
        function=lambda addr, create=False: function if addr == 0x2000 else None,
        values=lambda: (),
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=functions),
    )
    _publish_two_argument_contract(project)
    codegen = _Codegen(project)
    arguments = [
        CVariable(
            SimStackVariable(offset, 4, base="bp", name=name, region=0x2000),
            variable_type=guessed_wide,
            codegen=codegen,
        )
        for offset, name in ((4, "left"), (6, "right"))
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x2000,
        arg_list=arguments,
        functy=prototype,
        prototype=prototype,
        statements=None,
        unified_local_vars={},
    )

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is True
    assert accepted_stack_input_layout_8616(project, 0x2000) == ((4, 2), (6, 2))
    assert all(isinstance(arg_type, SimTypeShort) for arg_type in codegen.cfunc.functy.args)
    assert [argument.variable.size for argument in arguments] == [2, 2]
