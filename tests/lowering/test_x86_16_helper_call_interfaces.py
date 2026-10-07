from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CFunctionCall,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimMemoryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.helper_call_interfaces import (
    materialize_known_helper_call_interfaces_8616,
)
from inertia.lowering.near_pointer_type import SimTypeNearPointer16_8616
from inertia.lowering.semantic_cast import CSemanticCast8616


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        arch = Arch86_16()
        arch.bits = 32
        self.project = SimpleNamespace(arch=arch)
        self.cfunc: object | None = None
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _helper_call_surface() -> tuple[_Codegen, CFunctionCall, SimpleNamespace]:
    codegen = _Codegen()
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    callee = SimpleNamespace(
        addr=0x2000,
        name="ERROR",
        prototype=SimTypeFunction([short_type], short_type).with_arch(codegen.project.arch),
        is_prototype_guessed=False,
    )
    global_value = CVariable(
        SimMemoryVariable(0x7000, 2, name="SG452"),
        variable_type=short_type,
        codegen=codegen,
    )
    call = CFunctionCall(
        "ERROR",
        callee,
        [CUnaryOp("Reference", global_value, codegen=codegen)],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    root = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_callsite_summaries[id(call)] = CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x2000,
        return_addr=0x1013,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
    )
    return codegen, call, callee


def test_known_helper_interface_refines_exact_pointer_abi_and_is_idempotent() -> None:
    codegen, call, callee = _helper_call_surface()

    assert materialize_known_helper_call_interfaces_8616(codegen.project, codegen)

    assert isinstance(callee.prototype, SimTypeFunction)
    assert callee.prototype.variadic
    assert isinstance(callee.prototype.args[0], SimTypeNearPointer16_8616)
    assert callee.prototype.args[0].size == 16
    assert isinstance(callee.prototype.args[0].pts_to, SimTypeChar)
    assert isinstance(call.args[0], CSemanticCast8616)
    assert codegen._inertia_known_helper_call_interface_stats_8616.raw_fact_count == 1
    assert codegen._inertia_known_helper_call_interface_stats_8616.classified_fact_count == 1
    assert codegen._inertia_known_helper_call_interface_stats_8616.materialized_count == 1
    assert codegen._inertia_known_helper_call_interface_stats_8616.failure_count == 0

    assert not materialize_known_helper_call_interfaces_8616(codegen.project, codegen)
    assert codegen._inertia_known_helper_call_interface_stats_8616.materialized_count == 1


def test_known_helper_interface_refuses_name_without_exact_callsite_identity() -> None:
    codegen, call, callee = _helper_call_surface()
    original_prototype = callee.prototype
    codegen._inertia_callsite_summaries = {}

    assert not materialize_known_helper_call_interfaces_8616(codegen.project, codegen)

    assert callee.prototype is original_prototype
    assert not isinstance(call.args[0], CSemanticCast8616)
    assert codegen._inertia_known_helper_call_interface_stats_8616.raw_fact_count == 1
    assert codegen._inertia_known_helper_call_interface_stats_8616.classified_fact_count == 0
    assert codegen._inertia_known_helper_call_interface_stats_8616.failure_count == 1


def test_known_helper_interface_refuses_scalar_to_pointer_recovery() -> None:
    codegen, call, callee = _helper_call_surface()
    original_prototype = callee.prototype
    short_type = SimTypeShort(False).with_arch(codegen.project.arch)
    call.args = [CConstant(0x7000, short_type, codegen=codegen)]

    assert not materialize_known_helper_call_interfaces_8616(codegen.project, codegen)

    assert callee.prototype is original_prototype
    assert not isinstance(call.args[0], CSemanticCast8616)
    assert codegen._inertia_known_helper_call_interface_stats_8616.raw_fact_count == 1
    assert codegen._inertia_known_helper_call_interface_stats_8616.classified_fact_count == 0
    assert codegen._inertia_known_helper_call_interface_stats_8616.failure_count == 1
