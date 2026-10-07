"""Regression tests for software-interrupt callsite tag boundaries."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.rustylib.ailment import Tags
from inertia.frontend.x86_16.interrupt_contract import (
    DOS_SERVICE_BASE_ADDR,
    SoftwareInterruptServiceTargetFact8616,
    interrupt_core_addr_8616,
    record_software_interrupt_service_target_8616,
)
from inertia.lowering.software_interrupt_calls import (
    _callsite_addr_8616 as lowering_callsite_addr_8616,
)
from inertia.lowering.software_interrupt_calls import (
    materialize_software_interrupt_service_targets_8616,
)

from inertia.structuring.software_interrupt_returns import (
    _callsite_addr_8616 as structuring_callsite_addr_8616,
)
from inertia.validation.validation_interrupt_calls import (
    _callsite_addr_8616 as validation_callsite_addr_8616,
)


class _Codegen:
    def next_idx(self) -> int:
        return 1

    def next_node_idx(self) -> int:
        return 1

    def next_ident(self, _node_type: str) -> str:
        return "node_1"


def test_software_interrupt_callsite_accepts_current_angr_tags() -> None:
    call = structured_c.CFunctionCall(
        "interrupt_int33",
        None,
        [],
        tags=Tags({"ins_addr": 0x1020}),
        codegen=_Codegen(),
    )

    assert lowering_callsite_addr_8616(call) == 0x1020
    assert structuring_callsite_addr_8616(call) == 0x1020
    assert validation_callsite_addr_8616(call) == 0x1020


def test_software_interrupt_targets_follow_exact_tags_not_ast_order() -> None:
    """Service identity remains attached when structuring reverses call order."""
    codegen = _Codegen()
    exit_call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        tags=Tags({"ins_addr": 0x1030}),
        codegen=codegen,
    )
    print_call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        tags=Tags({"ins_addr": 0x1020}),
        codegen=codegen,
    )
    root = structured_c.CStatements([exit_call, print_call], codegen=codegen)
    targets = {
        0x1020: DOS_SERVICE_BASE_ADDR + 0x09,
        0x1030: DOS_SERVICE_BASE_ADDR + 0x4C,
    }
    function = SimpleNamespace(get_call_target=targets.get)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen.project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda *, addr: function if addr == 0x1000 else None)
        )
    )

    assert materialize_software_interrupt_service_targets_8616(codegen)
    assert exit_call.callee_target == DOS_SERVICE_BASE_ADDR + 0x4C
    assert print_call.callee_target == DOS_SERVICE_BASE_ADDR + 0x09


def test_software_interrupt_targets_survive_rebuilt_function_callsite_map() -> None:
    """Project evidence survives a rebuilt function with stale raw targets."""
    codegen = _Codegen()
    call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        tags=Tags({"ins_addr": 0x1030}),
        codegen=codegen,
    )
    root = structured_c.CStatements([call], codegen=codegen)
    function = SimpleNamespace(
        get_call_target=lambda _addr: interrupt_core_addr_8616(0x21)
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr: function if addr == 0x1000 else None
            )
        )
    )
    record_software_interrupt_service_target_8616(
        project,
        SoftwareInterruptServiceTargetFact8616(
            function_addr=0x1000,
            callsite_addr=0x1030,
            vector=0x21,
            target_addr=DOS_SERVICE_BASE_ADDR + 0x4C,
            helper_name="dos_exit",
        ),
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen.project = project

    assert materialize_software_interrupt_service_targets_8616(codegen)
    assert call.callee_target == "dos_exit"
