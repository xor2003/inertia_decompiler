"""Native conditional boundaries retain fallthrough writes and unsafe effects."""
from __future__ import annotations

import angr
import pytest
import pyvex
from test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

from tools.dosunit.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.flat32_call_lowering import _check_exits


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("changed_store", [False, True])
def test_jecxz_keeps_taken_and_store_fallthrough_paths(driver: str, changed_store: bool) -> None:
    """A skipped store is optional; changing its value on the other path matters."""
    original = "e302 8907 c3"  # JECXZ skips MOV [EDI],EAX and reaches RET.
    candidate = "e302 8917 c3" if changed_store else original
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: 5}, candidate_functions={BASE: 5},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == ("failed" if changed_store else "passed"), result


def test_effect_inside_exiting_instruction_is_still_refused() -> None:
    """Splitting later instructions must not admit effects after this Exit."""
    project = angr.load_shellcode(bytes.fromhex("e300"), arch="x86", load_address=BASE)
    block = project.factory.block(BASE, size=2, opt_level=0).vex
    exit_index = next(index for index, statement in enumerate(block.statements)
                      if isinstance(statement, pyvex.stmt.Exit))
    eax_offset = project.arch.registers["eax"][0]
    block.statements.insert(exit_index + 1, pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U32(1)), eax_offset))
    with pytest.raises(CallCompositionRefusal, match="effect_after_conditional_exit"):
        _check_exits(block, project.arch.ip_offset)


def test_native_division_fault_edge_is_still_refused() -> None:
    """Conditional control support does not erase native exception outcomes."""
    project = angr.load_shellcode(bytes.fromhex("f7f1c3"), arch="x86", load_address=BASE)
    block = project.factory.block(BASE, size=3, opt_level=0).vex
    with pytest.raises(CallCompositionRefusal, match="exception_edge"):
        _check_exits(block, project.arch.ip_offset)
