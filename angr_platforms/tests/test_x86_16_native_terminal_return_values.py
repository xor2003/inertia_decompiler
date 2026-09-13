"""Keep proven return-register reads when native calling conventions are absent."""

from itertools import count
from types import SimpleNamespace

import networkx as nx
import pytest
from angr.ailment import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import Return
from angr.analyses.decompiler.clinic import Clinic
from angr.sim_type import SimTypeBottom, SimTypeFunction
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import native_terminal_return_values as binding
from angr_platforms.X86_16.lowering.native_terminal_return_values import bind_terminal_return_register_8616
from angr_platforms.X86_16.semantics.terminal_return_storage import TerminalReturnStorage8616


@pytest.mark.parametrize("storage", [TerminalReturnStorage8616.AL, TerminalReturnStorage8616.AH,
                                     TerminalReturnStorage8616.AX])
def test_empty_return_consumes_exact_proven_register(storage) -> None:
    arch = Arch86_16()
    original = Return(0, [], ins_addr=0x1000)
    block = Block(0x1000, 1, statements=[original])
    rewritten = bind_terminal_return_register_8616(block, arch, storage, count().__next__)
    value = rewritten.statements[-1].ret_exprs[0]
    offset, size = arch.registers[storage.value]
    assert isinstance(value, Register)
    assert (value.reg_offset, value.bits) == (offset, size * 8)
    assert original.ret_exprs == []
    assert rewritten.statements[-1].tags == original.tags


@pytest.mark.parametrize("storage", [None, TerminalReturnStorage8616.NONE,
                                     TerminalReturnStorage8616.CALL_OUTPUT, TerminalReturnStorage8616.DX_AX])
def test_unknown_or_unsupported_storage_does_not_invent_return(storage) -> None:
    block = Block(0x1000, 1, statements=[Return(0, [], ins_addr=0x1000)])
    assert bind_terminal_return_register_8616(block, Arch86_16(), storage, count().__next__) is block


def test_existing_return_value_is_not_replaced() -> None:
    block = Block(0x1000, 1, statements=[Return(0, [Const(1, 9, 16)], ins_addr=0x1000)])
    assert bind_terminal_return_register_8616(
        block, Arch86_16(), TerminalReturnStorage8616.AX, count().__next__,
    ) is block


@pytest.mark.parametrize("explicit_void", [False, True])
def test_native_clinic_binds_partial_return_contract_without_inventing_abi(monkeypatch, explicit_void) -> None:
    block = Block(0x1000, 1, statements=[Return(0, [], ins_addr=0x1000)])
    graph = nx.DiGraph()
    graph.add_node(block)
    prototype = SimTypeFunction([], SimTypeBottom(label="void")) if explicit_void else None
    function = SimpleNamespace(prototype=prototype, calling_convention=None)
    clinic = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), function=function,
        _ail_manager=SimpleNamespace(next_atom=count().__next__),
    )
    monkeypatch.setattr(binding, "terminal_return_storage_8616", lambda *_: TerminalReturnStorage8616.AX)
    result = Clinic._make_returns(clinic, graph)
    terminal = next(iter(result)).statements[-1]
    assert bool(terminal.ret_exprs) is not explicit_void
    assert function.prototype is prototype
    assert function.calling_convention is None
    if not explicit_void:
        report = clinic._inertia_terminal_return_binding_report_8616
        assert report.raw_fact_count == report.normalized_fact_count == report.classified_fact_count == 1
        assert report.materialized_count == 1
        assert report.failure_count == 0
