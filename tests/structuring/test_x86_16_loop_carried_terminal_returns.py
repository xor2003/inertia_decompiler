from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDoWhileLoop,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.structuring.loop_carried_terminal_returns as loop_carried_terminal_returns

from inertia.semantics.terminal_return_storage import TerminalReturnStorage8616
from inertia.structuring.loop_carried_terminal_return_contracts import (
    LoopCarriedTerminalReturnRefusal8616,
    LoopCarriedTerminalReturnStatus8616,
)
from inertia.structuring.loop_carried_terminal_returns import (
    materialize_loop_carried_terminal_return_8616,
)


class _Codegen(SimpleNamespace):
    def __init__(self, arch: Arch86_16) -> None:
        super().__init__(cstyle_null_cmp=False, project=SimpleNamespace(arch=arch))
        self._indices: dict[str, int] = {}

    def next_idx(self, kind: str) -> int:
        index = self._indices.get(kind, 0)
        self._indices[kind] = index + 1
        return index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


_AST_CODEGEN = _Codegen(Arch86_16())


class _FunctionManager:
    def __init__(self, function: SimpleNamespace) -> None:
        self.function_value = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self.function_value if addr == self.function_value.addr else None


def _word_type() -> SimTypeShort:
    return SimTypeShort(signed=False).with_arch(Arch86_16())


def _register(offset: int, size: int) -> CVariable:
    return CVariable(
        SimRegisterVariable(offset, size),
        variable_type=SimTypeShort(signed=False),
        codegen=_AST_CODEGEN,
    )


def _temporary(tmp_id: int) -> CVariable:
    return CVariable(
        SimTemporaryVariable(tmp_id, 2),
        variable_type=SimTypeShort(signed=False),
        codegen=_AST_CODEGEN,
    )


def _codegen(loop: object, return_node: CReturn) -> tuple[SimpleNamespace, SimpleNamespace]:
    arch = Arch86_16()
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000})
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=_FunctionManager(function)),
    )
    cfunc = SimpleNamespace(
        addr=function.addr,
        functy=SimTypeFunction([], SimTypeShort(signed=False)).with_arch(arch),
        statements=CStatements([loop, return_node], codegen=_AST_CODEGEN),
    )
    _AST_CODEGEN.cfunc = cfunc
    return project, _AST_CODEGEN


def _full_ax_assignment(rhs: object) -> CAssignment:
    return CAssignment(
        _register(0, 2),
        rhs,
        codegen=_AST_CODEGEN,
        tags={"ins_addr": 0x1010, "vex_block_addr": 0x100B},
    )


def test_loop_carried_terminal_ax_becomes_one_typed_local(monkeypatch) -> None:
    source = _temporary(1)
    assignment = _full_ax_assignment(source)
    consumer = CAssignment(_temporary(2), _register(0, 2), codegen=_AST_CODEGEN)
    loop = CDoWhileLoop(
        CConstant(1, _word_type(), codegen=_AST_CODEGEN),
        CStatements([assignment, consumer], codegen=_AST_CODEGEN),
        codegen=_AST_CODEGEN,
    )
    return_node = CReturn(None, codegen=_AST_CODEGEN)
    project, codegen = _codegen(loop, return_node)
    monkeypatch.setattr(
        loop_carried_terminal_returns,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_loop_carried_terminal_return_8616(project, codegen)

    assert result.status is LoopCarriedTerminalReturnStatus8616.MATERIALIZED
    assert result.evidence.raw_fact_count == 1
    assert result.evidence.normalized_fact_count == 1
    assert result.evidence.classified_fact_count == 1
    assert result.evidence.materialized_count == 1
    assert result.evidence.failure_count == 0
    assert isinstance(assignment.lhs, CVariable)
    assert isinstance(assignment.lhs.variable, SimTemporaryVariable)
    assert isinstance(consumer.rhs, CVariable)
    assert consumer.rhs.variable is assignment.lhs.variable
    assert isinstance(return_node.retval, CVariable)
    assert return_node.retval.variable is assignment.lhs.variable

    repeated = materialize_loop_carried_terminal_return_8616(project, codegen)

    assert repeated.changed is False
    assert repeated.status is LoopCarriedTerminalReturnStatus8616.ALREADY_MATERIALIZED
    assert repeated.evidence.materialized_count == 1


def test_loop_carried_terminal_return_refuses_pretest_loop(monkeypatch) -> None:
    assignment = _full_ax_assignment(_temporary(1))
    loop = CWhileLoop(
        CConstant(1, _word_type(), codegen=_AST_CODEGEN),
        CStatements([assignment], codegen=_AST_CODEGEN),
        codegen=_AST_CODEGEN,
    )
    project, codegen = _codegen(loop, CReturn(None, codegen=_AST_CODEGEN))
    monkeypatch.setattr(
        loop_carried_terminal_returns,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_loop_carried_terminal_return_8616(project, codegen)

    assert result.status is LoopCarriedTerminalReturnStatus8616.REFUSED
    assert result.refusal is LoopCarriedTerminalReturnRefusal8616.INCOMPLETE_STRUCTURED_SHAPE
    assert isinstance(assignment.lhs.variable, SimRegisterVariable)


def test_loop_carried_terminal_return_refuses_partial_ax_consumer(monkeypatch) -> None:
    assignment = _full_ax_assignment(_temporary(1))
    partial_consumer = CAssignment(_temporary(2), _register(0, 1), codegen=_AST_CODEGEN)
    loop = CDoWhileLoop(
        CConstant(1, _word_type(), codegen=_AST_CODEGEN),
        CStatements([assignment, partial_consumer], codegen=_AST_CODEGEN),
        codegen=_AST_CODEGEN,
    )
    project, codegen = _codegen(loop, CReturn(None, codegen=_AST_CODEGEN))
    monkeypatch.setattr(
        loop_carried_terminal_returns,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_loop_carried_terminal_return_8616(project, codegen)

    assert result.status is LoopCarriedTerminalReturnStatus8616.REFUSED
    assert result.refusal is LoopCarriedTerminalReturnRefusal8616.UNSAFE_AX_FLOW
    assert isinstance(assignment.lhs.variable, SimRegisterVariable)


def test_loop_carried_terminal_return_refuses_recursive_ax_definition(monkeypatch) -> None:
    rhs = CBinaryOp(
        "Add",
        _register(0, 2),
        CConstant(1, _word_type(), codegen=_AST_CODEGEN),
        codegen=_AST_CODEGEN,
    )
    assignment = _full_ax_assignment(rhs)
    loop = CDoWhileLoop(
        CConstant(1, _word_type(), codegen=_AST_CODEGEN),
        CStatements([assignment], codegen=_AST_CODEGEN),
        codegen=_AST_CODEGEN,
    )
    project, codegen = _codegen(loop, CReturn(None, codegen=_AST_CODEGEN))
    monkeypatch.setattr(
        loop_carried_terminal_returns,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_loop_carried_terminal_return_8616(project, codegen)

    assert result.status is LoopCarriedTerminalReturnStatus8616.REFUSED
    assert result.refusal is LoopCarriedTerminalReturnRefusal8616.UNSAFE_AX_FLOW
    assert isinstance(assignment.lhs.variable, SimRegisterVariable)
