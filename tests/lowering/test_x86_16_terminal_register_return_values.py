from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimTemporaryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.terminal_register_return_values as terminal_register_return_values
from inertia.lowering.terminal_register_return_values import (
    TerminalRegisterReturnValueRefusal8616,
    TerminalRegisterReturnValueStatus8616,
    materialize_terminal_register_return_value_8616,
)

from inertia.semantics.terminal_return_storage import TerminalReturnStorage8616


class _Codegen(SimpleNamespace):
    def __init__(self, arch: Arch86_16) -> None:
        super().__init__(
            cstyle_null_cmp=False,
            project=SimpleNamespace(arch=arch),
        )
        self._indices: dict[str, int] = {}

    def next_idx(self, kind: str) -> int:
        index = self._indices.get(kind, 0)
        self._indices[kind] = index + 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _FunctionManager:
    def __init__(self, function: SimpleNamespace) -> None:
        self.function_value = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self.function_value if addr == self.function_value.addr else None


def _fixture() -> tuple[SimpleNamespace, _Codegen, structured_c.CAssignment, structured_c.CReturn]:
    arch = Arch86_16()
    codegen = _Codegen(arch)
    word_type = SimTypeShort(signed=True).with_arch(arch)
    argument = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    rhs = structured_c.CBinaryOp(
        "Add",
        argument,
        structured_c.CConstant(1, word_type, codegen=codegen),
        codegen=codegen,
    )
    ax = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=word_type,
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(ax, rhs, codegen=codegen, tags={"ins_addr": 0x1010})
    return_node = structured_c.CReturn(None, codegen=codegen, tags={"ins_addr": 0x1014})
    root = structured_c.CStatements([assignment, return_node], codegen=codegen)
    prototype = SimTypeFunction([word_type], word_type).with_arch(arch)
    codegen.cfunc = SimpleNamespace(addr=0x1000, functy=prototype, statements=root)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000})
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=_FunctionManager(function)),
    )
    return project, codegen, assignment, return_node


def test_terminal_ax_value_materializes_linear_argument_expression(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert result.evidence.materialized_count == 1
    assert isinstance(return_node.retval, structured_c.CBinaryOp)
    assert return_node.retval is not assignment.rhs


def test_terminal_ax_value_uses_last_linear_definition(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    final_value = structured_c.CConstant(
        2,
        SimTypeShort(signed=True),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.insert(
        1,
        structured_c.CAssignment(assignment.lhs, final_value, codegen=codegen),
    )
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert result.evidence.raw_fact_count == 2
    assert isinstance(return_node.retval, structured_c.CConstant)
    assert return_node.retval.value == 2


def test_terminal_ax_value_flattens_nested_statement_wrappers(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    codegen.cfunc.statements.statements = [
        structured_c.CStatements([assignment], codegen=codegen),
        structured_c.CStatements([return_node], codegen=codegen),
    ]
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert isinstance(return_node.retval, structured_c.CBinaryOp)


def test_terminal_ax_value_refuses_structured_control_flow(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    condition = structured_c.CConstant(
        1,
        SimTypeShort(signed=True),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements = [
        structured_c.CIfElse(
            condition,
            structured_c.CStatements([assignment], codegen=codegen),
            None,
            codegen=codegen,
        ),
        return_node,
    ]
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.REFUSED
    assert result.refusal is TerminalRegisterReturnValueRefusal8616.NONLINEAR_AX_DEFINITION
    assert return_node.retval is None


def test_terminal_ax_value_accepts_linear_suffix_after_structured_control_flow(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    condition = structured_c.CConstant(
        1,
        SimTypeShort(signed=True),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.insert(
        0,
        structured_c.CIfElse(
            condition,
            structured_c.CStatements([], codegen=codegen),
            None,
            codegen=codegen,
        ),
    )
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert isinstance(return_node.retval, structured_c.CBinaryOp)
    assert return_node.retval is not assignment.rhs


def test_terminal_ax_value_allows_proven_segmented_frame_read(monkeypatch) -> None:
    project, codegen, _assignment, return_node = _fixture()
    word_type = SimTypeShort(signed=False).with_arch(project.arch)
    frame_read = structured_c.CFunctionCall(
        "SEG_U16",
        None,
        [
            structured_c.CConstant(0, word_type, codegen=codegen),
            structured_c.CConstant(2, word_type, codegen=codegen),
        ],
        codegen=codegen,
    )
    frame_carrier = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="saved_bp", region=codegen.cfunc.addr),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.insert(
        -1,
        structured_c.CAssignment(frame_carrier, frame_read, codegen=codegen),
    )
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert isinstance(return_node.retval, structured_c.CBinaryOp)


def test_terminal_ax_value_refuses_intervening_argument_definition(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    assert isinstance(assignment.rhs, structured_c.CBinaryOp)
    argument = assignment.rhs.lhs
    codegen.cfunc.statements.statements.insert(
        -1,
        structured_c.CAssignment(
            argument,
            structured_c.CConstant(3, SimTypeShort(signed=True), codegen=codegen),
            codegen=codegen,
        ),
    )
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.REFUSED
    assert result.refusal is TerminalRegisterReturnValueRefusal8616.INTERVENING_DEFINITION
    assert return_node.retval is None


def test_terminal_ax_value_refuses_call_rhs(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    assignment.rhs = structured_c.CFunctionCall("unknown", None, [], codegen=codegen)
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.REFUSED
    assert result.evidence.classified_fact_count == 0
    assert return_node.retval is None


def test_terminal_ax_value_accepts_shared_scalar_subtree(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    assert isinstance(assignment.rhs, structured_c.CBinaryOp)
    shared_argument = assignment.rhs.lhs
    assignment.rhs = structured_c.CBinaryOp(
        "Add",
        shared_argument,
        shared_argument,
        codegen=codegen,
    )
    assignment.rhs.collapsed = True
    shared_argument.collapsed = True
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert isinstance(return_node.retval, structured_c.CBinaryOp)
    assert isinstance(return_node.retval.lhs, structured_c.CVariable)
    assert isinstance(return_node.retval.rhs, structured_c.CVariable)
    assert return_node.retval.lhs.variable is return_node.retval.rhs.variable
    assert return_node.retval.collapsed is False
    assert return_node.retval.lhs.collapsed is False


def test_terminal_ax_value_replaces_undefined_generated_return_from_linear_carriers(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    word_type = SimTypeShort(signed=False).with_arch(project.arch)
    source_lhs = structured_c.CDirtyExpression(
        SimpleNamespace(varid=8, reg_offset=0, bits=16),
        codegen=codegen,
    )
    source_read = structured_c.CDirtyExpression(SimpleNamespace(varid=8), codegen=codegen)
    low_lhs = structured_c.CVariable(SimTemporaryVariable(39, 16), codegen=codegen)
    low_read = structured_c.CVariable(SimTemporaryVariable(39, 16), codegen=codegen)
    high_lhs = structured_c.CVariable(SimTemporaryVariable(41, 8), codegen=codegen)
    high_read = structured_c.CVariable(SimTemporaryVariable(41, 8), codegen=codegen)
    broken_high = structured_c.CVariable(SimTemporaryVariable(43, 16), codegen=codegen)
    assert isinstance(assignment.rhs, structured_c.CBinaryOp)
    argument_a = assignment.rhs.lhs
    argument_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_b", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    high_load = structured_c.CFunctionCall(
        "SEG_U8",
        None,
        [
            structured_c.CConstant(0, word_type, codegen=codegen),
            structured_c.CConstant(7, word_type, codegen=codegen),
        ],
        codegen=codegen,
    )
    joined = structured_c.CBinaryOp(
        "Or",
        low_read,
        structured_c.CBinaryOp(
            "Shl",
            high_read,
            structured_c.CConstant(8, word_type, codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    assignment.rhs = structured_c.CBinaryOp("Mul", source_read, joined, codegen=codegen)
    return_node.retval = structured_c.CBinaryOp(
        "Mul",
        argument_a,
        structured_c.CBinaryOp("Or", argument_b, broken_high, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements = [
        structured_c.CAssignment(source_lhs, argument_a, codegen=codegen),
        structured_c.CAssignment(low_lhs, argument_b, codegen=codegen),
        structured_c.CAssignment(high_lhs, high_load, codegen=codegen),
        assignment,
        return_node,
    ]
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert isinstance(return_node.retval, structured_c.CBinaryOp)
    nodes = tuple(terminal_register_return_values._iter_c_nodes_deep_8616(return_node.retval))
    assert not any(isinstance(node, structured_c.CDirtyExpression) for node in nodes)
    assert not any(
        isinstance(node, structured_c.CVariable) and isinstance(node.variable, SimTemporaryVariable)
        for node in nodes
    )
    assert any(isinstance(node, structured_c.CFunctionCall) for node in nodes)


def test_terminal_ax_value_preserves_existing_resolved_return(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    return_node.retval = assignment.rhs
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.REFUSED
    assert result.refusal is TerminalRegisterReturnValueRefusal8616.INCOMPLETE_TERMINAL_SHAPE
    assert return_node.retval is assignment.rhs


def test_terminal_ax_value_uncollapses_existing_resolved_return(monkeypatch) -> None:
    project, codegen, assignment, return_node = _fixture()
    return_node.retval = assignment.rhs
    assignment.rhs.collapsed = True
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.MATERIALIZED
    assert isinstance(return_node.retval, structured_c.CBinaryOp)
    assert return_node.retval is not assignment.rhs
    assert return_node.retval.collapsed is False
