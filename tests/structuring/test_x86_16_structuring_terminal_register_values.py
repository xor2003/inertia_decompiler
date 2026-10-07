from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CReturn, CStatements, CVariable
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.structuring.terminal_register_values import (
    TerminalReturnValueMaterializationRefusal8616,
    TerminalReturnValueMaterializationStatus8616,
    compose_ax_byte_lanes_8616,
    materialize_linear_terminal_return_value_8616,
    materialize_proven_terminal_return_value_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_compose_ax_byte_lanes_masks_and_shifts_proven_values() -> None:
    codegen = _DummyCodegen()
    low = CVariable(
        SimStackVariable(-4, 1, base="bp", name="low", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    high = CVariable(
        SimStackVariable(-2, 1, base="bp", name="high", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )

    result = compose_ax_byte_lanes_8616(codegen, low, high)

    assert result.op == "Or"
    assert isinstance(result.lhs, CBinaryOp)
    assert result.lhs.op == "And"
    assert result.lhs.rhs.value == 0xFF
    assert isinstance(result.rhs, CBinaryOp)
    assert result.rhs.op == "Shl"
    assert result.rhs.rhs.value == 8


def test_materialize_proven_terminal_return_replaces_stale_scalar_value() -> None:
    codegen = _DummyCodegen()
    argument_a = CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    argument_b = CVariable(
        SimStackVariable(6, 2, base="bp", name="b", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return_node = CReturn(argument_a, codegen=codegen)
    proven_value = CBinaryOp("Mul", argument_a, argument_b, codegen=codegen)

    result = materialize_proven_terminal_return_value_8616(
        (return_node,),
        proven_value,
        terminal_value_block_count=1,
        expressions_equivalent=lambda current, proven: current is proven,
    )

    assert result.status is TerminalReturnValueMaterializationStatus8616.MATERIALIZED
    assert result.refusal is TerminalReturnValueMaterializationRefusal8616.NONE
    assert result.changed is True
    assert result.classified_fact_count == result.materialized_count == 1
    assert return_node.retval is proven_value


def test_materialize_proven_terminal_return_refuses_multiple_value_blocks() -> None:
    codegen = _DummyCodegen()
    stale_value = CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return_node = CReturn(stale_value, codegen=codegen)

    result = materialize_proven_terminal_return_value_8616(
        (return_node,),
        CBinaryOp("Mul", stale_value, stale_value, codegen=codegen),
        terminal_value_block_count=2,
        expressions_equivalent=lambda current, proven: current is proven,
    )

    assert result.status is TerminalReturnValueMaterializationStatus8616.REFUSED
    assert result.refusal is TerminalReturnValueMaterializationRefusal8616.TERMINAL_BLOCK_COUNT
    assert result.materialized_count == 0
    assert return_node.retval is stale_value


def test_linear_terminal_return_consumer_replaces_plausible_stale_return() -> None:
    codegen = _DummyCodegen()
    argument_a = CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    argument_b = CVariable(
        SimStackVariable(6, 2, base="bp", name="b", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return_node = CReturn(argument_a, codegen=codegen)
    root = CStatements([return_node], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=root,
        functy=SimpleNamespace(returnty=SimTypeShort(False).with_arch(codegen.project.arch)),
    )
    function = SimpleNamespace(prototype=None)
    proven_value = CBinaryOp("Mul", argument_a, argument_b, codegen=codegen)

    def recover_proven_value(project: object, actual_codegen: object, actual_function: object) -> CBinaryOp:
        assert project is codegen.project
        assert actual_codegen is codegen
        assert actual_function is function
        codegen._inertia_missing_terminal_ax_return_terminal_value_block_count_8616 = 1
        return proven_value

    result = materialize_linear_terminal_return_value_8616(
        codegen.project,
        codegen,
        function,
        recover_proven_value=recover_proven_value,
        expressions_equivalent=lambda current, proven: current is proven,
    )

    assert result.status is TerminalReturnValueMaterializationStatus8616.MATERIALIZED
    assert result.classified_fact_count == result.materialized_count == 1
    assert return_node.retval is proven_value

    unrelated_value = CBinaryOp("Mul", argument_b, argument_a, codegen=codegen)
    refused = materialize_linear_terminal_return_value_8616(
        codegen.project,
        codegen,
        function,
        recover_proven_value=lambda *_args: unrelated_value,
        expressions_equivalent=lambda current, proven: current is proven,
    )

    assert refused.status is TerminalReturnValueMaterializationStatus8616.REFUSED
    assert refused.refusal is TerminalReturnValueMaterializationRefusal8616.PROVEN_VALUE_NOT_EXTENSION
    assert return_node.retval is proven_value


def test_linear_terminal_return_replaces_narrow_projected_stack_carrier() -> None:
    codegen = _DummyCodegen()
    stale_carrier = CVariable(
        SimStackVariable(-2, 1, base="bp", name="stack_sp_m2", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    projected_local = CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_2", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_local.variable,
        cvar=projected_local,
        bp_offset=-2,
        entry_sp_offset=-6,
        size=2,
    )
    return_node = CReturn(stale_carrier, codegen=codegen)
    root = CStatements([return_node], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=root,
        functy=SimpleNamespace(returnty=SimTypeShort(False).with_arch(codegen.project.arch)),
    )
    function = SimpleNamespace(prototype=None)

    def recover_proven_value(*_args: object) -> CVariable:
        codegen._inertia_missing_terminal_ax_return_terminal_value_block_count_8616 = 1
        return projected_local

    result = materialize_linear_terminal_return_value_8616(
        codegen.project,
        codegen,
        function,
        recover_proven_value=recover_proven_value,
        expressions_equivalent=lambda current, proven: current is proven,
    )

    assert result.status is TerminalReturnValueMaterializationStatus8616.MATERIALIZED
    assert return_node.retval is projected_local


def test_linear_terminal_return_refuses_narrow_stack_carrier_without_projection() -> None:
    codegen = _DummyCodegen()
    stale_carrier = CVariable(
        SimStackVariable(-2, 1, base="bp", name="stack_sp_m2", region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    unproven_local = CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_2", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return_node = CReturn(stale_carrier, codegen=codegen)
    root = CStatements([return_node], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=root,
        functy=SimpleNamespace(returnty=SimTypeShort(False).with_arch(codegen.project.arch)),
    )
    function = SimpleNamespace(prototype=None)

    def recover_proven_value(*_args: object) -> CVariable:
        codegen._inertia_missing_terminal_ax_return_terminal_value_block_count_8616 = 1
        return unproven_local

    result = materialize_linear_terminal_return_value_8616(
        codegen.project,
        codegen,
        function,
        recover_proven_value=recover_proven_value,
        expressions_equivalent=lambda current, proven: current is proven,
    )

    assert result.status is TerminalReturnValueMaterializationStatus8616.REFUSED
    assert result.refusal is TerminalReturnValueMaterializationRefusal8616.PROVEN_VALUE_NOT_EXTENSION
    assert return_node.retval is stale_carrier
