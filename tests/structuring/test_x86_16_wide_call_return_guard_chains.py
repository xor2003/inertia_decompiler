from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpression,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace

from inertia.lowering.c_ast_utils import _same_c_expression_8616
from inertia.structuring.wide_call_return_guard_chains import (
    WideCallReturnGuardCollapseStatus8616,
    collapse_wide_call_return_guard_chain_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self._next_node_idx = 0

    def next_idx(self, _kind: str) -> int:
        self._next_node_idx += 1
        return self._next_node_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _condition(src_insn: int) -> ConditionIR:
    return ConditionIR(
        op="eq",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=src_insn,
    )


def _direct_ins_addr(node: object) -> int | None:
    if not isinstance(node, CIfElse):
        return None
    value = node.tags.get("ins_addr")
    return value if isinstance(value, int) else None


def _return_body(value: int, codegen: object) -> CStatements:
    expression = CConstant(value, SimTypeShort(False), codegen=codegen)
    return CStatements([CReturn(expression, codegen=codegen)], codegen=codegen)


def _guard_fixture(
    *,
    nested_return: int = 0,
    nested_source: int = 0x20,
    nested_condition: CExpression | None = None,
    sibling_continuation: bool = False,
    retain_nested_else: bool = True,
) -> tuple[CIfElse, CStatements]:
    codegen = _Codegen()
    condition = nested_condition or CConstant(
        1,
        SimTypeShort(False),
        codegen=codegen,
    )
    continuation = CStatements([], codegen=codegen)
    nested = CIfElse(
        [(condition, _return_body(nested_return, codegen))],
        else_node=continuation if retain_nested_else else None,
        tags={"ins_addr": nested_source},
        codegen=codegen,
    )
    outer = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen),
                _return_body(0, codegen),
            )
        ],
        else_node=CStatements(
            [nested, continuation] if sibling_continuation else [nested],
            codegen=codegen,
        ),
        tags={"ins_addr": 0x10},
        codegen=codegen,
    )
    return outer, continuation


def test_wide_call_return_guard_collapse_consumes_identical_nested_exit() -> None:
    node, continuation = _guard_fixture()

    result = collapse_wide_call_return_guard_chain_8616(
        node,
        (_condition(0x10), _condition(0x20), _condition(0x30)),
        _direct_ins_addr,
        _same_c_expression_8616,
    )

    assert result.status is WideCallReturnGuardCollapseStatus8616.MATERIALIZED
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert node.else_node is continuation


def test_wide_call_return_guard_collapse_consumes_sibling_continuation() -> None:
    node, continuation = _guard_fixture(
        sibling_continuation=True,
        retain_nested_else=False,
    )

    result = collapse_wide_call_return_guard_chain_8616(
        node,
        (_condition(0x10), _condition(0x20), _condition(0x30)),
        _direct_ins_addr,
        _same_c_expression_8616,
    )

    assert result.status is WideCallReturnGuardCollapseStatus8616.MATERIALIZED
    assert node.else_node is continuation


def test_wide_call_return_guard_collapse_refuses_two_continuations() -> None:
    node, _continuation = _guard_fixture(sibling_continuation=True)
    original_else = node.else_node

    result = collapse_wide_call_return_guard_chain_8616(
        node,
        (_condition(0x10), _condition(0x20), _condition(0x30)),
        _direct_ins_addr,
        _same_c_expression_8616,
    )

    assert result.status is WideCallReturnGuardCollapseStatus8616.REFUSED
    assert result.stats.failure_count == 1
    assert node.else_node is original_else


def test_wide_call_return_guard_collapse_refuses_different_return() -> None:
    node, _continuation = _guard_fixture(nested_return=1)
    original_else = node.else_node

    result = collapse_wide_call_return_guard_chain_8616(
        node,
        (_condition(0x10), _condition(0x20), _condition(0x30)),
        _direct_ins_addr,
        _same_c_expression_8616,
    )

    assert result.status is WideCallReturnGuardCollapseStatus8616.REFUSED
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
    assert node.else_node is original_else


def test_wide_call_return_guard_collapse_refuses_side_effecting_condition() -> None:
    codegen = _Codegen()
    call = CFunctionCall(
        "clock",
        SimpleNamespace(addr=0x4000),
        [],
        codegen=codegen,
    )
    node, _continuation = _guard_fixture(nested_condition=call)
    original_else = node.else_node

    result = collapse_wide_call_return_guard_chain_8616(
        node,
        (_condition(0x10), _condition(0x20), _condition(0x30)),
        _direct_ins_addr,
        _same_c_expression_8616,
    )

    assert result.status is WideCallReturnGuardCollapseStatus8616.REFUSED
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert node.else_node is original_else


def test_wide_call_return_guard_collapse_ignores_unrelated_nested_guard() -> None:
    node, _continuation = _guard_fixture(nested_source=0x99)
    original_else = node.else_node

    result = collapse_wide_call_return_guard_chain_8616(
        node,
        (_condition(0x10), _condition(0x20), _condition(0x30)),
        _direct_ins_addr,
        _same_c_expression_8616,
    )

    assert result.status is WideCallReturnGuardCollapseStatus8616.NOT_APPLICABLE
    assert result.stats.raw_fact_count == 0
    assert node.else_node is original_else
