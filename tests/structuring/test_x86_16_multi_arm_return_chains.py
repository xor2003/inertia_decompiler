from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.ir.condition_ir import ConditionIR
from archinfo import ArchX86

from inertia.structuring.multi_arm_return_chains import (
    MultiArmReturnCandidate8616,
    MultiArmReturnChainStatus8616,
    is_wide_register_return_setup_body_8616,
    recover_multi_arm_wide_return_chain_8616,
)
from inertia.structuring.return_chains import (
    ReturnSelectorCallbacks8616,
    materialize_cfg_selector_return_branches_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _wide_return_setup(codegen: _Codegen, stack_offset: int, target: int) -> CStatements:
    assignments = [
        CAssignment(
            CVariable(SimRegisterVariable(0, 2), codegen=codegen),
            CVariable(SimStackVariable(stack_offset, 2), codegen=codegen),
            codegen=codegen,
        ),
        CAssignment(
            CVariable(SimRegisterVariable(8, 2), codegen=codegen),
            CVariable(SimStackVariable(stack_offset + 2, 2), codegen=codegen),
            codegen=codegen,
        ),
    ]
    return CStatements(assignments, codegen=codegen, tags={"ins_addr": target})


def _candidate(
    codegen: _Codegen,
    *,
    block: int,
    source: int,
    true_target: int,
    false_target: int,
    stack_offset: int,
) -> MultiArmReturnCandidate8616:
    fact = ConditionIR(
        "slt",
        "lhs",
        "rhs",
        src_insn=source,
        block_addr=block,
        producer_insn=source - 2,
        taken_target=true_target,
        fallthrough_target=false_target,
    )
    structured = CConstant(0, SimTypeShort(False), codegen=codegen)
    return MultiArmReturnCandidate8616(
        fact,
        structured,
        _wide_return_setup(codegen, stack_offset, true_target),
        true_target,
        false_target,
    )


def test_multi_arm_wide_return_chain_materializes_atomically() -> None:
    codegen = _Codegen()
    candidates = (
        _candidate(
            codegen,
            block=0x1000,
            source=0x1004,
            true_target=0x1100,
            false_target=0x1200,
            stack_offset=8,
        ),
        _candidate(
            codegen,
            block=0x1200,
            source=0x1204,
            true_target=0x1300,
            false_target=0x1400,
            stack_offset=12,
        ),
    )
    else_body = _wide_return_setup(codegen, 4, 0x1400)
    condition_calls: list[tuple[int, int, int]] = []

    def materialize(fact: ConditionIR, true_target: int, false_target: int) -> CConstant:
        condition_calls.append((fact.block_addr or 0, true_target, false_target))
        return CConstant(1, SimTypeShort(False), codegen=codegen)

    result = recover_multi_arm_wide_return_chain_8616(
        codegen,
        candidates,
        else_body,
        0x1400,
        materialize,
        lambda target: CConstant(target, SimTypeShort(False), codegen=codegen),
    )

    assert result.status is MultiArmReturnChainStatus8616.MATERIALIZED
    assert condition_calls == [(0x1000, 0x1100, 0x1200), (0x1200, 0x1300, 0x1400)]
    assert result.stats.materialized_count == 2
    assert len(result.condition_and_nodes) == 2
    assert all(
        isinstance(body, CStatements)
        and len(body.statements) == 1
        and isinstance(body.statements[0], CReturn)
        for _condition, body in result.condition_and_nodes
    )
    assert isinstance(result.else_node, CStatements)
    assert isinstance(result.else_node.statements[0], CReturn)
    assert all(
        condition.tags["inertia_structuring_multi_arm_return_chain_materialized_8616"]
        for condition, _body in result.condition_and_nodes
    )
    assert len(candidates[0].body.statements) == 2


def test_wide_return_setup_accepts_repeated_widened_stack_object() -> None:
    codegen = _Codegen()
    body = _wide_return_setup(codegen, 8, 0x1100)
    for assignment in body.statements:
        assignment.rhs = CVariable(SimStackVariable(8, 4), codegen=codegen)

    assert is_wide_register_return_setup_body_8616(body)


def test_wide_return_setup_accepts_wide_low_and_word_high_views() -> None:
    codegen = _Codegen()
    body = _wide_return_setup(codegen, 8, 0x1100)
    body.statements[0].rhs = CVariable(
        SimStackVariable(8, 4), codegen=codegen
    )

    assert is_wide_register_return_setup_body_8616(body)


def test_multi_arm_wide_return_chain_refuses_partial_return_proof() -> None:
    codegen = _Codegen()
    candidates = (
        _candidate(
            codegen,
            block=0x1000,
            source=0x1004,
            true_target=0x1100,
            false_target=0x1200,
            stack_offset=8,
        ),
        _candidate(
            codegen,
            block=0x1200,
            source=0x1204,
            true_target=0x1300,
            false_target=0x1400,
            stack_offset=12,
        ),
    )

    result = recover_multi_arm_wide_return_chain_8616(
        codegen,
        candidates,
        _wide_return_setup(codegen, 4, 0x1400),
        0x1400,
        lambda _fact, _true, _false: CConstant(
            1, SimTypeShort(False), codegen=codegen
        ),
        lambda target: (
            None
            if target == 0x1300
            else CConstant(target, SimTypeShort(False), codegen=codegen)
        ),
    )

    assert result.status is MultiArmReturnChainStatus8616.REFUSED
    assert result.condition_and_nodes == ()
    assert result.else_node is None
    assert result.stats.failure_count == 1
    assert len(candidates[0].body.statements) == 2


def test_multi_arm_wide_return_chain_refuses_observable_stack_write() -> None:
    codegen = _Codegen()
    first = _candidate(
        codegen,
        block=0x1000,
        source=0x1004,
        true_target=0x1100,
        false_target=0x1200,
        stack_offset=8,
    )
    unsafe_body = _wide_return_setup(codegen, 12, 0x1300)
    unsafe_body.statements[0].lhs = CVariable(
        SimStackVariable(-2, 2), codegen=codegen
    )
    second = MultiArmReturnCandidate8616(
        ConditionIR(
            "sgt",
            "lhs",
            "rhs",
            src_insn=0x1204,
            block_addr=0x1200,
            taken_target=0x1300,
            fallthrough_target=0x1400,
        ),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        unsafe_body,
        0x1300,
        0x1400,
    )

    result = recover_multi_arm_wide_return_chain_8616(
        codegen,
        (first, second),
        _wide_return_setup(codegen, 4, 0x1400),
        0x1400,
        lambda _fact, _true, _false: CConstant(
            1, SimTypeShort(False), codegen=codegen
        ),
        lambda target: CConstant(target, SimTypeShort(False), codegen=codegen),
    )

    assert result.status is MultiArmReturnChainStatus8616.REFUSED
    assert result.condition_and_nodes == ()


def test_selector_return_refuses_to_collapse_existing_multi_arm_obligations() -> None:
    codegen = _Codegen()
    first_body = _wide_return_setup(codegen, 8, 0x1100)
    second_body = _wide_return_setup(codegen, 12, 0x1300)
    else_body = _wide_return_setup(codegen, 4, 0x1400)
    multi_arm = CIfElse(
        [
            (CConstant(1, SimTypeShort(False), codegen=codegen), first_body),
            (CConstant(2, SimTypeShort(False), codegen=codegen), second_body),
        ],
        else_node=else_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([multi_arm], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    selector_pair = (
        CConstant(3, SimTypeShort(False), codegen=codegen),
        CConstant(4, SimTypeShort(False), codegen=codegen),
        CConstant(5, SimTypeShort(False), codegen=codegen),
    )

    def reject_root_replacement(_codegen: object, _root: CStatements) -> None:
        raise AssertionError("selector must preserve existing multi-arm obligations")

    callbacks = ReturnSelectorCallbacks8616(
        materialize_decrement_switch_return_chain=lambda _project, _codegen: False,
        ordered_32bit_selector_return_expr_pairs=lambda _project, _codegen: [
            selector_pair
        ],
        ordered_conditional_return_expr_pairs=lambda _project, _codegen: [],
        selector_condition_call_addrs=lambda _pairs: frozenset(),
        selector_condition_call_addrs_from_cfg=lambda _project, _codegen: frozenset(),
        selector_function_has_unsafe_effects=lambda _project, _codegen, _allowed: False,
        clone_c_value_for_codegen_tree=lambda expression: expression,
        set_cfunc_statements_root=reject_root_replacement,
        expr_fingerprint=lambda expression, _project: str(id(expression)),
    )

    changed = materialize_cfg_selector_return_branches_8616(
        object(), codegen, callbacks
    )

    assert not changed
    assert codegen.cfunc.statements is root
    assert codegen._inertia_cfg_selector_return_stats_8616["refused"] == 2
