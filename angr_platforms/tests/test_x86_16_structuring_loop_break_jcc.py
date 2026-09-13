from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CExpression,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.structuring import loop_break_jcc
from angr_platforms.X86_16.structuring.loop_break_jcc import (
    LoopBranchGuardFact8616,
    LoopHeaderDuplicateGuardRemovalFact8616,
    UnconsumedLoopBreakJccCallbacks8616,
    loop_branch_guard_facts_8616,
    loop_header_duplicate_guard_removal_facts_8616,
    materialize_unconsumed_loop_break_jcc_8616,
)
from angr_platforms.X86_16.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_tags_8616,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = SimpleNamespace(addr=0x4000, statements=None, body=None)
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Insn:
    def __init__(self, address: int, mnemonic: str, target: int | None = None, size: int = 2):
        self.address = address
        self.mnemonic = mnemonic
        self.target = target
        self.size = size


def _const(value: int, codegen: _DummyCodegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(name: str, codegen: _DummyCodegen) -> CVariable:
    return CVariable(SimRegisterVariable(0, 2, name=name), codegen=codegen)


def _global(addr: int, codegen: _DummyCodegen) -> CVariable:
    return CVariable(SimMemoryVariable(addr, 2), codegen=codegen)


def _fingerprint(expr: object, _project: object) -> str:
    return str(getattr(expr, "op", repr(expr)))


def _callbacks(
    jcc: _Insn,
    *,
    evidence: list[tuple[object | None, object]],
    condition_lhs: Callable[[_DummyCodegen], CExpression] | None = None,
) -> UnconsumedLoopBreakJccCallbacks8616:
    def _condition(op: str, project: object, codegen: _DummyCodegen, tags: dict[str, int]) -> CBinaryOp:
        lhs = condition_lhs(codegen) if condition_lhs is not None else _reg("ax", codegen)
        return CBinaryOp(op, lhs, _reg("bx", codegen), codegen=codegen, tags=dict(tags))

    return UnconsumedLoopBreakJccCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x4000, jcc),),
        branch_target_imm=lambda insn: insn.target,
        next_unconditional_target_after_jcc=lambda _project, _block_addr, _jcc_addr: 0x4020,
        resolve_one_hop_jmp_target=lambda _project, target: target,
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, _jcc_addr: SimpleNamespace(op="CmpGT"),
        decoded_condition_expr=lambda project, codegen, _decoded, tags: _condition("CmpGT", project, codegen, tags),
        inverted_condition_expr=lambda project, codegen, _decoded, tags: _condition("CmpLE", project, codegen, tags),
        expr_fingerprint=_fingerprint,
        same_c_expression=lambda left, right: left is right,
        clone_c_value=lambda value: value,
        record_condition_evidence=lambda _project, _codegen, removed, added: evidence.append((removed, added)),
    )


def _collapsed_loop_header_fixture(
    codegen: _DummyCodegen,
    *,
    include_suffix_guard: bool = True,
    include_body_effect: bool = True,
) -> tuple[CWhileLoop, CIfBreak, CAssignment, list[tuple[object | None, object]]]:
    """Build a loop whose header duplicates two body JCCs and one body effect."""

    first_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000},
    )
    collapsed_effect = CBinaryOp(
        "Add",
        _reg("ax", codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4012, "vex_block_addr": 0x4010},
    )
    suffix_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4015, "vex_block_addr": 0x4010},
    )
    loop_condition = CBinaryOp(
        "LogicalAnd",
        first_condition,
        CBinaryOp(
            "LogicalAnd",
            collapsed_effect,
            suffix_condition,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    first_break = CIfBreak(
        CBinaryOp(
            "CmpLE",
            _reg("ax", codegen),
            _reg("bx", codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000},
        ),
        codegen=codegen,
        cstyle_ifs=True,
    )
    body_target = CAssignment(
        _reg("ax", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    body_effect = CAssignment(
        _reg("ax", codegen),
        _const(3, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4012},
    )
    suffix_break = CIfBreak(
        CBinaryOp(
            "CmpLE",
            _reg("ax", codegen),
            _reg("bx", codegen),
            codegen=codegen,
            tags={"ins_addr": 0x4015, "vex_block_addr": 0x4010},
        ),
        codegen=codegen,
        cstyle_ifs=True,
    )
    statements: list[object] = [first_break, body_target]
    if include_body_effect:
        statements.append(body_effect)
    if include_suffix_guard:
        statements.append(suffix_break)
    loop = CWhileLoop(
        loop_condition,
        CStatements(statements, codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    codegen._inertia_loop_branch_guard_facts_8616 = (
        LoopBranchGuardFact8616(
            jcc_addr=0x4015,
            block_addr=0x4010,
            body_target=0x4018,
            fallthrough_target=0x4017,
            false_target=0x4020,
            decoded_condition_fingerprint="CmpGT",
            guard_condition_fingerprint="CmpLE",
        ),
    )
    evidence: list[tuple[object | None, object]] = []
    return loop, first_break, body_effect, evidence


def test_structuring_splits_fully_materialized_collapsed_loop_header() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    loop, first_break, body_effect, evidence = _collapsed_loop_header_fixture(
        codegen
    )

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is True
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpGT"
    assert first_break not in loop.body.statements
    assert body_effect in loop.body.statements
    assert any(
        isinstance(statement, CIfBreak)
        and statement.condition.tags["ins_addr"] == 0x4015
        for statement in loop.body.statements
    )
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.split_loop_header_condition_chain == 1
    assert stats.removed_loop_header_duplicate_guard == 1
    assert loop_header_duplicate_guard_removal_facts_8616(codegen) == (
        LoopHeaderDuplicateGuardRemovalFact8616(
            jcc_addr=0x4005,
            block_addr=0x4000,
            removed_guard_fingerprint="CmpLE",
            retained_loop_fingerprint="CmpGT",
        ),
    )
    assert evidence[-1][0] is first_break.condition
    assert evidence[-1][1] is loop.condition


@pytest.mark.parametrize(
    ("include_suffix_guard", "include_body_effect"),
    ((False, True), (True, False)),
)
def test_structuring_refuses_partial_collapsed_loop_header_materialization(
    include_suffix_guard: bool,
    include_body_effect: bool,
) -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    loop, first_break, _body_effect, evidence = _collapsed_loop_header_fixture(
        codegen,
        include_suffix_guard=include_suffix_guard,
        include_body_effect=include_body_effect,
    )
    original_condition = loop.condition

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is False
    assert loop.condition is original_condition
    assert first_break in loop.body.statements
    assert (
        codegen._inertia_unconsumed_loop_break_jcc_stats_8616.split_loop_header_condition_chain
        == 0
    )
    assert loop_header_duplicate_guard_removal_facts_8616(codegen) == ()
    assert evidence == []


def test_structuring_unconsumed_loop_break_jcc_inserts_guard_before_taken_body(monkeypatch):
    from test_x86_16_loop_break_topology import topology

    monkeypatch.setattr(loop_break_jcc, "collect_loop_break_topology_8616", lambda *_: topology())
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    pre_stmt = CAssignment(_reg("ax", codegen), _const(1, codegen), codegen=codegen, tags={"ins_addr": 0x4002})
    taken_stmt = CAssignment(_reg("bx", codegen), _const(2, codegen), codegen=codegen, tags={"ins_addr": 0x4010})
    loop = CWhileLoop(_const(1, codegen), CStatements([pre_stmt, taken_stmt], codegen=codegen), codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is True
    assert loop.body.statements[0] is pre_stmt
    assert isinstance(loop.body.statements[1], CIfBreak)
    assert loop.body.statements[2] is taken_stmt
    assert loop.body.statements[1].condition.op == "CmpLE"
    assert codegen._inertia_unconsumed_loop_break_jcc_stats_8616.materialized_count == 1
    assert loop_branch_guard_facts_8616(codegen) == (
        LoopBranchGuardFact8616(
            jcc_addr=0x4005,
            block_addr=0x4000,
            body_target=0x4010,
            fallthrough_target=0x4007,
            false_target=0x4020,
            decoded_condition_fingerprint="CmpGT",
            guard_condition_fingerprint="CmpLE",
        ),
    )
    assert evidence and evidence[0][1] is loop.body.statements[1].condition


def test_structuring_refuses_break_when_loop_header_already_consumes_jcc():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    loop_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
    )
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        loop_condition,
        CStatements([taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is False
    assert loop.body.statements == [taken_stmt]
    assert loop_branch_guard_facts_8616(codegen) == ()
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.refused_existing_condition == 1
    assert stats.materialized_count == 0
    assert evidence == []


def test_structuring_refuses_break_for_typed_loop_continuation() -> None:
    """A typed loop latch must not be reclassified as a missing break guard."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    loop_condition = CBinaryOp(
        "CmpNE",
        _reg("ax", codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x4005,
            "vex_block_addr": 0x4000,
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": (0x4005, 0x4000),
        },
    )
    loop = CWhileLoop(
        loop_condition,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "je", 0x4020), evidence=evidence),
    )

    assert changed is False
    assert loop_branch_guard_facts_8616(codegen) == ()
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.refused_existing_condition == 1
    assert stats.materialized_count == 0
    assert evidence == []


def test_structuring_refuses_duplicate_untagged_semantic_break_guard():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    existing_guard = CIfBreak(
        CBinaryOp(
            "CmpLE",
            _reg("ax", codegen),
            _reg("bx", codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([existing_guard, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is False
    assert loop.body.statements == [existing_guard, taken_stmt]
    assert len(loop_branch_guard_facts_8616(codegen)) == 1
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.refused_duplicate_guard == 1
    assert stats.materialized_count == 0
    assert evidence == []


def test_structuring_refuses_segmented_alias_of_existing_global_break_guard() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    segmented_load = CFunctionCall(
        "opaque_segment_load",
        None,
        [],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            SegmentedLoadIdentity8616(
                space=MemSpace.DS,
                offset=0x0BA2,
                width=2,
                region=0x4000,
            )
        ),
    )
    existing_guard = CIfBreak(
        CBinaryOp(
            "CmpLE",
            segmented_load,
            _reg("bx", codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([existing_guard, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(
            _Insn(0x4005, "jg", 0x4010),
            evidence=evidence,
            condition_lhs=lambda owner: _global(0x0BA2, owner),
        ),
    )

    assert changed is False
    assert loop.body.statements == [existing_guard, taken_stmt]
    assert len(loop_branch_guard_facts_8616(codegen)) == 1
    assert codegen._inertia_unconsumed_loop_break_jcc_stats_8616.refused_duplicate_guard == 1
    assert evidence == []


def test_structuring_loop_break_fact_reader_requires_typed_tuple() -> None:
    codegen = _DummyCodegen()
    fact = LoopBranchGuardFact8616(
        jcc_addr=0x4005,
        block_addr=0x4000,
        body_target=0x4010,
        fallthrough_target=0x4007,
        false_target=0x4020,
        decoded_condition_fingerprint="CmpGT",
        guard_condition_fingerprint="CmpLE",
    )
    codegen._inertia_loop_branch_guard_facts_8616 = (fact,)

    assert loop_branch_guard_facts_8616(codegen) == (fact,)

    codegen._inertia_loop_branch_guard_facts_8616 = [fact]
    try:
        loop_branch_guard_facts_8616(codegen)
    except TypeError:
        pass
    else:
        raise AssertionError("untyped loop-break fact container was accepted")


def test_structuring_loop_guard_removal_fact_reader_requires_typed_tuple() -> None:
    codegen = _DummyCodegen()
    fact = LoopHeaderDuplicateGuardRemovalFact8616(
        jcc_addr=0x4005,
        block_addr=0x4000,
        removed_guard_fingerprint="CmpLE",
        retained_loop_fingerprint="CmpGT",
    )
    codegen._inertia_loop_header_duplicate_guard_removal_facts_8616 = (fact,)

    assert loop_header_duplicate_guard_removal_facts_8616(codegen) == (fact,)

    codegen._inertia_loop_header_duplicate_guard_removal_facts_8616 = [fact]
    with pytest.raises(TypeError):
        loop_header_duplicate_guard_removal_facts_8616(codegen)


def test_structuring_removes_break_duplicated_by_exact_jcc_loop_header() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    loop_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x4005,
            "vex_block_addr": 0x4003,
            "inertia_typed_loop_condition_bound_8616": True,
        },
    )
    break_condition = CBinaryOp(
        "CmpLE",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000},
    )
    duplicate_break = CIfBreak(
        break_condition,
        codegen=codegen,
        cstyle_ifs=True,
    )
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        loop_condition,
        CStatements([duplicate_break, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is True
    assert loop.body.statements == [taken_stmt]
    assert evidence == [(break_condition, loop_condition)]
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.materialized_count == 1
    assert stats.removed_loop_header_duplicate_guard == 1
    assert loop_header_duplicate_guard_removal_facts_8616(codegen) == (
        LoopHeaderDuplicateGuardRemovalFact8616(
            jcc_addr=0x4005,
            block_addr=0x4000,
            removed_guard_fingerprint="CmpLE",
            retained_loop_fingerprint="CmpGT",
        ),
    )

    changed_again = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed_again is False
    assert loop.body.statements == [taken_stmt]
    assert (
        codegen._inertia_unconsumed_loop_break_jcc_stats_8616.refused_existing_condition
        == 1
    )


def test_structuring_removes_untagged_break_duplicated_by_exact_jcc_loop_header() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    loop_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4003},
    )
    break_condition = CBinaryOp(
        "CmpLE",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
    )
    duplicate_break = CIfBreak(
        break_condition,
        codegen=codegen,
        cstyle_ifs=True,
    )
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        loop_condition,
        CStatements([duplicate_break, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is True
    assert loop.body.statements == [taken_stmt]
    assert evidence == [(break_condition, loop_condition)]
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.materialized_count == 1
    assert stats.removed_loop_header_duplicate_guard == 1
    assert len(loop_header_duplicate_guard_removal_facts_8616(codegen)) == 1


def test_structuring_refuses_ambiguous_untagged_loop_header_breaks() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    loop_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4003},
    )
    duplicate_breaks = [
        CIfBreak(
            CBinaryOp(
                "CmpLE",
                _reg("ax", codegen),
                _reg("bx", codegen),
                codegen=codegen,
            ),
            codegen=codegen,
            cstyle_ifs=True,
        )
        for _ in range(2)
    ]
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        loop_condition,
        CStatements([*duplicate_breaks, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is False
    assert loop.body.statements == [*duplicate_breaks, taken_stmt]
    assert loop_header_duplicate_guard_removal_facts_8616(codegen) == ()
    assert evidence == []


def test_structuring_does_not_classify_existing_ordinary_if_as_loop_guard() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    existing_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
    )
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    ordinary_if = CIfElse(
        [
            (
                existing_condition,
                CStatements([taken_stmt], codegen=codegen),
            ),
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([ordinary_if], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is False
    assert loop_branch_guard_facts_8616(codegen) == ()
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.refused_existing_condition == 1


def test_structuring_does_not_persist_unanchored_loop_guard_fact() -> None:
    """Missing placement proof must remain a refusal, not a classified guard."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    taken_stmt = CAssignment(
        _reg("bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    root = CStatements([taken_stmt], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is False
    assert loop_branch_guard_facts_8616(codegen) == ()
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.refused_no_loop_anchor == 1


def test_structuring_unconsumed_loop_break_jcc_inverts_existing_single_break_ifelse():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    body_edge_cond = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        _reg("bx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000},
    )
    existing_break_if = CIfElse(
        [(body_edge_cond, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    taken_stmt = CAssignment(_reg("bx", codegen), _const(2, codegen), codegen=codegen, tags={"ins_addr": 0x4010})
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([existing_break_if, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    evidence: list[tuple[object | None, object]] = []

    changed = materialize_unconsumed_loop_break_jcc_8616(
        project,
        codegen,
        _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence),
    )

    assert changed is True
    rewritten_cond = existing_break_if.condition_and_nodes[0][0]
    assert rewritten_cond is not body_edge_cond
    assert isinstance(rewritten_cond, CBinaryOp)
    assert rewritten_cond.op == "CmpLE"
    assert evidence == [(body_edge_cond, rewritten_cond)]


def test_structuring_loop_break_replay_accepts_equivalent_typed_block_boundary(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    stale_stack = CVariable(
        SimStackVariable(-8, 2, base="bp", name="barTemp"),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    stale_condition = CBinaryOp(
        "CmpGT",
        _reg("ax", codegen),
        stale_stack,
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000},
    )
    existing_break = CIfBreak(stale_condition, codegen=codegen, cstyle_ifs=True)
    taken_stmt = CAssignment(_reg("bx", codegen), _const(2, codegen), codegen=codegen, tags={"ins_addr": 0x4010})
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([existing_break, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="sgt",
            lhs=IRValue(MemSpace.REG, name="ax", offset=0, size=2),
            rhs=IRValue(MemSpace.SS, name="bp", offset=-6, size=2),
            src_insn=0x4005,
            block_addr=0x3FFE,
            taken_target=0x4010,
            fallthrough_target=0x4007,
        ),
    )
    evidence: list[tuple[object | None, object]] = []
    legacy_decode_calls = 0
    callbacks = _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence)

    def _legacy_decode(*_args):
        nonlocal legacy_decode_calls
        legacy_decode_calls += 1
        return None

    callbacks = UnconsumedLoopBreakJccCallbacks8616(
        linear_jcc_block_starts=callbacks.linear_jcc_block_starts,
        branch_target_imm=callbacks.branch_target_imm,
        next_unconditional_target_after_jcc=callbacks.next_unconditional_target_after_jcc,
        resolve_one_hop_jmp_target=callbacks.resolve_one_hop_jmp_target,
        translate_cmp_jcc_guard=_legacy_decode,
        decoded_condition_expr=callbacks.decoded_condition_expr,
        inverted_condition_expr=callbacks.inverted_condition_expr,
        expr_fingerprint=callbacks.expr_fingerprint,
        same_c_expression=callbacks.same_c_expression,
        clone_c_value=callbacks.clone_c_value,
        record_condition_evidence=callbacks.record_condition_evidence,
    )

    def _materialize(_project, _codegen, condition):
        assert condition is codegen._inertia_typed_conditions[0]
        return CBinaryOp(
            "CmpGT",
            _reg("ax", codegen),
            CVariable(
                SimStackVariable(-6, 2, base="bp", name="iLength"),
                variable_type=SimTypeShort(True),
                codegen=codegen,
            ),
            codegen=codegen,
        )

    monkeypatch.setattr(loop_break_jcc, "materialize_condition_ir_expression_8616", _materialize)

    changed = materialize_unconsumed_loop_break_jcc_8616(project, codegen, callbacks)

    assert changed is True
    assert legacy_decode_calls == 0
    assert isinstance(existing_break.condition, CBinaryOp)
    assert existing_break.condition.op == "CmpLE"
    assert isinstance(existing_break.condition.rhs, CVariable)
    assert isinstance(existing_break.condition.rhs.variable, SimStackVariable)
    assert existing_break.condition.rhs.variable.offset == -6
    assert evidence == [(stale_condition, existing_break.condition)]

    changed_again = materialize_unconsumed_loop_break_jcc_8616(project, codegen, callbacks)

    assert changed_again is False
    assert legacy_decode_calls == 0
    assert isinstance(existing_break.condition.rhs, CVariable)
    assert isinstance(existing_break.condition.rhs.variable, SimStackVariable)
    assert existing_break.condition.rhs.variable.offset == -6
    assert codegen._inertia_unconsumed_loop_break_jcc_stats_8616.refused_duplicate_guard == 1


def test_structuring_loop_break_refuses_typed_condition_with_wrong_targets(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    taken_stmt = CAssignment(_reg("bx", codegen), _const(2, codegen), codegen=codegen, tags={"ins_addr": 0x4010})
    loop = CWhileLoop(_const(1, codegen), CStatements([taken_stmt], codegen=codegen), codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="sgt",
            lhs=IRValue(MemSpace.REG, name="ax", offset=0, size=2),
            rhs=IRValue(MemSpace.SS, name="bp", offset=-6, size=2),
            src_insn=0x4005,
            block_addr=0x4000,
            taken_target=0x4999,
            fallthrough_target=0x4007,
        ),
    )
    evidence: list[tuple[object | None, object]] = []
    callbacks = _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=evidence)
    monkeypatch.setattr(
        loop_break_jcc,
        "materialize_condition_ir_expression_8616",
        lambda *_args: (_ for _ in ()).throw(AssertionError("mismatched typed fact was consumed")),
    )

    changed = materialize_unconsumed_loop_break_jcc_8616(project, codegen, callbacks)

    assert changed is False
    assert loop.body.statements == [taken_stmt]
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.refused_decode == 1
    assert stats.failure_count == 1
