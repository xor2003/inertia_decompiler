from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CSwitchCase,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from archinfo import ArchX86

from inertia.structuring.loop_body_repair import (
    SwitchLoopExitReturnEvidence8616,
)
from inertia.structuring.loop_break_jcc import (
    LoopBranchGuardFact8616,
)
from inertia.validation.tail_validation import (
    X86_16TailValidationSummary,
    build_x86_16_tail_validation_cached_result,
    collect_x86_16_tail_validation_summary,
    refresh_x86_16_final_semantic_validation_8616,
    x86_16_tail_validation_snapshot_passed,
)
from inertia.validation.validation_control_flow import (
    LoopBranchGuardIssueKind8616,
    validate_structured_control_flow_8616,
)
from inertia.validation.validation_control_flow_obligations import (
    ControlFlowObligationIssueKind8616,
    validate_switch_exit_obligations_8616,
)


class _Project:
    def __init__(self) -> None:
        self.arch = ArchX86()


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.project = _Project()
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _local(codegen: _Codegen) -> CVariable:
    return CVariable(
        SimStackVariable(-2, 2, base="bp", name="index"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _const(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _condition(
    local: CVariable,
    value: int,
    codegen: _Codegen,
) -> CBinaryOp:
    return CBinaryOp(
        "CmpEQ",
        local,
        _const(value, codegen),
        codegen=codegen,
    )


def _guarded_assignment(
    condition: object,
    local: CVariable,
    codegen: _Codegen,
) -> CIfElse:
    body = CStatements(
        [CAssignment(local, _const(1, codegen), codegen=codegen)],
        codegen=codegen,
    )
    return CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )


def _loop_branch_fact(
    *,
    block_addr: int = 0x4000,
    body_target: int = 0x4010,
    false_target: int = 0x4020,
    decoded_condition_fingerprint: str = "CmpEQ(var:index,const:0)",
    guard_condition_fingerprint: str = "CmpNE(var:index,const:0)",
) -> LoopBranchGuardFact8616:
    return LoopBranchGuardFact8616(
        jcc_addr=0x4005,
        block_addr=block_addr,
        body_target=body_target,
        fallthrough_target=0x4007,
        false_target=false_target,
        decoded_condition_fingerprint=decoded_condition_fingerprint,
        guard_condition_fingerprint=guard_condition_fingerprint,
    )


def _loop_branch_condition(
    local: CVariable,
    codegen: _Codegen,
    *,
    block_addr: int = 0x4000,
) -> CBinaryOp:
    return CBinaryOp(
        "CmpEQ",
        local,
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": block_addr},
    )


def _validation_condition_fingerprint(condition: object) -> str:
    if isinstance(condition, CBinaryOp):
        return (
            f"{condition.op}("
            f"{_validation_condition_fingerprint(condition.lhs)},"
            f"{_validation_condition_fingerprint(condition.rhs)})"
        )
    if isinstance(condition, CVariable):
        return f"var:{condition.variable.name}"
    if isinstance(condition, CConstant):
        return f"const:{condition.value}"
    raise TypeError(f"unsupported test condition: {type(condition).__name__}")


def _target_statement(
    local: CVariable,
    codegen: _Codegen,
    *,
    ins_addr: int,
) -> CAssignment:
    return CAssignment(
        local,
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": ins_addr},
    )


def _empty_summary(
    *,
    control_flow_issues: tuple[str, ...] = (),
) -> X86_16TailValidationSummary:
    return X86_16TailValidationSummary(
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        (),
        control_flow_issues=control_flow_issues,
    )


def test_control_flow_refuses_effectful_body_after_equivalent_break_guard() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    first_condition = _condition(local, 0, codegen)
    second_condition = _condition(local, 0, codegen)
    root = CStatements(
        [
            CIfBreak(first_condition, codegen=codegen),
            _guarded_assignment(second_condition, local, codegen),
        ],
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(root)

    assert report.passed is False
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.issue_tokens() == (
        "unreachable-duplicate-guard-body:sequence=0:statement=0",
    )


def test_control_flow_accepts_distinct_adjacent_guards() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    root = CStatements(
        [
            CIfBreak(_condition(local, 0, codegen), codegen=codegen),
            _guarded_assignment(_condition(local, 1, codegen), local, codegen),
        ],
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(root)

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_control_flow_does_not_join_nonadjacent_guards() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    root = CStatements(
        [
            CIfBreak(_condition(local, 0, codegen), codegen=codegen),
            CAssignment(local, _const(1, codegen), codegen=codegen),
            _guarded_assignment(_condition(local, 0, codegen), local, codegen),
        ],
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(root)

    assert report.passed
    assert report.raw_fact_count == 0


def test_control_flow_refuses_to_reason_about_effectful_conditions() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    condition = CFunctionCall("next_value", None, [], codegen=codegen)
    root = CStatements(
        [
            CIfBreak(condition, codegen=codegen),
            _guarded_assignment(condition, local, codegen),
        ],
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(root)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 0
    assert report.classified_fact_count == 0


def test_control_flow_accepts_exact_proven_loop_break_guard() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    guard = CIfBreak(
        _loop_branch_condition(local, codegen),
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([guard], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)

    report = validate_structured_control_flow_8616(
        root,
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_control_flow_accepts_exact_proven_loop_header_guard() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        _loop_branch_condition(local, codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_control_flow_joins_rebuilt_loop_header_by_exact_jcc_identity() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        _loop_branch_condition(local, codegen, block_addr=0x4003),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(_loop_branch_fact(block_addr=0x4000),),
    )

    assert report.passed
    assert report.materialized_count == 1


def test_control_flow_accepts_unique_tagged_header_with_nested_exit_anchor() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        _loop_branch_condition(local, codegen),
        CStatements(
            [
                _target_statement(local, codegen, ins_addr=0x4010),
                _target_statement(local, codegen, ins_addr=0x4020),
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_control_flow_selects_target_matched_header_from_stale_duplicate_tags() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    stale_loop = CWhileLoop(
        _loop_branch_condition(local, codegen),
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4030)],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    owning_loop = CWhileLoop(
        _loop_branch_condition(local, codegen),
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4010)],
            codegen=codegen,
        ),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([stale_loop, owning_loop], codegen=codegen),
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.passed
    assert report.materialized_count == 1


def test_control_flow_accepts_unique_untagged_folded_loop_by_semantics_and_targets() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        local,
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4010)],
            codegen=codegen,
        ),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(
                decoded_condition_fingerprint="CmpNE(var:index,const:0)",
                guard_condition_fingerprint="CmpEQ(var:index,const:0)",
            ),
        ),
        condition_fingerprint=_validation_condition_fingerprint,
    )

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_control_flow_accepts_untagged_folded_loop_by_block_local_header_anchor() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        local,
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4040)],
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4003},
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(
                decoded_condition_fingerprint="CmpNE(var:index,const:0)",
                guard_condition_fingerprint="CmpEQ(var:index,const:0)",
            ),
        ),
        condition_fingerprint=_validation_condition_fingerprint,
    )

    assert report.passed
    assert report.materialized_count == 1


def test_control_flow_refuses_folded_loop_with_anchor_outside_jcc_block() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        local,
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4040)],
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4006},
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(
                decoded_condition_fingerprint="CmpNE(var:index,const:0)",
                guard_condition_fingerprint="CmpEQ(var:index,const:0)",
            ),
        ),
        condition_fingerprint=_validation_condition_fingerprint,
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD


def test_control_flow_refuses_folded_loop_containing_proven_exit_target() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        local,
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4020)],
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4003},
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(
                decoded_condition_fingerprint="CmpNE(var:index,const:0)",
                guard_condition_fingerprint="CmpEQ(var:index,const:0)",
            ),
        ),
        condition_fingerprint=_validation_condition_fingerprint,
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD


def test_control_flow_refuses_untagged_folded_loop_with_wrong_body_target() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        local,
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4999)],
            codegen=codegen,
        ),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(
                decoded_condition_fingerprint="CmpNE(var:index,const:0)",
                guard_condition_fingerprint="CmpEQ(var:index,const:0)",
            ),
        ),
        condition_fingerprint=_validation_condition_fingerprint,
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD


def test_control_flow_refuses_untagged_folded_loop_condition_mismatch() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop = CWhileLoop(
        _condition(local, 1, codegen),
        CStatements(
            [_target_statement(local, codegen, ins_addr=0x4010)],
            codegen=codegen,
        ),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(
                decoded_condition_fingerprint="CmpNE(var:index,const:0)",
                guard_condition_fingerprint="CmpEQ(var:index,const:0)",
            ),
        ),
        condition_fingerprint=_validation_condition_fingerprint,
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD


def test_control_flow_refuses_ambiguous_untagged_folded_loop_match() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loops = [
        CWhileLoop(
            local,
            CStatements(
                [_target_statement(local, codegen, ins_addr=0x4010)],
                codegen=codegen,
            ),
            codegen=codegen,
        )
        for _index in range(2)
    ]

    report = validate_structured_control_flow_8616(
        CStatements(loops, codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(
                decoded_condition_fingerprint="CmpNE(var:index,const:0)",
                guard_condition_fingerprint="CmpEQ(var:index,const:0)",
            ),
        ),
        condition_fingerprint=_validation_condition_fingerprint,
    )

    assert report.passed is False
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.DUPLICATE_GUARD
    assert report.issues[0].match_count == 2


def test_control_flow_refuses_missing_proven_loop_break_guard() -> None:
    codegen = _Codegen()
    root = CStatements([], codegen=codegen)

    report = validate_structured_control_flow_8616(
        root,
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.passed is False
    assert report.materialized_count == 0
    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.MISSING_GUARD


def test_control_flow_refuses_proven_jcc_on_non_break_shape() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    ordinary_if = CIfElse(
        [
            (
                _loop_branch_condition(local, codegen),
                CStatements(
                    [CAssignment(local, _const(1, codegen), codegen=codegen)],
                    codegen=codegen,
                ),
            )
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

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.WRONG_GUARD_SHAPE


def test_control_flow_refuses_proven_break_guard_outside_loop() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    guard = CIfBreak(
        _loop_branch_condition(local, codegen),
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([guard, loop], codegen=codegen),
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.GUARD_OUTSIDE_LOOP


def test_control_flow_refuses_duplicate_proven_loop_break_guard() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    guards = [
        CIfBreak(_loop_branch_condition(local, codegen), codegen=codegen),
        CIfBreak(_loop_branch_condition(local, codegen), codegen=codegen),
    ]
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements(guards, codegen=codegen),
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(
        CStatements([loop], codegen=codegen),
        loop_branch_facts=(_loop_branch_fact(),),
    )

    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.DUPLICATE_GUARD
    assert report.issues[0].match_count == 2


def test_control_flow_refuses_invalid_loop_break_fact() -> None:
    codegen = _Codegen()

    report = validate_structured_control_flow_8616(
        CStatements([], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(body_target=0x4010, false_target=0x4010),
        ),
    )

    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.INVALID_EVIDENCE


def test_control_flow_refuses_conflicting_loop_break_facts() -> None:
    codegen = _Codegen()

    report = validate_structured_control_flow_8616(
        CStatements([], codegen=codegen),
        loop_branch_facts=(
            _loop_branch_fact(false_target=0x4020),
            _loop_branch_fact(block_addr=0x4003, false_target=0x4030),
        ),
    )

    assert report.issues[0].kind is LoopBranchGuardIssueKind8616.CONFLICTING_EVIDENCE
    assert report.issues[0].match_count == 2


def test_tail_validation_refuses_duplicate_guard_when_baseline_already_has_it() -> None:
    issue = "unreachable-duplicate-guard-body:sequence=0:statement=0"

    result = build_x86_16_tail_validation_cached_result(
        owner={},
        stage="postprocess",
        mode="live_out",
        before_fingerprint="same-unreachable-body",
        after_fingerprint="same-unreachable-body",
        before_summary=_empty_summary(control_flow_issues=(issue,)),
        after_summary=_empty_summary(control_flow_issues=(issue,)),
    )

    assert result["changed"] is True
    assert result["status"] == "failed"
    assert result["semantic_failures"] == {"control_flow": (issue,)}


def test_final_semantic_refresh_promotes_absolute_control_flow_failure() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    loop_body = CStatements(
        [
            CIfBreak(_condition(local, 0, codegen), codegen=codegen),
            _guarded_assignment(_condition(local, 0, codegen), local, codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements(
            [
                CAssignment(local, _const(0, codegen), codegen=codegen),
                CWhileLoop(_const(1, codegen), loop_body, codegen=codegen),
            ],
            codegen=codegen,
        ),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    assert report.passed is False
    assert report.control_flow.failure_count == 1
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {
        "control_flow": (
            "unreachable-duplicate-guard-body:sequence=1:statement=0",
        )
    }
    assert postprocess["final_semantic_guard"]["control_flow"] == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_tail_validation_summary_cache_keys_control_flow_state_separately() -> None:
    codegen = _Codegen()
    local = _local(codegen)
    bad_body = CStatements(
        [
            CIfBreak(_condition(local, 0, codegen), codegen=codegen),
            _guarded_assignment(_condition(local, 0, codegen), local, codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements(
            [
                CAssignment(local, _const(0, codegen), codegen=codegen),
                CWhileLoop(_const(1, codegen), bad_body, codegen=codegen),
            ],
            codegen=codegen,
        ),
    )

    before = collect_x86_16_tail_validation_summary(
        codegen.project,
        codegen,
        boundary_fingerprint="same-control-flow-boundary",
    )
    bad_body.statements.pop(1)
    after = collect_x86_16_tail_validation_summary(
        codegen.project,
        codegen,
        boundary_fingerprint="same-control-flow-boundary",
    )

    assert before.control_flow_issues
    assert after.control_flow_issues == ()
    assert codegen._inertia_tail_validation_last_summary_cache_hit is False


def test_final_semantic_refresh_promotes_missing_proven_loop_break_guard() -> None:
    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_loop_branch_guard_facts_8616 = (_loop_branch_fact(),)
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    assert report.passed is False
    assert report.control_flow.failure_count == 1
    assert report.control_flow.issues[0].kind is (
        LoopBranchGuardIssueKind8616.MISSING_GUARD
    )
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False


def _switch_exit_root(
    codegen: _Codegen,
    *,
    include_case: bool = True,
    return_from_case: bool = True,
) -> CStatements:
    case_body = CStatements(
        [
            CReturn(None, codegen=codegen, tags={"ins_addr": 0x441A})
            if return_from_case
            else CAssignment(_local(codegen), _const(1, codegen), codegen=codegen)
        ],
        addr=0x441A,
        codegen=codegen,
    )
    switch = CSwitchCase(
        _const(0, codegen),
        [(27, case_body)] if include_case else [],
        None,
        codegen=codegen,
    )
    return CStatements([switch], codegen=codegen)


def test_switch_exit_obligation_accepts_exact_unconditional_return() -> None:
    codegen = _Codegen()
    evidence = (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),)

    report = validate_switch_exit_obligations_8616(
        _switch_exit_root(codegen),
        evidence,
    )

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_switch_exit_obligation_rejects_missing_or_nonreturn_case() -> None:
    codegen = _Codegen()
    evidence = (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),)

    missing = validate_switch_exit_obligations_8616(
        _switch_exit_root(codegen, include_case=False),
        evidence,
    )
    wrong_exit = validate_switch_exit_obligations_8616(
        _switch_exit_root(codegen, return_from_case=False),
        evidence,
    )

    assert missing.issues[0].kind is ControlFlowObligationIssueKind8616.MISSING_CASE
    assert wrong_exit.issues[0].kind is ControlFlowObligationIssueKind8616.WRONG_EXIT_SHAPE


def test_switch_exit_obligation_rejects_unanchored_and_ambiguous_cases() -> None:
    codegen = _Codegen()
    evidence = (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),)
    unanchored_root = _switch_exit_root(codegen)
    unanchored_switch = unanchored_root.statements[0]
    assert isinstance(unanchored_switch, CSwitchCase)
    unanchored_body = unanchored_switch.cases[0][1]
    unanchored_body.addr = None
    unanchored_body.statements[0].tags = {}
    first_root = _switch_exit_root(codegen)
    second_root = _switch_exit_root(codegen)
    ambiguous_root = CStatements(
        [first_root.statements[0], second_root.statements[0]],
        codegen=codegen,
    )

    unanchored = validate_switch_exit_obligations_8616(unanchored_root, evidence)
    ambiguous = validate_switch_exit_obligations_8616(ambiguous_root, evidence)

    assert unanchored.issues[0].kind is (
        ControlFlowObligationIssueKind8616.MISSING_TARGET_ANCHOR
    )
    assert ambiguous.issues[0].kind is (
        ControlFlowObligationIssueKind8616.AMBIGUOUS_CASE
    )


def test_switch_exit_obligation_rejects_malformed_and_conflicting_evidence() -> None:
    codegen = _Codegen()
    root = _switch_exit_root(codegen)

    malformed = validate_switch_exit_obligations_8616(root, (object(),))
    conflicting = validate_switch_exit_obligations_8616(
        root,
        (
            SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),
            SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x4480),
        ),
    )

    assert malformed.issues[0].kind is (
        ControlFlowObligationIssueKind8616.INVALID_EVIDENCE
    )
    assert malformed.classified_fact_count == 1
    assert malformed.materialized_count == 0
    assert {issue.kind for issue in conflicting.issues} == {
        ControlFlowObligationIssueKind8616.CONFLICTING_EVIDENCE
    }
    assert conflicting.classified_fact_count == 2
    assert conflicting.materialized_count == 0


def test_final_semantic_refresh_rejects_missing_binary_proven_switch_exit() -> None:
    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=_switch_exit_root(codegen, include_case=False),
    )
    codegen._inertia_structuring_switch_loop_exit_return_evidence_8616 = (
        SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
    )

    assert report.passed is False
    assert report.control_flow.classified_fact_count == 1
    assert report.control_flow.materialized_count == 0
    assert report.control_flow.issues[0].kind is (
        ControlFlowObligationIssueKind8616.MISSING_CASE
    )
    assert x86_16_tail_validation_snapshot_passed(
        codegen._inertia_tail_validation_snapshot
    ) is False


def test_tail_summary_rejects_missing_binary_proven_switch_exit() -> None:
    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(
        arg_list=[],
        statements=_switch_exit_root(codegen, include_case=False),
    )
    codegen._inertia_structuring_switch_loop_exit_return_evidence_8616 = (
        SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),
    )

    summary = collect_x86_16_tail_validation_summary(codegen.project, codegen)

    assert summary.control_flow_issues == (
        "switch-exit:missing-case:index=0:case=27:target=0x441a:"
        "exit=0x447b:matches=0",
    )
