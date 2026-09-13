from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfElse,
    CLabel,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR, ConditionRegisterBindingIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.lowering.call_output_stack_objects import (
    WideCallReturnConditionResult8616,
    WideCallReturnConditionStats8616,
)
from angr_platforms.X86_16.structuring import condition_materialization
from angr_platforms.X86_16.structuring.condition_chain_provenance import (
    ConditionChainProvenance8616,
    condition_chain_provenance_8616,
)


class _Codegen:
    def __init__(self):
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Project:
    pass


def test_structuring_condition_materialization_delegates_legacy_consumers_in_order(monkeypatch):
    calls = []

    def _typed(project, codegen):
        calls.append(("typed", project, codegen))
        return True

    def _jcc(project, codegen):
        calls.append(("jcc", project, codegen))
        return False

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        _typed,
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        _jcc,
    )
    monkeypatch.setattr(
        condition_materialization,
        "materialize_structuring_condition_chains_8616",
        lambda project, codegen: calls.append(("chains", project, codegen)) or False,
    )
    project = _Project()
    codegen = _Codegen()

    result = condition_materialization.materialize_structuring_conditions_8616(project, codegen)

    assert result.changed is True
    assert result.typed_conditions_changed is True
    assert result.condition_chains_changed is False
    assert result.decoded_jcc_changed is False
    assert calls == [
        ("typed", project, codegen),
        ("jcc", project, codegen),
        ("chains", project, codegen),
    ]
    assert codegen._inertia_structuring_condition_materialization_8616 == {
        "typed_conditions_changed": True,
        "condition_chains_changed": False,
        "decoded_jcc_changed": False,
        "loop_conditions_changed": False,
        "segment_access_provenance_changed": False,
        "condition_evidence_complete": True,
        "changed": True,
        "owner": "structuring.condition_materialization",
    }
    assert codegen._inertia_condition_materialization_structuring_pass_ran_8616 is True
    assert project._inertia_decompiler_stage == "structuring:condition_materialization:provenance"


def test_cfg_condition_chain_reuses_reconverged_typed_suffixes(monkeypatch):
    """Materialize each equal-address suffix once instead of every syntactic path."""
    codegen = _Codegen()
    project = _Project()
    condition_count = 18
    conditions = tuple(
        ConditionIR(
            op="eq",
            lhs=object(),
            rhs=object(),
            src_insn=0x2000 + index,
            block_addr=0x1000 + index,
            taken_target=(0x1001 + index if index + 1 < condition_count else 0x3000),
            fallthrough_target=(0x1001 + index if index + 1 < condition_count else 0x3001),
        )
        for index in range(condition_count)
    )
    materialized_sources: list[int | None] = []
    expected_assignment_index = object()
    index_builds: list[object] = []

    def _build_assignment_index(active_codegen):
        index_builds.append(active_codegen)
        return expected_assignment_index

    monkeypatch.setattr(
        condition_materialization,
        "build_same_block_register_assignment_index_8616",
        _build_assignment_index,
    )

    monkeypatch.setattr(
        condition_materialization,
        "recover_wide_stack_condition_chain_8616",
        lambda *_args: SimpleNamespace(condition=None),
    )
    monkeypatch.setattr(
        condition_materialization,
        "recover_local_wide_stack_condition_chain_8616",
        lambda *_args: SimpleNamespace(condition=None),
    )

    def _materialize(
        _project,
        active_codegen,
        condition,
        *,
        assignment_index=None,
    ):
        assert assignment_index is expected_assignment_index
        materialized_sources.append(condition.src_insn)
        return CConstant(1, SimTypeShort(False), codegen=active_codegen)

    monkeypatch.setattr(
        condition_materialization,
        "materialize_condition_ir_expression_8616",
        _materialize,
    )
    monkeypatch.setattr(
        condition_materialization,
        "lower_call_output_stack_fields_in_condition_8616",
        lambda _codegen, expression, _conditions: SimpleNamespace(expression=expression),
    )
    monkeypatch.setattr(
        condition_materialization,
        "bind_condition_chain_provenance_8616",
        lambda _expression, _conditions: None,
    )

    result = condition_materialization._materialize_cfg_condition_chain_expr_8616(
        project,
        codegen,
        conditions[0],
        {condition.block_addr: condition for condition in conditions},
        {},
        0x3000,
        0x3001,
    )

    assert isinstance(result, CExpression)
    assert index_builds == [codegen]
    assert materialized_sources == [condition.src_insn for condition in conditions]


def test_canonical_wide_return_owner_blocks_competing_condition_consumers(monkeypatch):
    codegen = _Codegen()
    project = _Project()
    monkeypatch.setattr(
        condition_materialization,
        "wide_stack_return_predicate_materialized_8616",
        lambda _codegen: True,
    )
    monkeypatch.setattr(
        condition_materialization,
        "materialize_structuring_condition_chains_8616",
        lambda _project, _codegen: pytest.fail("canonical wide root was replayed"),
    )
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        lambda _project, _codegen: pytest.fail("canonical wide root was rewritten"),
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        lambda _project, _codegen: pytest.fail("canonical wide root was rewritten"),
    )

    result = condition_materialization.materialize_structuring_conditions_8616(
        project,
        codegen,
    )

    assert result.condition_chains_changed is False
    assert result.typed_conditions_changed is False
    assert result.decoded_jcc_changed is False


def test_condition_chains_materialize_before_loop_conditions(monkeypatch):
    calls = []
    project = _Project()
    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_typed_conditions = ()

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        condition_materialization,
        "materialize_structuring_condition_chains_8616",
        lambda _project, _codegen: calls.append("chains") or False,
    )
    monkeypatch.setattr(
        condition_materialization,
        "materialize_typed_loop_continuation_conditions_8616",
        lambda *_args: calls.append("loops")
        or condition_materialization.LoopConditionMaterializationStats8616(),
    )

    condition_materialization.materialize_structuring_conditions_8616(project, codegen)

    assert calls == ["chains", "loops"]


def test_structuring_condition_materialization_bool_entrypoint(monkeypatch):
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        lambda _project, _codegen: True,
    )

    assert condition_materialization.apply_structuring_condition_materialization_8616(_Project(), _Codegen()) is True


def test_structuring_condition_replay_cleanup_delegates_flag_cleanup_in_order(monkeypatch):
    calls = []

    def _typed(project, codegen):
        calls.append(("typed", project, codegen))
        return False

    def _jcc(project, codegen):
        calls.append(("jcc", project, codegen))
        return True

    def _flag_pairs(codegen):
        calls.append(("flag_pairs", codegen))
        return True

    def _flag_bits(codegen):
        calls.append(("flag_bits", codegen))
        return False

    def _interval(codegen):
        calls.append(("interval", codegen))
        return True

    def _unused(project, codegen):
        calls.append(("unused", project, codegen))
        return True

    def _overwritten(project, codegen):
        calls.append(("overwritten", project, codegen))
        return False

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        _typed,
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        _jcc,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_rewrite_flag_condition_pairs_8616",
        _flag_pairs,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_rewrite_flag_bit_value_uses_8616",
        _flag_bits,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_fix_interval_guard_conditions_8616",
        _interval,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_unused_flag_assignments_8616",
        _unused,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_overwritten_flag_assignments_8616",
        _overwritten,
    )
    project = _Project()
    codegen = _Codegen()

    result = condition_materialization.cleanup_structuring_conditions_after_replay_8616(project, codegen)

    assert result.changed is True
    assert result.materialization.typed_conditions_changed is False
    assert result.materialization.condition_chains_changed is False
    assert result.materialization.decoded_jcc_changed is True
    assert result.flag_condition_pairs_changed is True
    assert result.flag_bit_values_changed is False
    assert result.interval_guards_changed is True
    assert result.unused_flag_assignments_pruned is True
    assert result.overwritten_flag_assignments_pruned is False
    assert calls == [
        ("typed", project, codegen),
        ("jcc", project, codegen),
        ("flag_pairs", codegen),
        ("flag_bits", codegen),
        ("interval", codegen),
        ("unused", project, codegen),
        ("overwritten", project, codegen),
    ]
    assert codegen._inertia_structuring_condition_replay_cleanup_8616 == {
        "typed_conditions_changed": False,
        "condition_chains_changed": False,
        "decoded_jcc_changed": True,
        "condition_evidence_complete": True,
        "flag_condition_pairs_changed": True,
        "flag_bit_values_changed": False,
        "interval_guards_changed": True,
        "unused_flag_assignments_pruned": True,
        "overwritten_flag_assignments_pruned": False,
        "changed": True,
        "owner": "structuring.condition_materialization",
    }


def test_structuring_condition_replay_cleanup_bool_entrypoint(monkeypatch):
    monkeypatch.setattr(
        condition_materialization,
        "cleanup_structuring_conditions_after_replay_8616",
        lambda _project, _codegen: type("Result", (), {"changed": True})(),
    )

    assert condition_materialization.apply_structuring_condition_replay_cleanup_8616(object(), _Codegen()) is True


def test_final_structuring_dead_flag_cleanup_runs_overwrite_fixed_point_first(monkeypatch):
    calls: list[str] = []
    project = _Project()
    codegen = _Codegen()

    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_overwritten_flag_assignments_8616",
        lambda actual_project, actual_codegen: calls.append("overwritten")
        or (actual_project is project and actual_codegen is codegen),
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_unused_flag_assignments_8616",
        lambda actual_project, actual_codegen: calls.append("unused")
        or (actual_project is project and actual_codegen is codegen),
    )

    result = condition_materialization.prune_dead_flag_assignments_after_structuring_8616(project, codegen)

    assert result.changed is True
    assert calls == ["overwritten", "unused"]
    assert codegen._inertia_structuring_dead_flag_cleanup_8616 == {
        "condition_evidence_complete": True,
        "overwritten_flag_assignments_pruned": True,
        "unused_flag_assignments_pruned": True,
        "changed": True,
        "owner": "structuring.condition_materialization",
    }


def test_final_structuring_dead_flag_cleanup_refuses_unclosed_condition_evidence(monkeypatch):
    calls: list[str] = []
    codegen = _Codegen()
    codegen._inertia_structuring_condition_materialization_result_8616 = (
        condition_materialization.StructuringConditionMaterializationResult8616(
            False,
            False,
            False,
            False,
            False,
            condition_evidence_complete=False,
        )
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_overwritten_flag_assignments_8616",
        lambda *_args: calls.append("overwritten") or True,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_unused_flag_assignments_8616",
        lambda *_args: calls.append("unused") or True,
    )

    result = condition_materialization.prune_dead_flag_assignments_after_structuring_8616(
        _Project(),
        codegen,
    )

    assert result.changed is False
    assert calls == []
    assert codegen._inertia_structuring_dead_flag_cleanup_8616 == {
        "condition_evidence_complete": False,
        "overwritten_flag_assignments_pruned": False,
        "unused_flag_assignments_pruned": False,
        "changed": False,
        "owner": "structuring.condition_materialization",
    }


class _Graph:
    def __init__(self, edges):
        self._successors = {}
        for source, target in edges:
            self._successors.setdefault(source, []).append(target)
            self._successors.setdefault(target, [])
        self.nodes = tuple(self._successors)

    def successors(self, node):
        return tuple(self._successors[node])


def _tagged_statements(ins_addr, codegen):
    statements = CStatements([], codegen=codegen)
    statements.tags = {"ins_addr": ins_addr}
    return statements


def _targeted_condition(src_insn, block_addr, taken_target, fallthrough_target):
    return ConditionIR(
        op="ne",
        lhs=src_insn,
        rhs=0,
        src_insn=src_insn,
        block_addr=block_addr,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
    )


def test_structuring_lowers_proven_loop_counter_binding() -> None:
    """Structuring must consume Alias's exact LOOP input instead of a register live-in."""
    codegen = _Codegen()
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name="cx", size=2),
        rhs=IRValue(MemSpace.CONST, const=1, size=2),
        width_bits=16,
        source=("loop",),
        src_insn=0x1003,
        block_addr=0x1003,
        producer_insn=0x1003,
        producer_semantics=("loop_counter_predecrement", "cx", 1),
        register_bindings=(
            ConditionRegisterBindingIR(
                "cx",
                IRValue(MemSpace.CONST, const=0xC8, size=2),
            ),
        ),
    )

    expression = condition_materialization.materialize_condition_ir_expression_8616(
        codegen.project,
        codegen,
        condition,
    )

    assert isinstance(expression, CBinaryOp)
    assert expression.op == "CmpNE"
    assert isinstance(expression.lhs, CConstant)
    assert expression.lhs.value == 0xC8
    assert isinstance(expression.rhs, CConstant)
    assert expression.rhs.value == 1


def test_structuring_projects_high_byte_from_same_block_word_assignment() -> None:
    """A BH condition must reuse the exact BX SSA definition in its VEX block."""
    codegen = _Codegen()
    prior_bx = CVariable(
        SimRegisterVariable(12, 2, ident="ir_6", region=0x1000, name="bx"),
        codegen=codegen,
    )
    updated_bx = CVariable(
        SimRegisterVariable(12, 2, ident="ir_9", region=0x1000, name="bx"),
        codegen=codegen,
    )
    update = CAssignment(
        updated_bx,
        CBinaryOp(
            "Add",
            prior_bx,
            CConstant(0x16C, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x100D, "vex_block_addr": 0x100D},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements([update], codegen=codegen),
    )
    condition = ConditionIR(
        op="ult",
        lhs=IRValue(MemSpace.REG, name="bh", offset=13, size=1),
        rhs=IRValue(MemSpace.CONST, const=0x40, size=1),
        width_bits=8,
        source=("cmp", "jb"),
        src_insn=0x1012,
        block_addr=0x100D,
        producer_insn=0x100F,
        taken_target=0x0FFE,
        fallthrough_target=0x1014,
        producer_semantics=("cmp_reg_imm8", "bh", 0x40),
    )

    expression = condition_materialization.materialize_condition_ir_expression_8616(
        codegen.project,
        codegen,
        condition,
    )

    assert isinstance(expression, CBinaryOp)
    assert expression.op == "CmpLT"
    assert isinstance(expression.lhs, CBinaryOp)
    assert expression.lhs.op == "And"
    assert isinstance(expression.lhs.lhs, CBinaryOp)
    assert expression.lhs.lhs.op == "Shr"
    assert expression.lhs.lhs.rhs.value == 8
    assert expression.lhs.rhs.value == 0xFF
    assert expression.rhs.value == 0x40


def test_structuring_replays_high_byte_projection_into_typed_condition(monkeypatch) -> None:
    """The structuring pass must project conditions built by the legacy consumer."""
    codegen = _Codegen()
    prior_bx = CVariable(
        SimRegisterVariable(12, 2, ident="ir_6", region=0x1000, name="bx"),
        codegen=codegen,
    )
    updated_bx = CVariable(
        SimRegisterVariable(12, 2, ident="ir_9", region=0x1000, name="bx"),
        codegen=codegen,
    )
    update = CAssignment(
        updated_bx,
        CBinaryOp(
            "Add",
            prior_bx,
            CConstant(0x16C, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x100D, "vex_block_addr": 0x100D},
    )
    typed = CBinaryOp(
        "CmpLT",
        CVariable(
            SimRegisterVariable(13, 1, ident="ir_bh", region=0x1000, name="bh"),
            codegen=codegen,
        ),
        CConstant(0x40, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x100D,
            "vex_block_addr": 0x100D,
        },
    )
    branch = CIfElse(
        [(typed, CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([update, branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    condition = ConditionIR(
        op="ult",
        lhs=IRValue(MemSpace.REG, name="bh", offset=13, size=1),
        rhs=IRValue(MemSpace.CONST, const=0x40, size=1),
        width_bits=8,
        source=("cmp", "jb"),
        src_insn=0x1012,
        block_addr=0x100D,
        producer_insn=0x100F,
        taken_target=0x0FFE,
        fallthrough_target=0x1014,
        producer_semantics=("cmp_reg_imm8", "bh", 0x40),
    )
    real_builder = condition_materialization.build_same_block_register_assignment_index_8616
    real_condition_key = condition_materialization.condition_key_from_tags_8616
    index_builds: list[object] = []
    condition_key_queries: list[object] = []

    def _record_index_build(active_codegen):
        index_builds.append(active_codegen)
        return real_builder(active_codegen)

    def _record_condition_key_query(node):
        condition_key_queries.append(node)
        return real_condition_key(node)

    monkeypatch.setattr(
        condition_materialization,
        "build_same_block_register_assignment_index_8616",
        _record_index_build,
    )
    monkeypatch.setattr(
        condition_materialization,
        "condition_key_from_tags_8616",
        _record_condition_key_query,
    )

    stats = condition_materialization.materialize_same_block_condition_register_projections_8616(
        root,
        codegen.project,
        codegen,
        (condition,),
    )

    assert stats == condition_materialization.SameBlockConditionRegisterProjectionStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        changed_count=1,
    )
    assert index_builds == [codegen]
    assert condition_key_queries == [typed]
    assert isinstance(typed.lhs, CBinaryOp)
    assert typed.lhs.op == "And"
    assert isinstance(typed.lhs.lhs, CBinaryOp)
    assert typed.lhs.lhs.op == "Shr"
    assert typed.lhs.lhs.rhs.value == 8
    assert typed.lhs.rhs.value == 0xFF


def test_structuring_preserves_noncanonical_duplicate_instruction_surface(monkeypatch) -> None:
    """One typed owner must prevent a second internal exit claiming the same fact."""
    codegen = _Codegen()
    untyped = CConstant(
        0,
        SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x1003, "vex_block_addr": 0x1003},
    )
    typed = CBinaryOp(
        "CmpNE",
        CConstant(0xC8, SimTypeShort(False), codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x1003,
            "vex_block_addr": 0x1003,
            "typed_condition": True,
        },
    )
    first = CIfElse(
        [(untyped, _tagged_statements(0x1005, codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    second = CIfElse(
        [(typed, _tagged_statements(0x1003, codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([first, second], codegen=codegen)
    fact = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name="cx", size=2),
        rhs=IRValue(MemSpace.CONST, const=1, size=2),
        width_bits=16,
        source=("loop",),
        src_insn=0x1003,
        block_addr=0x1003,
        producer_insn=0x1003,
        taken_target=0x1003,
        fallthrough_target=0x1005,
        producer_semantics=("loop_counter_predecrement", "cx", 1),
    )
    graph = _Graph(((0x1003, 0x1003), (0x1003, 0x1005)))
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes),
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function))
    )
    codegen.cfunc = SimpleNamespace(addr=0x1003, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    calls: list[CExpression] = []

    def _materialize(
        _project,
        _codegen,
        _fact,
        structured_condition,
        _body,
        _conditions_by_block,
        _successors,
        **_kwargs,
    ):
        calls.append(structured_condition)
        return CBinaryOp(
            "CmpNE",
            CConstant(0xC8, SimTypeShort(False), codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    monkeypatch.setattr(
        condition_materialization,
        "_materialize_cfg_single_branch_expr_8616",
        _materialize,
    )

    assert condition_materialization.materialize_structuring_condition_chains_8616(
        project,
        codegen,
    )
    assert calls == [typed]
    assert first.condition_and_nodes[0][0] is untyped
    replacement = second.condition_and_nodes[0][0]
    assert replacement.tags["inertia_structuring_condition_cfg_materialized_8616"] is True
    assert codegen._inertia_structuring_condition_chain_stats_8616.materialized_count == 1


def test_structuring_condition_surface_token_detects_in_place_branch_reownership():
    codegen = _Codegen()
    condition = CBinaryOp(
        "CmpEQ",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1002, "vex_block_addr": 0x1000},
    )
    return_body = _tagged_statements(0x1020, codegen)
    guarded_body = _tagged_statements(0x1010, codegen)
    branch = CIfElse(
        [(condition, return_body)],
        else_node=guarded_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    before = condition_materialization.structuring_condition_surface_token_8616(codegen)
    branch.condition_and_nodes = [(condition, guarded_body)]
    branch.else_node = None
    after = condition_materialization.structuring_condition_surface_token_8616(codegen)

    assert before != after


def test_structuring_condition_surface_token_detects_rebuilt_loop_condition():
    codegen = _Codegen()
    original_condition = CBinaryOp(
        "CmpLT",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1002, "vex_block_addr": 0x1000},
    )
    loop = CForLoop(
        None,
        original_condition,
        None,
        _tagged_statements(0x1010, codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([loop], codegen=codegen)
    )

    before = condition_materialization.structuring_condition_surface_token_8616(
        codegen
    )
    loop.condition = CBinaryOp(
        "CmpLT",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1002, "vex_block_addr": 0x1000},
    )
    after = condition_materialization.structuring_condition_surface_token_8616(
        codegen
    )

    assert before != after


def test_structuring_condition_surface_token_detects_in_place_operand_replacement():
    codegen = _Codegen()
    condition = CBinaryOp(
        "CmpLT",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1002, "vex_block_addr": 0x1000},
    )
    loop = CForLoop(
        None,
        condition,
        None,
        _tagged_statements(0x1010, codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([loop], codegen=codegen)
    )

    before = condition_materialization.structuring_condition_surface_token_8616(
        codegen
    )
    condition.rhs = CConstant(3, SimTypeShort(False), codegen=codegen)
    after = condition_materialization.structuring_condition_surface_token_8616(
        codegen
    )

    assert before != after


def test_structuring_condition_chain_materializes_three_branch_short_circuit(monkeypatch):
    codegen = _Codegen()
    root_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    root_condition.tags = {"ins_addr": 0x103F, "vex_block_addr": 0x103B}
    true_body = _tagged_statements(0x1056, codegen)
    true_body.tags["vex_block_addr"] = 0x1056
    false_body = _tagged_statements(0x105E, codegen)
    false_body.tags["vex_block_addr"] = 0x105E
    branch = CIfElse(
        [(root_condition, true_body)],
        else_node=false_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    branch.tags = {"ins_addr": 0x103B}
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x103F, 0x103B, 0x1044, 0x1041),
        _targeted_condition(0x1048, 0x1044, 0x104D, 0x104A),
        ConditionIR(
            op="eq",
            lhs=0x1051,
            rhs=0,
            src_insn=0x1051,
            block_addr=0x104D,
            taken_target=0x1056,
            fallthrough_target=0x1053,
        ),
    )
    graph = _Graph(
        (
            (0x103B, 0x1044),
            (0x103B, 0x1041),
            (0x1041, 0x1056),
            (0x1044, 0x104D),
            (0x1044, 0x104A),
            (0x104A, 0x1056),
            (0x104D, 0x1056),
            (0x104D, 0x1053),
            (0x1053, 0x105E),
        )
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x103B, 0x1044, 0x104D})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = conditions

    def _materialize(_project, condition, _codegen):
        value = CConstant(condition.src_insn, SimTypeShort(False), codegen=codegen)
        zero = CConstant(0, SimTypeShort(False), codegen=codegen)
        return CBinaryOp("CmpEQ" if condition.op == "eq" else "CmpNE", value, zero, codegen=codegen)

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "LogicalOr"
    assert replacement.lhs.op == "CmpEQ"
    assert replacement.lhs.lhs.value == 0x103F
    assert replacement.rhs.op == "LogicalOr"
    assert replacement.rhs.lhs.op == "CmpEQ"
    assert replacement.rhs.lhs.lhs.value == 0x1048
    assert replacement.rhs.rhs.op == "CmpEQ"
    assert replacement.rhs.rhs.lhs.value == 0x1051
    assert condition_chain_provenance_8616(replacement) == (
        ConditionChainProvenance8616((0x103F, 0x1048, 0x1051))
    )
    assert replacement.lhs.tags["ins_addr"] == 0x103F
    assert replacement.rhs.lhs.tags["ins_addr"] == 0x1048
    assert replacement.rhs.rhs.tags["ins_addr"] == 0x1051
    assert replacement.tags["inertia_structuring_condition_chain_materialized_8616"] is True
    assert codegen._inertia_structuring_condition_chain_stats_8616 == (
        condition_materialization.StructuringConditionChainStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )
    )


def test_structuring_complementary_if_else_prefers_direct_root_condition(monkeypatch):
    codegen = _Codegen()
    original = CConstant(1, SimTypeShort(False), codegen=codegen)
    original.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    true_body = _tagged_statements(0x1010, codegen)
    true_body.tags["vex_block_addr"] = 0x1010
    false_body = _tagged_statements(0x1020, codegen)
    false_body.tags["vex_block_addr"] = 0x1020
    branch = CIfElse(
        [(original, true_body)],
        else_node=false_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    fact = _targeted_condition(0x1002, 0x1000, 0x1010, 0x1020)
    graph = _Graph(
        (
            (0x1000, 0x1010),
            (0x1000, 0x1020),
            (0x1010, 0x1030),
            (0x1020, 0x1030),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes),
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function))
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = (fact,)

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(0x1002, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )
    monkeypatch.setattr(
        condition_materialization,
        "_materialize_cfg_condition_chain_expr_8616",
        lambda *_args, **_kwargs: CConstant(0xDEAD, SimTypeShort(False), codegen=codegen),
    )

    assert condition_materialization.materialize_structuring_condition_chains_8616(
        project,
        codegen,
    )
    replacement = branch.condition_and_nodes[0][0]
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "CmpNE"
    assert replacement.lhs.value == 0x1002
    replay = condition_materialization.condition_replay_facts_8616(codegen)
    assert len(replay) == 1
    assert replay[0].true_target == 0x1010
    assert replay[0].false_target == 0x1020


def test_structuring_condition_chain_collapses_cfg_proven_assignment_diamond(monkeypatch):
    codegen = _Codegen()
    root_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    root_condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    second_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    second_condition.tags = {"ins_addr": 0x1012, "vex_block_addr": 0x1010}
    third_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    third_condition.tags = {"ins_addr": 0x1022, "vex_block_addr": 0x1020}
    result_variable = SimStackVariable(-4, 2, base="bp", name="result", region=0x1000)
    true_assignment = CAssignment(
        CVariable(result_variable, codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1030, "vex_block_addr": 0x1030},
    )
    false_assignment = CAssignment(
        CVariable(result_variable, codegen=codegen),
        CConstant(15, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1040, "vex_block_addr": 0x1040},
    )
    second_branch = CIfElse(
        [
            (
                second_condition,
                CStatements(
                    [CGoto(0x1030, None, codegen=codegen, tags={"ins_addr": 0x1012})],
                    codegen=codegen,
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
        tags={"ins_addr": 0x1012},
    )
    third_branch = CIfElse(
        [
            (
                third_condition,
                CStatements(
                    [CGoto(0x1030, None, codegen=codegen, tags={"ins_addr": 0x1022})],
                    codegen=codegen,
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
        tags={"ins_addr": 0x1022},
    )
    branch = CIfElse(
        [
            (
                root_condition,
                CStatements(
                    [second_branch, third_branch, false_assignment],
                    codegen=codegen,
                ),
            )
        ],
        else_node=CStatements(
            [
                CLabel("LABEL_1030", codegen=codegen, tags={"ins_addr": 0x1030}),
                true_assignment,
            ],
            codegen=codegen,
        ),
        cstyle_ifs=True,
        codegen=codegen,
        tags={"ins_addr": 0x1002},
    )
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x1002, 0x1000, 0x1010, 0x1030),
        _targeted_condition(0x1012, 0x1010, 0x1020, 0x1030),
        ConditionIR(
            op="eq",
            lhs=0x1022,
            rhs=0,
            src_insn=0x1022,
            block_addr=0x1020,
            taken_target=0x1030,
            fallthrough_target=0x1040,
        ),
    )
    graph = _Graph(
        (
            (0x1000, 0x1010),
            (0x1000, 0x1030),
            (0x1010, 0x1020),
            (0x1010, 0x1030),
            (0x1020, 0x1030),
            (0x1020, 0x1040),
            (0x1030, 0x1050),
            (0x1040, 0x1050),
        )
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes))
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = conditions

    def _materialize(_project, condition, _codegen):
        value = CConstant(condition.src_insn, SimTypeShort(False), codegen=codegen)
        zero = CConstant(0, SimTypeShort(False), codegen=codegen)
        return CBinaryOp("CmpEQ" if condition.op == "eq" else "CmpNE", value, zero, codegen=codegen)

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement, true_body = branch.condition_and_nodes[0]
    assert replacement.tags["inertia_structuring_assignment_diamond_materialized_8616"] is True
    assert true_body.statements == [true_assignment]
    assert branch.else_node.statements == [false_assignment]
    assert all(not isinstance(node, CGoto) for node in condition_materialization._iter_c_nodes_deep_8616(branch))
    assert codegen._inertia_structuring_condition_chain_stats_8616.materialized_count == 1
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 0
    replay_facts = codegen._inertia_structuring_condition_replay_facts_8616
    assert len(replay_facts) == 1
    assert replay_facts[0].true_target == 0x1030
    assert replay_facts[0].false_target == 0x1040

    changed_again = condition_materialization.materialize_structuring_condition_chains_8616(
        project,
        codegen,
    )

    assert changed_again is False
    assert branch.condition_and_nodes[0][0] is replacement
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 0


def test_structuring_assignment_diamond_refuses_extra_semantic_call(monkeypatch):
    codegen = _Codegen()
    root_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    root_condition.tags = {"ins_addr": 0x2002, "vex_block_addr": 0x2000}
    nested_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    nested_condition.tags = {"ins_addr": 0x2012, "vex_block_addr": 0x2010}
    result_variable = SimStackVariable(-4, 2, base="bp", name="result", region=0x2000)
    true_assignment = CAssignment(
        CVariable(result_variable, codegen=codegen),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x2030, "vex_block_addr": 0x2030},
    )
    false_assignment = CAssignment(
        CVariable(result_variable, codegen=codegen),
        CConstant(15, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x2040, "vex_block_addr": 0x2040},
    )
    semantic_call = CFunctionCall(
        "side_effect",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x2014, "vex_block_addr": 0x2010},
    )
    nested_branch = CIfElse(
        [
            (
                nested_condition,
                CStatements(
                    [CGoto(0x2030, None, codegen=codegen, tags={"ins_addr": 0x2012})],
                    codegen=codegen,
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
        tags={"ins_addr": 0x2012},
    )
    branch = CIfElse(
        [
            (
                root_condition,
                CStatements(
                    [semantic_call, nested_branch, false_assignment],
                    codegen=codegen,
                ),
            )
        ],
        else_node=CStatements([true_assignment], codegen=codegen),
        cstyle_ifs=True,
        codegen=codegen,
        tags={"ins_addr": 0x2002},
    )
    conditions = (
        _targeted_condition(0x2002, 0x2000, 0x2010, 0x2030),
        _targeted_condition(0x2012, 0x2010, 0x2030, 0x2040),
    )
    graph = _Graph(
        (
            (0x2000, 0x2010),
            (0x2000, 0x2030),
            (0x2010, 0x2030),
            (0x2010, 0x2040),
            (0x2030, 0x2050),
            (0x2040, 0x2050),
        )
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes))
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=CStatements([branch], codegen=codegen))
    codegen._inertia_typed_conditions = conditions
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CConstant(1, SimTypeShort(False), codegen=codegen),
    )

    condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    replacement = branch.condition_and_nodes[0][0]
    assert replacement.tags.get("inertia_structuring_assignment_diamond_materialized_8616") is not True
    assert semantic_call in branch.condition_and_nodes[0][1].statements


def test_structuring_replays_typed_wide_condition_over_existing_boolean_form(monkeypatch):
    codegen = _Codegen()
    expression = CUnaryOp(
        "Not",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    expression.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    body = _tagged_statements(0x1040, codegen)
    branch = CIfElse([(expression, body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    dx = IRValue(MemSpace.REG, name="dx", offset=4, size=2)
    ax = IRValue(MemSpace.REG, name="ax", offset=0, size=2)
    high = IRValue(MemSpace.SS, name="bp", offset=-2, size=2)
    low = IRValue(MemSpace.SS, name="bp", offset=-4, size=2)
    conditions = (
        ConditionIR(
            op="sle",
            lhs=dx,
            rhs=high,
            src_insn=0x1002,
            block_addr=0x1000,
            taken_target=0x1010,
            fallthrough_target=0x1030,
        ),
        ConditionIR(
            op="sge",
            lhs=dx,
            rhs=high,
            src_insn=0x1012,
            block_addr=0x1010,
            taken_target=0x1020,
            fallthrough_target=0x1030,
        ),
        ConditionIR(
            op="ule",
            lhs=ax,
            rhs=low,
            src_insn=0x1022,
            block_addr=0x1020,
            taken_target=0x1040,
            fallthrough_target=0x1030,
        ),
    )
    call = CFunctionCall("clock", None, [], codegen=codegen)
    lowered = CBinaryOp(
        "CmpGT",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    prune_calls: list[CFunctionCall] = []
    monkeypatch.setattr(
        condition_materialization,
        "lower_wide_call_return_condition_chain_8616",
        lambda *_args: WideCallReturnConditionResult8616(
            expression=lowered,
            stats=WideCallReturnConditionStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
            ),
            consumed_call=call,
        ),
    )
    monkeypatch.setattr(
        condition_materialization,
        "prune_materialized_wide_condition_call_carrier_8616",
        lambda _codegen, consumed_call: prune_calls.append(consumed_call) or 1,
    )
    monkeypatch.setattr(
        condition_materialization,
        "prune_materialized_call_output_stack_carriers_8616",
        lambda _codegen: 0,
    )

    changed, stats = condition_materialization._materialize_existing_wide_call_return_conditions_8616(
        codegen,
        conditions,
        {condition.src_insn: condition for condition in conditions},
        {
            0x1000: (0x1010, 0x1030),
            0x1010: (0x1020, 0x1030),
            0x1020: (0x1040, 0x1030),
            0x1030: (),
            0x1040: (),
        },
    )

    assert changed is True
    replacement = branch.condition_and_nodes[0][0]
    assert replacement is lowered
    assert replacement.tags["inertia_structuring_wide_call_return_condition_materialized_8616"] is True
    assert prune_calls == [call]
    assert stats == condition_materialization.StructuringConditionChainStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def test_structuring_shared_body_chain_materializes_all_cfg_conditions(monkeypatch):
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    first_condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    last_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    last_condition.tags = {"ins_addr": 0x1022, "vex_block_addr": 0x1020}
    shared_body = _tagged_statements(0x1040, codegen)
    shared_body.tags["vex_block_addr"] = 0x1040
    branch = CIfElse(
        [(first_condition, shared_body), (last_condition, shared_body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    branch.tags = {"ins_addr": 0x1000}
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x1002, 0x1000, 0x1010, 0x1004),
        _targeted_condition(0x1012, 0x1010, 0x1020, 0x1014),
        _targeted_condition(0x1022, 0x1020, 0x1030, 0x1024),
    )
    graph = _Graph(
        (
            (0x1000, 0x1010),
            (0x1000, 0x1004),
            (0x1004, 0x1040),
            (0x1010, 0x1020),
            (0x1010, 0x1014),
            (0x1014, 0x1000),
            (0x1020, 0x1030),
            (0x1020, 0x1024),
            (0x1030, 0x1000),
            (0x1024, 0x1040),
        )
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes))
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = conditions

    def _materialize(_project, condition, _codegen):
        value = CConstant(condition.src_insn, SimTypeShort(False), codegen=codegen)
        zero = CConstant(0, SimTypeShort(False), codegen=codegen)
        return CBinaryOp("CmpNE", value, zero, codegen=codegen)

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    refused = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert refused is False
    assert len(branch.condition_and_nodes) == 2
    assert codegen._inertia_structuring_condition_chain_stats_8616 == (
        condition_materialization.StructuringConditionChainStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )
    )

    def _lower_wide(_codegen, expression, _conditions):
        return WideCallReturnConditionResult8616(
            expression=expression,
            stats=WideCallReturnConditionStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
            ),
        )

    monkeypatch.setattr(
        condition_materialization,
        "lower_wide_call_return_condition_chain_8616",
        _lower_wide,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    assert len(branch.condition_and_nodes) == 1
    replacement, body = branch.condition_and_nodes[0]
    assert body is shared_body
    assert replacement.op == "LogicalOr"
    assert replacement.lhs.op == "CmpEQ"
    assert replacement.lhs.lhs.value == 0x1002
    assert replacement.rhs.op == "LogicalAnd"
    assert replacement.rhs.lhs.op == "CmpNE"
    assert replacement.rhs.lhs.lhs.value == 0x1012
    assert replacement.rhs.rhs.op == "CmpEQ"
    assert replacement.rhs.rhs.lhs.value == 0x1022
    assert replacement.tags["inertia_structuring_shared_body_condition_chain_materialized_8616"] is True
    assert replacement.tags["inertia_structuring_shared_body_target_8616"] == 0x1040
    assert codegen._inertia_structuring_condition_chain_stats_8616 == (
        condition_materialization.StructuringConditionChainStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )
    )

    changed_again = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed_again is False
    assert branch.condition_and_nodes[0][0] is replacement


def test_structuring_shared_body_chain_refuses_missing_middle_condition(monkeypatch):
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    first_condition.tags = {"ins_addr": 0x2002, "vex_block_addr": 0x2000}
    last_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    last_condition.tags = {"ins_addr": 0x2022, "vex_block_addr": 0x2020}
    shared_body = _tagged_statements(0x2040, codegen)
    shared_body.tags["vex_block_addr"] = 0x2040
    branch = CIfElse(
        [(first_condition, shared_body), (last_condition, shared_body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x2002, 0x2000, 0x2010, 0x2004),
        _targeted_condition(0x2022, 0x2020, 0x2030, 0x2024),
    )
    graph = _Graph(
        (
            (0x2000, 0x2010),
            (0x2000, 0x2004),
            (0x2004, 0x2040),
            (0x2010, 0x2020),
            (0x2010, 0x2014),
            (0x2014, 0x2000),
            (0x2020, 0x2030),
            (0x2020, 0x2024),
            (0x2030, 0x2000),
            (0x2024, 0x2040),
        )
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes))
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=root)
    codegen._inertia_typed_conditions = conditions
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert len(branch.condition_and_nodes) == 2
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 1


def test_structuring_shared_body_chain_refuses_different_body_targets():
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    first_condition.tags = {"ins_addr": 0x3002, "vex_block_addr": 0x3000}
    second_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    second_condition.tags = {"ins_addr": 0x3012, "vex_block_addr": 0x3010}
    first_body = _tagged_statements(0x3040, codegen)
    first_body.tags["vex_block_addr"] = 0x3040
    second_body = _tagged_statements(0x3050, codegen)
    second_body.tags["vex_block_addr"] = 0x3050
    branch = CIfElse(
        [(first_condition, first_body), (second_condition, second_body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x3002, 0x3000, 0x3010, 0x3004),
        _targeted_condition(0x3012, 0x3010, 0x3040, 0x3014),
    )
    graph = _Graph(((0x3000, 0x3010), (0x3000, 0x3004), (0x3010, 0x3040), (0x3010, 0x3014)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x3050})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x3000, statements=root)
    codegen._inertia_typed_conditions = conditions

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert len(branch.condition_and_nodes) == 2
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 1


def test_structuring_condition_owner_refuses_unrelated_container_tag():
    fact = _targeted_condition(0x103F, 0x103B, 0x1044, 0x1041)
    condition_blocks = frozenset({fact.block_addr})

    assert condition_materialization._structured_node_owns_condition_fact_8616(
        0x103F, fact, {}, condition_blocks
    )
    assert condition_materialization._structured_node_owns_condition_fact_8616(
        0x103B, fact, {}, condition_blocks
    )
    assert condition_materialization._structured_node_owns_condition_fact_8616(
        None, fact, {}, condition_blocks
    )
    assert not condition_materialization._structured_node_owns_condition_fact_8616(
        0x9999, fact, {}, condition_blocks
    )


def test_structuring_condition_chain_refuses_unproven_leaf(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x2002, "vex_block_addr": 0x2000}
    true_body = _tagged_statements(0x2010, codegen)
    false_body = _tagged_statements(0x2020, codegen)
    root = CStatements(
        [CIfElse([(condition, true_body)], else_node=false_body, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x2002, 0x2000, 0x2004, 0x2006)
    graph = _Graph(((0x2004, 0x2010),))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x2000, 0x2006, 0x2020})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert root.statements[0].condition_and_nodes[0][0] is condition
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 1


def test_structuring_single_branch_materializes_hidden_taken_path_condition(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    body = _tagged_statements(0x1012, codegen)
    body.tags["vex_block_addr"] = 0x1000
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    facts = (
        _targeted_condition(0x1002, 0x1000, 0x1004, 0x1020),
        _targeted_condition(0x1006, 0x1004, 0x1012, 0x1020),
    )
    graph = _Graph(
        ((0x1000, 0x1004), (0x1000, 0x1020), (0x1004, 0x1012), (0x1004, 0x1020))
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x1000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = facts
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda _project, typed_condition, _codegen: CBinaryOp(
            "CmpNE",
            CConstant(typed_condition.src_insn, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "LogicalAnd"
    assert replacement.lhs.lhs.value == 0x1002
    assert replacement.rhs.lhs.value == 0x1006
    assert replacement.tags["inertia_structuring_single_branch_materialized_8616"] is True
    assert replacement.tags["inertia_structuring_condition_cfg_materialized_8616"] is True
    provenance = condition_chain_provenance_8616(replacement)
    assert provenance == ConditionChainProvenance8616((0x1002, 0x1006))
    assert condition_materialization.condition_replay_facts_8616(codegen)[0].true_target == 0x1012
    assert condition_materialization.condition_replay_facts_8616(codegen)[0].false_target == 0x1020

    changed_again = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed_again is False
    assert root.statements[0].condition_and_nodes[0][0] is replacement
    assert codegen._inertia_structuring_condition_chain_stats_8616.materialized_count == 1


def test_structuring_semantic_call_records_empty_true_arm_replay() -> None:
    codegen = _Codegen()
    call = CFunctionCall(
        "is_flag",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x100D6, "vex_block_addr": 0x100D0},
    )
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100DF, "vex_block_addr": 0x100D9},
    )
    true_body = CStatements([], codegen=codegen)
    false_body = _tagged_statements(0x100EC, codegen)
    false_body.tags["vex_block_addr"] = 0x100EC
    branch = CIfElse(
        [(condition, true_body)],
        else_node=false_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    fact = _targeted_condition(0x100DF, 0x100D9, 0x100E4, 0x100E1)
    graph = _Graph(
        (
            (0x100D9, 0x100E4),
            (0x100D9, 0x100E1),
            (0x100E4, 0x1011C),
            (0x100E1, 0x100EC),
            (0x100EC, 0x1011C),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes),
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function))
    )
    codegen.cfunc = SimpleNamespace(addr=0x10058, statements=root)
    codegen._inertia_typed_conditions = (fact,)

    changed = condition_materialization.materialize_structuring_condition_chains_8616(
        project,
        codegen,
    )

    assert changed is False
    assert branch.condition_and_nodes == [(condition, true_body)]
    replay = condition_materialization.condition_replay_facts_8616(codegen)
    assert len(replay) == 1
    assert replay[0].true_target == 0x100E4
    assert replay[0].false_target == 0x100E1


def test_structuring_selector_return_prefers_return_target_evidence_over_stale_body_tags(monkeypatch):
    codegen = _Codegen()
    value = CVariable(
        SimStackVariable(4, 2, base="bp"),
        codegen=codegen,
        variable_type=SimTypeShort(False),
    )
    limit = CVariable(
        SimStackVariable(6, 2, base="bp"),
        codegen=codegen,
        variable_type=SimTypeShort(False),
    )
    condition = CBinaryOp("CmpGE", limit, value, codegen=codegen)
    condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    body = CStatements([CReturn(value, codegen=codegen)], codegen=codegen)
    body.tags = {"ins_addr": 0x1004, "vex_block_addr": 0x1004}
    branch = CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    root = CStatements([branch, CReturn(limit, codegen=codegen)], codegen=codegen)
    fact = _targeted_condition(0x1002, 0x1000, 0x1010, 0x1004)
    graph = _Graph(((0x1004, 0x1020), (0x1010, 0x1020)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x1000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp("CmpGE", limit, value, codegen=codegen),
    )
    monkeypatch.setattr(
        condition_materialization,
        "recover_branch_target_return_expression_8616",
        lambda _project, _codegen, target: value if target == 0x1010 else limit if target == 0x1004 else None,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = branch.condition_and_nodes[0][0]
    assert replacement.op == "CmpGE"
    assert replacement.tags["inertia_structuring_single_branch_materialized_8616"] is True
    replay = condition_materialization.condition_replay_facts_8616(codegen)[0]
    assert replay.true_target == 0x1010
    assert replay.false_target == 0x1004


def test_structuring_single_branch_rematerializes_tagged_condition_drift(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    body = _tagged_statements(0x1012, codegen)
    body.tags["vex_block_addr"] = 0x1010
    branch = CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    root = CStatements([branch], codegen=codegen)
    fact = _targeted_condition(0x1002, 0x1000, 0x1010, 0x1004)
    graph = _Graph(((0x1004, 0x1020), (0x1010, 0x1018), (0x1018, 0x1020)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x1000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = (fact,)

    def _materialize(*_args):
        return CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    assert condition_materialization.materialize_structuring_condition_chains_8616(project, codegen) is True
    materialized = branch.condition_and_nodes[0][0]
    drifted = CBinaryOp(
        "CmpEQ",
        materialized.lhs,
        materialized.rhs,
        codegen=codegen,
    )
    drifted.tags = dict(materialized.tags)
    branch.condition_and_nodes = [(drifted, body)]

    assert condition_materialization.materialize_structuring_condition_chains_8616(project, codegen) is True
    repaired = branch.condition_and_nodes[0][0]
    assert repaired.op == "CmpNE"
    assert repaired is not drifted
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_structuring_single_branch_refuses_to_rebind_tagged_condition_by_body_shape(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x4092, "vex_block_addr": 0x4090}
    body = _tagged_statements(0x4012, codegen)
    body.tags["vex_block_addr"] = 0x4010
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    correct_fact = _targeted_condition(0x4002, 0x4000, 0x4010, 0x4004)
    stale_fact = _targeted_condition(0x4092, 0x4090, 0x40A0, 0x4094)
    graph = _Graph(
        (
            (0x4004, 0x4020),
            (0x4010, 0x4020),
            (0x4094, 0x40B0),
            (0x40A0, 0x40B0),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes) | {0x4000, 0x4090},
    )
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root)
    codegen._inertia_typed_conditions = (correct_fact, stale_fact)

    def _materialize(_project, typed_condition, _codegen):
        return CBinaryOp(
            "CmpNE",
            CConstant(typed_condition.src_insn, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert root.statements[0].condition_and_nodes[0][0] is condition
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_structuring_single_branch_prefers_exact_container_owner_over_stale_condition(
    monkeypatch,
):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x4092, "vex_block_addr": 0x4090}
    body = _tagged_statements(0x4012, codegen)
    body.tags["vex_block_addr"] = 0x4010
    branch = CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    branch.tags = {"ins_addr": 0x4002, "vex_block_addr": 0x4000}
    root = CStatements([branch], codegen=codegen)
    correct_fact = _targeted_condition(0x4002, 0x4000, 0x4010, 0x4004)
    stale_fact = _targeted_condition(0x4092, 0x4090, 0x40A0, 0x4094)
    graph = _Graph(
        (
            (0x4004, 0x4020),
            (0x4010, 0x4020),
            (0x4094, 0x40B0),
            (0x40A0, 0x40B0),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes) | {0x4000, 0x4090},
    )
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root)
    codegen._inertia_typed_conditions = (correct_fact, stale_fact)

    def _materialize(_project, typed_condition, _codegen):
        return CBinaryOp(
            "CmpNE",
            CConstant(typed_condition.src_insn, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = branch.condition_and_nodes[0][0]
    assert replacement.op == "CmpNE"
    assert replacement.lhs.value == 0x4002
    assert replacement.tags["ins_addr"] == 0x4002
    assert replacement.tags["vex_block_addr"] == 0x4000
    assert replacement.tags["inertia_structuring_single_branch_materialized_8616"] is True
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_structuring_single_branch_binds_untagged_condition_to_unique_body_owner(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    body = _tagged_statements(0x5012, codegen)
    body.tags["vex_block_addr"] = 0x5010
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x5002, 0x5000, 0x5010, 0x5004)
    graph = _Graph(((0x5004, 0x5020), (0x5010, 0x5020)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x5000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x5000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "CmpNE"
    assert replacement.tags["inertia_structuring_single_branch_materialized_8616"] is True


def test_structuring_single_branch_inverts_condition_for_fallthrough_owned_body(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x2002, "vex_block_addr": 0x2000}
    body = _tagged_statements(0x2012, codegen)
    body.tags["vex_block_addr"] = 0x2010
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x2002, 0x2000, 0x2020, 0x2010)
    graph = _Graph(((0x2010, 0x2018), (0x2018, 0x2030), (0x2020, 0x2030)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x2000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "CmpEQ"
    assert condition_materialization.condition_replay_facts_8616(codegen)[0].true_target == 0x2010
    assert condition_materialization.condition_replay_facts_8616(codegen)[0].false_target == 0x2020


def test_structuring_single_branch_refuses_shared_body_reachability(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x3002, "vex_block_addr": 0x3000}
    body = _tagged_statements(0x3032, codegen)
    body.tags["vex_block_addr"] = 0x3030
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x3002, 0x3000, 0x3010, 0x3020)
    graph = _Graph(((0x3010, 0x3030), (0x3020, 0x3030)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x3000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x3000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert root.statements[0].condition_and_nodes[0][0] is condition
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
