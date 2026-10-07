from __future__ import annotations

from types import SimpleNamespace

import inertia.postprocess.decompiler_postprocess_stage as postprocess_stage
import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.postprocess.decompiler_postprocess_stage import finalize_late_ast_cleanup_8616

from inertia.postprocess.optimization.trivial_copy import (
    prune_adjacent_temporary_copy_assignments_8616,
)


class _FakeCodegen(SimpleNamespace):
    const_formats = {}  # noqa: RUF012

    def __init__(self):
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _mk_codegen_with_statements(statements):
    codegen = _FakeCodegen()
    codegen.cfunc = SimpleNamespace()
    codegen.cfunc.statements = structured_c.CStatements(list(statements), codegen=codegen)
    return codegen


def _cvar(codegen, name: str, reg: int):
    return structured_c.CVariable(
        SimRegisterVariable(reg, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _stack_cvar(codegen, name: str, offset: int):
    return structured_c.CVariable(
        SimStackVariable(offset, 2, base="bp", name=name, region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _const(codegen, value: int):
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def test_prune_adjacent_dead_register_copy_collapses_pure_rhs():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "cx", 0)
    dst = _stack_cvar(codegen, "local_0", 0)
    first = structured_c.CAssignment(temp, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs.value == 75


def test_prune_adjacent_dead_register_copy_matches_physical_identity():
    codegen = _mk_codegen_with_statements([])
    temp_def = _cvar(codegen, "cx", 0)
    temp_use = _cvar(codegen, "cx", 0)
    dst = _stack_cvar(codegen, "local_0", 0)
    first = structured_c.CAssignment(temp_def, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp_use, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs.value == 75


def test_prune_adjacent_temporary_copy_preserves_call_rhs():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_224", 0)
    dst = _cvar(codegen, "ch", 2)
    call = structured_c.CFunctionCall("getch", None, [], codegen=codegen)
    first = structured_c.CAssignment(temp, call, codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs is call


def test_prune_temporary_constant_copy_skips_pure_generated_setup():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_195", 0)
    setup_src = _cvar(codegen, "vvar_7", 4)
    setup_tmp = _cvar(codegen, "vvar_196", 6)
    dst = _cvar(codegen, "ch", 2)
    first = structured_c.CAssignment(temp, _const(codegen, 75), codegen=codegen)
    setup = structured_c.CAssignment(setup_tmp, setup_src, codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, setup, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [setup, second]
    assert statements[1].rhs.value == 75


def test_prune_temporary_call_copy_refuses_to_skip_setup():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_224", 0)
    setup_src = _cvar(codegen, "vvar_48", 4)
    setup_tmp = _cvar(codegen, "vvar_228", 6)
    dst = _cvar(codegen, "ch", 2)
    call = structured_c.CFunctionCall("getch", None, [], codegen=codegen)
    first = structured_c.CAssignment(temp, call, codegen=codegen)
    setup = structured_c.CAssignment(setup_tmp, setup_src, codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, setup, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first, setup, second]


def test_prune_dead_temp_to_unread_local_assignment():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_17", 0)
    local = _stack_cvar(codegen, "local_0", 0)
    live_dst = _cvar(codegen, "ch", 4)
    dead = structured_c.CAssignment(local, temp, codegen=codegen)
    live = structured_c.CAssignment(live_dst, _const(codegen, 75), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([dead, live], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    assert list(codegen.cfunc.statements.statements) == [live]
    assert codegen.trivial_copy_dead_temp_to_local_pruned_8616 == 1


def test_prune_dead_temp_to_local_assignment_refuses_when_local_is_read():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_17", 0)
    local = _stack_cvar(codegen, "local_0", 0)
    dst = _cvar(codegen, "ch", 4)
    first = structured_c.CAssignment(local, temp, codegen=codegen)
    second = structured_c.CAssignment(dst, local, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first, second]
    assert codegen.trivial_copy_dead_temp_to_local_pruned_8616 == 0


def test_prune_dead_temp_to_local_assignment_refuses_source_local_stack_slot():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_224", 0)
    ch = _stack_cvar(codegen, "local_2", -2)
    first = structured_c.CAssignment(ch, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first]
    assert codegen.trivial_copy_dead_temp_to_local_pruned_8616 == 0


def test_prune_adjacent_temporary_copy_moves_call_from_same_emitted_temp_name():
    codegen = _mk_codegen_with_statements([])
    temp_def = _cvar(codegen, "vvar_224", 0)
    temp_use = _cvar(codegen, "vvar_224", 4)
    dst = _cvar(codegen, "ch", 2)
    call = structured_c.CFunctionCall("getch", None, [], codegen=codegen)
    first = structured_c.CAssignment(temp_def, call, codegen=codegen)
    second = structured_c.CAssignment(dst, temp_use, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert statements == [second]
    assert statements[0].rhs is call


def test_finalize_late_ast_cleanup_marks_refresh_after_temp_copy_fold(monkeypatch):
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "vvar_195", 0)
    dst = _cvar(codegen, "ch", 2)
    first = structured_c.CAssignment(temp, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)
    monkeypatch.setattr(
        postprocess_stage,
        "_prune_late_semantically_empty_noop_guards_8616",
        lambda _codegen: postprocess_stage.LateEmptyNoopGuardCleanupStats8616(0, 0, 0, 0, 0),
    )

    result = finalize_late_ast_cleanup_8616(SimpleNamespace(), codegen)

    assert result.changed is True
    assert result.adjacent_temporary_copy_changed is True
    assert result.empty_noop_guard_changed is False
    assert result.dead_condition_carrier_changed is False
    assert result.requires_dce_after_cleanup is True
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True
    assert codegen._inertia_late_ast_cleanup_finalize_8616 == {
        "changed": True,
        "adjacent_temporary_copy_changed": True,
        "empty_noop_guard_changed": False,
        "dead_condition_carrier_changed": False,
        "requires_dce_after_cleanup": True,
        "owner": "postprocess.stage",
    }
    assert list(codegen.cfunc.statements.statements) == [second]


def test_finalize_late_ast_cleanup_removes_semantically_empty_noop_guard():
    codegen = _mk_codegen_with_statements([])
    condition = structured_c.CBinaryOp(
        "<",
        _cvar(codegen, "vvar_1715", 0),
        _stack_cvar(codegen, "local_6", -6),
        codegen=codegen,
    )
    empty_guard = structured_c.CIfElse(
        [(condition, structured_c.CStatements([], codegen=codegen))],
        else_node=structured_c.CStatements([], codegen=codegen),
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([empty_guard], codegen=codegen)

    result = finalize_late_ast_cleanup_8616(SimpleNamespace(), codegen)

    assert result.changed is True
    assert result.adjacent_temporary_copy_changed is False
    assert result.empty_noop_guard_changed is True
    assert result.dead_condition_carrier_changed is False
    assert result.requires_dce_after_cleanup is False
    assert list(codegen.cfunc.statements.statements) == []
    assert codegen._inertia_late_empty_noop_guard_cleanup_stats_8616 == (
        postprocess_stage.LateEmptyNoopGuardCleanupStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )
    )
    assert codegen._inertia_late_ast_cleanup_finalize_8616 == {
        "changed": True,
        "adjacent_temporary_copy_changed": False,
        "empty_noop_guard_changed": True,
        "dead_condition_carrier_changed": False,
        "requires_dce_after_cleanup": False,
        "owner": "postprocess.stage",
    }


def test_finalize_late_ast_cleanup_preserves_nonempty_guard():
    codegen = _mk_codegen_with_statements([])
    condition = _cvar(codegen, "vvar_1715", 0)
    assignment = structured_c.CAssignment(
        _stack_cvar(codegen, "local_6", -6),
        _const(codegen, 1),
        codegen=codegen,
    )
    guard = structured_c.CIfElse(
        [(condition, structured_c.CStatements([assignment], codegen=codegen))],
        else_node=structured_c.CStatements([], codegen=codegen),
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([guard], codegen=codegen)

    result = finalize_late_ast_cleanup_8616(SimpleNamespace(), codegen)

    assert result.changed is False
    assert result.empty_noop_guard_changed is False
    assert list(codegen.cfunc.statements.statements) == [guard]
    assert codegen._inertia_late_empty_noop_guard_cleanup_stats_8616 == (
        postprocess_stage.LateEmptyNoopGuardCleanupStats8616(
            raw_fact_count=1,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=0,
        )
    )


def test_prune_adjacent_dead_register_copy_refuses_when_register_used_later():
    codegen = _mk_codegen_with_statements([])
    temp_def = _cvar(codegen, "cx", 0)
    temp_use = _cvar(codegen, "cx", 0)
    temp_later = _cvar(codegen, "cx", 0)
    dst = _cvar(codegen, "bx", 2)
    later_dst = _cvar(codegen, "dx", 4)
    first = structured_c.CAssignment(temp_def, _const(codegen, 75), codegen=codegen)
    second = structured_c.CAssignment(dst, temp_use, codegen=codegen)
    later = structured_c.CAssignment(later_dst, temp_later, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second, later], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(codegen.cfunc.statements.statements) == [first, second, later]
    assert codegen.trivial_copy_candidates_8616 == 1
    assert codegen.trivial_copy_pruned_8616 == 0
    assert codegen.trivial_copy_refused_live_temp_8616 == 1


def test_prune_adjacent_temporary_copy_refuses_when_temp_is_live_after_do_while():
    codegen = _mk_codegen_with_statements([])
    temp = _cvar(codegen, "tmp_4112", 0)
    destination = _cvar(codegen, "destination", 2)
    producer = structured_c.CAssignment(temp, _const(codegen, 75), codegen=codegen)
    consumer = structured_c.CAssignment(destination, temp, codegen=codegen)
    body = structured_c.CStatements([producer, consumer], codegen=codegen)
    loop = structured_c.CDoWhileLoop(_const(codegen, 1), body, codegen=codegen)
    returned = structured_c.CReturn(temp, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([loop, returned], codegen=codegen)

    assert prune_adjacent_temporary_copy_assignments_8616(codegen) is False

    assert list(body.statements) == [producer, consumer]
    assert codegen.trivial_copy_candidates_8616 == 1
    assert codegen.trivial_copy_pruned_8616 == 0
    assert codegen.trivial_copy_refused_live_temp_8616 == 1
