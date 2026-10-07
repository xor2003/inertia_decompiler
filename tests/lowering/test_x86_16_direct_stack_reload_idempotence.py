"""Regression tests for direct-stack register reload placement."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
import inertia.structuring.decompiler_structuring_stage as structuring_stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.real_mode_linear as real_mode_linear
from inertia.lowering.real_mode_linear import (
    DirectStackMoveSourceKind8616,
    DirectStackReloadFact8616,
    _DirectStackReloadPlacement8616,
)
from inertia.pipeline.structured_ast_generation import structured_ast_generation_8616
from inertia.pipeline.structured_ast_query_index import (
    TaggedAssignmentAddressIndex8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _reload_surface(rhs: object) -> tuple[CStatements, CAssignment, CVariable, DirectStackReloadFact8616]:
    codegen = _Codegen()
    source = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    destination = CVariable(
        SimRegisterVariable(0, 2, name="ax", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(destination, rhs, codegen=codegen, tags={"ins_addr": 0x4018})
    root = CStatements([assignment], codegen=codegen)
    fact = DirectStackReloadFact8616(
        source_offset=-2,
        width=2,
        dst_reg_id=0,
        dst_reg_name="ax",
        ins_addr=0x4018,
        source_store_ins_addr=0x4014,
        source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
    )
    return root, assignment, source, fact


def test_tagged_reload_reports_already_present_without_ast_churn(monkeypatch) -> None:
    equivalent_source = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=_Codegen(),
    )
    root, assignment, source, fact = _reload_surface(equivalent_source)
    monkeypatch.setattr(real_mode_linear, "_node_has_instruction_address_8616", lambda *_args: True)

    result = real_mode_linear._replace_tagged_register_reload_assignment_8616(
        root,
        SimpleNamespace(),
        fact,
        source,
    )

    assert result is _DirectStackReloadPlacement8616.ALREADY_PRESENT
    assert root.statements == [assignment]


def test_tagged_reload_reports_materialized_only_for_a_real_replacement(monkeypatch) -> None:
    codegen = _Codegen()
    root, assignment, source, fact = _reload_surface(CConstant(7, SimTypeShort(False), codegen=codegen))
    monkeypatch.setattr(real_mode_linear, "_node_has_instruction_address_8616", lambda *_args: True)

    result = real_mode_linear._replace_tagged_register_reload_assignment_8616(
        root,
        SimpleNamespace(),
        fact,
        source,
    )

    assert result is _DirectStackReloadPlacement8616.MATERIALIZED
    assert root.statements[0] is not assignment
    assert root.statements[0].rhs is source


def test_tagged_reload_stops_after_first_materialized_assignment(monkeypatch) -> None:
    codegen = _Codegen()
    root, assignment, source, fact = _reload_surface(CConstant(7, SimTypeShort(False), codegen=codegen))
    root.statements.append(
        CAssignment(
            assignment.lhs,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    )
    visited: list[object] = []
    monkeypatch.setattr(
        real_mode_linear,
        "_node_has_instruction_address_8616",
        lambda node, *_args: visited.append(node) or True,
    )

    result = real_mode_linear._replace_tagged_register_reload_assignment_8616(
        root,
        SimpleNamespace(),
        fact,
        source,
    )

    assert result is _DirectStackReloadPlacement8616.MATERIALIZED
    assert visited == [assignment]


def test_tagged_reload_candidate_index_skips_absent_addresses(monkeypatch) -> None:
    """An absent exact tag must avoid one whole-tree reload search."""
    codegen = _Codegen()
    root, _assignment, source, fact = _reload_surface(CConstant(7, SimTypeShort(False), codegen=codegen))
    candidate_index = TaggedAssignmentAddressIndex8616(set())
    monkeypatch.setattr(
        real_mode_linear,
        "_node_has_instruction_address_8616",
        lambda *_args: (_ for _ in ()).throw(AssertionError("absent candidate traversed the AST")),
    )

    result = real_mode_linear._replace_tagged_register_reload_assignment_8616(
        root,
        SimpleNamespace(),
        fact,
        source,
        candidate_index=candidate_index,
    )

    assert result is _DirectStackReloadPlacement8616.NO_MATCH
    stats = candidate_index.stats()
    assert stats.query_count == 1
    assert stats.hit_count == 0
    assert stats.miss_count == 1
    assert stats.record_count == 0


def test_tagged_assignment_index_tracks_relocated_addresses() -> None:
    """The prefilter must preserve both address domains used by exact matching."""
    codegen = _Codegen()
    assignment = CAssignment(
        CVariable(
            SimRegisterVariable(0, 2, name="ax", region=0x4010),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018, "inertia_relocated_from_ins_addr": 0x3018},
    )

    index = TaggedAssignmentAddressIndex8616.build(CStatements([assignment], codegen=codegen))

    assert index.addresses == {0x3018, 0x4018}
    assert index.intersects(frozenset({0x4018})) is True
    stats = index.stats()
    assert stats.query_count == 1
    assert stats.hit_count == 1
    assert stats.miss_count == 0


def test_tagged_reload_index_proves_wrong_register_miss() -> None:
    """An exact address with the wrong destination must not rewalk the AST."""
    codegen = _Codegen()
    root, assignment, source, fact = _reload_surface(
        CConstant(7, SimTypeShort(False), codegen=codegen)
    )
    assignment.lhs = CVariable(
        SimRegisterVariable(4, 2, name="dx", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    candidate_index = TaggedAssignmentAddressIndex8616.build(root)

    result = real_mode_linear._replace_tagged_register_reload_assignment_8616(
        root,
        SimpleNamespace(),
        fact,
        source,
        candidate_index=candidate_index,
    )

    assert result is _DirectStackReloadPlacement8616.NO_MATCH
    assert assignment.rhs.value == 7
    assert candidate_index.stats().query_count == 1


def test_tagged_reload_index_updates_exact_assignment_in_place() -> None:
    """An indexed exact reload must preserve its statement owner and tags."""
    codegen = _Codegen()
    root, assignment, source, fact = _reload_surface(
        CConstant(7, SimTypeShort(False), codegen=codegen)
    )
    candidate_index = TaggedAssignmentAddressIndex8616.build(root)

    result = real_mode_linear._replace_tagged_register_reload_assignment_8616(
        root,
        SimpleNamespace(),
        fact,
        source,
        candidate_index=candidate_index,
    )

    assert result is _DirectStackReloadPlacement8616.MATERIALIZED
    assert root.statements == [assignment]
    assert assignment.rhs is source
    assert assignment.tags["ins_addr"] == fact.ins_addr


def test_structured_ast_generation_detects_in_place_child_replacement() -> None:
    codegen = _Codegen()
    source = CConstant(1, SimTypeShort(False), codegen=codegen)
    root, assignment, _stack_source, _fact = _reload_surface(source)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    before = structured_ast_generation_8616(codegen)

    assignment.rhs = CConstant(2, SimTypeShort(False), codegen=codegen)
    after = structured_ast_generation_8616(codegen)

    assert after != before
    assert structured_ast_generation_8616(codegen) == after


def test_structured_ast_generation_does_not_evaluate_opaque_properties() -> None:
    """Generation must inspect storage without executing angr-style descriptors."""

    class _OpaqueBoundary:
        @property
        def offset(self) -> int:
            raise AssertionError("mutation generation evaluated a third-party property")

    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(body=_OpaqueBoundary())

    generation = structured_ast_generation_8616(codegen)

    assert generation.structured_node_count == 0


def test_structuring_stage_delegates_replay_stability_to_lowering_owner(monkeypatch) -> None:
    codegen = _Codegen()
    root = CStatements([], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_typed_conditions_transferred = True
    project = SimpleNamespace()
    function = SimpleNamespace()
    calls: list[str] = []

    monkeypatch.setattr(structuring_stage, "_current_structuring_function_8616", lambda *_args: function)
    monkeypatch.setattr(structuring_stage, "_bind_direct_stack_move_branch_ownership_8616", lambda *_args: None)
    for name in (
        "prune_callee_saved_stack_spills_8616",
        "materialize_direct_stack_mov_instructions_8616",
        "materialize_direct_stack_incdec_instructions_8616",
        "materialize_direct_global_incdec_instructions_8616",
    ):
        monkeypatch.setattr(
            structuring_stage,
            name,
            lambda *_args, _name=name, **_kwargs: calls.append(_name) or False,
        )

    assert structuring_stage._apply_structuring_direct_stack_materialization_8616(project, codegen) is False
    assert structuring_stage._apply_structuring_direct_stack_materialization_8616(project, codegen) is False
    assert len(calls) == 8

    root.statements.append(CConstant(3, SimTypeShort(False), codegen=codegen))
    assert structuring_stage._apply_structuring_direct_stack_materialization_8616(project, codegen) is False
    assert len(calls) == 12
    assert not hasattr(codegen, "_inertia_direct_stack_replay_generation_skip_count_8616")


def test_direct_stack_ownership_callback_skips_only_a_stable_generation(monkeypatch) -> None:
    codegen = _Codegen()
    root = CStatements([], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    project = SimpleNamespace()
    function = SimpleNamespace()
    calls: list[str] = []

    for name in (
        "materialize_direct_stack_move_branch_ownership_8616",
        "materialize_direct_stack_move_loop_entry_ownership_8616",
        "materialize_direct_stack_move_loop_tail_ownership_8616",
    ):
        monkeypatch.setattr(
            structuring_stage,
            name,
            lambda *_args, _name=name: calls.append(_name) or False,
        )

    structuring_stage._bind_direct_stack_move_branch_ownership_8616(
        project,
        codegen,
        function,
    )
    replay = codegen._inertia_direct_stack_move_branch_ownership_replay_8616
    assert replay() is False
    assert replay() is False
    assert len(calls) == 3

    root.statements.append(CConstant(3, SimTypeShort(False), codegen=codegen))
    assert replay() is False
    assert len(calls) == 6
    assert codegen._inertia_direct_stack_ownership_replay_skip_count_8616 == 1
