from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
import inertia.structuring.direct_stack_move_loop_tail_replay as loop_tail_replay_module
import inertia.structuring.direct_stack_move_loops as loop_module
from archinfo import ArchX86
from capstone import CS_GRP_JUMP
from capstone.x86_const import X86_OP_IMM

from inertia.structuring.direct_stack_move_loop_tail_replay import (
    materialize_direct_stack_move_loop_tail_ownership_8616,
)
from inertia.structuring.direct_stack_move_loops import (
    place_direct_stack_move_loop_tail_assignment_8616,
)


class CWhileLoop:
    def __init__(self, condition: object, body: object) -> None:
        self.condition = condition
        self.body = body


class CDoWhileLoop:
    def __init__(self, condition: object, body: object) -> None:
        self.condition = condition
        self.body = body


def _tag(address: int) -> SimpleNamespace:
    return SimpleNamespace(tags={"ins_addr": address})


def _function(move_addr: int, jump_addr: int, target_addr: int) -> SimpleNamespace:
    move = SimpleNamespace(address=move_addr, groups=(), operands=())
    jump = SimpleNamespace(
        address=jump_addr,
        groups=(CS_GRP_JUMP,),
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=target_addr),),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(move, jump)))
    return SimpleNamespace(blocks=(block,))


def _function_with_intervening_instruction(
    move_addr: int,
    jump_addr: int,
    target_addr: int,
) -> SimpleNamespace:
    function = _function(move_addr, jump_addr, target_addr)
    move, jump = function.blocks[0].capstone.insns
    intervening = SimpleNamespace(address=move_addr + 2, groups=(), operands=())
    function.blocks[0].capstone.insns = (move, intervening, jump)
    return function


def _fact(address: int) -> DirectStackMoveFact8616:
    return DirectStackMoveFact8616(
        dst_offset=-2,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
        ins_addr=address,
        source_offset=-2,
    )


def test_places_move_after_nested_posttest_loop_at_outer_loop_tail() -> None:
    inner_body = SimpleNamespace(statements=[_tag(0x1010)])
    inner = CDoWhileLoop(_tag(0x1020), inner_body)
    outer_body = SimpleNamespace(statements=[inner])
    outer = CWhileLoop(SimpleNamespace(), outer_body)
    root = SimpleNamespace(statements=[outer])
    codegen = SimpleNamespace(cfunc=SimpleNamespace(statements=root))
    assignment = SimpleNamespace(tags={"ins_addr": 0x1030})

    changed = place_direct_stack_move_loop_tail_assignment_8616(
        SimpleNamespace(),
        codegen,
        _function(0x1030, 0x1033, 0x1008),
        _fact(0x1030),
        assignment,
    )

    assert changed is True
    assert outer_body.statements == [inner, assignment]
    assert inner_body.statements == [_tag(0x1010)]


def test_places_move_before_posttest_condition_at_inner_loop_tail() -> None:
    inner_body = SimpleNamespace(statements=[_tag(0x1010)])
    inner = CDoWhileLoop(_tag(0x101B), inner_body)
    outer_body = SimpleNamespace(statements=[inner])
    outer = CWhileLoop(_tag(0x1000), outer_body)
    root = SimpleNamespace(statements=[outer])
    codegen = SimpleNamespace(cfunc=SimpleNamespace(statements=root))
    assignment = SimpleNamespace(tags={"ins_addr": 0x1018})

    changed = place_direct_stack_move_loop_tail_assignment_8616(
        SimpleNamespace(),
        codegen,
        _function(0x1018, 0x101B, 0x1010),
        _fact(0x1018),
        assignment,
    )

    assert changed is True
    assert inner_body.statements[-1] is assignment
    assert outer_body.statements == [inner]


def test_refuses_non_tail_move_with_intervening_instruction_before_loopback() -> None:
    body = SimpleNamespace(statements=[_tag(0x1010)])
    loop = CWhileLoop(_tag(0x1008), body)
    root = SimpleNamespace(statements=[loop])
    codegen = SimpleNamespace(cfunc=SimpleNamespace(statements=root))
    assignment = SimpleNamespace(tags={"ins_addr": 0x1030})

    changed = place_direct_stack_move_loop_tail_assignment_8616(
        SimpleNamespace(),
        codegen,
        _function_with_intervening_instruction(0x1030, 0x1035, 0x1008),
        _fact(0x1030),
        assignment,
    )

    assert changed is False
    assert body.statements == [_tag(0x1010)]


def test_non_loop_tail_refusal_skips_assignment_location_scan(monkeypatch) -> None:
    root = SimpleNamespace(statements=[_tag(0x1010)])
    codegen = SimpleNamespace(cfunc=SimpleNamespace(statements=root))

    monkeypatch.setattr(loop_module, "_loopback_after_move_8616", lambda *_args: None)

    def fail_location_scan(*_args, **_kwargs):
        raise AssertionError("non-loop-tail move scanned structured assignments")

    monkeypatch.setattr(
        loop_module,
        "tagged_assignment_locations_8616",
        fail_location_scan,
    )

    changed = place_direct_stack_move_loop_tail_assignment_8616(
        SimpleNamespace(),
        codegen,
        SimpleNamespace(),
        _fact(0x1030),
        SimpleNamespace(tags={"ins_addr": 0x1030}),
    )

    assert changed is False
    stats = codegen._inertia_direct_stack_move_loop_tail_placement_8616
    assert stats.normalized_fact_count == 0
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_non_loop_tail_replay_skips_assignment_location_scan(monkeypatch) -> None:
    move_fact = _fact(0x1030)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(statements=SimpleNamespace(statements=[])),
        _inertia_direct_stack_move_facts_8616=(move_fact,),
    )

    def fail_location_scan(*_args, **_kwargs):
        raise AssertionError("non-loop-tail replay scanned structured assignments")

    monkeypatch.setattr(
        loop_tail_replay_module,
        "tagged_assignment_locations_8616",
        fail_location_scan,
    )

    changed = materialize_direct_stack_move_loop_tail_ownership_8616(
        SimpleNamespace(),
        codegen,
        _function_with_intervening_instruction(0x1030, 0x1035, 0x1008),
    )

    assert changed is False
    stats = codegen._inertia_direct_stack_move_loop_tail_replay_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 0
    assert stats.classified_fact_count == 0


def test_replay_moves_regenerated_assignment_to_proven_loop_tail() -> None:
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(next_idx=lambda _name: 1, cstyle_null_cmp=False, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    destination = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="parent"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    move_fact = DirectStackMoveFact8616(
        dst_offset=-2,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_SLOT,
        ins_addr=0x1030,
        source_offset=-4,
    )
    assignment = structured_c.CAssignment(
        destination,
        source,
        codegen=codegen,
        tags={"ins_addr": move_fact.ins_addr},
    )
    prior_statement = structured_c.CAssignment(
        source,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    body = structured_c.CStatements([assignment, prior_statement], codegen=codegen)
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x1008}),
        body,
        codegen=codegen,
    )
    root = structured_c.CStatements([loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_direct_stack_move_facts_8616 = (move_fact,)

    changed = materialize_direct_stack_move_loop_tail_ownership_8616(
        project,
        codegen,
        _function(0x1030, 0x1033, 0x1008),
    )

    assert changed is True
    assert body.statements == [prior_statement, assignment]
    stats = codegen._inertia_direct_stack_move_loop_tail_replay_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.moved_count == 1
