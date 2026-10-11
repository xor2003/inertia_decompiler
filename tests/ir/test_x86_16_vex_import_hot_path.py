from __future__ import annotations

from types import SimpleNamespace

from pytest import MonkeyPatch

import inertia.ir.vex_import as vex_import
from inertia.ir.core import IRInstr
from inertia.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
    collect_vex_condition_demand_8616,
)


def test_binary_temporary_normalizes_each_operand_once(monkeypatch: MonkeyPatch) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=3))
    binary = SimpleNamespace(
        tag="Iex_Binop",
        op="Iop_Add16",
        args=(left, right),
    )
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=0, data=binary)
    converted: list[object] = []
    original = vex_import._expr_to_value

    def tracked(expr: object, *args: object, **kwargs: object):
        converted.append(expr)
        return original(expr, *args, **kwargs)

    monkeypatch.setattr(vex_import, "_expr_to_value", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(), VexConditionDemandStats8616()
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert instruction.op == "Iop_Add16"
    assert converted == [left, right]


def test_condition_demand_collects_only_direct_exit_guard_temporaries() -> None:
    statements = (
        SimpleNamespace(tag="Ist_WrTmp", tmp=4, data=object()),
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_RdTmp", tmp=4),
        ),
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_Binop", args=()),
        ),
    )

    demand = collect_vex_condition_demand_8616(statements)

    assert demand.complete
    assert demand.eager_tmp_ids == frozenset({4})
    assert demand.stats.raw_fact_count == 1
    assert demand.stats.materialized_count == 1
    assert demand.stats.failure_count == 0


def test_invalid_direct_exit_guard_disables_condition_suppression() -> None:
    statements = (
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_RdTmp", tmp="invalid"),
        ),
    )

    demand = collect_vex_condition_demand_8616(statements)

    assert not demand.complete
    assert demand.stats.raw_fact_count == 1
    assert demand.stats.failure_count == 1
    assert demand.requires_eager_condition(99)


def test_non_exit_logical_tmp_skips_eager_condition_classification(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_And16", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=7, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("nonzero", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(), VexConditionDemandStats8616()
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == []


def test_exit_guard_logical_tmp_retains_eager_condition_classification(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_And16", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=7, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("nonzero", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset({7}),
            VexConditionDemandStats8616(1, 1, 1, 1, 0),
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == [binary]


def test_comparison_retains_eager_classification_without_exit_demand(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_CmpLT16S", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=8, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("slt", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(), VexConditionDemandStats8616()
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == [binary]


def test_incomplete_condition_demand_retains_legacy_eager_behavior(
    monkeypatch: MonkeyPatch,
) -> None:
    left = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=1))
    right = SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=2))
    binary = SimpleNamespace(tag="Iex_Binop", op="Iop_Or16", args=(left, right))
    statement = SimpleNamespace(tag="Ist_WrTmp", tmp=9, data=binary)
    classified: list[object] = []

    def tracked(expr: object, *args: object, **kwargs: object):
        classified.append(expr)
        return vex_import.IRCondition("nonzero", ())

    monkeypatch.setattr(vex_import, "expr_to_condition", tracked)
    instruction = vex_import._stmt_to_instr(
        statement,
        {},
        {},
        instruction_addr=0x1000,
        segment_hints={},
        tmp_exprs={},
        type_environment=None,
        condition_demand=VexConditionDemand8616(
            frozenset(),
            VexConditionDemandStats8616(1, 0, 0, 0, 1),
        ),
    )

    assert isinstance(instruction, IRInstr)
    assert classified == [binary]


def _deadline_import_fixture(monkeypatch: MonkeyPatch, *, expired: bool = False, expire_after_first: bool = False):
    """Retain actual import-core products while controlling synthetic lift cost."""
    from inertia.frontend.x86_16.relative_control_edge import decode_relative_edge
    from inertia.ir import direct_evidence_deadline as deadlines
    from inertia.ir.core import IRBlock, IRFunctionArtifact, IRRefusal
    from inertia.ir.vex_condition_transport import VexConditionTransportStats8616
    from inertia.ir.vex_terminal_jump import TerminalJumpEvidenceStats8616

    pending = vex_import.TerminalJumpEvidence8616(
        retain=True, proven_target=None, refusals=(),
        failure=vex_import.TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED,
        stats=TerminalJumpEvidenceStats8616(1, 1, 1, 0, 1),
        decoded=decode_relative_edge(0x1000, b"\xeb\x00"),
    )
    clock = [21.0 if expired else 10.0]
    calls = []
    finalized = []
    monkeypatch.setattr(deadlines.time, "monotonic", lambda: clock[0])
    def block(address, **kwargs):
        calls.append(address)
        return SimpleNamespace(addr=address, size=1)
    project = SimpleNamespace(factory=SimpleNamespace(block=block))
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000, 0x1001})
    retained_refusal = IRRefusal("synthetic_pending_fact", "retained decoded fact", 0x1000)
    def lift(block, **kwargs):
        instruction = IRInstr("NOP", None, (), size=1, addr=block.addr)
        refusals = (retained_refusal,) if expire_after_first else ()
        product = IRBlock(block.addr, (instruction,), refusals)
        if expire_after_first:
            clock[0] = 21.0
        return product, VexConditionTransportStats8616(), pending if expire_after_first else None
    def finalize(current, surface, blocks, refusals, **kwargs):
        finalized.append(surface)
        assert clock[0] < 20.0, "expired import must not normalize or prove"
        return IRFunctionArtifact(function_addr=surface.function_addr, blocks=blocks, refusals=refusals)
    monkeypatch.setattr(vex_import, "_block_to_ir", lift)
    monkeypatch.setattr(vex_import, "_finalize_x86_16_ir_artifact_8616", finalize)
    return SimpleNamespace(project=project, function=function, calls=calls, finalized=finalized, clock=clock, retained_refusal=retained_refusal, pending=pending)


def test_import_expired_before_first_block_performs_no_lift(monkeypatch: MonkeyPatch) -> None:
    """Both finishing routes reject expired work before requesting a block."""
    from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616

    for raw in (False, True):
        world = _deadline_import_fixture(monkeypatch, expired=True)
        with direct_evidence_deadline_scope_8616(world.project, 20.0):
            result = (vex_import.raw_x86_16_function_bundle_8616 if raw else vex_import.build_x86_16_ir_function_artifact)(world.project, world.function)
        artifact = result.artifact if raw else result
        assert world.calls == []
        assert world.finalized == []
        assert artifact.blocks == ()
        assert artifact.refusals[-1].kind == vex_import.IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value


def test_ordinary_import_expiry_retains_first_block_and_skips_second(monkeypatch: MonkeyPatch) -> None:
    """Whole-surface intake cannot continue lifting after the first block expires."""
    from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616

    world = _deadline_import_fixture(monkeypatch, expire_after_first=True)
    with direct_evidence_deadline_scope_8616(world.project, 20.0):
        artifact = vex_import.build_x86_16_ir_function_artifact(world.project, world.function)
    assert world.calls == [0x1000]
    assert world.finalized == []
    assert [block.addr for block in artifact.blocks] == [0x1000]
    assert artifact.blocks[0].instrs[0].addr == 0x1000
    assert artifact.refusals[:-1] == (world.retained_refusal,)
    assert artifact.refusals[-1].kind == vex_import.IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value
    assert artifact.logical_memory is None and artifact.condition_evidence is None


def test_raw_bundle_expiry_preserves_partial_evidence_without_finalizing(monkeypatch: MonkeyPatch) -> None:
    """Raw bundles retain collected products as refused transport, never proof."""
    from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616

    world = _deadline_import_fixture(monkeypatch, expire_after_first=True)
    with direct_evidence_deadline_scope_8616(world.project, 20.0):
        bundle = vex_import.raw_x86_16_function_bundle_8616(world.project, world.function)
    assert world.calls == [0x1000]
    assert world.finalized == []
    assert bundle.terminal_evidence[0x1000] is world.pending
    assert [block.addr for block in bundle.artifact.blocks] == [0x1000]
    assert bundle.artifact.blocks[0].refusals == (world.retained_refusal,)
    assert bundle.artifact.refusals[:-1] == (world.retained_refusal,)
    assert bundle.artifact.refusals[-1].kind == vex_import.IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value
    assert bundle.artifact.logical_memory is None and bundle.artifact.condition_evidence is None


def test_live_import_budget_preserves_both_complete_finishing_routes(monkeypatch: MonkeyPatch) -> None:
    """A live deadline changes neither the block census nor normalization route."""
    from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616

    for raw in (False, True):
        world = _deadline_import_fixture(monkeypatch)
        with direct_evidence_deadline_scope_8616(world.project, 20.0):
            result = (vex_import.raw_x86_16_function_bundle_8616 if raw else vex_import.build_x86_16_ir_function_artifact)(world.project, world.function)
        artifact = result.artifact if raw else result
        assert world.calls == [0x1000, 0x1001]
        assert len(world.finalized) == 1
        assert [block.addr for block in artifact.blocks] == [0x1000, 0x1001]
        assert not artifact.refusals
