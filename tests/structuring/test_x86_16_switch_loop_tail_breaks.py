from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBreak,
    CGoto,
    CIfElse,
    CLabel,
    CStatements,
    CSwitchCase,
    CVariable,
    CWhileLoop,
)
import inertia.structuring.decompiler_structuring_stage as decompiler_structuring_stage

from inertia.structuring.switch_loop_tail_breaks import (
    SwitchLoopTailBreakDecision8616,
    SwitchLoopTailBreakMaterialization8616,
    SwitchLoopTailBreakResult8616,
    SwitchLoopTailBreakStats8616,
    materialize_switch_loop_tail_breaks_8616,
)
from inertia.validation.validation_switch_loop_tail_breaks import (
    SwitchLoopTailBreakValidationStatus8616,
    consume_switch_loop_tail_break_validation_delta_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _goto(codegen: _Codegen, target: int, *, target_idx: int | None = None) -> CGoto:
    return CGoto(target, target_idx, codegen=codegen, tags={"ins_addr": target - 2})


def _label(codegen: _Codegen, target: int) -> CLabel:
    return CLabel(f"LABEL_{target:x}", codegen=codegen, tags={"ins_addr": target})


def _switch(codegen: _Codegen, body: CStatements) -> CSwitchCase:
    return CSwitchCase(CVariable("ax", codegen=codegen), [(69, body)], None, codegen=codegen)


def test_switch_loop_tail_breaks_materialize_nested_if_and_close_evidence() -> None:
    codegen = _Codegen()
    target = 0x10488
    direct = _goto(codegen, target)
    conditional = _goto(codegen, target)
    condition = CVariable("condition", codegen=codegen)
    branch = CIfElse([(condition, conditional)], codegen=codegen)
    switch = _switch(codegen, CStatements([branch, direct], codegen=codegen))
    loop_body = CStatements([switch, _label(codegen, target)], codegen=codegen)
    root = CStatements([CWhileLoop(None, loop_body, codegen=codegen)], codegen=codegen)

    result = materialize_switch_loop_tail_breaks_8616(root)

    assert result.replaced_goto_count == 2
    assert result.removed_label_count == 1
    assert result.materializations == (
        SwitchLoopTailBreakMaterialization8616(target, 2),
    )
    assert result.decisions == (SwitchLoopTailBreakDecision8616.MATERIALIZED,)
    assert result.stats == SwitchLoopTailBreakStats8616(1, 1, 1, 1, 0)
    assert loop_body.statements == [switch]
    assert isinstance(branch.condition_and_nodes[0][1], CBreak)
    assert isinstance(switch.cases[0][1].statements[-1], CBreak)

    repeated = materialize_switch_loop_tail_breaks_8616(root)
    assert repeated.changed is False
    assert repeated.stats == SwitchLoopTailBreakStats8616()


def test_switch_loop_tail_breaks_refuse_executable_suffix() -> None:
    codegen = _Codegen()
    target = 0x2000
    goto = _goto(codegen, target)
    switch = _switch(codegen, CStatements([goto], codegen=codegen))
    label = _label(codegen, target)
    loop_body = CStatements([switch, label, CBreak(codegen=codegen)], codegen=codegen)
    root = CStatements([CWhileLoop(None, loop_body, codegen=codegen)], codegen=codegen)

    result = materialize_switch_loop_tail_breaks_8616(root)

    assert result.changed is False
    assert result.decisions == (
        SwitchLoopTailBreakDecision8616.REFUSED_EXECUTABLE_SUFFIX,
    )
    assert result.stats == SwitchLoopTailBreakStats8616(1, 0, 0, 0, 1)
    assert loop_body.statements == [switch, label, loop_body.statements[-1]]
    assert switch.cases[0][1].statements == [goto]


def test_switch_loop_tail_breaks_refuse_nested_loop_target() -> None:
    codegen = _Codegen()
    target = 0x3000
    nested_goto = _goto(codegen, target)
    nested_loop = CWhileLoop(
        None,
        CStatements([nested_goto], codegen=codegen),
        codegen=codegen,
    )
    switch = _switch(codegen, CStatements([nested_loop], codegen=codegen))
    label = _label(codegen, target)
    loop_body = CStatements([switch, label], codegen=codegen)
    root = CStatements([CWhileLoop(None, loop_body, codegen=codegen)], codegen=codegen)

    result = materialize_switch_loop_tail_breaks_8616(root)

    assert result.changed is False
    assert result.decisions == (
        SwitchLoopTailBreakDecision8616.REFUSED_NESTED_BREAKABLE,
    )
    assert result.stats == SwitchLoopTailBreakStats8616(1, 1, 0, 0, 1)
    assert nested_loop.body.statements == [nested_goto]


def test_switch_loop_tail_breaks_refuse_external_target_reference() -> None:
    codegen = _Codegen()
    target = 0x4000
    case_goto = _goto(codegen, target)
    external_goto = _goto(codegen, target)
    switch = _switch(codegen, CStatements([case_goto], codegen=codegen))
    label = _label(codegen, target)
    loop_body = CStatements([switch, label], codegen=codegen)
    loop = CWhileLoop(None, loop_body, codegen=codegen)
    root = CStatements([loop, external_goto], codegen=codegen)

    result = materialize_switch_loop_tail_breaks_8616(root)

    assert result.changed is False
    assert result.decisions == (
        SwitchLoopTailBreakDecision8616.REFUSED_EXTERNAL_TARGET_REFERENCE,
    )
    assert result.stats == SwitchLoopTailBreakStats8616(1, 1, 0, 0, 1)
    assert loop_body.statements == [switch, label]


def test_switch_loop_tail_breaks_refuse_indexed_goto_target() -> None:
    codegen = _Codegen()
    target = 0x5000
    goto = _goto(codegen, target, target_idx=1)
    switch = _switch(codegen, CStatements([goto], codegen=codegen))
    label = _label(codegen, target)
    loop_body = CStatements([switch, label], codegen=codegen)
    root = CStatements([CWhileLoop(None, loop_body, codegen=codegen)], codegen=codegen)

    result = materialize_switch_loop_tail_breaks_8616(root)

    assert result.changed is False
    assert result.decisions == (
        SwitchLoopTailBreakDecision8616.REFUSED_AMBIGUOUS_GOTO_TARGET,
    )
    assert result.stats == SwitchLoopTailBreakStats8616(1, 1, 0, 0, 1)


def test_switch_loop_tail_breaks_refuse_duplicate_binary_label() -> None:
    codegen = _Codegen()
    target = 0x6000
    goto = _goto(codegen, target)
    switch = _switch(codegen, CStatements([goto], codegen=codegen))
    label = _label(codegen, target)
    loop_body = CStatements([switch, label], codegen=codegen)
    loop = CWhileLoop(None, loop_body, codegen=codegen)
    root = CStatements([loop, _label(codegen, target)], codegen=codegen)

    result = materialize_switch_loop_tail_breaks_8616(root)

    assert result.changed is False
    assert result.decisions == (
        SwitchLoopTailBreakDecision8616.REFUSED_AMBIGUOUS_LABEL,
    )
    assert result.stats == SwitchLoopTailBreakStats8616(1, 0, 0, 0, 1)


def test_structuring_stage_places_switch_tail_collapse_after_exit_repair() -> None:
    names = [spec.name for spec in decompiler_structuring_stage.DECOMPILER_STRUCTURING_PASSES]

    assert names.index("_switch_loop_exit_return_repair_8616") < names.index(
        "_switch_loop_tail_break_collapse_8616"
    )
    assert names.index("_switch_loop_tail_break_collapse_8616") < names.index(
        "_void_tail_call_guard_repair_8616"
    )


def test_structuring_stage_publishes_typed_switch_tail_result() -> None:
    codegen = _Codegen()
    target = 0x7000
    switch = _switch(codegen, CStatements([_goto(codegen, target)], codegen=codegen))
    root = CStatements(
        [CWhileLoop(None, CStatements([switch, _label(codegen, target)], codegen=codegen), codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)

    changed = decompiler_structuring_stage._collapse_structuring_switch_loop_tail_breaks_8616(
        object(), codegen
    )

    assert changed is True
    assert codegen._inertia_structuring_switch_loop_tail_break_result_8616.changed is True


def _closed_validation_result(target: int) -> SwitchLoopTailBreakResult8616:
    return SwitchLoopTailBreakResult8616(
        replaced_goto_count=3,
        removed_label_count=1,
        materializations=(SwitchLoopTailBreakMaterialization8616(target, 3),),
        decisions=(SwitchLoopTailBreakDecision8616.MATERIALIZED,),
        stats=SwitchLoopTailBreakStats8616(1, 1, 1, 1, 0),
    )


def test_switch_loop_tail_validation_consumes_only_proven_goto() -> None:
    target = 0x10488
    validation: dict[str, object] = {
        "changed": True,
        "status": "changed",
        "precision_improvements": {},
        "delta": {
            "control_flow_effects": {
                "added": ("if:replacement",),
                "removed": (f"goto:{target}", "if:carrier"),
            }
        },
    }

    result = consume_switch_loop_tail_break_validation_delta_8616(
        _closed_validation_result(target), validation
    )

    assert result.accepted is True
    assert result.residual_changed is True
    assert result.consumed_gotos == (f"goto:{target}",)
    delta = validation["delta"]
    assert isinstance(delta, dict)
    assert delta["control_flow_effects"]["removed"] == ("if:carrier",)
    assert validation["changed"] is True
    precision = validation["precision_improvements"]
    assert isinstance(precision, dict)
    assert precision["switch_loop_tail_breaks"]["targets"] == (target,)


def test_switch_loop_tail_validation_closes_exact_delta() -> None:
    target = 0x8000
    validation: dict[str, object] = {
        "changed": True,
        "status": "changed",
        "precision_improvements": {},
        "delta": {
            "control_flow_effects": {
                "added": (),
                "removed": (f"goto:{target}",),
            }
        },
    }

    result = consume_switch_loop_tail_break_validation_delta_8616(
        _closed_validation_result(target), validation
    )

    assert result.accepted is True
    assert result.residual_changed is False
    assert validation["changed"] is False
    assert validation["status"] == "stable"


def test_switch_loop_tail_validation_refuses_unproved_target_without_mutation() -> None:
    target = 0x9000
    validation: dict[str, object] = {
        "changed": True,
        "status": "changed",
        "precision_improvements": {},
        "delta": {
            "control_flow_effects": {
                "added": (),
                "removed": (f"goto:{target + 2}",),
            }
        },
    }
    original_delta = validation["delta"]

    result = consume_switch_loop_tail_break_validation_delta_8616(
        _closed_validation_result(target), validation
    )

    assert result.status is SwitchLoopTailBreakValidationStatus8616.REFUSED_MISSING_TARGET
    assert validation["delta"] is original_delta
    assert validation["changed"] is True


def test_switch_loop_tail_validation_refuses_unclosed_evidence() -> None:
    target = 0xA000
    unclosed = SwitchLoopTailBreakResult8616(
        replaced_goto_count=1,
        removed_label_count=1,
        materializations=(SwitchLoopTailBreakMaterialization8616(target, 1),),
        decisions=(SwitchLoopTailBreakDecision8616.MATERIALIZED,),
        stats=SwitchLoopTailBreakStats8616(1, 1, 1, 0, 1),
    )
    validation: dict[str, object] = {
        "precision_improvements": {},
        "delta": {"control_flow_effects": {"added": (), "removed": (f"goto:{target}",)}},
    }

    result = consume_switch_loop_tail_break_validation_delta_8616(unclosed, validation)

    assert result.status is SwitchLoopTailBreakValidationStatus8616.REFUSED_UNCLOSED_EVIDENCE
