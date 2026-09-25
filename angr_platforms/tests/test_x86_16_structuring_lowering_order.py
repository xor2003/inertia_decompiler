from __future__ import annotations

import ast
import inspect
import textwrap
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16 import decompiler_structuring_stage as stage
from angr_platforms.X86_16.structuring.pass_effects import (
    StructuringLoweringReplayImpact8616,
    structuring_lowering_replay_impact_after_changes_8616,
    structuring_return_closure_requires_segment_replay_8616,
)


def test_direct_stack_ownership_observes_typed_conditions(monkeypatch) -> None:
    """Transfer ConditionIR before choosing a structured stack-move owner."""
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x4010)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))
    events: list[str] = []

    monkeypatch.setattr(
        stage,
        "_current_structuring_function_8616",
        lambda *_args: function,
    )

    def transfer(_project, func_addr, transferred_codegen) -> None:
        assert _project is project
        assert func_addr == 0x4010
        assert transferred_codegen is codegen
        events.append("condition-transfer")

    def bind(_project, bound_codegen, bound_function) -> None:
        assert _project is project
        assert bound_codegen is codegen
        assert bound_function is function
        assert codegen._inertia_typed_conditions_transferred is True
        events.append("stack-owner-bind")

    monkeypatch.setattr(stage, "transfer_typed_conditions_to_codegen_8616", transfer)
    monkeypatch.setattr(stage, "_bind_direct_stack_move_branch_ownership_8616", bind)
    for name in (
        "prune_callee_saved_stack_spills_8616",
        "materialize_direct_stack_mov_instructions_8616",
        "materialize_direct_stack_incdec_instructions_8616",
        "materialize_direct_global_incdec_instructions_8616",
        "materialize_direct_stack_move_branch_ownership_8616",
        "materialize_direct_stack_move_loop_entry_ownership_8616",
    ):
        monkeypatch.setattr(stage, name, lambda *_args, **_kwargs: False)

    assert not stage._apply_structuring_direct_stack_materialization_8616(
        project,
        codegen,
    )
    assert events == ["condition-transfer", "stack-owner-bind"]


def test_call_return_conditions_are_rebound_after_all_lowering(monkeypatch) -> None:
    """Keep call conditions bound when a later Lowering pass rebuilds their AST."""
    no_change_passes = (
        "materialize_annotated_stack_prototype_8616",
        "_materialize_structuring_callsite_prototypes_8616",
        "_materialize_structuring_callsite_stack_arguments_8616",
        "replay_call_return_switch_selectors_8616",
        "_materialize_structuring_pointer_arg_indirect_loads_8616",
        "_materialize_structuring_stdlib_call_chains_8616",
        "_apply_structuring_stable_stack_semantics_8616",
        "materialize_software_interrupt_calls_8616",
        "materialize_software_interrupt_status_outputs_8616",
        "_prime_structuring_segment_global_semantics_8616",
        "prune_frame_prologue_stack_assignments_8616",
        "_replay_materialized_call_stack_metadata_8616",
        "prune_unused_structured_insert_intrinsics_8616",
        "lower_structured_insert_intrinsics_8616",
        "materialize_signed_global_declarations_8616",
        "apply_condition_scalar_types_8616",
        "materialize_explicit_scalar_char_types_8616",
    )
    for name in no_change_passes:
        monkeypatch.setattr(stage, name, lambda *args, **kwargs: False)
    monkeypatch.setattr(stage, "_current_structuring_function_8616", lambda *args: None)
    monkeypatch.setattr(
        stage,
        "materialize_loop_carried_terminal_return_8616",
        lambda *args, **kwargs: SimpleNamespace(changed=False),
    )
    monkeypatch.setattr(
        stage,
        "finalize_typed_register_locals_8616",
        lambda *args, **kwargs: SimpleNamespace(changed=False),
    )

    events: list[str] = []

    def materialize_call_return(*args, **kwargs) -> bool:
        events.append("call-return")
        return False

    def rebuild_direct_stack(*args, **kwargs) -> bool:
        events.append("direct-stack")
        return False

    monkeypatch.setattr(stage, "materialize_call_return_conditions_8616", materialize_call_return)
    monkeypatch.setattr(stage, "_apply_structuring_direct_stack_materialization_8616", rebuild_direct_stack)

    assert not stage._replay_structuring_lowering_before_validation_8616(object(), object())
    assert events == ["call-return", "direct-stack", "call-return"]


def _is_named_span_call(expression: ast.expr) -> bool:
    """Return whether a with-item calls ``span("<str>")``."""
    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "span"
        and bool(expression.args)
        and isinstance(expression.args[0], ast.Constant)
        and isinstance(expression.args[0].value, str)
    )


def test_shared_tail_ownership_closes_the_final_structuring_ast() -> None:
    """Keep shared-tail ownership after every pass that can rebuild call nodes."""
    source = textwrap.dedent(inspect.getsource(stage._decompile_structuring_8616))
    span_lines: dict[str, int] = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            expression = item.context_expr
            if _is_named_span_call(expression):
                span_lines[expression.args[0].value] = node.lineno

    final_shared_tail = span_lines["x86_16.structuring.final_shared_call_ownership"]
    assert span_lines["x86_16.structuring.terminal_call_result_return"] < final_shared_tail
    assert span_lines["x86_16.structuring.final_lowering_replay"] < final_shared_tail
    assert span_lines["x86_16.structuring.final_selector_return_projection"] < final_shared_tail
    assert final_shared_tail < span_lines["x86_16.structuring.return_chain_integrity"]
    assert final_shared_tail < span_lines["x86_16.structuring.validation.after_fingerprint"]


def test_post_regeneration_uses_one_full_lowering_replay() -> None:
    """Do not duplicate direct and segmented lowering immediately before full replay."""
    source = textwrap.dedent(inspect.getsource(stage._decompile_structuring_8616))
    called_names = tuple(
        node.func.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    )

    assert called_names.count("_apply_structuring_direct_stack_materialization_8616") == 1
    assert called_names.count("_prime_structuring_segment_global_semantics_8616") == 1
    assert called_names.count("_replay_structuring_lowering_before_validation_8616") == 2


def test_unobserved_return_declares_only_liveness_replay_impact() -> None:
    """Replacing a pure return carrier cannot introduce stack/global address patterns."""
    specs = {spec.name: spec for spec in stage._build_decompiler_structuring_passes()}

    assert (
        specs["_unobserved_return_lowering_8616"].lowering_replay_impact
        is StructuringLoweringReplayImpact8616.RETURN_LIVENESS_ONLY
    )
    assert (
        specs["_structuring_codegen_8616"].lowering_replay_impact
        is StructuringLoweringReplayImpact8616.FULL_AST
    )


def test_late_ast_change_upgrades_return_liveness_to_full_replay() -> None:
    """A later AST mutation must override a narrower pass-declared impact."""
    impact = StructuringLoweringReplayImpact8616.RETURN_LIVENESS_ONLY

    assert (
        structuring_lowering_replay_impact_after_changes_8616(
            impact,
            return_liveness_changed=False,
            full_ast_changes=(False, False),
        )
        is StructuringLoweringReplayImpact8616.RETURN_LIVENESS_ONLY
    )
    assert (
        structuring_lowering_replay_impact_after_changes_8616(
            impact,
            return_liveness_changed=True,
            full_ast_changes=(False, False),
        )
        is StructuringLoweringReplayImpact8616.RETURN_LIVENESS_ONLY
    )
    assert (
        structuring_lowering_replay_impact_after_changes_8616(
            impact,
            return_liveness_changed=False,
            full_ast_changes=(False, True),
        )
        is StructuringLoweringReplayImpact8616.FULL_AST
    )


def test_prebaseline_prime_does_not_invalidate_postprime_consumers() -> None:
    """Priming is already closed before the Structuring validation baseline."""
    assert (
        structuring_lowering_replay_impact_after_changes_8616(
            StructuringLoweringReplayImpact8616.NONE,
            return_liveness_changed=False,
            full_ast_changes=(),
        )
        is StructuringLoweringReplayImpact8616.NONE
    )


@pytest.mark.parametrize(
    ("switch_changed", "terminal_changed", "shape_changed", "expected"),
    (
        (False, False, False, False),
        (True, False, False, True),
        (False, True, False, True),
        (False, False, True, True),
    ),
)
def test_return_closure_replays_segment_owner_only_after_mutation(
    switch_changed: bool,
    terminal_changed: bool,
    shape_changed: bool,
    expected: bool,
) -> None:
    """Stable return closure cannot invalidate segment/global lowering."""
    assert (
        structuring_return_closure_requires_segment_replay_8616(
            switch_exit_changed=switch_changed,
            terminal_call_return_changed=terminal_changed,
            terminal_return_shape_changed=shape_changed,
        )
        is expected
    )
