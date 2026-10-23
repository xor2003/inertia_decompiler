from __future__ import annotations

import ast
import inspect
import textwrap
from dataclasses import replace
from types import SimpleNamespace

import pytest

import inertia.structuring.decompiler_structuring_stage as stage
from inertia.structuring.pass_effects import (
    StructuringLoweringReplayImpact8616,
    structuring_lowering_replay_impact_after_changes_8616,
    structuring_return_closure_requires_segment_replay_8616,
)
from tests.ir.test_declared_entry_pipeline_attach import installed_leaf as installed_leaf


def test_standalone_stack_semantics_always_prepares_once(monkeypatch):
    """Independent consumers cannot inherit another operation's preparation."""
    calls = []
    monkeypatch.setattr(stage, '_prepare_structuring_stack_semantics_8616', lambda *args: calls.append('prepare'))
    monkeypatch.setattr(stage, '_lower_prepared_structuring_stack_semantics_8616', lambda *args: calls.append('lower') or False)
    assert not stage._apply_structuring_stable_stack_semantics_8616(object(), object())
    assert not stage._apply_structuring_stable_stack_semantics_8616(object(), object())
    assert calls == ['prepare', 'lower', 'prepare', 'lower']


@pytest.mark.parametrize('mutation', [None, 'source', 'ir', 'ssa', 'effects', 'outputs', 'projection',
                                     'indexed_ir', 'indexed_alias', 'stack_alias', 'numeric_returns', 'context'])
def test_local_prefix_reuse_requires_unchanged_native_projections(installed_leaf, monkeypatch, mutation):
    """A genuine native prefix can be reused only until an owned input changes."""
    project, codegen, _ = installed_leaf
    prepared = stage._prepare_structuring_stack_semantics_8616(project, codegen)
    assert prepared is not None
    assert prepared.matches(project, codegen)
    fields = {
        'source': '_inertia_raw_vex_ir_artifact_8616',
        'ir': '_inertia_vex_ir_artifact',
        'ssa': '_inertia_vex_ir_function_ssa',
        'effects': '_inertia_call_stack_effect_artifact_8616',
        'outputs': '_inertia_call_output_artifact_8616',
        'projection': '_inertia_call_semantic_projection_8616',
        'indexed_ir': '_inertia_indexed_address_evidence_8616',
        'indexed_alias': '_inertia_indexed_address_alias_evidence_8616',
        'stack_alias': '_inertia_stack_memory_ssa_alias_artifact',
        'numeric_returns': '_inertia_numeric_stack_pointer_returns_8616',
        'context': '_inertia_declared_entry_pipeline_8616',
    }
    if mutation is not None:
        field = fields[mutation]
        setattr(codegen, field, replace(getattr(codegen, field)))
    calls = []

    def prepare(*args):
        calls.append('prepare')

    monkeypatch.setattr(stage, '_prepare_structuring_stack_semantics_8616', prepare)
    monkeypatch.setattr(stage, '_lower_prepared_structuring_stack_semantics_8616', lambda *args: calls.append('lower') or False)
    assert not stage._continue_structuring_stack_semantics_8616(project, codegen, prepared)
    assert calls == (['lower'] if mutation is None else ['prepare', 'lower'])


def test_baseline_prefix_prepares_once_before_segment_consumers(installed_leaf, monkeypatch):
    """The actual baseline orchestration passes its local receipt to lowering."""
    project, codegen, _ = installed_leaf
    calls = []
    original = stage._prepare_structuring_stack_semantics_8616

    def prepare(*args):
        calls.append('prepare')
        return original(*args)

    class ReachedLowering(Exception):
        pass

    def continuation(selected_project, selected_codegen, receipt):
        assert selected_project is project and selected_codegen is codegen
        assert receipt is not None and receipt.matches(project, codegen)
        calls.append('continue')
        raise ReachedLowering

    monkeypatch.setattr(stage, '_prepare_structuring_stack_semantics_8616', prepare)
    monkeypatch.setattr(stage, '_continue_structuring_stack_semantics_8616', continuation)
    for owner, name in (
        (stage._segment_stack_restore, 'apply_x86_16_segment_stack_restore_artifact'),
        (stage._segment_stack_restore, 'apply_x86_16_stack_register_restore_artifact_8616'),
        (stage, 'prune_proven_segment_stack_restore_carriers_8616'),
        (stage, 'apply_pipeline_segment_state_8616'),
        (stage._segment_contract, 'apply_x86_16_segment_function_contract'),
        (stage._segment_function_summary, 'apply_x86_16_segment_function_summary'),
    ):
        monkeypatch.setattr(owner, name, lambda *args: False)
    with pytest.raises(ReachedLowering):
        stage._prime_validation_pipeline_prefix_8616(project, codegen)
    assert calls == ['prepare', 'continue']


def test_baseline_removes_legacy_duplicate_native_producers(installed_leaf, monkeypatch):
    """Restoring only the old continuation doubles all five native producers."""
    project, codegen, _ = installed_leaf
    counts = {}
    producers = (
        (stage._vex_ir, 'apply_x86_16_vex_ir_artifact'),
        (stage._indexed_address_ir, 'apply_x86_16_indexed_address_evidence_8616'),
        (stage, 'apply_x86_16_call_stack_effects_8616'),
        (stage._indexed_address_aliases, 'apply_x86_16_indexed_address_aliases_8616'),
        (stage._stack_memory_ssa, 'apply_x86_16_stack_memory_ssa_alias_artifact'),
    )
    for owner, name in producers:
        real = getattr(owner, name)

        def counted(*args, _name=name, _real=real):
            counts[_name] = counts.get(_name, 0) + 1
            return _real(*args)

        monkeypatch.setattr(owner, name, counted)
    for owner, name in (
        (stage._segment_stack_restore, 'apply_x86_16_segment_stack_restore_artifact'),
        (stage._segment_stack_restore, 'apply_x86_16_stack_register_restore_artifact_8616'),
        (stage, 'prune_proven_segment_stack_restore_carriers_8616'),
        (stage, 'apply_pipeline_segment_state_8616'),
        (stage._segment_contract, 'apply_x86_16_segment_function_contract'),
        (stage._segment_function_summary, 'apply_x86_16_segment_function_summary'),
    ):
        monkeypatch.setattr(owner, name, lambda *args: False)

    class ReachedLowering(Exception):
        pass

    def stop(*args):
        raise ReachedLowering

    monkeypatch.setattr(stage, '_lower_prepared_structuring_stack_semantics_8616', stop)
    with monkeypatch.context() as legacy:
        legacy.setattr(stage, '_continue_structuring_stack_semantics_8616',
                       lambda p, c, prepared: stage._apply_structuring_stable_stack_semantics_8616(p, c))
        with pytest.raises(ReachedLowering):
            stage._prime_validation_pipeline_prefix_8616(project, codegen)
    assert set(counts.values()) == {2}
    assert len(counts) == 5
    counts.clear()
    with pytest.raises(ReachedLowering):
        stage._prime_validation_pipeline_prefix_8616(project, codegen)
    assert set(counts.values()) == {1}
    assert len(counts) == 5


@pytest.mark.parametrize('mode', ['current', 'legacy', 'effects', 'alias', 'context'])
def test_baseline_retains_original_prefix_receipt_through_lowering_replay(installed_leaf, monkeypatch, mode):
    """One baseline shares its original receipt; changed inputs still reprepare."""
    project, codegen, _ = installed_leaf
    prepared_receipts = []
    actual_prepare = stage._prepare_structuring_stack_semantics_8616

    def prepare(p, c):
        receipt = actual_prepare(p, c)
        assert receipt is not None
        prepared_receipts.append(receipt)
        return receipt

    def prefix(p, c):
        receipt = stage._prepare_structuring_stack_semantics_8616(p, c)
        mutations = {'effects': '_inertia_call_stack_effect_artifact_8616',
                     'alias': '_inertia_stack_memory_ssa_alias_artifact',
                     'context': '_inertia_declared_entry_pipeline_8616'}
        if mode in mutations:
            field = mutations[mode]
            setattr(c, field, replace(getattr(c, field)))
        return False, receipt

    def replay(p, c, *, prepared=None):
        assert prepared is prepared_receipts[0]
        if mode == 'legacy':
            return stage._apply_structuring_stable_stack_semantics_8616(p, c)
        return stage._continue_structuring_stack_semantics_8616(p, c, prepared)

    monkeypatch.setattr(stage, '_prepare_structuring_stack_semantics_8616', prepare)
    monkeypatch.setattr(stage, '_prime_validation_pipeline_prefix_8616', prefix)
    monkeypatch.setattr(stage, '_replay_structuring_lowering_before_validation_8616', replay)
    monkeypatch.setattr(stage, '_lower_prepared_structuring_stack_semantics_8616', lambda *args: False)
    for name in ('_repair_structuring_switch_loop_exit_returns_8616',
                 '_materialize_structuring_terminal_call_result_return_8616',
                 '_prime_terminal_return_shape_8616', '_prime_return_closure_segment_replay_8616',
                 '_prime_validation_pipeline_suffix_8616'):
        monkeypatch.setattr(stage, name, lambda *args: False)
    assert not stage._prime_structuring_validation_semantics_8616(project, codegen)
    assert len(prepared_receipts) == (1 if mode == 'current' else 2)


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


def test_word_projection_widening_precedes_first_condition_ownership(monkeypatch):
    """Required byte casts become one word before shared-return orientation."""
    from angr.analyses.decompiler.structured_codegen.c import CVariable

    from inertia.lowering import real_mode_linear
    from tests.widening.test_word_cast_recomposition import _fixture

    codegen, assignment, _ = _fixture()
    codegen.cfunc.addr = 0x4010
    codegen._inertia_typed_conditions_transferred = True
    calls = []
    for owner, name in (
        (stage, '_prepare_structuring_stack_semantics_8616'),
        (stage, '_continue_structuring_stack_semantics_8616'),
        (stage._segment_stack_restore, 'apply_x86_16_segment_stack_restore_artifact'),
        (stage._segment_stack_restore, 'apply_x86_16_stack_register_restore_artifact_8616'),
        (stage, 'prune_proven_segment_stack_restore_carriers_8616'),
        (stage, 'apply_pipeline_segment_state_8616'),
        (stage._segment_contract, 'apply_x86_16_segment_function_contract'),
        (stage._segment_function_summary, 'apply_x86_16_segment_function_summary'),
        (stage, '_apply_structuring_direct_stack_materialization_8616'),
        (stage, '_prime_structuring_segment_global_semantics_8616'),
        (real_mode_linear, 'lower_stable_ds_es_linear_global_dereferences_8616'),
    ):
        monkeypatch.setattr(owner, name, lambda *args, **kwargs: False)
    monkeypatch.setattr(stage._segmented_mem, 'apply_x86_16_segmented_memory_reasoning',
                        lambda *args: calls.append('alias-lowering'))

    class ReachedCondition(Exception):
        pass

    def first_condition(*args):
        assert calls == ['alias-lowering']
        assert isinstance(assignment.rhs, CVariable)
        raise ReachedCondition

    monkeypatch.setattr(stage, '_materialize_structuring_wide_stack_return_predicate_8616', first_condition)
    with pytest.raises(ReachedCondition):
        stage._prime_validation_pipeline_prefix_8616(codegen.project, codegen)
