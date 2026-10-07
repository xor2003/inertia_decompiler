from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
import inertia.postprocess.decompiler_postprocess as postprocess
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.cli import cli_decompilation
from inertia.pipeline.contracts import assert_pipeline_contracts_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.compiler_helpers import CompilerHelperEvidenceKind8616
from inertia.structuring.clinic_option_policy import enforce_x86_16_clinic_options_8616


def test_indexed_global_regeneration_replay_delegates_to_stage_owned_order(monkeypatch) -> None:
    cod_metadata = object()
    synthetic_globals: dict[str, object] = {}
    project = SimpleNamespace(_inertia_cod_metadata_by_func_addr_8616={0x4010: cod_metadata})
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_synthetic_globals=synthetic_globals,
    )
    calls: list[str] = []

    def segment_global(
        actual_project: object,
        actual_codegen: object,
        actual_globals: object,
        *,
        cod_metadata: object | None = None,
    ) -> SimpleNamespace:
        assert (actual_project, actual_codegen, actual_globals) == (
            project,
            codegen,
            synthetic_globals,
        )
        assert cod_metadata is project._inertia_cod_metadata_by_func_addr_8616[0x4010]
        calls.extend(("indexed", "direct"))
        return SimpleNamespace(changed=True)

    monkeypatch.setattr(
        cli_decompilation,
        "run_segment_global_materialization_8616",
        segment_global,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "reapply_proven_named_global_aggregate_types_8616",
        lambda _codegen: calls.append("named_types") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "reapply_proven_stack_aggregate_types_8616",
        lambda _codegen: calls.append("stack_types") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "reapply_proven_stack_aggregate_field_projections_8616",
        lambda _codegen: calls.append("field_projections") or False,
    )

    assert cli_decompilation._replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
    assert calls == ["indexed", "direct", "named_types", "stack_types", "field_projections"]


def test_callsite_finalization_reapplies_stack_aggregate_facts_when_call_replay_is_stable(
    monkeypatch,
) -> None:
    project = object()
    codegen = SimpleNamespace(project=project)
    calls: list[str] = []

    def reapply(_codegen: object) -> bool:
        calls.append("aggregate_reapply")
        return False

    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "reapply_stack_aggregate_object_facts_8616",
        reapply,
    )

    assert cli_decompilation._finalize_callsite_arguments_after_noncall_regen_8616(codegen) is False
    assert calls == ["aggregate_reapply"]
    assert codegen._inertia_stack_aggregate_decay_render_replay_count_8616 == 1


def test_callsite_finalization_does_not_repeat_direct_stack_after_indexed_replay(monkeypatch) -> None:
    project = object()
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(statements=object()),
    )
    calls: list[str] = []

    def direct_stack(_codegen: object) -> bool:
        calls.append("direct_stack")
        return len(calls) == 1

    monkeypatch.setattr(cli_decompilation, "_replay_direct_stack_semantics_after_regen_8616", direct_stack)
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: calls.append("calls") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_typed_call_interfaces_before_render_8616",
        lambda _codegen: calls.append("interfaces") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "finalize_shared_call_occurrences_8616",
        lambda _project, _codegen: calls.append("occurrences") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_named_segmented_global_lowering_after_regen_8616",
        lambda _codegen: calls.append("named") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_indexed_segmented_global_lowering_after_regen_8616",
        lambda _codegen: calls.append("indexed") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_stack_address_lowering_after_regen_8616",
        lambda _codegen: calls.append("stack_address") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_runtime_segment_lowering_after_regen_8616",
        lambda _codegen: calls.append("runtime") or True,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "recover_structuring_canonical_for_loops_8616",
        lambda _codegen: calls.append("canonical_for") or False,
    )

    assert cli_decompilation._finalize_callsite_arguments_after_noncall_regen_8616(codegen) is True
    assert calls == [
        "direct_stack",
        "calls",
        "interfaces",
        "occurrences",
        "indexed",
        "stack_address",
        "runtime",
        "indexed",
        "canonical_for",
    ]


def test_regenerated_noncall_finalization_cleans_carriers_after_lowering_replay(
    monkeypatch,
) -> None:
    project = object()
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(statements=object()),
    )
    calls: list[str] = []

    def widening(candidate_project: object, candidate_codegen: object) -> bool:
        assert candidate_project is project
        assert candidate_codegen is codegen
        calls.append("widening")
        return False

    def structuring(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        calls.append("structuring")
        return True

    def shared_calls(candidate_project: object, candidate_codegen: object) -> bool:
        assert candidate_project is project
        assert candidate_codegen is codegen
        calls.append("shared_calls")
        return False

    def cleanup(candidate_project: object, candidate_codegen: object) -> SimpleNamespace:
        assert candidate_project is project
        assert candidate_codegen is codegen
        calls.append("cleanup")
        return SimpleNamespace(changed=False)

    monkeypatch.setattr(cli_decompilation, "_run_typed_widening_pass", widening)
    monkeypatch.setattr(
        cli_decompilation,
        "prune_redundant_loop_break_carriers_after_lowering_8616",
        structuring,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "finalize_shared_call_occurrences_8616",
        shared_calls,
    )
    monkeypatch.setattr(cli_decompilation, "finalize_late_ast_cleanup_8616", cleanup)
    monkeypatch.setattr(
        cli_decompilation,
        "recover_structuring_canonical_for_loops_8616",
        lambda candidate_codegen: calls.append("canonical_for") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_indexed_segmented_global_lowering_after_regen_8616",
        lambda candidate_codegen: calls.append("indexed_global") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_simplify_structured_expressions_8616",
        lambda candidate_codegen: calls.append("simplify") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_call_return_selector_lowering_after_regen_8616",
        lambda candidate_codegen: calls.append("call_return_selector") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        lambda candidate_codegen: calls.append("direct_stack") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_runtime_segment_lowering_after_regen_8616",
        lambda candidate_codegen: calls.append("runtime_segment") or False,
    )

    changed = cli_decompilation._finalize_regenerated_noncall_ast_8616(codegen)

    assert changed is True
    assert calls == [
        "shared_calls",
        "widening",
        "structuring",
        "cleanup",
        "indexed_global",
        "canonical_for",
        "simplify",
        "call_return_selector",
        "direct_stack",
        "runtime_segment",
        "shared_calls",
        "canonical_for",
        "cleanup",
    ]


def test_call_return_selector_replay_uses_bound_lowering_owner() -> None:
    calls: list[object] = []

    def replayer(candidate_codegen: object) -> bool:
        calls.append(candidate_codegen)
        return True

    codegen = SimpleNamespace(
        _inertia_call_return_selector_replayer_8616=replayer,
    )

    assert cli_decompilation._replay_call_return_selector_lowering_after_regen_8616(codegen) is True
    assert calls == [codegen]


def test_regeneration_replays_stack_updates_through_structuring_stage(monkeypatch) -> None:
    project = object()
    codegen = SimpleNamespace(project=project)
    calls: list[tuple[object, object, bool, bool]] = []

    def run_stage(
        candidate_project: object,
        candidate_codegen: object,
        *,
        include_direct_stack_mov: bool,
        include_direct_global_incdec: bool,
    ) -> SimpleNamespace:
        calls.append(
            (
                candidate_project,
                candidate_codegen,
                include_direct_stack_mov,
                include_direct_global_incdec,
            )
        )
        return SimpleNamespace(direct_stack_incdec_changed=True)

    monkeypatch.setattr(cli_decompilation, "run_direct_instruction_materialization_8616", run_stage)

    changed = cli_decompilation._replay_direct_stack_updates_after_regen_8616(codegen)

    assert changed is True
    assert calls == [(project, codegen, False, False)]


def test_regeneration_replays_stack_moves_before_updates(monkeypatch) -> None:
    codegen = object()
    calls: list[str] = []

    def replay_moves(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        calls.append("moves")
        return False

    def replay_updates(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        calls.append("updates")
        return True

    monkeypatch.setattr(cli_decompilation, "_replay_direct_stack_mov_after_regen_8616", replay_moves)
    monkeypatch.setattr(cli_decompilation, "_replay_direct_stack_updates_after_regen_8616", replay_updates)

    changed = cli_decompilation._replay_direct_stack_semantics_after_regen_8616(codegen)

    assert changed is True
    assert calls == ["moves", "updates"]


def test_large_regeneration_replays_proven_stack_moves_without_reloads(monkeypatch) -> None:
    codegen = SimpleNamespace(
        _inertia_skip_per_pass_validation_large_function=True,
        _inertia_pre_validation_stack_semantics_primed=True,
        _inertia_direct_stack_move_lowering_8616={"raw_fact_count": 3},
    )
    calls: list[tuple[object, object]] = []

    def materialize(candidate_codegen: object, **kwargs: object) -> bool:
        assert candidate_codegen is codegen
        calls.append((kwargs.get("source_kinds"), kwargs.get("materialize_reloads")))
        return True

    monkeypatch.setattr(cli_decompilation, "materialize_direct_stack_mov_instructions_8616", materialize)

    changed = cli_decompilation._replay_direct_stack_mov_after_regen_8616(codegen)

    assert changed is True
    assert calls == [
        (
            frozenset(
                {
                    cli_decompilation.DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
                    cli_decompilation.DirectStackMoveSourceKind8616.STACK_SLOT,
                }
            ),
            False,
        )
    ]
    assert codegen._inertia_direct_stack_mov_targeted_replay_large_function_8616 == 1


def test_regenerate_replays_stack_semantics_after_tree_replacement(monkeypatch) -> None:
    stale_text = "void f(void) { }\n"
    fresh_text = "void f(void) { i += 1; }\n"

    class _FakeCFunc:
        def __init__(self) -> None:
            self.text = stale_text

        def c_repr(self) -> str:
            return self.text

    class _FakeCodegen:
        def __init__(self) -> None:
            self.text = stale_text
            self.cfunc = _FakeCFunc()
            self.project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
            self._inertia_postprocess_changed = True

        def regenerate_text(self) -> None:
            self.text = stale_text
            self.cfunc = _FakeCFunc()

        def render_text(self, cfunc: _FakeCFunc) -> str:
            return cfunc.c_repr()

    codegen = _FakeCodegen()
    replay_roots: list[_FakeCFunc] = []

    def replay_stack_semantics(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        replay_roots.append(codegen.cfunc)
        codegen.cfunc.text = fresh_text
        return True

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        replay_stack_semantics,
    )
    monkeypatch.setattr(cli_decompilation, "_stabilize_regenerated_noncall_ast_8616", lambda _codegen: False)
    monkeypatch.setattr(cli_decompilation, "_simplify_structured_expressions_8616", lambda _codegen: False)

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert text == fresh_text
    assert replay_roots[-1] is codegen.cfunc


def test_regeneration_arg_local_split_detector_flags_regressed_header_arg():
    cached = "unsigned short classify(short local_4)\n{\n    return local_4;\n}\n"
    rendered = (
        "unsigned short classify(short local)\n{\n"
        "    unsigned short local_4;\n"
        "    return local_4;\n"
        "}\n"
    )

    assert cli_decompilation._regeneration_introduced_arg_local_split_8616(cached, rendered) is True


def test_regeneration_arg_local_split_detector_keeps_stable_rename():
    cached = "unsigned short classify(short local_4)\n{\n    return local_4;\n}\n"
    rendered = "unsigned short classify(short local)\n{\n    return local;\n}\n"

    assert cli_decompilation._regeneration_introduced_arg_local_split_8616(cached, rendered) is False


def test_regeneration_arg_local_split_detector_ignores_unused_stale_declaration():
    cached = "short sum_words(unsigned short *src, unsigned short local_6)\n{\n    return local_6;\n}\n"
    rendered = (
        "short sum_words(unsigned short *src, short count)\n{\n"
        "    unsigned short local_6;  // [bp-0x6]\n"
        "    return count;\n"
        "}\n"
    )

    assert cli_decompilation._regeneration_introduced_arg_local_split_8616(cached, rendered) is False


def test_regenerate_prefers_cfunc_text_after_call_arg_materialization(monkeypatch):
    stale_text = "void f(void) { Sleep(); }\n"
    fresh_text = "void f(void) { Sleep(SEG_U32(ds, 306)); }\n"

    codegen = SimpleNamespace(
        text=stale_text,
        cfunc=SimpleNamespace(c_repr=lambda: fresh_text),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        _inertia_callsite_args_ast_materialized_8616=True,
        _inertia_codegen_call_args_render_refresh_required_8616=True,
    )

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert text == fresh_text
    assert codegen.text == fresh_text


def test_regenerate_does_not_restore_stale_stack_text_over_live_out_identical_ast(monkeypatch):
    stale_text = """unsigned short f(void)
{
    unsigned short local_2;  // [bp-0x2]
    local_2 = SEG_U16(ds, 2978);
    return local_2;
}
"""
    fresh_text = """unsigned short f(void)
{
    return clStart;
}
"""
    summary = object()
    codegen = SimpleNamespace(
        text=stale_text,
        cfunc=SimpleNamespace(c_repr=lambda: fresh_text),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        _inertia_postprocess_changed=True,
        _inertia_callsite_args_ast_materialized_8616=True,
    )

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_typed_call_interfaces_before_render_8616",
        lambda _codegen: None,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_callsite_arguments_after_noncall_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )
    for name in (
        "_replay_named_segmented_global_lowering_after_regen_8616",
        "_replay_indexed_segmented_global_lowering_after_regen_8616",
        "_replay_stack_address_lowering_after_regen_8616",
        "_replay_direct_stack_semantics_after_regen_8616",
        "_replay_runtime_segment_lowering_after_regen_8616",
        "_stabilize_regenerated_noncall_ast_8616",
        "_simplify_structured_expressions_8616",
    ):
        monkeypatch.setattr(cli_decompilation, name, lambda _codegen: False)
    monkeypatch.setattr(
        cli_decompilation,
        "_collect_render_refresh_tail_summary_8616",
        lambda _codegen: summary,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "compare_x86_16_tail_validation_summaries",
        lambda before, after: {
            "changed": before is not after,
            "status": "stable" if before is after else "changed",
        },
    )

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert text == fresh_text
    assert codegen._inertia_render_refresh_replay_accepted_by_live_out_8616 == 1
    evidence = codegen._inertia_render_refresh_semantic_replay_evidence_8616
    assert (
        evidence.raw_fact_count,
        evidence.normalized_fact_count,
        evidence.classified_fact_count,
        evidence.materialized_count,
        evidence.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_render_refresh_live_out_identity_refuses_changed_replay(monkeypatch):
    before_summary = object()
    after_summary = object()
    codegen = SimpleNamespace(project=object())

    monkeypatch.setattr(
        cli_decompilation,
        "_collect_render_refresh_tail_summary_8616",
        lambda _codegen: after_summary,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "compare_x86_16_tail_validation_summaries",
        lambda before, after: {
            "changed": before is not after,
            "status": "changed",
        },
    )

    assert not cli_decompilation._render_refresh_replay_preserves_live_out_8616(
        codegen,
        before_summary,
    )
    evidence = codegen._inertia_render_refresh_semantic_replay_evidence_8616
    assert evidence.materialized_count == 0
    assert evidence.failure_count == 1


def test_regenerate_replays_indexed_segmented_globals_after_regeneration(monkeypatch):
    stale_text = "void f(void) { MEM_U16(&mem_08F0 + local_0 * 2); }\n"
    fresh_text = "void f(void) { abarWork[local_0] = abarPerm[local_0]; }\n"

    class _FakeCFunc:
        def __init__(self):
            self.text = stale_text
            self.statements = object()

        def c_repr(self):
            return self.text

    class _FakeCodegen:
        def __init__(self):
            self.text = stale_text
            self.cfunc = _FakeCFunc()
            self.project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
            self._inertia_callsite_args_ast_materialized_8616 = False

        def regenerate_text(self):
            self.text = stale_text
            self.cfunc.text = stale_text

        def render_text(self, cfunc):
            return cfunc.c_repr()

    codegen = _FakeCodegen()
    def fake_indexed_replay(replay_codegen):
        replay_codegen.cfunc.text = fresh_text
        return True

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_indexed_segmented_global_lowering_after_regen_8616",
        fake_indexed_replay,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_stack_address_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_named_segmented_global_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_runtime_segment_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(cli_decompilation, "_simplify_structured_expressions_8616", lambda _codegen: False)

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert text == fresh_text
    assert codegen.text == fresh_text


def test_indexed_replay_reapplies_lowering_owned_stack_aggregate_types(monkeypatch) -> None:
    project = SimpleNamespace(_inertia_cod_metadata_by_func_addr_8616={0x1000: "metadata"})
    codegen = SimpleNamespace(project=project, cfunc=SimpleNamespace(addr=0x1000))
    calls: list[tuple[str, object]] = []

    def replay_named(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        calls.append(("replay_named", candidate_codegen))
        return False

    def reapply_globals(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        calls.append(("reapply_global_types", candidate_codegen))
        return False

    def reapply(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        calls.append(("reapply_types", candidate_codegen))
        return True

    def reapply_fields(candidate_codegen: object) -> bool:
        assert candidate_codegen is codegen
        calls.append(("reapply_fields", candidate_codegen))
        return False

    monkeypatch.setattr(
        cli_decompilation,
        "_replay_named_segmented_global_lowering_after_regen_8616",
        replay_named,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "reapply_proven_named_global_aggregate_types_8616",
        reapply_globals,
    )
    monkeypatch.setattr(cli_decompilation, "reapply_proven_stack_aggregate_types_8616", reapply)
    monkeypatch.setattr(
        cli_decompilation,
        "reapply_proven_stack_aggregate_field_projections_8616",
        reapply_fields,
    )

    assert cli_decompilation._replay_indexed_segmented_global_lowering_after_regen_8616(codegen) is True
    assert calls == [
        ("replay_named", codegen),
        ("reapply_global_types", codegen),
        ("reapply_types", codegen),
        ("reapply_fields", codegen),
    ]


def test_regenerate_replays_pointer_arg_indirect_loads_after_regeneration(monkeypatch):
    stale_text = "void Swaps(unsigned short *left) { tmp = SEG_U16(ds, 0 + left); }\n"
    fresh_text = "void Swaps(unsigned short *left) { tmp = left[0]; }\n"

    class _FakeCFunc:
        def __init__(self):
            self.text = stale_text

        def c_repr(self):
            return self.text

    class _FakeCodegen:
        def __init__(self):
            self.text = stale_text
            self.cfunc = _FakeCFunc()
            self.project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
            self._inertia_postprocess_changed = True

        def regenerate_text(self):
            self.text = stale_text
            self.cfunc.text = stale_text

        def render_text(self, cfunc):
            return cfunc.c_repr()

    codegen = _FakeCodegen()

    def fake_pointer_replay(replay_codegen):
        replay_codegen.cfunc.text = fresh_text
        return True

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_named_segmented_global_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_indexed_segmented_global_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_stack_address_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_direct_stack_semantics_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_runtime_segment_lowering_after_regen_8616",
        fake_pointer_replay,
    )
    monkeypatch.setattr(cli_decompilation, "_simplify_structured_expressions_8616", lambda _codegen: False)

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x10066 Swaps")

    assert regenerated is True
    assert text == fresh_text
    assert codegen.text == fresh_text


def test_pointer_arg_indirect_load_stats_fail_when_classified_load_not_materialized(monkeypatch):
    class _Codegen(SimpleNamespace):
        def __init__(self):
            super().__init__()
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _Codegen()
    codegen.project = SimpleNamespace(arch=Arch86_16())
    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [
                CAssignment(
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                )
            ],
            codegen=codegen,
        )
    )
    project = SimpleNamespace()
    func = SimpleNamespace()
    fact = postprocess.PointerArgIndirectFact8616(
        postprocess.PointerArgIndirectFactKind8616.LOAD_WORD,
        insn_addr=0x1000,
        stack_offset=4,
        base_reg="ax",
    )

    monkeypatch.setattr(postprocess, "_pointer_arg_offsets_for_codegen_8616", lambda _codegen: {4: object()})
    monkeypatch.setattr(
        postprocess,
        "_candidate_functions_for_pointer_arg_fact_scan_8616",
        lambda _project, _codegen, _func: ((project, func),),
    )
    monkeypatch.setattr(postprocess, "_collect_pointer_arg_indirect_facts_8616", lambda *_args: (fact,))

    changed = postprocess._materialize_pointer_arg_indirect_loads_8616(project, codegen, func)

    assert changed is False
    stats = codegen._inertia_pointer_arg_indirect_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.refused_count == 1
    with pytest.raises(PipelineHardError, match="pointer_arg_indirect: 1 facts classified but 0 materialized"):
        assert_pipeline_contracts_8616(codegen)


def test_pointer_arg_indirect_load_stats_count_existing_indexed_load(monkeypatch):
    class _Codegen(SimpleNamespace):
        def __init__(self):
            super().__init__()
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx
        def next_node_idx(self) -> int:
            return self.next_idx("")
        def next_ident(self, name: str) -> str:
            return name

    codegen = _Codegen()
    codegen.project = SimpleNamespace(arch=Arch86_16())
    pointer_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="left"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    indexed_load = CIndexedVariable(
        pointer_arg,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [
                CAssignment(
                    CVariable(SimStackVariable(-2, 2, base="bp", name="tmp"), codegen=codegen),
                    indexed_load,
                    codegen=codegen,
                )
            ],
            codegen=codegen,
        )
    )
    project = SimpleNamespace()
    func = SimpleNamespace()
    fact = postprocess.PointerArgIndirectFact8616(
        postprocess.PointerArgIndirectFactKind8616.LOAD_WORD,
        insn_addr=0x1000,
        stack_offset=4,
        base_reg="ax",
    )

    monkeypatch.setattr(postprocess, "_pointer_arg_offsets_for_codegen_8616", lambda _codegen: {4: pointer_arg})
    monkeypatch.setattr(
        postprocess,
        "_candidate_functions_for_pointer_arg_fact_scan_8616",
        lambda _project, _codegen, _func: ((project, func),),
    )
    monkeypatch.setattr(postprocess, "_collect_pointer_arg_indirect_facts_8616", lambda *_args: (fact,))

    changed = postprocess._materialize_pointer_arg_indirect_loads_8616(project, codegen, func)

    assert changed is False
    stats = codegen._inertia_pointer_arg_indirect_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert_pipeline_contracts_8616(codegen)


def test_force_regeneration_prefers_live_cfunc_repr_after_ast_cleanup(monkeypatch):
    stale_text = "void f(void) { vvar_1 = 1; }\n"
    fresh_text = "void f(void) { return; }\n"
    finalization_calls: list[object] = []

    class _FakeCFunc:
        text = fresh_text

        def c_repr(self):
            assert finalization_calls
            return self.text

    class _FakeCodegen:
        def __init__(self):
            self.text = stale_text
            self.cfunc = _FakeCFunc()
            self.project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
            self._inertia_force_codegen_regeneration_8616 = True
            self._inertia_pointer_memory_materialized_8616 = "pointer_swap"

        def regenerate_text(self):
            raise AssertionError("force-refresh should render the live C AST before full regeneration")

        def render_text(self, cfunc):
            return cfunc.c_repr()

    codegen = _FakeCodegen()

    monkeypatch.setattr(cli_decompilation, "repair_cfunctioncall_render_targets_8616", lambda _codegen: None)
    monkeypatch.setattr(cli_decompilation, "_bind_codegen_render_variable_types_8616", lambda _codegen: None)
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_typed_interfaces_and_projections_before_render_8616",
        lambda active_codegen: finalization_calls.append(active_codegen) or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "replay_callsite_stack_arguments_after_regeneration_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_named_segmented_global_lowering_after_regen_8616",
        lambda _codegen: (_ for _ in ()).throw(
            AssertionError("CLI semantic replay must not run after lowering-owned pointer memory")
        ),
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_finalize_callsite_arguments_after_noncall_regen_8616",
        lambda _codegen: (_ for _ in ()).throw(
            AssertionError("CLI callsite finalization must not rewrite lowering-owned pointer memory")
        ),
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_indexed_segmented_global_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_stack_address_lowering_after_regen_8616",
        lambda _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_runtime_segment_lowering_after_regen_8616",
        lambda _codegen: (_ for _ in ()).throw(
            AssertionError("CLI pointer replay must not reverse lowering-owned pointer memory")
        ),
    )

    text, regenerated = cli_decompilation._regenerate_codegen_text_safely(codegen, context="0x1000 f")

    assert regenerated is True
    assert text == fresh_text
    assert codegen.text == fresh_text
    assert finalization_calls == [codegen]


def test_render_candidate_score_refuses_stale_stack_base_when_calls_tie():
    stale_text = """
int main(void)
{
    unsigned short v;
    v = stack_base + -8;
    InitBars();
    InitMenu();
    RunMenu();
    return 0;
}
"""
    clean_text = """
int main(void)
{
    InitBars();
    InitMenu();
    RunMenu();
    return 0;
}
"""

    assert cli_decompilation._render_candidate_score_8616(clean_text, None) > (
        cli_decompilation._render_candidate_score_8616(stale_text, None)
    )


def test_render_candidate_score_preserves_repeated_non_probe_calls():
    one_call = """
unsigned short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    value = fn(value);
}
"""
    two_calls = """
unsigned short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    value = fn(value);
    value = fn(value);
}
"""

    assert cli_decompilation._non_probe_executable_call_count_8616(one_call) == 1
    assert cli_decompilation._non_probe_executable_call_count_8616(two_calls) == 2
    assert cli_decompilation._render_candidate_score_8616(two_calls, None) > (
        cli_decompilation._render_candidate_score_8616(one_call, None)
    )


def test_non_probe_executable_call_count_ignores_prototypes_and_stack_probes():
    text = """
void aNchkstk(void);
unsigned short helper(unsigned short value);
unsigned short apply_twice(unsigned short value)
{
    aNchkstk();
    value = helper(value);
    return helper(value);
}
"""

    assert cli_decompilation._non_probe_executable_call_count_8616(text) == 2


def test_expected_loop_presence_score_ignores_cod_source_text_evidence():
    cod_metadata = SimpleNamespace(
        source_lines=(
            "int f(void)",
            "{",
            "    for (i = 0; i < 3; ++i) {",
            "        x += i;",
            "    }",
            "}",
        )
    )
    loop_text = "int f(void) { for (i = 0; i < 3; ++i) { x += i; } return x; }"
    linear_text = "int f(void) { x += 0; return x; }"

    assert cli_decompilation._expected_loop_presence_score_8616(loop_text, cod_metadata) == 0
    assert cli_decompilation._expected_loop_presence_score_8616(linear_text, cod_metadata) == 0


def test_validated_payload_replacement_does_not_reject_source_text_loop_loss():
    cod_metadata = SimpleNamespace(
        source_lines=(
            "int f(void)",
            "{",
            "    for (i = 0; i < 3; ++i) {",
            "        x += i;",
            "    }",
            "    return x;",
            "}",
        ),
        call_names=(),
    )
    current_payload = "int f(void) { for (i = 0; i < 3; ++i) { x += i; } return x; }"
    validated_payload = "int f(void) { x += 0; return x; }"

    evidence = cli_decompilation._validated_payload_replacement_evidence_8616(
        current_payload,
        validated_payload,
        cod_metadata,
    )

    assert evidence.decision is cli_decompilation.ValidatedPayloadReplacementDecision8616.USE_VALIDATED
    assert evidence.current_loop_score == 0
    assert evidence.validated_loop_score == 0


def test_validated_payload_replacement_ignores_cod_call_name_text_on_score_tie():
    cod_metadata = SimpleNamespace(
        source_lines=(),
        call_names=("clock", "sprintf"),
    )
    current_payload = "void f(void) { clock(); }"
    validated_payload = "void f(void) { sprintf(buf, fmt); }"

    evidence = cli_decompilation._validated_payload_replacement_evidence_8616(
        current_payload,
        validated_payload,
        cod_metadata,
    )

    assert evidence.current_call_score == evidence.validated_call_score
    assert evidence.current_missing_calls == ()
    assert evidence.validated_missing_calls == ()
    assert evidence.decision is cli_decompilation.ValidatedPayloadReplacementDecision8616.USE_VALIDATED


def test_validated_payload_replacement_rejects_repeated_call_loss():
    current_payload = """
unsigned short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    value = fn(value);
    value = fn(value);
}
"""
    validated_payload = """
unsigned short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    value = fn(value);
}
"""

    evidence = cli_decompilation._validated_payload_replacement_evidence_8616(
        current_payload,
        validated_payload,
        None,
    )

    assert evidence.current_call_score == (0, 0, 2)
    assert evidence.validated_call_score == (0, 0, 1)
    assert evidence.decision is cli_decompilation.ValidatedPayloadReplacementDecision8616.REJECT_WORSE_CALL_EVIDENCE


def test_validated_payload_cache_requires_passing_tail_snapshot_when_enabled():
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        _inertia_last_tail_validation_snapshot={
            "structuring": {"status": "stable"},
            "postprocess": {"status": "changed"},
        },
    )

    assert cli_decompilation._validated_payload_cache_tail_validation_passed_8616(project) is False

    project._inertia_last_tail_validation_snapshot = {
        "structuring": {"status": "stable"},
        "postprocess": {"status": "stable"},
    }

    assert cli_decompilation._validated_payload_cache_tail_validation_passed_8616(project) is True

    project._inertia_tail_validation_enabled = False
    project._inertia_last_tail_validation_snapshot = None

    assert cli_decompilation._validated_payload_cache_tail_validation_passed_8616(project) is True


def test_sidecar_cod_metadata_resolver_accepts_structural_metadata(tmp_path):
    cod_path = tmp_path / "TEST.COD"
    cod_path.write_text(
        "\n".join(
            (
                "_f\tPROC NEAR",
                ";|*** int f(void)",
                ";|*** {",
                ";|***     for (i = 0; i < 3; ++i) {",
                ";|***         x += i;",
                ";|***     }",
                ";|***     return x;",
                ";|*** }",
                "\t*** 0000\tc3 \t\tret",
                "_f\tENDP",
            )
        ),
        encoding="utf-8",
    )
    project = SimpleNamespace(
        _inertia_lst_metadata=SimpleNamespace(
            cod_path=str(cod_path),
            cod_proc_kinds={0x1000: "NEAR"},
        )
    )
    function = SimpleNamespace(addr=0x1000, name="f")

    metadata = cli_decompilation._sidecar_cod_metadata_for_function(
        project,
        function,
        tmp_path / "TEST.EXE",
        None,
    )

    assert metadata is not None
    assert cli_decompilation._expected_loop_count_from_cod_metadata_8616(metadata) == 0


def test_function_profile_ignores_proven_stack_probe_calls(monkeypatch):
    stack_probe_target = 0x1504
    operand = SimpleNamespace(type=2, imm=stack_probe_target)
    call_insn = SimpleNamespace(mnemonic="call", op_str=f"{stack_probe_target:#x}", operands=(operand,))
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(call_insn,)))
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda _addr, opt_level=0: block),
        _inertia_original_linear_delta=0xF132,
        _inertia_original_project=SimpleNamespace(),
    )
    function = SimpleNamespace(
        project=project,
        block_addrs_set={0x1000},
        get_call_sites=lambda: (0x1006,),
    )

    def identify_helper(candidate_project, candidate_addr):
        if candidate_project is project:
            return None
        if candidate_addr == 0x10636:
            return SimpleNamespace(kind=CompilerHelperEvidenceKind8616.STACK_PROBE)
        return None

    monkeypatch.setattr(cli_decompilation, "identify_x86_16_compiler_helper_at_8616", identify_helper)

    profile = cli_decompilation._function_decompilation_profile(function, 11, 0x83)

    assert profile["raw_call_site_count"] == 1
    assert profile["call_site_count"] == 0
    assert profile["internal_call_count"] == 0
    assert profile["stack_probe_call_count"] == 1


def test_preferred_options_can_disable_dead_memdefs_without_no_call_guard():
    options = cli_decompilation._preferred_decompiler_options(
        11,
        0x83,
        disable_dead_memdefs=True,
    )

    assert options == [("remove_dead_memdefs", False)]


def test_x86_16_clinic_policy_disables_ite_diamonds_only_for_straightline_cfgs():
    options = cli_decompilation._preferred_decompiler_options(
        3,
        26,
        disable_dead_memdefs=True,
    )
    straightline = SimpleNamespace(
        graph=SimpleNamespace(nodes=(0, 1, 2), out_degree=lambda node: {0: 1, 1: 1, 2: 0}[node])
    )
    branching = SimpleNamespace(
        graph=SimpleNamespace(nodes=(0, 1, 2), out_degree=lambda node: {0: 2, 1: 0, 2: 0}[node])
    )

    assert options == [("remove_dead_memdefs", False)]
    assert enforce_x86_16_clinic_options_8616(options, function=straightline) == [
        ("remove_dead_memdefs", False),
        ("rewrite_ites_to_diamonds", False),
    ]
    assert enforce_x86_16_clinic_options_8616(options, function=branching) == options
