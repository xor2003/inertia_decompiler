"""Record reviewed owner layers for tests that hide imports dynamically.

Layer: Tooling/gates.
Responsibility: preserve explicit test-module ownership decisions that cannot
be derived from normal Python imports or the changed-file ownership manifest.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


@dataclass(frozen=True, slots=True)
class RetiredTestContract:
    """Document one removed redundant test and the contracts that supersede it."""

    reason: str
    replacements: tuple[str, ...]


REVIEWED_TEST_MODULE_LAYERS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "tools/dev/tests/test_agent_test_focus.py": ("tooling/gates",),
        "tests/cli/test_batch_decompile_procs_runtime.py": (
            "tooling/gates",
            "inertia/cli",
        ),
        # Mutation checks exercise another test's oracle, not decompiler imports.
        "tests/cli/test_cod_openfilewrapper_consolidation.py": ("tooling/gates",),
        "tests/cli/test_decompile_jit_restart.py": ("inertia/cli",),
        "tools/dev/tests/test_makefile_quiet_output.py": ("tooling/gates",),
        "tools/signatures/tests/test_omf_pat_far_transfer_variants.py": ("compiler-flags",),
        "tools/signatures/tests/test_omf_pat_fixup_widths.py": ("compiler-flags",),
        "tools/signatures/tests/test_omf_pat_lidata.py": ("compiler-flags",),
        "tools/signatures/tests/test_omf_pat_x87_emulator_variants.py": ("compiler-flags",),
        "tools/signatures/tests/test_omf_pat_zero_displacement.py": ("compiler-flags",),
        "tools/dev/tests/test_parallel_job_defaults.py": ("tooling/gates",),
        "tools/compiler_id/tests/test_flags.py": ("compiler-flags",),
        "tools/compiler_toolchain/tests/test_scalar_types_runtime_fixture.py": ("tooling/gates",),
        "tests/integration/test_x86_16_access_trait_arrays.py": ("inertia/lowering", "inertia/cli"),
        "tests/integration/test_x86_16_access_trait_policy.py": ("inertia/lowering", "inertia/cli"),
        "tests/integration/test_x86_16_access_trait_strides.py": ("inertia/lowering", "inertia/cli"),
        "tests/postprocess/test_x86_16_boolean_simplify.py": ("inertia/postprocess", "inertia/cli"),
        "tests/cli/test_x86_16_helper_replacements.py": ("inertia/postprocess", "inertia/cli"),
        # These modules reach the CLI or executable oracle through test helpers.
        "tests/cli/test_x86_16_inbox_long_live.py": ("inertia/cli",),
        "tests/integration/test_x86_16_reinitbars_execution.py": ("tooling/gates",),
        "tests/integration/test_x86_16_setgear_behavior.py": ("tooling/gates",),
        "tests/integration/test_x86_16_tidshowrange_behavior.py": ("tooling/gates",),
        "tests/lowering/test_x86_16_mypy_monkeytype_targets.py": ("tooling/gates",),
        "tests/cli/test_x86_16_msc6_regressions.py": ("inertia/cli",),
        "tests/integration/test_x86_16_msc6_sort_patterns_regression.py": ("inertia/cli",),
        "tests/integration/test_x86_16_segment_association.py": ("inertia/lowering", "inertia/cli"),
        "tests/lowering/test_x86_16_prevalidation_stack_prototype.py": (
            "inertia/lowering",
            "inertia/validation",
        ),
        "tests/lowering/test_x86_16_string_corpus_anchors.py": ("inertia/cli",),
        "tests/structuring/test_x86_16_structuring_cyclic.py": ("inertia/structuring",),
        "tests/structuring/test_x86_16_structuring_stage_environment.py": ("inertia/structuring",),
        "tests/integration/test_x86_16_tail_callsite_inventory.py": (
            "inertia/frontend",
            "inertia/postprocess",
        ),
        "tests/frontend/test_x86_16_void_return_pass_ownership.py": (
            "inertia/postprocess",
            "inertia/validation",
        ),
    }
)

RETIRED_TEST_CONTRACTS: Final[Mapping[str, RetiredTestContract]] = MappingProxyType(
    {
        **{
            "tests/postprocess/test_x86_16_decompiler_postprocess_calls.py::" + previous: RetiredTestContract(
                reason="renamed to enforce evidence-backed consumption and retain unproven memory stores",
                replacements=("tests/postprocess/test_x86_16_decompiler_postprocess_calls.py::" + replacement,),
            )
            for previous, replacement in (
                (
                    "test_materialize_callsite_stack_arguments_prefers_generic_probe_stores_over_push_arg_sources",
                    "test_materialize_callsite_stack_arguments_requires_exact_consumed_push_evidence",
                ),
                (
                    "test_materialize_callsite_stack_arguments_prunes_direct_push_source_far_pointer_stores",
                    "test_materialize_callsite_stack_arguments_keeps_unproven_far_pointer_stores",
                ),
                (
                    "test_materialize_callsite_stack_arguments_prunes_keep_existing_scalar_byte_pair_stores",
                    "test_materialize_callsite_stack_arguments_keeps_unproven_scalar_byte_pair_stores",
                ),
            )
        },
        **{
            "tests/cli/test_x86_16_cod_regressions.py::" + retired: RetiredTestContract(
                reason="identical CLI invocation; existing status and output checks consolidated into behavior regression",
                replacements=("tests/cli/test_x86_16_cod_regressions.py::" + replacement,),
            )
            for retired, replacement in (
                ("test_cod_regression_targets_are_recoverable[BIOSFUNC.COD-_bios_clearkeyflags-20]",
                 "test_cod_biosfunc_clearkeyflags_far_word_store"),
                ("test_cod_regression_targets_are_recoverable[DOSFUNC.COD-_dos_getfree-20]",
                 "test_cod_dos_getfree_call_and_return_recovered"),
                ("test_cod_regression_targets_are_recoverable[DOSFUNC.COD-_dos_loadOverlay-20]",
                 "test_cod_dos_loadoverlay_wrapper_returns_loadprog"),
                ("test_cod_regression_targets_are_recoverable[DOSFUNC.COD-_dos_getReturnCode-20]",
                 "test_cod_dos_getreturncode_returns_value"),
                ("test_cod_regression_targets_are_recoverable[EGAME2.COD-_openFileWrapper-20]",
                 "test_cod_openfilewrapper_direct_forwarding"),
                ("test_cod_known_helper_signatures_are_declared[DOSFUNC.COD-_dos_getfree-anchors0]",
                 "test_cod_dos_getfree_call_and_return_recovered"),
                ("test_cod_known_helper_signatures_are_declared[DOSFUNC.COD-_dos_loadOverlay-anchors1]",
                 "test_cod_dos_loadoverlay_wrapper_returns_loadprog"),
                ("test_cod_known_helper_signatures_are_declared[EGAME2.COD-_openFileWrapper-anchors2]",
                 "test_cod_openfilewrapper_direct_forwarding"),
            )
        },
        "tests/cli/test_x86_16_cli.py::test_decompile_cli_small_cod_logic_batch"
        "[path12-_TIDShowRange-NEAR-10-30-expected_tokens12-forbidden_tokens12]": RetiredTestContract(
            reason="duplicate command whose timeout branch bypassed all nominal output assertions",
            replacements=(
                "tests/cli/test_x86_16_cli.py::test_decompile_cli_recovers_tidshowrange_layout_logic",
            ),
        ),
        "tests/cli/test_x86_16_cli.py::test_decompile_cli_small_cod_logic_batch"
        "[path13-_DrawRadarAlt-NEAR-10-30-expected_tokens13-forbidden_tokens13]": RetiredTestContract(
            reason="duplicate command with output assertions strictly weaker than its dedicated regression",
            replacements=(
                "tests/cli/test_x86_16_cli.py::test_decompile_cli_recovers_drawradaralt_branch_logic",
            ),
        ),
        "tests/cli/test_x86_16_cod_regressions.py::test_cod_regression_targets_are_recoverable"
        "[OVERLAY.COD-_overlay_load-20]": RetiredTestContract(
            reason="duplicate command with status and output assertions covered by the overlay sample regression",
            replacements=(
                "tests/cli/test_x86_16_cod_samples.py::"
                "test_overlay_cod_sample_wrapper_returns_overlay_segment",
            ),
        ),
        "tests/cli/test_x86_16_cod_regressions.py::"
        "test_cod_overlay_load_preserves_guarded_free_memory_probe_before_final_return": RetiredTestContract(
            reason="duplicate command whose successful-path assertions are a strict subset of the overlay sample regression",
            replacements=(
                "tests/cli/test_x86_16_cod_samples.py::"
                "test_overlay_cod_sample_wrapper_returns_overlay_segment",
            ),
        ),
        "tests/structuring/test_x86_16_structuring_cyclic.py::"
        "TestLoopExitClassification::test_simple_while_loop_classification": RetiredTestContract(
            reason="pass-only placeholder superseded by executable natural-loop classification",
            replacements=(
                "tests/structuring/test_x86_16_structuring_cyclic.py::"
                "test_structure_analysis_publishes_proven_topology_without_collapse",
            ),
        ),
        "tests/structuring/test_x86_16_structuring_cyclic.py::"
        "TestLoopExitClassification::test_loop_with_break_classification": RetiredTestContract(
            reason="pass-only placeholder superseded by typed loop-break materialization",
            replacements=(
                "tests/structuring/test_x86_16_structuring_loop_break_jcc.py::"
                "test_structuring_unconsumed_loop_break_jcc_inserts_guard_before_taken_body",
            ),
        ),
        "tests/structuring/test_x86_16_structuring_integration.py::"
        "TestStructuringIntegration::test_natural_loop_stats_tracking": RetiredTestContract(
            reason="untyped placeholder expected graph mutation without explicit loop evidence",
            replacements=(
                "tests/structuring/test_x86_16_structuring_loops.py::"
                "test_detect_natural_loop_returns_exact_typed_topology",
                "tests/structuring/test_x86_16_loop_recovery.py::"
                "test_exact_natural_loop_topology_is_proven_without_graph_mutation",
            ),
        ),
        "tests/structuring/test_x86_16_structuring_codegen.py::"
        "TestStructuringCodegen::test_codegen_integration_with_structuring": RetiredTestContract(
            reason="untyped empty regions cannot prove loop topology or emit executable C statements",
            replacements=(
                "tests/structuring/test_x86_16_structuring_cyclic.py::"
                "test_structure_analysis_publishes_proven_topology_without_collapse",
                "tests/structuring/test_x86_16_structuring_codegen.py::"
                "TestStructuringCodegen::test_loop_render_contains_while",
            ),
        ),
    }
)
