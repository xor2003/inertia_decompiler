# Full-Suite Audit: 2026-09-10

## Scope And Result

`PYTHON_JIT=1 PYTHONHASHSEED=0 make pytest-all PYTHON=./.venv/bin/python PARALLEL_JOBS=7`
used the existing partitioned runner: seven normal-worker slots, two conservative
heavy-worker slots and a 2 GiB aggregate RSS limit. Source was held fixed.
Command launch was observed at 06:56:27 CEST; the final summary was written at
07:19:32 CEST. The runner timing below excludes the initial inventory/setup.

- Collected and accounted for: 11536 tests; no missing or duplicate nodes.
- Passed: 11326; failed: 40; skipped: 170.
- Runner wall time: 1326.65 seconds (22.11 minutes).
- Peak aggregate RSS: 1731516 KiB; memory limit was not exceeded.
- Source stable: true; source SHA-256:
`e45bcdce862669f4a45fc1ee0049739955d070a11bc49ce7ccdd7f00a157aa80`.

The previous full audit had 11,008 passed, 52 failed and 170 skipped in
1,833.57 seconds. Collection grew by 306 tests. The new result supersedes
that test-status baseline, but is not a controlled performance comparison.
The full suite is not green, and its runtime is still above the accepted target.

Authoritative machine report: `.cache/pytest/partitioned-summary.json`.
Full log: `/tmp/inertia-full-suite-direction-audit.log`. This document preserves
the failure inventory even after a later audit replaces those artifacts.

## Priority And Acceptance

1. Close the direction helper's missing positive IR/SSA cache-source entry.
   Reason: later frontend edits must invalidate persisted IR. DoD: reproduce
   the missing dependency in the existing manifest test, add the owner, and
   pass cache tests and scoped types/linters. Failure: stale cache reuse or
   broadening the manifest to unrelated downstream stages.
2. Investigate QuickSort's newly observed self-comparison at the owning value/
   condition layer. The emitted partition-order test compares the same array
   address expression with itself instead of the two partition sizes. Tail
   validation says clean; strict GCC catches it. DoD: correct binary-derived
   operands, preserve both recursive paths and arguments, pass the unchanged
   regression and strict compilation, and add a generic regression for the
   underlying defect. Failure: suppressing the warning, deleting the branch
   without source-IR proof, or rewriting generated C.
3. Close shared semantic failures: ExchangeSort's uninitialized stack-local
   report, wide argument/predicate recovery, indexed storage and return
   contracts. Reason: these mechanisms affect multiple corpus cases. DoD:
   group by a verified common owner and pass each original failing regression
   plus focused refusal tests. Failure: sample-specific repair or weaker
   validation. The inventory below is not proof that every failure in one
   module has the same root cause.
4. Reconcile CLI fixtures and exact-output assertions with current contracts.
   Reason: some failures involve native CFunction snapshots, loader fixtures,
   reporting text or parentheses. Verify each before calling it obsolete.
   DoD: retain the original behavioral obligation with accurate fixtures or
   structural assertions. Failure: deleting useful coverage to make counts green.
5. Repeat the complete audit after a meaningful repair batch. DoD: all nodes
   accounted for, unchanged source during execution, zero failures, justified
   skips and measured resource/timing results. Failure: substituting the
   routine lane's passing count for the complete collection.

## Slowest Tests

Cache follow-up: the new manifest assertion failed before adding
`direction_step.py`. After the correction, eight cache tests pass in 8.46
seconds; scoped Ruff `check --fix`, MyPy and Pyright pass. No downstream cache
owners were added. The full-suite numbers above precede this manifest change;
they remain the latest complete audit, not a rerun of the changed source tree.

| Seconds | Test |
| ---: | --- |
| 137.13 | `angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_openfilewrapper_direct_forwarding` |
| 114.64 | `angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_tidshowrange_layout_logic` |
| 94.82 | `angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_known_helper_signatures_are_declared[EGAME2.COD-_openFileWrapper-anchors2]` |
| 83.91 | `angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_regression_targets_are_recoverable[EGAME2.COD-_openFileWrapper-20]` |
| 60.85 | `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_quicksort_preserves_pivot_swaps_and_recursive_calls` |
| 53.40 | `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants` |
| 46.79 | `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls` |
| 39.86 | `angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_setgear_guard_logic` |
| 37.44 | `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_exchangesort_preserves_inner_loop_setup_and_guarded_minimum_update` |
| 36.67 | `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_runmenu_typed_switch_artifacts_are_safe_and_materialized` |

Three `_openFileWrapper` cases are candidates for inspecting repeated setup
and equivalent invocations. Their shared target alone does not prove duplicate
coverage. Compare arguments, environments and assertions before sharing a
fixture or using `/home/xor/pytest_deduplicate`; no deletion is justified yet.

## Failure Inventory

- `angr_platforms/tests/test_cli_function_discovery_isolation.py::test_evidence_only_function_recovery_skips_convention_seeding`.
- `angr_platforms/tests/test_decompiler_architecture_check.py::test_current_decompiler_architecture_contract_is_clean`.
- `angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_drawradaralt_branch_logic`.
- `angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_setgear_guard_logic`.
- `angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_small_cod_byte_condition_logic`.
- `angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_tidshowrange_layout_logic`.
- `angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_small_cod_logic_batch[path8-_InBoxLng-NEAR-10-30-expected_tokens8-forbidden_tokens8]`.
- `angr_platforms/tests/test_x86_16_cli.py::test_decompile_function_disables_structuring_for_tiny_single_call_helpers`.
- `angr_platforms/tests/test_x86_16_cli.py::test_emit_function_result_does_not_reprint_validation_failed_ok_payload`.
- `angr_platforms/tests/test_x86_16_cli.py::test_emit_function_result_rejects_raw_segmented_access_even_with_stable_tail`.
- `angr_platforms/tests/test_x86_16_cli.py::test_main_aggregate_asm_fallback_does_not_reuse_stale_project_snapshot`.
- `angr_platforms/tests/test_x86_16_cli.py::test_main_falls_back_to_partial_timeout_before_asm_when_available`.
- `angr_platforms/tests/test_x86_16_cli.py::test_main_parallel_does_not_promote_late_partial_after_deadline`.
- `angr_platforms/tests/test_x86_16_cli.py::test_main_parallel_keeps_timeout_after_deadline`.
- `angr_platforms/tests/test_x86_16_cli.py::test_main_reports_pure_recovery_mode_and_attempt_states`.
- `angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_loadprog_preserves_binary_arguments_and_recompiles`.
- `angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_overlay_function_address_keeps_proven_known_object_bindings`.
- `angr_platforms/tests/test_x86_16_cod_regressions.py::test_decompiler_return_compat_infers_ax_stack_load_without_prototype`.
- `angr_platforms/tests/test_x86_16_cod_regressions.py::test_decompiler_return_compat_keeps_guessed_scalar_when_caller_uses_return`.
- `angr_platforms/tests/test_x86_16_cod_regressions.py::test_decompiler_return_compat_keeps_unknown_caller_unconditional_predecessor_return`.
- `angr_platforms/tests/test_x86_16_cod_regressions.py::test_decompiler_return_compat_requires_unbranched_scalar_for_unused_caller[terminal-scalar]`.
- `angr_platforms/tests/test_x86_16_cod_regressions.py::test_decompiler_return_compat_resolves_ax_self_update_return_source`.
- `angr_platforms/tests/test_x86_16_cod_samples.py::test_bios_cod_sample_decompilation`.
- `angr_platforms/tests/test_x86_16_heapsort_widening_regression.py::test_sortdemo_heapsort_uses_widened_word_access_for_crow_anchor`.
- `angr_platforms/tests/test_x86_16_msc_caller_cleanup.py::test_caller_cleanup_loop_preserves_affine_stack_pointer`.
- `angr_platforms/tests/test_x86_16_sortd_indexed_aggregate_regression.py::test_sortd_indexed_aggregate_load_and_store_recompile_sidecar_free`.
- `angr_platforms/tests/test_x86_16_sortdemo_positive_bp_acceptance.py::test_sortd_drawtime_proves_forwarded_wide_runtime_return`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_insertionsort_word_stores_materialized_without_raw_high_byte_memory`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawtime_sidecar_free_materializes_wide_delay_arguments`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_insertionsort_sidecar_free_splits_header_and_rebases_source`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_quicksort_sidecar_free_preserves_typed_control_flow_and_compiles`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_exchangesort_preserves_inner_loop_setup_and_guarded_minimum_update`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_heapsort_anchor_no_longer_prunes_local_lane_after_repeated_empty_results`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_heapsort_materializes_call_arguments_without_stack_leaks`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_main_uses_portable_flat_int_main_signature`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_quicksort_preserves_pivot_swaps_and_recursive_calls`.
- `angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swapbars_materializes_arguments_without_dead_setup_artifacts`.
- `angr_platforms/tests/test_x86_16_string_corpus_anchors.py::test_monoprin_fimemset_emits_string_intrinsic_fallback_anchor`.

Audit completion establishes this baseline, not completion of the plan.
