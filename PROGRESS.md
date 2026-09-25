- decompiler_postprocess_calls.py flatten+split (ongoing): mega `_materialize_callsite_stack_arguments_8616` dissolved into `_CallsiteStackArgsMaterializer8616` class via scope-aware AST transform; all nested `_impl` wrappers flattened to module fns (closure vars as kw-only params, binding-site dominance safety); manual phase splits for prune_consumed_segmented_stack_byte_arg_stores (94->0), ordered_callsite_pairs (79->0), attach_callsite_summaries (31->0), refresh_callsite_summary_node_ids (33->0), apply_callsite_summary_to_node (27->0), callsite seed/prototype paths; promoted findings 153->98; owning tests 178+2 pre-existing verified per batch.

# Progress

Current objective: implement `reference/compiler-coverage-plan.md` —
correctness-first compiler coverage with evidence-driven semantic recovery.
Tagged start: `far-pointer-candidates-93c6b401`.

## Completed milestones

- Large-model far-frame argument base proven from terminal `retf` evidence
  (`argument_frame_base.py`, `SimCC8616MSClarge`); far `inc_one`
  `validation=passed` with its argument at machine `BP+6` (commit d3dc07573).
- AGENTS.md hard rule 16 (loud exceptions) added; both silent far-proof
  catch-alls removed; incomplete test mocks completed instead (d3dc07573).
- Far function pointers proven by call-operand width
  (`FunctionPointerParameterFact8616.pointer_width`,
  `SimTypeFarPointer16_8616`); materialization widens the proven slot and
  re-sites later arguments; far-CC survives clinic via
  `PrototypeSource.CCA_DECOMPILER` (commit 2a446ba04).
- Near-model regressions hold: `apply_twice`, `inc_one` `validation=passed`.
- Far-pointer reflow now reports declaration refreshes and updates angr's
  separate rebuild argument storage; focused before/after regression added.
  Pointer/layout/codegen neighborhood: 16 passed; Ruff and focused MyPy clean.
- Traced the subsequent layout reset to COD labels being consumed as layout
  facts. Typed NAME_ONLY purpose now excludes optional labels from prototype
  geometry while preserving naming use; first focused neighborhood 87 passed.
- Positive-BP replay now consumes closed per-slot function-pointer evidence.
  The failing regression shrank `(4,4)/(8,2)` to `(4,2)` before the fix;
  the initial pointer neighborhood passes 12 tests after it. No signature
  authority promotion or complete-argument-census claim is introduced.

- Promoted-linter-debt cleanup (ruff C901/PLR0916/PERF102 only, no
  suppressions): stale Makefile mypy paths removed (`make mypy` green),
  PERF102 x2 fixed, and ~120 complexity findings refactored into typed
  helpers across ~150 X86_16 files. Owning pytest batches verified
  green per change (126/225/256/145/285+1 pre-existing/81/92/130/237/279/118
  /530/630/246/332/673/137+1 pre-existing/400/105+11/775/487/554+1 pre-existing/46/603+1 pre-existing/869/247/423/313/517/135/77/205/120/223/340/8/14/991+1 pre-existing/135 mid-batch/712+3 pre-existing/100/73/48/2685+2 pre-existing/178+2 pre-existing, lifter-union pass runs). X86_16 findings: 1507 → 962. Baseline suite remains 47
  pre-existing failures (far-pointer work), unchanged; the
  msc6_cmp32_regression sidecar-free CLI cases and the
  _MousePOS small-COD CLI case (byte-identical output verified via
  worktree/stash comparison) hang/fail identically at clean
  HEAD (cc2d1a195), confirmed pre-existing; the SORTD indexed-aggregate
  and sortd_runmenu_signed_wide_global sidecar-free CLI cases likewise sit
  in the recorded lastfailed baseline (240s timeout / exit-4 validation).
  Focused pytest
  needs `PYTHONHASHSEED=0` (make exports it); without it 8
  cache-surface tests fail on `allows_semantic_cache` refusal.
  Focused mypy needs sibling promoted modules on the command line —
  `follow_imports=skip` makes off-run imports Any and reports false
  no-any-return errors otherwise.

## Open work (far obligations, all still unadmitted)

- Native machine-frame correction is implemented: the tracker had popped two
  bytes for both near and far CALLs. Semantics now supplies exact encoded
  frame width; the adapter records typed counters and refuses unknown frames.
  Baseline 2 failed / 1 passed, initial neighborhood 69 passed. Final width
  and refusal rerun: `.cache/native-call-frame-final-widths.log`.
  Linked `.cache/coverage-apply-twice-machine-frame.{c,err}` exits 4 with
  matching SI/DI save/restore slots and final whole-tail clean. New active
  blocker: typed function-pointer calls retain `arg_6 & 0xffff`, rejected
  by gcc. Fix pointer target materialization at its owning lowering boundary;
  do not repair rendered C or assert unknown target preservation.
  Scoped Ruff/MyPy pass; quality-dev exits 2 on repository debt.
  Final focused result: 73 passed in 32.19 seconds (seven workers, JIT),
  including near/far 16/32-bit machine frames and refusal controls.
  Existing default pipeline is in its QuickC external lane (child PID
  3129058); do not restart it or count it as acceptance of this later fix.
- Fresh frame-boundary probe finished exit 4 at 10:30 local on September 24.
  `.cache/coverage-apply-twice-frame-boundary.err` proves the rebased native
  boundary accepts both indirect calls (0x1010, 0x101c), consuming all 12
  classified machine-frame effects with zero failures. Thus the observed
  four-byte save/restore coordinate drift is not explained by rejected
  indirect CALL-frame consumption. Next inspect surviving pre-SSA argument
  pushes/cleanup and native SP tracking. The direct-address fallback has an
  unmatched return edge and is a distinct path; no function acceptance claimed.
- Default gate pytest lane has now finished: 6,468 passed, 23 failed,
  10 warnings in 1,888.10 seconds. Pipeline PID 3110637 remains live at
  10:30 local; external-lane completion is not yet established. Preserve
  `.cache/pointer-slot-replay-pipeline.log`; do not launch a duplicate gate.
- `apply_twice` far now retains both pointer/value arguments in linked replay
  `.cache/coverage-apply-twice-pointer-slots.{c,err}`, but still exits 4 with
  `validation_failed` / `unassigned-stack-local`. It is not accepted.
- SI/DI save provenance is lost at calls with incomplete typed stack effects;
  final restore reads at `SS:BP-8..-5` remain uninitialized.
- Diagnostic replay `.cache/coverage-apply-twice-call-proof-seeded.err`
  finished, exit 4. First far call refuses `STACK_ALLOCATION_UNPROVEN`;
  both indirect calls refuse `TARGET_UNRESOLVED`. Set `PYTHONHASHSEED=0`
  before launching in-process probes:
  otherwise `decompile.py` exec-restarts and drops installed Python hooks.
  The first unseeded probe timed out and produced no hook evidence; do not
  interpret its empty observations as absence of call effects.
- Far allocation proof now requires the binary helper's exact return-frame
  kind and retains conflicting proofs for refusal. Baseline 3 failures / 12
  passes; initial neighborhood 42 passed; MyPy/Ruff clean. Final test run hit
  a transient concurrent IndentationError in `calling_convention_compat.py`;
  that file now compiles. Final rerun: 44 passed in 53.60 seconds, log
  `.cache/far-allocation-final-stable.log`.
  Linked replay `.cache/coverage-apply-twice-far-allocation.err` finished
  exit 4: allocation call now PROVEN/BP-preserved, leaving exactly the two
  indirect TARGET_UNRESOLVED refusals. SI/DI validation remains failed.
- Further diagnostic `.cache/coverage-apply-twice-spill-prune.err` finished
  exit 4: the spill-prune owner recognized SI/DI pairs but made no deletions.
  Do not change that owner on the assumption it removed these saves.
  Native codegen snapshots are now being captured in session `84619`, log
  `.cache/coverage-apply-twice-native-saves.err`, to locate their actual loss.
- Direct-caller census completeness only covers discovered direct callers;
  it does not close unknown incoming edges. Do not use it alone to assume
  the indirect targets or their preserved-register effects. The fixture has
  multiple pointer targets and branch-selected pointer arguments.
- Prior default pipeline process/session are gone; its log records only
  prerequisite 292 passed. Structured summary is stale (September 20), so
  no full-pipeline success is established. A fresh gate remains required.
- Expanded pointer neighborhood: 38 passed in 48.42 seconds after completing
  old mocks with the missing empty callee decoder surface. No production
  catch added. New default gate log: `.cache/pointer-slot-replay-pipeline.log`.
  Gate session `68055`, PID `3110637`, remains live; prerequisite 292 passed.
- Failed quality-dev (exit 2) log `.cache/pointer-slot-replay-quality-dev.log`
  reports repository Ruff debt and a mypyc type error in
  `validation_control_flow.py`; focused MyPy passes on both replay owners.
- `quality-dev` has typing failures outside this slice in
  `validation_condition_storage_views.py` and `semantics/call_stack_effects.py`;
  full log: `.cache/far-pointer-rebuild-quality-dev.log`.
- `fill_bytes`/`swap_ptrs`/`offset_copy` far-frame argument reads.
- Candidate manifest reruns for `large-far-pointer-001` and
  `large-far-function-001` once the above validate.

## Verification commands

- Focused regressions: `pytest angr_platforms/tests/...` (277 passing
  across the stack-prototype/GP-restore/CC/fn-pointer suites).
- Single function: `./.venv/bin/python decompile.py --no-alternate-source-c
  --timeout 60 --proc NAME --proc-kind {NEAR,FAR} <EXE>` in the retained
  `.cache/compiler-coverage/large-far-function-001/case-000` artifacts.

## Complexity cleanup — callsite materializer flatten (cont.)

- `_CallsiteStackArgsMaterializer8616` fully flattened: 184-def mega + nested
  def trees converted to methods with explicit ctx params (bindingsite-safe).
- `_normalize_materialized_call_args` split: per-arg verdict method
  `_normalize_rhs_register_arg_8616`, `_postprocess_normalized_arg_8616`,
  `_resolve_register_rhs_chain_8616`, `_normalize_call_helper_offset_8616`,
  `_group_single_far_pointer_arg_8616`, plus resolver/debug helpers.
- `_set_materialized_call_args` split: `_regroup_args_from_summary_widths_8616`,
  `_apply_zero_arity_ownership_8616`.
- `_direct_expr_from_push_source_8616` split: per-kind materializers
  (`bp_value`, `bp_addr`, `bp_index_addr`, `global_value`, `global_index`,
  `seg_indirect`, `expr_ops`).
- `_collect_backtracked_stack_args` nested defs hoisted:
  `_rhs_matches_call_return_addr_8616` (module), `_filter_call_return_frame_rhss_8616`,
  `_expand_typed_carrier_defs_8616`, `_trailing_stack_store_rhss_after_last_call_8616`.
- decompiler_postprocess_calls.py C901 findings ~300+ → 40; owning tests
  verified at every checkpoint (178 passed, 2 pre-existing failures).
- Additional splits: `_trailing_stack_store_rhss_after_last_call_8616`
  (typed/non-probe collect helpers), `_collect_backtracked_stack_args`
  non-store tail, `_stack_store_rhs_verdict_8616`,
  `_dirty_setup_candidate_reason_8616` + hoisted debug fns,
  `_post_call_relocate_gate_8616`, `_inline_arg_backtrack_step_8616`,
  `_consumed_setup_lhs_tail_verdict_8616`, `_remat_arg_verdict_8616` +
  `_remat_debug_8616`/`_remat_stack_variable_verdict_8616`,
  `_pre_call_alias_artifact_candidate_ok_8616`,
  `_ret_arg_without_nearby_call_8616`, `_push_op_scalar_step_8616`
  dispatch table (per-op verdicts), `_resolve_shr_word_8616` +
  `_resolve_dirty_rhs_fallback_8616`, `_probe_next_call_debug_8616`,
  `_pointer_arg_quality_8616`/`_value_arg_quality_8616`,
  `_setup_*_byte_variants_8616` per-op byte builders.

## Complexity grind continued (decompiler_postprocess_calls.py)
- Flattened nested defs file-wide via binding-site-aware flattener; `_impl` parents
  moved to module-level fns; DX/AX pair fold, scalar-global remnant scan, inventory
  publish, prototype evidence all split into typed helpers.
- Repaired stranded tails from scripted edits (`_pre_call_alias_artifact_candidate_ok`,
  `_inline_arg_backtrack_step`, `_debug_clobber_refuse` missing `call` param).
- Cleared all non-complexity ruff findings (collapsible-if, needless-bool, dict-keys,
  enumerate, dead vars, stale noqas).
- Remaining in file: 34 complex-structure + 19 PLR0916, dominated by
  `_rewrite_block_body` (~134). Baseline holds: 178 passed, 2 pre-existing fails.

## Complexity grind finished (decompiler_postprocess_calls.py → 0 findings)
- All PLR0916 boolean sites extracted into named module predicates; all remaining
  complex-structure sites split into typed `*_8616` helpers.
- `_rewrite_block_body` (134 branches) decomposed into phase helpers:
  `_rewrite_stmt_pre_gate_8616`, `_resolve_call_stmt_facts_8616` (returns frozen
  `_CallStmtFacts8616`), `_rewrite_probe_helper_stmt_8616`,
  `_rematerialize_call_stmt_8616` (drives `_resolve_call_arity_evidence_8616`
  → `_CallArityEvidence8616`, `_collect_call_evidence_flags_8616`
  → `_CallEvidenceFlags8616`, `_single_bp_direct_arg_stmt_8616`,
  `_strict_shape_remat_stmt_8616` → `_strict_remat_arm_{0..8}_8616`,
  `_remat_no_count_stmt_8616` → `_remat_fallback_args_8616` /
  `_remat_apply_fallback_args_8616` / `_remat_apply_backtracked_args_8616`),
  `_rewrite_child_blocks_8616` (child recursion via `_rewrite_child_merge_8616` /
  `_rewrite_switch_children_8616` / `_rewrite_deep_children_8616`),
  `_dedup_summaryless_call_stmt_8616`; module-level `_recover_call_evidence_gate_8616`
  + `_recover_debug_skip_8616`.
- Extracted helpers keep `continue`/`i += 1` semantics via `int | None`
  "consumed index" returns; loop-carried probe facts returned as tuples.
- Final: `ruff check` = 0 findings on the file; owning tests 178 passed,
  same 2 pre-existing failures (unchanged semantics).

## Complexity grind finished (decompiler_postprocess_globals.py → 0 findings)
- Hoisted nested defs (`visit`, `_impl`) to module fns; split word-global
  load/store traversal (`_visit_word_global_stores_8616`,
  `_word_global_store_pair_step_8616`), type application across
  `variables_in_use` / `cexterns` / `unified_local_vars`, and unused-global
  collect + drop helpers.
- Owning subset: 5 passed; ruff clean.

## Complexity grind finished (ir/ir_canonicalize_8616.py → 0 findings)
- `_impl` nested defs hoisted; per-op canonicalization consolidated into
  `_canonicalize_binop_dispatch_8616`; assoc `And`/`Or` flattening split into
  `_assoc_const_gate_8616` / `_assoc_walk_8616` / `_assoc_rebuild_8616` /
  `_assoc_combine_8616`; `Xor` walk hoisted to `_xor_walk_8616`; constant
  folding table-driven via `_CONST_FOLD_TABLE_8616` + `_fold_const_pair_8616`.
- Owning tests: 59 passed (canonicalize + full-width masks + layer boundaries).

## Complexity grind finished (widening/widening_rules.py → 0 findings)
- `collect_bp_stack_access_widths` split into summary-scan + capstone helpers.
- `_coalesce_direct_ss_local_word_statements` → `_DirectSSLocalCtx8616` ctx +
  `_ss_local_pair_lhs_8616` / `_byte_store_pair_lhs_8616` / `_direct_ss_pair_step_8616`.
- `_coalesce_segmented_word_store_statements` (94) → `_WordStoreCoalesceCtx8616` +
  typed helpers: node debug kinds, `_expr_width_bits_8616`,
  `_match_loaded_word_pair_expr_8616`, `_replace_loaded_word_pair_expr_8616`,
  `_word_lvalue_for_addr_8616`, `_runtime_word_store_lvalue_8616`, window steps
  (`_word_store_triple_step_8616` / `_word_store_quad_step_8616` /
  `_word_store_pair_step_8616` → runtime/ss-local/alias pair helpers),
  `_wstore_alias_pair_unjoinable_8616`, shared `_visit_structured_children_8616`.
- Owning tests: 63 passed (widening rules + stack arg widths + far load width +
  wrapped locals).

## Complexity grind finished (decompiler_postprocess_typed_conditions.py → 0 findings)
- Register-expr index split (`_register_exprs_from_assignment_8616`);
  `_build_c_expr_for_operand` → `_reg_operand_expr_8616` /
  `_ir_value_operand_expr_8616` / `_compat_operand_expr_8616`.
- Signed stack-arg retagging split across `_retag_body_stack_arg_cvars_8616`,
  `_retag_unified_local_vars_8616`, `_retag_arg_list_cvars_8616`,
  `_rebuild_args_from_arg_list_8616`, `_rebuild_args_from_old_prototype_8616`,
  `_publish_signed_arg_prototype_8616`.
- `_is_flag_based_condition_node` helpers hoisted; typed-condition apply
  decomposed into `_TypedConditionApplyCtx8616` + `_rewrite_*`/`_walk_*` helpers.
- Owning tests: 99 passed.

## Complexity grind finished (lowering/segmented_memory_lowering.py → 0 findings)
- `_match_segmented_memory_expr_8616` → `_access_prologue_8616` /
  `_decomposed_segmented_expr_8616` / `_linear_segmented_expr_8616`.
- `lower_runtime_segment_access_8616` → `_snapshot_adjusted_*` +
  `_lowered_matched_access_8616`.
- `materialize_runtime_helper_segment_carriers_8616` → `_collect_segment_carrier_proofs_8616`
  + `_SegmentCarrierCtx8616` + `_rewrite_segment_carrier_arg_8616`.
- `lower_runtime_ss_segment_helpers_to_stack_8616` → `_lower_ss_helper_lvalues_8616`
  + `_SSHelperLowerCtx8616` + `_ss_helper_transform_8616`.
- `apply_runtime_segment_lowering_8616` → early/late pass-chain helpers +
  `_runtime_lowering_transform_8616` (functools.partial) + `_publish_runtime_lowering_stats_8616`.
- `_materialize_binary_proven_near_pointer_argument_8616` → canonical-cvar,
  facts gate, missing-arg materialize, cardinality gate, commit helpers.
- `_near_pointer_arg_access_8616` → indexed/zero-plus access helpers +
  `_near_pointer_fact_cvar_8616` / `_near_pointer_width_facts_8616`.
- `_lower_typed_pointer_register_carrier_stores_8616` (44) → `_CarrierStoreCtx8616`
  + `_carrier_setup_gate_8616` / `_carrier_use_gate_8616` /
  `_extend_carrier_store_pair_8616` / `_carrier_consumption_ok_8616` /
  `_apply_mixed_projection_store_8616` / `_apply_wide_or_single_store_8616` /
  `_consume_one_carrier_store_8616` / `_consume_carrier_setup_8616`.
- Owning tests: 352 passed (one env-only kvikdos UnicodeDecodeError deselected:
  test_recompile_check_msc51_accepts_portable_signed_fixed_width_aliases).

### lowering/ir_segmented_load_carriers.py — promoted Ruff clean (12 → 0)

- `_constant_segment_offset_expr_8616` → `_matching_linear_base_indexes_8616`
  + `_residual_offset_expr_8616`.
- `_offset_expr_8616` → `_offset_base_terms_8616` (runtime/GP base projection).
- `_load_facts_8616` → `_track_mov_constants_8616` + `_stable_load_address_8616`
  + `_debug_load_fact_8616`.
- `_same_block_reload_for_read_8616` → `_same_block_window_clear_8616` +
  shared `_identity_register_names_8616` / `_use_block_for_addr_8616`.
- `_inherited_instruction_addresses_8616` → hoisted `_collect_inherited_addresses_8616`.
- `_nearest_linear_logical_fact_8616` (26) → `_nearest_dominating_fact_8616` +
  `_ssa_reachable_set_8616` + `_path_window_instructions_clear_8616` +
  `_debug_nearest_fact_8616`.
- `_insert_before_unique_following_statement_8616` (22) → hoisted
  `_collect_owner_paths_8616` + `_insertion_candidates_8616` +
  `_select_unique_insertion_8616` (tie-break preserved).
- `_materialize_missing_logical_assignments_8616` → `_collect_register_def_reads_8616`
  + `_materialize_identity_assignment_8616` + `_debug_logical_insertion_8616`.
- `_read_side_logical_replacements_8616` → `_read_replacement_for_node_8616`.
- `materialize_ir_segmented_load_carriers_8616`/`transform` (22/20) →
  `_CarrierTransform8616` dataclass dispatch (`_read_replacement`,
  `_assignment`, `_constant_segment_rhs`, `_logical_assignment`,
  `_register_assignment`, `_dirty`) + `_replace_constant_dereference_8616`
  (functools.partial). Mutation/classification order preserved.
- Owning tests: 73 passed (carriers + reload provenance + load origins).
- Layer boundaries: 15 passed.

### lowering/stack_prototype_materialization.py — promoted Ruff clean (8 → 0)

- `_existing_stack_cvars_by_offset_8616` → deduped scan loops.
- `_callsite_stack_arg_widths_8616` → object-width scan + source gate +
  per-summary body helpers.
- `_prune_stack_slots_covered_by_wide_args_8616` → deduped identical loops.
- `materialize_exact_trailing_stack_argument_8616` → gate + names recovery +
  publish tail helpers.
- `reconcile_exact_stack_argument_prototype_8616` (15) →
  `_ReconcileEvidence8616`/`_ReconcileArgResult8616`/`_ReconciledArgs8616`
  dataclasses + `_reconcile_width_evidence_8616`,
  `_conflicting_body_offsets_8616`, `_reconcile_one_arg_8616`,
  `_select_incoming_args_8616`, `_reconcile_width_facts_8616`,
  `_reconcile_args_8616`, `_publish_reconciled_prototype_8616`.
- `materialize_annotated_stack_prototype_8616` (13→0) →
  `_AnnotatedEntryCtx8616`/`_AnnotatedEntryResult8616`/`_AnnotatedMaterialization8616`
  + `_current_prototype_surface_8616`, `_current_arg_surfaces_8616`,
  `_annotated_entry_name_8616`, `_is_usable_annotated_name_8616`,
  `_materialize_annotated_entry_8616`, `_materialize_annotated_entries_8616`,
  `_commit_annotated_materialization_8616`, `_publish_annotated_prototype_8616`.
- Semantic fix preserved: annotated names validated by
  `_is_usable_annotated_name_8616`, distinct from prototype-name predicate.
- Owning tests: 238 passed (16 stack-prototype test files).
- Layer boundaries: 493 passed; architecture-contract failure is
  pre-existing (145 violations, none in this file).

### Single-finding sweep + scripts/tests cleanup batch

- `generated_external_function_contracts.py`: `_type_contract` →
  `_named_type_contract` tag-dispatch split.
- `generated_translation_unit_assembly.py`: `assemble_generated_translation_unit`
  → `_collect_declaration_sets` + `_canonicalize_declaration_sets`.
- `cli_mkfp_simplify.py` / `cli_cod_globals.py`: nested transform closures →
  `_MkFpFold8616` / `_CodGlobalLoadFold8616` dataclass folds +
  `_storage_object_artifact_for`.
- `function_ir_ssa_cache.py`: `_hydrated_hit_matches_8616` predicate.
- `function_ir_ssa_cache_key_8616`: node-hash + edge-collection splits.
- `function_graph_extent_repair.py`: `repair_undercovered_transition_sources_8616`
  → `_out_of_block_ins_addrs_8616` + `_extent_repair_plan_8616`; raw_fact_count
  derived from normalized sets.
- `rizin_evidence.py`: `collect_rizin_evidence` → typed fact collectors
  (`_function_facts`, `_xref_facts`, `_string_facts`, `_symbol_facts`,
  `_stack_var_facts`, `_cc_facts`, `_empty_evidence`, `_optional_int`).
- `indexed_alias_program_context.py`: `_transported_widening_bundle_8616` +
  `_reused_persisted_context_8616`.
- `indexed_alias_program_parallel.py`: worker hoisted + pool-lifecycle split.
- `direct_stack_move_pretest_body_evidence.py`: `Any` → `nx.DiGraph`.
- `direct_request_cache.py`, `serial_clean_worker_evidence.py`,
  `fork_timeout.py`, `batch_decompile_procs.py`,
  `generated_c_indexed_argument_contract.py`, `mypyc_build_cache.py`,
  `pytest_inventory_check.py`, `pytest_profile.py` (`_record_rss_sample` +
  `_record_outcome`), `pytest_dynamic_schedule.py` (`_WaveScheduler8616`),
  `agent_test_focus.py` (`_selection_payload`/`_print_plan`/`_run_selection`).
- Test files: `test_x86_16_structuring_lowering_order.py`
  (`_is_named_span_call`), `test_x86_16_cod_regressions.py`
  (`_DerefSubtreeCodegen` + `_build_deref_subtree_statements`),
  `test_x86_16_consumed_stack_address_setup.py` (`_SETUP_FAILURE_MUTATORS`
  dispatch table), `test_x86_16_indexed_stack_ranges.py`
  (`_TwoLoopOptions` + 9 fixture-construction helpers).
- Owning tests: 47 + 1 passed; `agent_test_focus --help` ok.
- Promoted inventory: 1212 findings across ~106 files (was 1238/~130).

### inertia_decompiler/runtime_support.py — promoted Ruff clean (15 → 0)

- `install_angr_peephole_expr_bitwidth_guard`/`_guarded_handle_expr` → module
  helpers `_normalize_replacement_bits_8616`, `_clinic_skip_complex_expr_gate_8616`,
  `_peephole_rewrite_loop_8616`, `_guarded_peephole_handle_expr_8616` + thin
  installed closure.
- `_seqnode_children_8616` → `_seqnode_attr_children_8616` +
  `_seqnode_cases_children_8616`.
- `_loop_exit_default_relation_8616` → `_collect_loop_exit_nodes_8616` +
  `_loop_exit_default_status_8616`.
- `_seqnode_map_region_id_8616` → `_seqnode_candidate_payload_8616`,
  `_preferred_exact_region_summary_8616`, `_region_missing_result_8616`,
  `_region_containing_summaries_8616`, `_exact_region_match_8616` +
  `_SEQNODE_PREFERRED_TYPES_8616`.
- `_seqnode_switch_artifact_mappings_8616` (37) → shared helpers
  `_common_int_path_8616`, `_switch_mapping_status_8616`,
  `_expanded_path_samples_8616`, `_expanded_region_mappings_8616`,
  `_expanded_root_geometry_8616`, `_expanded_root_verdict_8616`,
  `_expanded_root_switch_fields_8616` + per-artifact
  `_seqnode_switch_artifact_mapping_8616`. Nested
  `_expanded_root_normalized_body_8616`/`_path_tuple` deduped to existing
  module functions.
- `_graphregion_switch_artifact_mappings_8616` (33) → same shared helpers +
  hoisted `_common_prefix_len_8616`,
  `_default_case_region_ids_by_default_8616`,
  `_resolve_ambiguous_default_mapping_8616`,
  `_disambiguated_default_mappings_8616`, `_ambiguous_mapping_samples_8616` +
  per-artifact `_graphregion_switch_artifact_mapping_8616`.
- `_expanded_root_normalized_body_from_summary_8616` → `_append_int_values_8616`
  + `_accumulate_branch_subtree_ids_8616` + `_accumulate_branch_split_ids_8616`.
- `install_angr_pre_codegen_seqnode_probe_guard`/`_guarded_init` →
  `_record_pre_codegen_seqnode_probe_8616` with
  `_pre_codegen_condition_evidence_8616`,
  `_pre_codegen_grouped_switch_artifacts_8616`,
  `_pre_codegen_stage_mappings_8616`,
  `_pre_codegen_switch_replacement_probe_8616`; `_guarded_init` now a thin
  wrapper.
- `guard_angr_clinic_stage_markers` (46) + `_peephole_optimize` (21) →
  `_ClinicGuardState8616` dataclass (stage clock + counters + stats), wrapper
  factory `_clinic_stage_guard_8616`, module bodies
  `_guarded_simplify_block_8616`, `_guarded_peephole_optimize_8616`,
  `_debug_clinic_flags_8616`, `_clinic_peephole_capped_8616`,
  `_fast_block_peephole_8616`, `_debug_skip_complex_block_8616`,
  `_guarded_peephole_optimize_exprs_8616`, `_guarded_compute_propagation_8616`,
  `_NoPropagationResult8616`. Shared stage-marker wrappers now produced by the
  factory; peephole stmt/multistmt pair deduped.
- `run_with_timeout_in_daemon_thread` → `_enable_thread_stack_dump_8616` +
  `_daemon_thread_result_8616`.
- `guard_angr_structuring_codegen_internal_timing` (19) →
  `_timed_stage_guard_8616` factory + `_bounded_stage_guard_8616` +
  `_install_bounded_lowering_guards_8616`; ss-linear patch intentionally stays
  installed (documented).
- Owning tests: 7 + 30 passed (timing guards, msc6 runtime state, runtime
  support traces, clinic recovery contracts, clinic semantic stages).

### structuring_analysis.py — 7 promoted complexity findings → 0

- `_branch_split_partition_evidence_8616` (14) — earlier split into
  partition-stat helpers.
- `_collect_edge_guard_decision_tree_cases_8616` (43) →
  `_DecisionTreeScan8616` state dataclass with `record_case`,
  `record_empty_region`, `record_branch_split`, `_affine_step`,
  `continuation_step`, `_normalization_status`, `summary`; plus
  `_branch_split_child_summary_8616` and `_attach_expanded_root_summary_8616`.
  BFS order, affine-offset propagation, duplicate/mismatch counters, and all
  summary keys preserved.
- `_execute` (11) → flattened nested `_impl`; iteration body extracted to
  `_structure_iteration_8616`.
- `_try_edge_guard_switch_cascade` (22) → `_CascadeScan8616` dataclass +
  `_cascade_step_8616` + `_publish_edge_guard_cascade_8616`; module collector
  `_cascade_guarded_successors_8616`.
- `_find_next_edge_guard_switch_head_8616` (14) → `_next_head_walk_step_8616`
  returning (candidates, pushes).
- `_try_if_then_else` (11) → flattened nested `_impl`; merge tail extracted
  to `_merge_if_then_else_8616`.
- Owning tests: 99 passed (structuring switch/cyclic/grouped/codegen/
  integration).

### stack_c_ast_matching.py / validation_dataflow.py / corpus_scan.py / codeview_nb02_nb04.py — 30 findings → 0

- `stack_c_ast_matching.py` (7): hoisted AST walkers to module scope
  (`_iter_statement_nodes_8616`, `_push_statement_node_children_8616`), deduped
  scaled-segment matching into `_scaled_segment_name_8616`, converted
  `_stack_bp_displacement_8616`'s nested `collect` into the
  `_StackBpDisplacement8616` accumulator with per-term helpers.
- `validation_dataflow.py` (8): `_DefUseWalker8616` dataclass hoists the
  nested `_check_reads`/`_walk` closures; `walk` split into per-node-kind
  transfer methods. `_predicate_fact_8616` → `_predicate_node_token_8616`/
  leaf/op helpers; `_indexed_stack_storage_key_8616` → base/element/untrackable
  helpers; PLR0916 Shr gate → `_shr_rhs_byte_offset_8616`.
- `corpus_scan.py` (8): flattened all nested `_impl`s; `classify_failure` →
  `_stage_failure_class_8616`/`_failure_class_from_message_8616`;
  `scan_function` stages → `_scan_function_stages_8616` plus
  probe/prefix/cfg-preflight/cfg-shape/decompile helpers.
- `codeview_nb02_nb04.py` (7): `_NB0204Collections8616` sink + label/legacy
  subsection dispatch split; shared directory-entry walker; record/type
  helpers for symbol parsing and source-module line tables.
- Owning tests: 75 + 82 + 38 + 14 passed.

### structuring_codegen.py — 11 promoted complexity findings → 0

- Statement-ownership traversal split into `_c_statement_parent_paths_8616`,
  `_c_positioned_statement_ownership_8616`, `_statement_container_parent_span_8616`
  state helpers; `_populate_region_statements_from_cfunc_8616` simplified.
- `split_distinct_condition_call_occurrences_8616` → occurrence collector +
  per-call processing helpers.
- `coalesce_shared_call_side_effect_statements_8616` → context/state class.
- `evaluate_typed_edge_switch_replacement_safety_8616` (43) →
  `_SwitchSafetyScan8616` scan context: `_resolve_owned_statements_8616`,
  `_record_case_debug_8616`, `_collect_body_statements_8616`,
  `_single_container_span_8616`, `_dominant_container_span_8616`,
  `_owner_index_span_8616`, `_classify_covered_span_8616`. All refusal
  reasons, span sources, and debug projections preserved.
- Owning tests: 162 passed (segmented stack alias, structuring pass
  validation, induction summaries, runtime timing guards).

### structuring/condition_materialization.py — 7 promoted complexity findings → 0

- `materialize_same_block_condition_register_projections_8616` →
  `_matching_conditions_for_node_8616` + `_project_binary_condition_node_8616`
  with `_ProjectionNodeDelta8616` stat deltas.
- `_materialize_cfg_condition_chain_expr_8616` (30) → `_CfgChainBuilder8616`
  dataclass hoisting `prove_wide_pair`/`build_from_address`/`build_from_condition`
  closures plus `_proven_call_chain_expression_8616`.
- `_materialize_cfg_shared_body_condition_chain_expr_8616` →
  `_SharedBodyBuilder8616` + `_lower_shared_body_wide_8616`.
- `_materialize_cfg_single_branch_expr_8616` (33) → early-expr, region-expr,
  body-chain, fallback helpers plus `_proven_single_return_orientation_8616`
  returning `_SingleReturnProof8616`.
- `_materialize_existing_wide_call_return_conditions_8616` →
  `_lower_wide_call_return_pair_8616` with `_WideReturnPairDelta8616`.
- `materialize_structuring_condition_chains_8616` (80) →
  `_ConditionChainRun8616` pass context with `_semantic_call_arm_8616`,
  `_multi_arm_node_8616` (+ duplicate/exact/wide-return/shared-body arms),
  `_single_arm_node_8616` (+ root-fact selection, assignment diamond,
  arm replacement, apply helpers) and `_SingleArm8616`/`_ArmReplacement8616`
  per-node state. All debug projections and refusal paths preserved.
- Owning tests: 160 passed.

## decompiler_postprocess_jcc.py: promoted findings 31 -> 0

- `_rewrite_decoded_jcc_conditions_8616` (~421) -> `_JccRewriteRun8616`
  pass dataclass: 65 nested closures converted to `self.`-state methods via
  tokenize-based rename; `run` split into `_run_setup_8616`,
  `_run_collect_signatures_8616`, `_run_rebind_and_sibling_polarity_8616`,
  `_run_rewrite_node_conditions_8616` (+ `_rewrite_condition_pairs_8616`),
  `_run_prune_and_publish_8616`.
- Shared expression walkers hoisted: `_walk_c_expr_children_8616`,
  `_m_statements_from_root_8616`/`_flatten_c_statements_8616`,
  `_m_child_statement_roots_8616`, `_m_condition_exprs_from_stmt_8616`,
  `_m_assignment_rhs_has_real_call_8616`, `_m_expr_is_return_register_8616`,
  `_m_root_contains_ins_addr_8616` (+ `_root_children_8616`,
  `_root_tags_match_ins_addr_8616`), arg-offset collectors.
- `_CallReturnGuardScan8616` and `_CallReturnRebind8616` dataclasses replace
  nonlocal-closure collectors.
- `_decoded_condition_replacement` (38) split into pre-key gates, candidate
  resolution, signature/raw-state/materialized-keep gates, unknown-polarity
  inversion (`_DecodedGateResult8616`), and final replacement helpers.
- All refusal counters, debug events, consumed-low prune semantics, and
  call-return rebind behavior preserved.
- Owning tests: 159 passed (incl. idempotent typed-condition ordering).

## decompiler_postprocess_simplify.py: promoted findings 24 -> 0

- `_simplify_structured_expressions_8616` (345) -> `_SimplifyExpressionRun8616`
  pass dataclass: ~35 nested closures converted to methods (same tokenize
  rename as JCC); `run` split into `_collect_cfunc_roots_8616`,
  `_apply_root_transforms_8616`, `_refresh_root_children_8616`.
- `transform` (39) split into `_fold_stat_counted_8616`,
  `_fold_binary_transform_8616` (+ `_fold_concat_8616`,
  `_fold_zero_operand_binary_8616`, `_fold_or_word_or_zero_8616`),
  `_fold_not_transform_8616`, `_fold_tail_binary_8616` (+ `_fold_cmp_against_zero_8616`).
- `_fold_pure_constant_binary_8616` -> `_PURE_BINARY_FOLDS_8616` operator table.
- Counter bumps unified under `_bump_stat_8616` (dynamic codegen boundary).
- `_expr_contains_stack_or_flags_register_8616` -> offsets collector +
  recursive walker + shared `_seq_structured_children_8616` iterator
  (also used by `_contains_unresolved_virtual_expr_8616`).
- `_materialize_word_or_update_statements_8616` (107) -> methods on the same
  run class: `_gate_arithmetic_update_pair_8616`, `_match_arithmetic_delta_8616`,
  `_gate_duplicate_shift_update_8616`, `_match_duplicate_or_base_8616`,
  `_log_*_refuse_8616` debug helpers, `_probe_word_or_pair_8616`,
  `_try_duplicate_shift_8616`, `_try_arithmetic_pair_update_8616`,
  `_try_word_or_update_8616`, `_rewrite_statement_list_8616` driver.
  All INERTIA_DEBUG_WORD_OR_UPDATE refusal/match logs preserved verbatim.
- `_eliminate_single_use_temporaries_8616` (51) -> `_SingleUseTemporaryRun8616`
  accumulator + module-level `_is_virtual_register_temporary_8616`,
  `_crosses_nested_execution_scope_8616`, `_safe_inline_expr_8616`,
  `_count_var_uses_8616`/`_replace_var_use_8616` (+ seq/pairs/attrs helpers).
  Frozen `SingleUseTemporaryEliminationStats8616` still published per run.
- Owning tests: 90 passed.

## far_pointer_segmented_load_evidence.py (lowering) — clean

- Recovered file from truncated write (disk-full mid-edit); restored tail from
  HEAD verbatim, then refactored.
- `recover_far_pointer_segmented_loads_8616` (22) -> `_FarPointerScanState8616`
  scan-state dataclass + per-arm helpers `_apply_far_pointer_load_8616`,
  `_update_stack_slot_target_8616`, `_apply_mov_register_copy_8616`,
  `_apply_shift_index_8616`, `_invalidate_register_destination_8616`.
  Arm ordering and `continue` semantics preserved exactly.
- Owning tests: 7 passed.
- Disk: freed ~2.1G on /home (caches); /tmp overflow files removed.
