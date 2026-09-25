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
