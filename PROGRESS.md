- decompiler_postprocess_calls.py flatten+split (ongoing): mega `_materialize_callsite_stack_arguments_8616` dissolved into `_CallsiteStackArgsMaterializer8616` class via scope-aware AST transform; all nested `_impl` wrappers flattened to module fns (closure vars as kw-only params, binding-site dominance safety); manual phase splits for prune_consumed_segmented_stack_byte_arg_stores (94->0), ordered_callsite_pairs (79->0), attach_callsite_summaries (31->0), refresh_callsite_summary_node_ids (33->0), apply_callsite_summary_to_node (27->0), callsite seed/prototype paths; promoted findings 153->98; owning tests 178+2 pre-existing verified per batch.

# Progress

Current objective: implement `reference/compiler-coverage-plan.md` —
correctness-first compiler coverage with evidence-driven semantic recovery.
Tagged start: `far-pointer-candidates-93c6b401`.

## Completed milestones

- Coverage now selects address-only recovery by default with same-build labels
  used only for harness binding. Original bodies and behavioral checks survive;
  injected prefixes and incomplete bindings refuse. 99 focused tests plus both
  artifact controls pass. Live `cmp_i16` exposes a DCE phase return-contract
  exception; raw artifacts retained. No new DOS witness admitted.

- Removed harness-side stack-argument/signature/global repair from acceptance;
  generated defects now remain visible to compilation. Four controls failed
  before removal; 70 focused tests pass, including real GCC corruption controls.
  Old round trips require revalidation under the stricter harness.

- MS C diagnostic bytes cannot crash UTF-8 decoding or erase the compiler verdict;
  two before-fix failures, then 24 recompile tests pass with scoped Ruff/MyPy clean.
  Live DOS execution still reports unavailable KVM; quality-dev remains red.

- Missing required fixture procedures now fail before rebuild rather than being
  skipped by diagnostic text; 65 focused runner/policy tests pass. Default
  pipeline terminated: 6,475 passed / 48 failed; fresh quality-dev exits 2.
  These broad failures remain open, with concurrent-edit effects to distinguish.

- Explicit source-free MS C runs can no longer enter sidecar-backed named
  fallback: before-fix regression reproduced the leak; 64 runner/policy tests
  now pass, with scoped MyPy clean. Coverage defaults retain their stronger
  behavioral harness; binary-only target binding remains required.

- Missing-body retry retains the selected small/large procedure model; large
  regression failed before repair, then 63 focused runner/policy tests passed.
  Scoped MyPy passes; 12 legacy builder Ruff findings remain. Source-free
  fallback policy propagation and broad acceptance remain open; see coverage plan.

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

- lowering/segmented_global_loads.py driven to zero ruff findings (was ~70
  promoted sites at batch start): indexed/direct-global materializers,
  store-evidence collectors, stride/byte-address matchers, aggregate
  type/promotion/reconcile paths, and capstone-window classifiers split into
  typed module helpers and run-state dataclasses. Two splice regressions
  found and repaired during review: `_seg_global_debug_log_8616` restored to
  its env-gated `log.warning` body, and
  `_materialize_indexed_global_store_assignments_from_instruction_evidence_8616`
  rebuilt with its three extracted phases (facts-by-insn, assignment index,
  per-instruction materialization) preserving exact stats/decision counters.
  Owning suites: 181+187+15 passed; `test_synthesized_dword_return_call_
  keeps_exact_callsite_identity` confirmed failing identically on clean HEAD
  (pre-existing).

- tail_validation.py driven to zero ruff findings (was 61 complexity sites
  at batch start): the summary-build pipeline converted to a
  `_TailSummaryBuildRun8616` dataclass (context/support collection,
  normalization, node processing, finalize phases), boundary-fingerprint
  dispatch, contextual callsite maps, observable-location and
  prunable-write scans, and ~40 validation-delta suppressors split into
  typed helpers (delta-shape bundles, per-field gates, evidence matchers,
  shared touched-fields and other-fields-stable gates). Refactor surfaced
  and fixed ~14 new mypy errors back to the file's baseline (typed
  `summary_inventory`, `observed_locations` as `StackObservedLocations8616`,
  tuple/cache element annotations). Owning suite: 384 passed; the
  switch-decision-tree compare test fails identically on clean HEAD
  (pre-existing).

- decompiler_postprocess_stage.py driven to zero ruff findings (was 81
  complexity sites at batch start): materialization-loop matchers,
  instruction-window helpers, validation-delta classifiers, clone walkers,
  and stack-arg/prototype paths split into typed module helpers and
  run-state dataclasses. One real regression found and fixed during review:
  the `active_status_flag_lift_context_8616` wrapper around `_decompile_8616`
  had been dropped by an earlier splice and is restored. Owning postprocess
  suite: 639 passed, 2 confirmed pre-existing baseline failures.
  Focused mypy needs sibling promoted modules on the command line —
  `follow_imports=skip` makes off-run imports Any and reports false
  no-any-return errors otherwise.

- cli_c_text_postprocess.py driven to zero ruff findings (was 59
  complexity sites at batch start): signature/declaration normalizers,
  unused-declaration/staging pruners, fragment-carrier and stack-pointer
  rewrites, COD alias annotation, boolean-condition repairs, and helper-call
  formatting split into typed module helpers, run-state dataclasses, and
  shared arg-splitter/brace-scan utilities. Text-layer boundary preserved —
  cleanup/formatting only, no semantic recovery moved into this layer.
  Owning suites: 113 passed. Three COD CLI regressions
  (strlen stack-local copy, dos_getReturnCode, dos_loadProgram) fail
  identically on bare HEAD without this file's changes, at a
  frontend-lifter gate (`proven dead status-flag writes` in
  status_flag_lift_context.py) — pre-existing, upstream of this layer;
  clean cc2d1a195 baseline fails the same tests on an MSC51 recompile
  UnicodeDecodeError (env-level subprocess decode, also pre-existing).

- cli_c_ast_rewrites.py driven to zero ruff findings (was 59 sites at
  batch start, incl. a 365-complexity `_impl` closure): the whole nested
  simplifier became `_StructuredSimplifyRun8616` — a typed run dataclass
  holding all alias maps, caches, and protected-expression ids — with all
  38 nested helpers promoted to methods. The 104-complexity `transform`
  split into `_BinarySimplifyCtx8616` plus ordered `_arm_*_8616` rewrite
  arms preserving pass order (widened pairs, far-pointer MK_FP, word
  deltas, const-fold via `_CONST_FOLD_OPS_8616`, bitwise terms, And/Mul/Shr
  arms, dead-init pruning). Conservative refusal semantics preserved:
  unproven OR-base widening still refuses, protected dereference address
  expressions untouched, alias resolution stays conservative. Owning
  suites: 20 passed (ast rewrites + simplifier identity), plus 98 in the
  related postprocess/access-trait/stack-lowering set. mypy: 34 errors,
  all pre-existing unused-ignore debt — zero net delta vs HEAD.
  `.codebase-memory` index artifacts refreshed.

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

## gp_stack_restore / positive_bp_arguments / structured_intrinsics / validation_storage — clean

- `gp_stack_restore.py`: `_snapshot_insertion_candidates_8616` + `_GpRestoreReplacer8616`
  (replacer closure -> dataclass) + debug/anchor/assignment helpers.
- `positive_bp_arguments.py`: `materialize_positive_bp_arguments_8616` (57) ->
  `_PositiveBpRun8616`/`_DesiredInterface8616` run dataclasses + phased helpers
  (prepare, collect, layout, body-plan, desired, source-types, publish, prune).
- `structured_intrinsics.py`: `_decoded_insert_operands_8616`,
  `_insert_identity_occurrence_counts_8616`, `_insert_statement_lists_8616`,
  `_prune_statement_list_8616`.
- `validation_storage.py`: `validate_storage_identities_8616` (42) ->
  `_StorageValidationRun8616` with per-phase methods (global/stack/field/copy).
- Owning tests: 422 + 77 + 54 passed. One tail_validation failure is
  pre-existing (baseline red, unrelated kvikdos/env path).
- cli_access_traits -> `_AccessTraitCollector` (traits buckets + stride evidence
  + indexed-key + address summarizer). cli.py lazy-proxy splits.
  cli_linear_aliases -> `_BytePairSeedVisitor`. telemetry -> env/summary splits.
  pytest_resource_history -> payload-decode splits. import_ultra_quickc_fixtures
  -> fixture-result/stage/decompile helpers. test files -> hoisted fakes +
  `_recorded_stub_8616`.
- One `test_x86_16_cli` failure: kvikdos non-UTF8 subprocess decode
  (pre-existing environmental, in recompile_check path).
- `turbo_debug_tdinfo.py`: full TDS 3.x table coverage — flat indexed type
  table (8B records, 1-based), member stream (fields/methods/var-decls/
  offset-exts/trailers), builtin descriptors + range extensions,
  MEMBER_FUNCTION(0x2D) + VL_STRUCT/VL_UNION extension slots, class table
  (11B: parent idx/count, member ordinal, name, vptr, info), parent table,
  module-class ranges, line/scope/correlation tables; per-module type
  copies reconciled by run anchoring + continuation; member offsets solved
  against aggregate trailer size (m_actor signal@82 matches TDUMP).
- `dump_debug_info.py`: serializes modules, sources, segments, classes,
  parents, module-class runs, line entries, scopes, correlations,
  descriptors (incl. builtin_type_id, member_ref), member lists
  (block_ordinal), and named raw_table_spans for every TDINFO region.
- `borland_mangling.py`: typed Borland C++ name demangler (`@scope@name$Q<types>`)
  — scopes, ctor/dtor/operator/conversion specials, builtins, near/far
  pointers & references, `<len>` class types, arrays, function-pointer
  signatures (`NQV$V`), member pointers, `T<n>` 1-based arg repeats,
  U/Z/X/W qualifiers. All 512 mangled names in RIPTIDE.EXE decode with
  zero errors; every function signature renders identical to TDUMP's own
  demangling (verified against TD.OUT). Exposed in the dump as
  `demangled_names` + per-list `method_signatures`.
- Member type resolution + `struct_declarations`: flat type indexes now
  render as C-style names via `TDINFO_BUILTIN_TYPE_NAMES` (evidence-mapped:
  id5=int, id8=uchar, id9=uint, id6=long, id0a=ulong, id4=char, id0=void,
  id0d/0f/10=float/double/ldouble; unconfirmed → builtin_NN).  Pointer
  targets recurse (m_actor far*, unsigned char far*, void(far*)() for fn
  pointers), array counts derive from size/elem_size when bounds absent
  (loop.cels → cel far*[16]), anonymous bitfield containers inline as
  `struct { unsigned deleting:1; ... }`.  Per-member `type_name` serialized;
  `struct_declarations` emits full reconstructed structs (m_actor 84B,
  FILE == stdio.h, GAME_CAST actors[200], PCXHEAD, TILEMAP 930B).
- MEMBER_FUNCTION extension decoded: the 8-byte slot after each 0x2D
  descriptor = `owner_type_idx u16, reserved u16, method_ordinal u16,
  flags u16` (owner verified: 0x6f3→m_actor, 0x7ce→text_pager; ordinal =
  the method's member-table record index, matching TDUMP [NNN]; flags
  0x1000=method / 0x3000=virtual — gui_item vtable methods — /0x9000).
  `TDInfoTypeDescriptor.extension` preserves all extension slots raw.
- `function_signatures`: symbol × descriptor join gives 492 signatures —
  seg:off address + demangled param list + descriptor return type
  (`m_actor::facing_actor` → `unsigned char`, `gm_read` → `long`,
  `check_new_pos` → `unsigned int`).  Return type is the piece mangling
  cannot express; this completes per-function signatures.
- BC31 empirical harness (dosbox + real BCC/TDUMP on TT/TT2/TT3.EXE) resolved
  the remaining unknowns: every Borland builtin id is now named from TDUMP's
  own Types Table — the exotics are Turbo-Pascal/DPMI shared builtins
  (0x07 signed quad→long long, 0x0C pascal_char, 0x0E pascal_real48,
  0x24 label, 0x28 pascal_bool, 0x2A pword, 0x2B tbyte); id4 corrected to
  `signed char` (TD32 folds plain char into id8=uchar, short/ushort into
  the int slots).  Pointer attr bits decoded: 0x01=huge, 0x04=_DS —
  serialized as `pointer_flags`.
- MEMBER_FUNCTION extension fully decoded against BC31: ext =
  `owner_type u16, vtab_offset u16, member_name_index u16, flags u16`.
  vtab_offset = byte offset into the owning class vtable (0 for
  non-virtual; gui_item/button virtuals at 4,8 — BC uses 2 slots for
  dtors).  Field [4:6] is the member's name-pool index (earlier
  `method_ordinal` was wrong — TDUMP's [NNN] is the name index; dump now
  emits `member_name_index`+`member_name`).  Flags high nibble
  (0x1000/0x3000/0x9000) varies per module for the same class —
  emission-state marker, not virtualness.
- New descriptor kind MEMBER_POINTER=0x38 (T K::*, size 4 data / 6 fn,
  ref=pointee descriptor, 8-byte ext slot).  SEGMENT=0x17 renders
  `T _seg *`, member ptrs render `member_ptr(T)`.
- VL_STRUCT/VL_UNION = named parameter-frame type tags (19 records named
  PARMS/WPPARMS/RPPARMS/SHOWPAGEPARMS, class STRUCT_UNION_OR_ENUM symbols);
  their member-payload encoding is the one unresolved format detail —
  redundant for reconstruction since signatures come from mangling.
- Coverage attribution verified: map entries are 1-based start indexes
  into the offsets table; regression test added
  (test_tdinfo_coverage_offsets_attribute_to_their_segment).

### Riptide reconstruction audit driven by recovered types (continued)

- Full struct dump cross-checked against decomp/riptide.h; every recovered
  struct annotated with original TDINFO names:
  m_actor (hit_x_step/my_map_width/my_map_height/hit_count/target_distance/
  aux_char_ptr; signal bitfield = deleting,in_window,dont_erase,hit,
  new_looping,sleep,aux1..aux9,active — door_open/s_aux2 kept as semantic
  names with orig-name comments), loop/g cel/pc_snd/voc/snd (all matched
  recon alias structs; loop_res was missing `name` far* at +0x02 — fixed,
  frames[] -> cels[16]), game_manager (player2_input/sprite_storage_total/
  game_flags[20]/sound_on/song/game_speed/player players[2]/loop_count/
  sound_count/all_loops[150]/all_sounds[40] — recon sounds[0x27]+tail was
  replaced with the real 40-entry array), tilemap (orig names incl.
  auxillery_ints[50], t_width/t_height/t_org/t_size/tiles/map_palette/speed/
  map — recon 'exploded'@0x39C is really 'speed'), ms_mouse, gui_item,
  vga_display+palette_cycle (speed/cur_shift/cycle_count/how_many/
  shifted_segments[48][16]/start/end/size/movsd_size), game_cast (size),
  level_def=game_level, score_entry=score_element (name[9]+pad),
  msl_def=projectile (sound/left_image/right_image/energy/max_speed/
  explosion/ego_hit_voc/bubbles), menu_entry=pull_down_item, map_entry=tattr.
- DERIVED-CLASS member offsets: TDUMP 'New Offset: 0013' marks the
  derived-part base (gui_item = 0x13; button.alignment@0x13 lives in
  gui_item's tail pad) — recon GUI layouts verified faithful.
- BUG FIXED in decomp/game.cpp kill_ego(): the `ego->status` guard was
  INVERTED (recon `== 2`, original `jnz` => `!= 2`) and the common tail
  (status=2, aux1=0x3C, kill_jason, control=0) was nested inside the else
  instead of covering both branches.  Effect: first death ran the gotcha
  grab path; repeated per-frame calls with status==2 re-ran
  load_loop("egodie2.l") until the element read failed — the reported
  `Error looking for loop : egodie2.l` crash.  Restructured to match
  seg03f9:1A65 flow exactly.
- check_new_pos return type corrected int -> uint (TDINFO signature).
- Rebuilt all touched translation units through BC31 -ml -3 -f -O -r- -vi-:
  actor/game/creature/gamemgr/gui/kbd/menu/scores/tilemap/util/vgadisp all
  compile with zero errors (only pre-existing warnings).

## decompiler_postprocess.py: promoted findings 55 -> 0

- Largest file cleared: 55 promoted sites incl. several 40-66 complexity
  `_impl` closures converted to typed run dataclasses
  (`_RetaddrPruneRun8616`, `_RepairExitGotosRun8616`, `_DedupeVarNamesRun8616`,
  `_SyncProtoLayoutRun8616`, `_ApplyAnnotationsRun8616`,
  `_SyncArgsFromAnnotationsRun8616`, `_ApplyRewritesRun8616`,
  `_PointerArgIndirectMaterializePass8616`, `_PruneFlagAssignRun8616`).
- Fat run bodies split into phase helpers: prototype resolution, candidate
  collection, arg promotion (annotated/fallback/legacy lanes), high-byte
  projection, return-carrier collapse, flag/return pruning, register
  read-before-write walkers (shared seq/pairs recursion helpers).
- Pointer-arg indirect-fact collection shares `_record_reg_indirect_fact_8616`
  for load/store arms; covered-slot prune shares
  `_prune_covered_stack_var_map_8616` over variables_in_use/unified maps.
- Semantic ownership preserved: all promoted closures are dynamic
  angr/codegen boundary accesses; no semantics moved into rewrite.
- Verification: ruff 0, mypy 0 (HEAD parity), arch-check 0 violations in
  file. Owning suite 631 passed; 13 failures all pre-existing —
  11 COD runs stop at the documented frontend-lifter blocker
  ("proven dead status-flag writes"), 1 wall-clock timeout flake,
  1 cli_decompilation CompilerHelperEvidenceKind attr failure on an
  untouched file.

## cli_function_discovery.py lint cleanup (ruff 53 -> 0)

- Same `_impl`-closure decomposition pattern: every promoted closure hoisted to
  module helpers or typed state dataclasses (`_SeededRecoveryState8616`,
  `_CandidateRecoveryCtx8616`, `_SeededExeCtx8616`, `_DisplayRankState8616`,
  `_SidecarShowcaseState8616`, `_GraphRepairDiscovery8616`).
- LST recovery split into lanes: exact-region derivation/validation,
  rebased-slice build/recover/evidence, lean windows, stitching + data-ref
  retry, truncated escalation, bounded fallback, tiny-candidate promotion.
- Seeded/cached/prologue recovery decomposed into context resolution,
  per-address processing, follow-on queueing, and merge/finalize phases.
- Label/seed ranking became ordered bucket helpers preserving the original
  elif priority; graph repair split into entry gates, BFS discovery, node
  seeding, and edge/return-site installation.
- Contract fixes preserved: stitch helper returns `(pair, score, stitched)` so
  `truncated` resets only on real stitch success; `nonlocal addr` rebase and
  raising semantics retained.
- Verification: ruff 0, mypy 0 (HEAD parity), arch-check 0 violations in file.
  Owning suite 78 passed; 5 failures all pre-existing on bare HEAD —
  cache-policy SimpleNamespace monkeypatch gaps in
  test_discovery_cache_contract / test_cli_function_discovery_regions.

## tail_validation_fingerprint.py — lint debt cleared (was 33 promoted findings)

- Same flatten + extraction recipe: nested `_impl` closures hoisted to typed
  module helpers (`_expr_fingerprint_impl_8616`, `_location_fingerprint_impl_8616`,
  `_cvariable_location_fingerprint_impl_8616`, `_iter_call_nodes_impl_8616`,
  `_contextual_call_fingerprints_run_8616`).
- Expression fingerprint split into cache ctx (`_FpCacheCtx8616` dataclass),
  probe lanes, semantic-cast arm, normalized arm dispatch, and typed per-node
  arms — preserving cache-identity-after-normalization semantics.
- Contextual call matching became contextual-call collection + two shared
  key-matching passes (callsite addr, canonical target) + singleton remainder.
- Location fingerprints split into early typed arms, stack/indexed/deref lanes,
  stable-SS dereference, and terminal cvar identities.
- Verification: ruff 0, mypy 0 (HEAD had 1 — improved), arch-check 0 violations
  in file. Owning suites 87 + 409 passed; 1 failure pre-existing on bare HEAD
  (test_tail_validation_compare_classifies_switch_decision_tree_without_helper_delta).

## cli_core.py — lint debt cleared (was 37 promoted findings)

- The two monster functions were converted to state dataclasses with phase
  methods: `_DirectAddrCliRun8616` (205-complexity `_run_direct_addr_cli_8616`)
  and `_MainCliRun8616` (136-complexity `_run_main_cli_8616`); thin wrappers
  preserve the original function signatures and entry points.
- Nested closures hoisted to methods; `self.`-field rewrites were
  position-targeted (AST columns) to protect kwargs, f-strings, handler names
  (`except ... as ex`), `nonlocal`, and loop variables.
- Phase methods return `int | None` exit codes propagated by the dispatcher;
  `break`/`continue` were kept inside their owning loops via sub-phase splits.
- Regressions found and fixed after extraction: inverted retry gate
  (`status == "ok"` must be rejected), main seed/rank dispatch reading
  pre-setup state (made lazy via dispatch phases), `.self.` injected mid
  attribute chain, duplicated expired-futures sweep block.
- Source-inspection tests updated to the class layout
  (`_DirectAddrCliRun8616`); serial-worker completion ordering invariant
  verified via dynamic call-chain discovery (b1 calls completion phase before
  the phase leading to robust retry).
- Verification: ruff 0, mypy 0, arch-check 0 violations in file, all HEAD
  top-level defs preserved. Delta test set vs HEAD baseline: all remaining
  failures (drawradaralt branch logic, 3 msc6 runtime-gate tests) reproduce
  identically on bare HEAD — environmental/pre-existing, including the
  kvikdos UTF-8 decode issue.

## straightline_ssa.py — lint debt cleared (was 48 promoted findings)

- Same recipe as prior files: dict-iterator fixes, op-dispatch tables
  (`_CONST_JSON_BINOPS`, `_Z3_*_BINOPS/_Z3_*_CMPS`), helper extraction, and
  state-dataclass conversions (`_ConnectivityGate` +
  `_ConnectivityPairTables`, `_LowerScanState/_LowerScanCtx`,
  `_TermInputScan`, `_RegionCompareCtx`).
- `_apply_ssa_connectivity_gate` (39) split into a gate dataclass with
  per-result/per-successor methods; `_z3_apply` (37) table-driven;
  `_const_json_term_value` (32) split into simple/structural/cmp op helpers;
  `_call_targets_equivalent` (30) into head/mapped/unmapped verdict helpers.
- `_BlockLiftTimeout.__exit__` narrowed to `Literal[False]` so mypy proves
  the alarm never suppresses the lowering return.
- Verification: ruff 0 (was 48), mypy 174 errors (HEAD baseline 175),
  arch-check 0 violations in file, all HEAD top-level defs preserved,
  `test_dosunit_tool.py` 198 passed.

## cli_decompilation.py — lint debt cleared (was 34 promoted findings)

- The 299-complexity `_decompile_function` became `_DecompileRun8616`: a
  plain state class whose `run_8616` dispatches phase methods via
  `_run_phases_8616` in the original order; nested defs hoisted to
  methods/module helpers and 166 shared fields declared `Any` in `__init__`.
- Remaining complexity ground down by lane extraction:
  `_decompiler_attempt_8616` (guarded with-chain + `_decompiler_codegen_empty_stop`
  + `_decompiler_timeout_lane`/`_partial_payload`/`_stage_detail` helpers),
  `_decompiler_codegen_none_lane` (isolated-retry + options lanes),
  `phase_emit_retry_8616` (x87 debug, `_call_semantics_retry_lane` +
  `_attempt`/`_score`), `phase_no_postprocess_lane_8616`
  (`_nonpost_arch_facts` + `_nonpost_call_arity_replay`),
  `_rewrite_round_8616` (prepare/apply/guarded-evidence split),
  `phase_late_lowering_8616` (three materialization chunks),
  `phase_cleanup_finalize_8616` (dead-local/stats + three finalize helpers),
  `phase_callsite_guard_8616` restored (its tail had been swallowed into a
  neighbor method during an earlier splice — repaired against HEAD text).
- Hoisted helpers re-typed (`CompilerHelperEvidence8616 | None`,
  `int | None`, `list[tuple[int, int]]`, `tuple[int, int] | None`, `Any` at
  dynamic angr/codegen boundaries) so mypy stays clean on this QA-typed file.
- Verification: ruff 0 (was 34), mypy 0 (HEAD 0), identical 62-failure set
  on `test_x86_16_cli.py -k "decompile or cli"` vs bare HEAD (all
  pre-existing env failures — kvikdos UTF-8 decode etc.), 10/10 targeted
  `_decompile_function`/retry/stub tests pass.

## Compiler coverage resume — 2026-09-26

- Refactored-checkout baseline: 45 focused stack-tracker/function-pointer
  tests passed in 48.38 seconds, seven workers, JIT enabled. Log:
  `.cache/coverage-resume-20260926-tests.log`.
- Live apply_twice replay now exits 4 with empty codegen / clinic=None and
  assembly fallback, earlier than the September 24 pointer-mask failure.
  `.cache/coverage-resume-20260926-apply-twice.{c,err}` retains the evidence.
  Do not attribute this to a particular refactor without a causal trace.
- Added a focused AST regression for the proven far-pointer target retaining
  an integer mask. After completing its mock codegen surface, it fails at
  the intended target assertion; `.cache/fptr-target-before-complete-mock.log`.
  This is an intentionally red regression awaiting its owner-layer fix, not
  a completed improvement. No production pointer-target changes yet.
- Diagnostic hook around Decompiler._decompile exposed no exception. The
  outer _decompile_with_cache probe also finished with empty codegen, exit 4;
  `.cache/coverage-resume-20260926-cache-error.{c,err}` retains the evidence.
- Entry-point repair started at 12:29 local. Commit `0388db438` removed the
  invocation of `_decompile_8616`'s nested implementation and placed its flag
  context around the validation-acceptance helper instead. Restored the context
  and call at the pipeline entry; acceptance again retains its explicitly
  supplied function. Four entry regressions failed before the repair; a fifth
  regression separately proved the acceptance helper replaced function identity.
  These tests live in the already-enrolled package-exports module.
- Scoped Ruff passes. The first after-fix neighborhood run had eight passes
  and two collection errors because a concurrent `stack_lowering_impl.py` edit
  was syntactically incomplete; not a completed after-fix regression run.
  `quality-dev` exits 2 with broader existing lint/type failures. Logs:
  `.cache/decompile-entry-{before,after,final-ruff,quality-dev}.log` and
  `.cache/decompile-acceptance-before-complete.log`.
- Linked replay finished with exit 4, enters the real pipeline, and reproduces the far-pointer
  target masks; the fallback also reports missing indirect-call arguments.
  `.cache/coverage-resume-entry-restored.{c,err}` retains the replay artifact.
  No far-pointer obligation or whole-plan completion is claimed.
- After the concurrent syntax repair, the entry/pointer neighborhood reported
  85 passes and the expected pointer-mask failure (56.18 seconds). Thus all
  five pipeline-entry regressions pass; earlier collection errors are not the
  current entry-repair result.
- Pointer-target Lowering now consumes a full-word IP mask only for an exact
  binary callsite fact and the same authoritative parameter storage. It preserves
  call arguments, unproven masks, other slots/regions, and non-call expressions.
  The typed evidence artifact retains a separate five-counter target census.
  A near-pointer coordinate control exposed the need to reuse exact argument
  object identity when no new coordinate publication is needed; that control
  failed before the adjustment. Final neighborhood: 94 passed, 65.31 seconds,
  seven workers/JIT, `.cache/function-pointer-target-verified.log`.
- Scoped Ruff and final MyPy pass; `.cache/function-pointer-target-final-mypy.log`
  is the clean final typing result (exit 0).
  Linked replay `.cache/coverage-pointer-target-materialized.{c,err}` emits both
  unmasked calls and reports a clean whole-tail check for the rebased attempt,
  but exits 4 on the integrated MS C check: `/dev/kvm` missing. The identical
  retained MSC payload compiles via direct kvikdos invocation (exit 0, identifier
  truncation warning). This discrepancy is under investigation, not round-trip
  acceptance. The direct-address fallback still lacks an indirect-call argument.
- `quality-dev` and `quality-hard` exit 2 on broader lint/type debt. Full logs:
  `.cache/function-pointer-target-quality-{dev,hard}.log`. The required default
  pipeline has started in `.cache/function-pointer-target-pipeline.log`; inspect
  its live handle/result before starting another broad gate.
- The default pipeline's prerequisite suite passes 292 tests in 66.16 seconds;
  the main curated pipeline is still live. The pointer result now has the same
  two sequential value-argument calls as the original `function_pointers.c`
  `apply_twice`; this source comparison is diagnostic, not source-assisted
  recovery or a substitute for DOS behavioral acceptance.
- Device diagnosis: `.cache/msc-kvm-import-diagnostic.log` reports `/dev/kvm`
  absent before and after project import, and kvikdos exits 252 in that process.
  Direct tool invocations see the device. Do not alter the compiler launcher
  to bypass this execution boundary; integrated acceptance remains pending.
- Recompile capability reporting repair (started 12:56 local): the MS C owner
  now uses kvikdos's documented execution probe before compilation. Failed,
  timed-out, missing, or denied probes return typed `TOOLCHAIN_UNAVAILABLE`;
  they never accept or reject the generated C. CLI diagnostics distinguish this
  from syntax failure and do not cache unavailable results. Three regressions
  failed before repair; the focused neighborhood passes 26 tests in 105.27
  seconds. Final five availability/cache boundary controls pass in 60.03 seconds;
  this repair checkpoint ended at 13:03 local (about seven minutes elapsed).
- Live evidence `.cache/recompile-capability-live.log` reports unavailable,
  exit 252, command `kvikdos --kvm-check`, with no compiler source artifact.
  Scoped Ruff passes. MyPy reports 13 pre-existing `cli_core.py` errors outside
  the edited collector; the recompile producer and contract have no findings.
  Logs: `.cache/recompile-capability-{before,after,mypy,final-boundaries}.log`.
  The existing broad pipeline predates this reporting change; do not use it as
  full-suite acceptance for this subsequent edit.

## check_decompiler_architecture.py — lint debt cleared (was 33 promoted findings)

- All 33 `complex-structure` findings ground down by behavior-preserving
  helper extraction: per-path/per-node check helpers, parameterized
  violation probes (`_node_references_any_name_8616`,
  `_textpp_helper_name_scan_violations_8616`, `_runtime_guard_main_violations_8616`),
  and table-grouped Makefile/manifest lane validators. Nested closures
  (`_find_getattr`, `_scan_statements`, `_function_returns_constant_zero`)
  hoisted to module helpers with explicit `class_fields`/`value` params;
  the terminating-guard scanner split into a per-statement
  `(found, guard)` dispatch plus the narrowing/invalidation loop.
- One defect caught and fixed during verification: the bulk
  name-reference predicate replacement had rewritten the predicate's own
  body into a self-call (infinite recursion); restored the leaf
  `Attribute`/`Constant`/`Name` conditions.
- Verification: ruff 0 (was 33), mypy 0 (new helper annotations typed
  concretely — `dict[str, tuple[frozenset[str], bool, str]]`,
  `frozenset[str]` skip sets, `tuple[tuple[str, str, tuple[str, ...], int], ...]`),
  checker output byte-identical to the pre-refactor baseline (same 189
  violations), `test_decompiler_architecture_check.py` 370 passed + the
  same single pre-existing contract failure as bare HEAD.

- 2026-09-26: MSC v8 flat32 comparison adapter staged at `artifacts/msc8-z3cmp32/` (external rebuild is read-only); 13 focused regressions pass, unnormalized six-target batch: 43 proved / 137 mismatches / 5805 refused, plus `sub_593B0` conditional relocation proof. PE candidate input and closed matched-CFG induction are available; future MSC-built binaries, calls, exception edges and differing CFGs remain pending. See `RESULTS.md` and the checked `rebuild.patch`; no shared dosunit modules edited by this task.

## stack_lowering_impl.py — lint debt cleared (was 18 promoted findings)

- `_canonicalize_stack_cvar_expr`'s 299-complexity nested `_impl` was
  converted into the stateful `_StackCvarCanonicalize8616` class
  (`__slots__`, `__init__` field declarations, `run_8616` phase dispatch,
  `run_8616_part{0..3}`), with the impl-level closure/nonlocal names
  becoming `self.` fields via a scope-aware, position-based rewrite
  (Store-context-only binding, comprehension/lambda/except/param scopes
  respected, `nonlocal` names forced to fields, sibling defs becoming
  methods).
- `run_8616_part3` split into five `(done, result)` lane methods
  (cvar/indexed/deref/stackaddr/tail); each lane further split
  (cvar-stackvar/rebind, indexed-materialize, deref-addr/chain/operand/
  resolve, deref-offset/apply) until all bodies are below the complexity
  gate. The trailing `active_expr_ids.discard(expr_id); return expr`
  tail is preserved verbatim.
- `_resolve_stack_pointer_alias_expr` split into reference/stack_base/
  cvar/binop arms plus a shared `_lookup_alias_keys_8616`.
- `_stack_pointer_aliases` fixpoint split into
  `_resolve_stack_pointer_alias_8616(aliases=...)` (with cvar/reference/
  binop arm methods), `_apply_assignment_alias_8616` per-statement step,
  `_stack_carrier_lhs_allowed_8616` guard, and
  `_fixpoint_stack_pointer_aliases_8616` loop.
- `_infer_stack_base_alias_from_bp_slots` deduplicated onto the existing
  `_stack_base_displacement_expr_8616` and split into
  `_known_bp_offsets_8616` / `_stack_base_displacements_8616` /
  `_best_stack_base_bias_8616`; `_iter_statement_nodes` attr walk became
  `_push_node_children_8616`; `_single_assignment_expr_for_cvar`'s
  `_same_lhs` hoisted with explicit node-* params;
  `_single_assignment_expr_for_virtual_name`'s index build became
  `_virtual_assignment_index_8616`; `run_8616_part0` refusal blocks
  became `_part0_{dirty_cycle,depth}_refusal_8616` -> bool.
- Module-level `_impl` pairs flattened: `_prefer_bound_stack_cvar_8616`
  (+ `_bound_cvar_for_stack_var_8616`),
  `_record_stack_canonicalization_bridge_8616`
  (+ `_local_unwrap_casts_8616`, `_indexed_bridge_operand_8616`),
  `_resolve_stack_cvar_at_offset` (+ `_best_stack_cvar_candidates_8616`),
  `_canonicalize_stack_cvars` (+ `_safe_child_update_eligible_8616`),
  `_bind_expr_types_to_project_arch_8616`
  (+ `_bind_expr_child_types_8616`).
- Verification: ruff 0 (was 18 incl. the 299-complexity `_impl`),
  mypy 0, 56 focused stack-lowering tests + 16 cli stack tests pass,
  no public API removed (only nested defs hoisted to `*_8616` methods).

- 2026-09-26: Hardened staged MSC v8 comparator verdicts (schema v2). Two pre-fix regressions reproduced false/unscoped PASS outcomes; now complete identified backend evidence is required, and relocation-dependent equality is `conditional`/exit 2. 25 tests pass; saved-report audit retains all 43 unconditional proofs. Fresh LINK selection: 5 passed; CL selection: 1 mismatch; normalized global leaf: 1 conditional. Standalone Makefile gate and checked nine-file rebuild patch are in `artifacts/msc8-z3cmp32/`; external rebuild remains read-only.

## cli_fallback_decompilation.py — lint debt cleared (was 12 promoted findings)

- Five wrapper+`_impl` pairs converted to typed state classes
  (`_SidecarSliceFallback8616`, `_NonOptimizedSliceFallback8616`,
  `_RuntimeHelperEmitter8616`, `_RuntimeHelperTail8616`,
  `_RuntimeHelperTail2_8616`) with thin compatibility wrappers; shared
  converter generalized (position-based `self.` insertion, Store-context
  binding, `nonlocal`/except-handler scopes).
- Three runtime-helper emitters (ordered `lowered`-dispatch chains of
  ~25-55 branches returning literal stub C) collapsed into ordered
  `(matcher, render)` tables consumed by `_runtime_helper_match_8616`;
  dynamic name-building branches became `(normalized, lowered)` render
  lambdas. Output verified byte-identical vs HEAD across ~100 names.
- `_recover_and_decompile`/`_attempt` nested closures hoisted to methods
  bound via `functools.partial` (decompile/inherit/run-attempt/failure/
  summarize callbacks keep their original signatures); fresh-project
  retry lane extracted to `_fresh_project_retry_lane_8616`.
- Converter regression found and fixed: `except ... as ex` names inside
  phase statements were wrongly field-qualified (`self.ex`) and then
  `ruff --fix` dropped the bindings; all five sites restored to real
  handler-scoped names.
- Module docstring gained the `Guard:` marker (clears the `cli-header`
  architecture rule; the remaining `cli-x86-16-import` violation is
  pre-existing on HEAD).
- Verification: ruff 0 (was 12), mypy 0 (HEAD 0), arch-check file
  findings equal-or-better than HEAD, all HEAD top-level defs preserved.
  5 focused slice-entry/non-optimized-policy tests pass; the
  ownership-manifest failure in the same run is pre-existing on bare
  HEAD.
## Compiler coverage: address-only replay checkpoint (2026-09-26 12:13 UTC)

- Verified the concurrent DCE repair with the saved fresh 77-test pass; this
  thread made no DCE implementation change.
- The original live `cmp_i16` replay is now terminal: CLI exit 3, analysis
  timeout, no emitted function body, tail validation uncollected. Full evidence
  is retained under `.cache/compiler-coverage/compare16-address-only-001/`.
- Identified an honest-reporting gap: the harness labels the inner timeout as
  validation failure. CLI exit 3 is also used for architecture-guard failure;
  a numeric-only timeout inference would be wrong.
- Started a bounded diagnostic profile in `.cache/cmp16-address-profile.*`;
  result pending. Routine deadline and acceptance requirements are unchanged.
  No DOS witness admitted; the full compiler-coverage plan remains incomplete.

### Follow-up completed 12:17 UTC

- Diagnostic replay finished with generated C and clean whole-tail validation,
  then failed the integrated compiler gate because `/dev/kvm` is unavailable.
  Actual spans show 51.94s direct decompilation; the changed isolation/deadline
  configuration is diagnostic, not routine acceptance or a performance win.
- Fixed coverage classification of an already-structured final function timeout.
  Regression before: 1 failed / 40 passed; after: 58 result/runner tests passed
  in 12.31s. Superseded attempts and malformed timeout fields remain distinct.
  Scoped Ruff/MyPy pass; quality-dev exits 2 on broader typing debt. Evidence:
  `.cache/coverage-timeout-classification-*.log`.
- Still open: structured CLI terminal-status transport, source-free routine
  round trips, unavailable DOS execution, and full witness/gate obligations.

### Structured timeout transport checkpoint (2026-09-26 12:23 UTC)

- Terminal direct, canonical-worker, and hard-exit timeout paths now publish a
  versioned typed record consumed by the shared MS C profile reader. No guessing
  from prose/exit code 3; malformed transport fails explicitly.
- Before: new profile control failed. After: 135 focused tests pass in 60.23s;
  scoped MyPy/new-code Ruff and ownership checks pass. Quality-dev exits 2 on
  broader lint/type debt. `.cache/cli-terminal-timeout-*.log` retains evidence.
- The live one-second probe exits 3 with the structured timeout record. This
  verifies transport, not a decompilation witness. Routine deadlines and the
  full coverage acceptance obligations remain unchanged; DOS execution remains
  unavailable in the last actual compiler probe.
## Lint debt: dce.py cleanup (2026-09-26)

- `angr_platforms/X86_16/postprocess/optimization/dce.py`: Ruff complexity
  debt cleared to zero (was 14 findings incl. the 424-complexity state-class
  conversion landed earlier this thread; this session extracted purity arm
  helpers `_dirty/_cvariable/_call/_indexed/_typecast/_binary_value_purity_8616`,
  `_expr_value_purity_dispatch_8616`, debug-shape/pair formatters, statement
  walk/read/protected-key helpers, and the part5 debug/fixpoint lanes).
- Fixed converter fallout: `run_8616_part5` returned a bare `bool` where the
  phase runner unpacks `(done, value)` (now `return True, self.changed`);
  `__slots__`/`__init__` dropped method-name collisions; `for self._` loop
  var removed.
- Verified: ruff 0, mypy 0, 125 dce tests pass, zero architecture violations
  against this file.
## Lint debt: cli_interrupt_modeling.py cleanup (2026-09-26)

- `inertia_decompiler/cli_interrupt_modeling.py`: Ruff complexity debt
  cleared to zero (11 findings). Extracted arg-slot mapping, mirror-write
  table for x/h register views, int21/int10 service-call builders,
  helper-arg collection, shared `_interrupt_wrapper_callee_name` boundary
  resolver (replaced 3 copies), byte-extract builders, dos_version rebuild,
  hoisted `visit` into `_visit_wrapper_result_node` + per-statement lanes,
  and DOS pseudo-callee collection helpers.
- Verified: ruff 0, mypy 0, 58 interrupt/helper-modeling tests pass, zero
  architecture violations against the file.
