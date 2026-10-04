# Careful audit of Basta's 52 unused-file candidates

Scope: the 52 findings reproduced on 2026-09-29 before this audit's two removals.
Basta 0.3.0's confidence is static reachability evidence, not permission to delete.
Candidate modules, imports, exports, docstrings, admission records, selected public
symbols, dynamic CLI/package loaders and active optimization registration were reviewed.

The bounded source pass visited 2,663 Python files listed by `rg --files -g '*.py'`.
Five parse failures were intentionally invalid generated `pytest-of-xor` fixtures;
no candidate source failed parsing. Generated caches, ignored trees, external plugins,
and arbitrary computed runtime imports are outside the static absence claims.
Relative imports and `from package import module` were checked using the AST.
Substring matches were followed up in source; e.g. root `address_ir` is not
`ir/address_ir`, and `collect_x86_16_tail_validation_summary` is not an invocation
of the separate `validation_summary` module.

Graph evidence: project `home-xor-vextest`, generation `2026-09-29T18:12:26Z`.
All 52 candidate paths had no recorded coverage issue, but this is best effort.
Broader scope gaps cover generated caches and binary fixtures. `query_graph` was
blocked by the tool approval policy; targeted `search_graph` and both-direction
traces worked, with source fallback used for the complete candidate list.
The graph reported no callers for the old value-flow pass or alternate validation
aggregator; source import/symbol checks corroborated those particular absences.

## What the findings actually mean

- **27 files in unwired proof/export chains**.
- **10 compatibility modules**.
- **4 test/reporting utilities**.
- **5 isolated implementations needing a keep/remove decision**.
- **2 explicitly gated prototypes**.
- **2 removed cleanup implementations**.
- **2 disabled fallback guards**.

After removing two private, uncalled cleanup implementations, 50 findings remain:
10 at Basta's 95% level and 40 test-only at its 70% level. Compatibility, explicit
prototypes, disabled fallback guards and tested nonpublishing proofs remain.
There is no basis for deleting the remaining list wholesale.

The older claim that every 95% candidate had only test/manifest references was too
broad: several have no function-level test at all, while some wrappers are consumed
by dynamic/header/admission checks. The old document's claim of no scripts finding
was also incorrect: the generated-unit compatibility shim is reported.

## Where integration would help

1. **Near scaled returns**: `ir/stack_argument_scaled_return` →
   `lowering/near_scaled_return_candidate` → `lowering/near_return_c_ast_congruence`
   has tests and a documented production gap in [compiler-coverage-plan.md](compiler-coverage-plan.md).
   The current plan ties that gap to the pointer-return compiler blocker. The owning
   Lowering publisher must join input-space/segment preservation and exact caller
   pointer-use evidence, then update input/body/return/caller types atomically.
   Arithmetic congruence alone cannot justify a pointer type. This audit did not
   reproduce the plan's game/compiler replay or claim a semantic fix.
2. **Entry-stack values**: Alias byte captures → Widening word/transport proofs
   are a connected chain, not dead independent utilities. An eventual consumer
   must retain raw-artifact identity, initial-entry scope and exact definition sites.
   Transport is restricted to an acyclic cone and is not a frame/return/callee proof.
3. **Far returns/callbacks**: keep the paired-use census, expression preflight,
   segment-entry lineage and callback grouping. Connect only after independent
   pointee/segment/ABI obligations and a closed caller inventory can be consumed
   by Types/Lowering. A caller dereference width does not prove input pointee type.
4. **Bounded globals/storage export**: the bounded-range producer and segmented
   storage-map exporter are tested but lack a production consumer. Wire at
   Widening/output-export respectively, using proved ranges/layouts/alias seeds;
   do not supply default extents or revive source-evidence fallback.

Do not wire `pipeline/linear_guard` as a semantic safeguard: it matches `repr`
substrings. Do not add the old cleanup copy-propagation implementation to Rewrite:
the active optimization registry already invokes Widening's owned implementation.

## Per-file evidence

Paths without a repository prefix are relative to
`angr_platforms/angr_platforms/X86_16/`. Import counts below distinguish non-test
import sites from test sites. A non-test importer inside another candidate module
is a proof-chain dependency, **not** evidence of production reachability. Counts
are from the pre-removal source snapshot; removed paths are retained as audit history.

| File | Decision | Non-test / test import sites | Rationale and representative evidence |
| --- | --- | --- | --- |
| [alias/entry_stack_byte_contracts.py](../angr_platforms/angr_platforms/X86_16/alias/entry_stack_byte_contracts.py) | Unwired proof/export chain | 4 / 5 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_stack_bytes.py](../angr_platforms/angr_platforms/X86_16/alias/entry_stack_bytes.py:43). |
| [alias/entry_stack_bytes.py](../angr_platforms/angr_platforms/X86_16/alias/entry_stack_bytes.py) | Unwired proof/export chain | 1 / 9 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_stack_word_values.py](../angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_values.py:19). |
| [alias/entry_stack_pointer_snapshots.py](../angr_platforms/angr_platforms/X86_16/alias/entry_stack_pointer_snapshots.py) | Unwired proof/export chain | 1 / 1 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_stack_bytes.py](../angr_platforms/angr_platforms/X86_16/alias/entry_stack_bytes.py:51). |
| [alias/stack_lowering.py](../angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py) | Compatibility | 0 / 1 | Legacy bridge to lowering.stack_lowering; existing compatibility test. [test_x86_16_alias_stack_lowering.py](../angr_platforms/tests/test_x86_16_alias_stack_lowering.py:3). |
| [cod_comment_emitter.py](../angr_platforms/angr_platforms/X86_16/cod_comment_emitter.py) | Test/reporting utility | 0 / 1 | Tested optional comment formatter; no production consumer. Reporting only, never proof. [test_cod_metadata_output_policy.py](../angr_platforms/tests/test_cod_metadata_output_policy.py:5). |
| [fast_tracer.py](../angr_platforms/angr_platforms/X86_16/fast_tracer.py) | Test/reporting utility | 0 / 1 | Tested optional entry-candidate tracer; no production consumer. Needs validated discovery admission. [test_x86_16_cli.py](../angr_platforms/tests/test_x86_16_cli.py:34). |
| [ir/address_ir.py](../angr_platforms/angr_platforms/X86_16/ir/address_ir.py) | Compatibility | 0 / 0 | Re-exports root address_ir and ir.core; layer-header test reads this path. No static importer; see reviewed module/header/registry references. |
| [ir/direct_call_segment_entry.py](../angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry.py) | Unwired proof/export chain | 0 / 3 | Project-owned DS=SS call-entry candidate; publishes no callee state or preservation proof. [test_x86_16_direct_call_segment_entry.py](../angr_platforms/tests/test_x86_16_direct_call_segment_entry.py:44). |
| [ir/direct_call_segment_entry_binding.py](../angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry_binding.py) | Unwired proof/export chain | 1 / 0 | Project-owned DS=SS call-entry candidate; publishes no callee state or preservation proof. [direct_call_segment_entry.py](../angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry.py:29). |
| [ir/effects.py](../angr_platforms/angr_platforms/X86_16/ir/effects.py) | Isolated implementation | 0 / 0 | Unused alternate effect records; active IR effects are owned by ir.core and dedicated semantic contracts. No static importer; see reviewed module/header/registry references. |
| [ir/ir_canonicalize_8616.py](../angr_platforms/angr_platforms/X86_16/ir/ir_canonicalize_8616.py) | Explicit prototype | 0 / 2 | Explicit TEST_ONLY_PROTOTYPE in layer_module_status; distinct from active validation.canonicalize. [test_x86_16_condition_full_width_masks.py](../angr_platforms/tests/test_x86_16_condition_full_width_masks.py:15). |
| [ir/scalar_instruction_effects.py](../angr_platforms/angr_platforms/X86_16/ir/scalar_instruction_effects.py) | Unwired proof/export chain | 2 / 6 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_stack_word_values.py](../angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_values.py:21). |
| [ir/stack_argument_scaled_return.py](../angr_platforms/angr_platforms/X86_16/ir/stack_argument_scaled_return.py) | Unwired proof/export chain | 3 / 3 | Near/far return proof/preflight chain; pointer type, segment binding, pointee and atomic C publication remain separate. [far_return_expression_binding.py](../angr_platforms/angr_platforms/X86_16/lowering/far_return_expression_binding.py:33). |
| [ir/value_ir.py](../angr_platforms/angr_platforms/X86_16/ir/value_ir.py) | Isolated implementation | 0 / 0 | Uncalled build_value_ir_8616 convenience constructor; layer-header test requires the module. No static importer; see reviewed module/header/registry references. |
| [ir/vex_operation_membership.py](../angr_platforms/angr_platforms/X86_16/ir/vex_operation_membership.py) | Unwired proof/export chain | 1 / 0 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_stack_bytes.py](../angr_platforms/angr_platforms/X86_16/alias/entry_stack_bytes.py:39). |
| [layer_module_status.py](../angr_platforms/angr_platforms/X86_16/layer_module_status.py) | Test/reporting utility | 0 / 2 | Admission metadata consumed by architecture tests; absence of runtime callers is intentional. [test_x86_16_layer_boundaries.py](../angr_platforms/tests/test_x86_16_layer_boundaries.py:9). |
| [lowering/far_callback_call_shape.py](../angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_shape.py) | Unwired proof/export chain | 0 / 1 | Publisher tested in isolation; production needs exact physical push/ABI/caller-object join. [test_x86_16_far_callback_call_shape.py](../angr_platforms/tests/test_x86_16_far_callback_call_shape.py:12). |
| [lowering/far_return_expression_binding.py](../angr_platforms/angr_platforms/X86_16/lowering/far_return_expression_binding.py) | Unwired proof/export chain | 0 / 1 | Near/far return proof/preflight chain; pointer type, segment binding, pointee and atomic C publication remain separate. [test_x86_16_far_return_expression_binding.py](../angr_platforms/tests/test_x86_16_far_return_expression_binding.py:19). |
| [lowering/far_return_pointer_census.py](../angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_census.py) | Unwired proof/export chain | 0 / 2 | Near/far return proof/preflight chain; pointer type, segment binding, pointee and atomic C publication remain separate. [test_x86_16_far_return_pointer_census_collection.py](../angr_platforms/tests/test_x86_16_far_return_pointer_census_collection.py:10). |
| [lowering/far_return_pointer_use.py](../angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use.py) | Unwired proof/export chain | 1 / 1 | Near/far return proof/preflight chain; pointer type, segment binding, pointee and atomic C publication remain separate. [far_return_pointer_census.py](../angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_census.py:32). |
| [lowering/far_return_pointer_use_contracts.py](../angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use_contracts.py) | Unwired proof/export chain | 2 / 0 | Near/far return proof/preflight chain; pointer type, segment binding, pointee and atomic C publication remain separate. [far_return_pointer_census.py](../angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_census.py:33). |
| [lowering/near_return_c_ast_congruence.py](../angr_platforms/angr_platforms/X86_16/lowering/near_return_c_ast_congruence.py) | Unwired proof/export chain | 0 / 1 | Near/far return proof/preflight chain; pointer type, segment binding, pointee and atomic C publication remain separate. [test_x86_16_near_return_c_ast_congruence.py](../angr_platforms/tests/test_x86_16_near_return_c_ast_congruence.py:37). |
| [lowering/near_scaled_return_candidate.py](../angr_platforms/angr_platforms/X86_16/lowering/near_scaled_return_candidate.py) | Unwired proof/export chain | 1 / 2 | Near/far return proof/preflight chain; pointer type, segment binding, pointee and atomic C publication remain separate. [near_return_c_ast_congruence.py](../angr_platforms/angr_platforms/X86_16/lowering/near_return_c_ast_congruence.py:31). |
| [pipeline/linear_guard.py](../angr_platforms/angr_platforms/X86_16/pipeline/linear_guard.py) | Isolated implementation | 0 / 0 | No caller found. Checks repr substrings, so it must not be wired as typed segmented-memory proof. No static importer; see reviewed module/header/registry references. |
| [postprocess/cleanup.py](../angr_platforms/angr_platforms/X86_16/postprocess/cleanup.py) | Compatibility | 0 / 0 | Explicit COMPATIBILITY_WRAPPER; reserved empty module; admission/header tests require it. No static importer; see reviewed module/header/registry references. |
| `postprocess/optimization/copy_prop.py` (removed) | Removed | 0 / 0 | Removed: no importer/caller/function test. Active pass_driver uses widening.widening_copyprop_8616. No static importer; see reviewed module/header/registry references. |
| [postprocess/simplify.py](../angr_platforms/angr_platforms/X86_16/postprocess/simplify.py) | Compatibility | 0 / 0 | Explicit compatibility wrapper for decompiler_postprocess_simplify. No static importer; see reviewed module/header/registry references. |
| `postprocess/value_flow.py` (removed) | Removed | 0 / 0 | Removed: no importer/caller/function test. Only inventory/header-fixture references found; not an active pass. No static importer; see reviewed module/header/registry references. |
| [quality.py](../angr_platforms/angr_platforms/X86_16/quality.py) | Compatibility | 0 / 2 | Compatibility exports backed by inertia_decompiler.acceptance_scorecard. [test_decompilation_quality.py](../angr_platforms/tests/test_decompilation_quality.py:194). |
| [recompilable_source_evidence.py](../angr_platforms/angr_platforms/X86_16/recompilable_source_evidence.py) | Disabled guard | 0 / 1 | Inert historical source-evidence API; must not become source-backed recovery. [test_x86_16_recompilable_source_evidence.py](../angr_platforms/tests/test_x86_16_recompilable_source_evidence.py:4). |
| [recompilable_storage_alias.py](../angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py) | Unwired proof/export chain | 0 / 1 | Alias/codegen seeds → storage rows; exporter is not called by production output assembly. [test_x86_16_recompilable_storage_map.py](../angr_platforms/tests/test_x86_16_recompilable_storage_map.py:9). |
| [recompilable_storage_fallback.py](../angr_platforms/angr_platforms/X86_16/recompilable_storage_fallback.py) | Disabled guard | 0 / 1 | Explicitly disabled selector: use_fallback remains False; refusal test verifies this. [test_x86_16_recompilable_storage_objects.py](../angr_platforms/tests/test_x86_16_recompilable_storage_objects.py:6). |
| [recompilable_storage_map.py](../angr_platforms/angr_platforms/X86_16/recompilable_storage_map.py) | Unwired proof/export chain | 2 / 1 | Alias/codegen seeds → storage rows; exporter is not called by production output assembly. [recompilable_storage_alias.py](../angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py:12). |
| [recompilable_storage_map_producer.py](../angr_platforms/angr_platforms/X86_16/recompilable_storage_map_producer.py) | Unwired proof/export chain | 1 / 1 | Alias/codegen seeds → storage rows; exporter is not called by production output assembly. [recompilable_storage_alias.py](../angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py:13). |
| [semantics/flag_semantics.py](../angr_platforms/angr_platforms/X86_16/semantics/flag_semantics.py) | Compatibility | 0 / 1 | Exports active condition/ALU owners; semantics-export test consumes it. [test_x86_16_semantics_exports.py](../angr_platforms/tests/test_x86_16_semantics_exports.py:4). |
| [semantics/memory_semantics.py](../angr_platforms/angr_platforms/X86_16/semantics/memory_semantics.py) | Compatibility | 0 / 1 | Exports active callsite/function-effect owners; semantics-export test consumes it. [test_x86_16_semantics_exports.py](../angr_platforms/tests/test_x86_16_semantics_exports.py:4). |
| [structured_function_helpers.py](../angr_platforms/angr_platforms/X86_16/structured_function_helpers.py) | Isolated implementation | 0 / 0 | No renderer consumer or function test found. Whole helper rendering needs binary-derived validation before admission. No static importer; see reviewed module/header/registry references. |
| [structuring/control_flow.py](../angr_platforms/angr_platforms/X86_16/structuring/control_flow.py) | Compatibility | 0 / 0 | Explicit compatibility exports for decompiler_structuring_stage. No static importer; see reviewed module/header/registry references. |
| [structuring/loop_recovery.py](../angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py) | Explicit prototype | 0 / 1 | Explicit TEST_ONLY_PROTOTYPE; metadata-only, unlike active simple_loop_recovery. [test_x86_16_loop_recovery.py](../angr_platforms/tests/test_x86_16_loop_recovery.py:7). |
| [validation_summary.py](../angr_platforms/angr_platforms/X86_16/validation_summary.py) | Isolated implementation | 0 / 0 | Unconsumed alternate ValidationRecord/aggregate API; cache provenance names the file. Not the active tail-validation collector. No static importer; see reviewed module/header/registry references. |
| [widening/entry_stack_word_bits.py](../angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_bits.py) | Unwired proof/export chain | 2 / 1 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_stack_word_value_contracts.py](../angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_value_contracts.py:23). |
| [widening/entry_stack_word_value_contracts.py](../angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_value_contracts.py) | Unwired proof/export chain | 4 / 5 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_stack_word_values.py](../angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_values.py:43). |
| [widening/entry_stack_word_values.py](../angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_values.py) | Unwired proof/export chain | 1 / 6 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_word_transport.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py:28). |
| [widening/entry_word_transport.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py) | Unwired proof/export chain | 0 / 5 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [test_x86_16_entry_word_transport.py](../angr_platforms/tests/test_x86_16_entry_word_transport.py:26). |
| [widening/entry_word_transport_contracts.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_contracts.py) | Unwired proof/export chain | 7 / 5 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_word_transport.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py:29). |
| [widening/entry_word_transport_flow.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_flow.py) | Unwired proof/export chain | 1 / 0 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_word_transport.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py:40). |
| [widening/entry_word_transport_snapshots.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_snapshots.py) | Unwired proof/export chain | 1 / 1 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_word_transport_state.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_state.py:39). |
| [widening/entry_word_transport_state.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_state.py) | Unwired proof/export chain | 1 / 2 | Entry-byte → word → acyclic transport proof chain; no output admission. Keep exact scope and raw-IR identity. [entry_word_transport.py](../angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py:44). |
| [widening/indexed_global_object_range_recovery.py](../angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_recovery.py) | Unwired proof/export chain | 0 / 1 | Bounded object-range producer called only through test fixture; needs proven loop bounds/layout join at Widening. [x86_16_indexed_global_object_range_fixtures.py](../angr_platforms/tests/x86_16_indexed_global_object_range_fixtures.py:68). |
| [scripts/generated_translation_unit_assembly.py](../scripts/generated_translation_unit_assembly.py) | Compatibility | 0 / 1 | Compatibility exports for the active CLI unit assembler; gate test consumes it. [test_generated_translation_unit_assembly.py](../angr_platforms/tests/test_generated_translation_unit_assembly.py:14). |
| [inertia_decompiler/packer_detect.py](../inertia_decompiler/packer_detect.py) | Compatibility | 0 / 0 | Documented historical API backed by frontend packed_mz; no repository caller found. No static importer; see reviewed module/header/registry references. |
| [inertia_decompiler/source_sidecar.py](../inertia_decompiler/source_sidecar.py) | Test/reporting utility | 0 / 3 | Used by three test modules for optional display labels; not a recovery consumer. [test_source_sidecar.py](../angr_platforms/tests/test_source_sidecar.py:7). |
## Changes and verification

- Removed `postprocess/optimization/copy_prop.py` and `postprocess/value_flow.py`:
  no imports, caller sites or behavior tests found in the reviewed source; public
  entry loaders do not enumerate them. Lint inventories and architecture path lists
  were updated. Existing generic fixture checks were preserved.
- Corrected the documentation table to match the existing typed admission registry:
  `validation.canonicalize` is production-wired, `quality` is a compatibility wrapper,
  and `postprocess.cleanup` is reserved and empty. No admission status was changed.
- Retained-prototype/admission checks: 73 tests passed across six focused files.
- Post-removal active Widening copy-propagation and postprocess architecture regressions: 61 passed.
- Ruff on the changed architecture checker and startup architecture checks passed.
- Final Basta run: 50 findings in 2,418 files; analyzer reported 6.75 seconds.

No semantic prototype was admitted, no proof scope was widened, and no blanket
Basta exclusion was added. The analyzer's final report remains available through
`make unused-python-files`.
