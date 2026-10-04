PYTHON ?= python
PYTHON_JIT ?= 1
export PYTHON_JIT
PYTHONHASHSEED ?= 0
export PYTHONHASHSEED
Q ?= @
MAKEFLAGS += --no-print-directory
TIMEOUT ?= timeout
PYRIGHT_DCE_TIMEOUT ?= 600
FILES ?=
CPU_COUNT ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)
PARALLEL_JOBS ?= $(shell count=$(CPU_COUNT); if [ "$$count" -gt 1 ]; then expr "$$count" - 1; else echo 1; fi)
PYRIGHT_WATCH ?= $(if $(CI),0,1)
PYRIGHT_STATS ?= 0
RUFF_OUTPUT_FLAGS ?= --quiet --output-format concise
MYPY_OUTPUT_FLAGS ?= --no-pretty --no-color-output --no-error-summary
PYRIGHT_OUTPUT_FLAGS ?= --level warning
PYTEST_OUTPUT_FLAGS ?= --tb=short --no-header
LIZARD_OUTPUT_FLAGS ?= --warnings_only
PYTEST_WORKERS ?= 3
# More concurrent wall-budgeted solvers caused avoidable refusals on the shared
# host. Keep serial requests serial; callers may explicitly override this cap.
COMPARATOR_PYTEST_WORKERS ?= $(if $(filter 1,$(PYTEST_WORKERS)),1,2)
PYTEST_ARGS ?= $(PYTEST_OUTPUT_FLAGS) -p scripts.pytest_directory_cache -n $(PYTEST_WORKERS) --dist loadgroup --durations=5
PYTEST_FOCUSED_MARKER_EXPR ?= not repository_contract
PYTEST_PROFILE_ARGS ?= -q $(PYTEST_OUTPUT_FLAGS) -n $(PYTEST_WORKERS) --dist loadgroup --durations=25
PYTEST_PROFILE_JSON ?= .cache/pytest/profile.json
PYTEST_PROFILE_TARGETS ?= $(QA_PYTEST_TARGETS)
PYTEST_INVENTORY_JSON ?= .cache/pytest/collection-inventory.json
PYTEST_ALL_WORKERS ?= $(PYTEST_WORKERS)
PYTEST_ALL_HEAVY_WORKERS ?= $(if $(filter 1,$(PYTEST_ALL_WORKERS)),1,2)
PYTEST_ALL_HEAVY_SHARDS ?= 16
PYTEST_ALL_MAX_RSS_MIB ?= 2048
PYTEST_ALL_SUMMARY_JSON ?= .cache/pytest/partitioned-summary.json
FOCUSED_TEST_DECOMPILE_TIMEOUT_SCALE ?= 1.5
FULL_TEST_DECOMPILE_TIMEOUT_SCALE ?= 4
AGENT_TEST_JSON ?=
AGENT_TEST_JSON_ONLY ?=
ifeq ($(strip $(PYRIGHT_WATCH)),1)
PYRIGHT_WATCH_FLAG := --watch
endif
ifeq ($(strip $(PYRIGHT_STATS)),1)
PYRIGHT_STATS_FLAG := --stats
endif
PYRIGHT_PYTHON_PATH := $(shell $(PYTHON) -c 'import sys; print(sys.executable)')
PYRIGHT_CMD_BASE := $(PYTHON) -m pyright $(PYRIGHT_OUTPUT_FLAGS) --pythonpath $(PYRIGHT_PYTHON_PATH) $(PYRIGHT_STATS_FLAG) $(PYRIGHT_WATCH_FLAG)
PY_FILES_ALL := $(shell git ls-files '*.py')
PY_FILES := $(filter %.py,$(FILES))
PYTEST_FILES := $(filter angr_platforms/tests/%.py tests/%.py,$(PY_FILES))
PY_CHANGED_FILES := $(shell { git diff --name-only -- '*.py'; git ls-files --others --exclude-standard -- '*.py'; } | sort -u)
LINT_JOBS ?= $(PARALLEL_JOBS)
MYPYC_JOBS ?= $(PARALLEL_JOBS)
MYPYC_ARTIFACT_LOCK ?= $(CURDIR)/.cache/locks/mypyc-artifacts.lock
TEST_PIPELINE_LOCK ?= $(CURDIR)/.cache/locks/test-pipeline.lock
PIPELINE_WORKERS ?= $(PARALLEL_JOBS)
INERTIA_ALLOW_PARALLEL_MSC6_WORKERS ?= 1
export INERTIA_ALLOW_PARALLEL_MSC6_WORKERS
LINTERS_DEV_MYPY_FILES ?= \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_inventory.py \
	angr_platforms/angr_platforms/X86_16/lowering/codegen_return_origin.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_restore_state.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_definition_return.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_local_return.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_local_reload.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_allocation.py \
	angr_platforms/angr_platforms/X86_16/ir/register_live_in.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_object_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_call_results.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_semantic_gap.py \
	angr_platforms/angr_platforms/X86_16/ir/function_ir_registry.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_register_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_status_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_constant_flow.py \
	inertia_decompiler/cache.py \
	inertia_decompiler/cache_file_digest.py \
	inertia_decompiler/cache_source_manifest.py \
	inertia_decompiler/function_ir_ssa_source_scope.py \
	inertia_decompiler/decompile_file_summary.py \
	inertia_decompiler/direct_indexed_alias_local_cache.py \
	inertia_decompiler/indexed_alias_program_context.py \
	inertia_decompiler/indexed_alias_program_parallel.py \
	inertia_decompiler/program_callsite_cache.py \
	inertia_decompiler/project_argument_evidence_ranges.py \
	inertia_decompiler/indexed_global_object_cache.py \
	inertia_decompiler/serial_clean_worker_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_seeding.py \
	angr_platforms/angr_platforms/X86_16/lowering/helper_call_interfaces.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_constant_segmented_store.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/authoritative_function_prototypes.py \
	angr_platforms/angr_platforms/X86_16/lowering/positive_bp_argument_plan.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_return_address_arguments.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_consumer_generation.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_local_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_variable_identity.py \
	angr_platforms/angr_platforms/X86_16/frontend_caller_return_use_program.py \
	angr_platforms/angr_platforms/X86_16/frontend_direct_callsite_index.py \
	angr_platforms/angr_platforms/X86_16/pipeline/result_contracts.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_assignment_index.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_ast_query_index.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_validation_policy.py \
	angr_platforms/angr_platforms/X86_16/postprocess/bootstrap_orchestration.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_runtime.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_transaction.py \
	angr_platforms/angr_platforms/X86_16/postprocess/runtime_configuration.py \
	angr_platforms/angr_platforms/X86_16/postprocess/rollback_snapshot_cache.py \
	angr_platforms/angr_platforms/X86_16/postprocess/validation_contracts.py \
	angr_platforms/angr_platforms/X86_16/validation/control_flow_ast_index.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_address_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_storage_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/linear_global_decomposition_cache.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_return_expressions.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_return_render_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_call_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_values.py \
	angr_platforms/angr_platforms/X86_16/lowering/unused_void_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_saved_frame.py \
	angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_coordinate_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/instruction_bp_stack_access.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_coordinate_rebinding.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/machine_stack_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_function_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_display_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_candidate.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_layout.py \
	angr_platforms/angr_platforms/X86_16/msvc_x87_interrupts.py \
	angr_platforms/angr_platforms/X86_16/structured_tags.py \
	angr_platforms/angr_platforms/X86_16/structuring/boolean_condition_ites.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/bound_call_condition.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_register_index.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_register_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_store_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_call_result_aliases.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_return_early_exit.py \
	angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_frame_spills.py \
	angr_platforms/angr_platforms/X86_16/validation_call_return_storage.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape_publication.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_arity_ownership.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_expression.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_semantic_token.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_bindings.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_stores.py \
	angr_platforms/angr_platforms/X86_16/validation_calls.py \
	angr_platforms/angr_platforms/X86_16/validation_call_multiplicity.py \
	angr_platforms/angr_platforms/X86_16/validation_dataflow.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_liveness_replay.py \
	angr_platforms/angr_platforms/X86_16/validation_predicates.py \
	angr_platforms/angr_platforms/X86_16/validation_control_flow.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_storage_views.py \
	angr_platforms/angr_platforms/X86_16/validation_required_memory_effects.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_codec.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_codec.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_program.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_program_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_range_callsite_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_callee_callsite_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_object_source_collection.py \
	angr_platforms/angr_platforms/X86_16/caller_return_use_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_census.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_count_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_width_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/block_ownership.py \
	angr_platforms/angr_platforms/X86_16/ir/block_successor_chain.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_fingerprint_masks.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_fingerprint_syntax.py \
	angr_platforms/angr_platforms/X86_16/ir/function_ssa_registry.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_object_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_validation.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_function_solver.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_paths.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_slot_join.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_pipeline.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_application.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_source_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_condition_graph.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_caller_context.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_block.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_stack.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_witness.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_expression_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_target_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_targets.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_type_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_physical_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_input_preflight.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_solver.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_simtypes.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_transaction.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_type_surface.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_interface.py \
	angr_platforms/angr_platforms/X86_16/function_evidence_inventory.py \
	angr_platforms/angr_platforms/X86_16/helper_abi.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_index_binding.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_type.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_stack_storage.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_ast.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_placement.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignments.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_destinations.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_sources.py \
	angr_platforms/angr_platforms/X86_16/alias/partial_register_address_break.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_classification.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_program.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/storage_fact_join.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_outputs.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/function_condition_artifact.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_lift_capture.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_cache.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_cfg.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_cfg_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_pipeline.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidate_helpers.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_induction_write_census.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidates.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_witnesses.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_write_value.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_constant_word_receipt.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_word_call_window.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_word_call_binding.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_definitions.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_sources.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/affine_indexed_address.py \
	angr_platforms/angr_platforms/X86_16/ir/affine_induction_role.py \
	angr_platforms/angr_platforms/X86_16/ir/frame_register_reaching_definition.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_collector_parity.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/bounded_global_array_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_declaration_extents.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_cfg.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_links.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_ssa.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_pipeline.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_provenance.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_outputs.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_pipeline.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_storage.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_values.py \
	angr_platforms/angr_platforms/X86_16/widening/global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/widening/global_object_layout_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_range_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_ranges.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_layouts.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_recovery.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_solver.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_ranges.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_word_register_transfers.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_memory_output_views.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_views.py

LINTERS_DEV_MYPY_FILES += \
	inertia_decompiler/accepted_payload_integrity.py \
	inertia_decompiler/angr_codegen_tags.py \
	angr_platforms/angr_platforms/X86_16/borrow_verification.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_bindings.py \
	angr_platforms/angr_platforms/X86_16/callsite_register_instruction_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/consumed_call_push_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_instruction_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_branch_carriers.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_joins.py \
	angr_platforms/angr_platforms/X86_16/verification_80386.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_carrier_liveness.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_frame.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_register_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_projections.py \
	angr_platforms/angr_platforms/X86_16/callsite_setup_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/consumed_stack_address_setup.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_entry_overwrite.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_value_preservation.py \
	angr_platforms/angr_platforms/X86_16/synthetic_call_stub_evidence.py

LINTERS_DEV_LIZARD_PATHS ?= inertia_decompiler/decompile_file_summary.py
BASTA ?= npx --yes basta@0.3.0

.PHONY: quality quality-dev quality-fast quality-hard decompiler-check decompiler-check-fast decompiler-check-expanded architecture-check architecture-check-fast agent-context-check test-ownership-check linters linters-hard linters-dev linters-dev-locked linters-files check-files check-all pytest pytest-profile pytest-inventory pytest-inventory-check pytest-files pytest-all ruff ruff-files ruff-all pyright pyright-files pyright-all mypy mypy-dev mypy-files mypy-all mypyc mypyc-smoke type-ratchet-files type-ratchet-changed vulture unused-python-files lizard lizard-dev test-pipeline test-pipeline-fast test-pipeline-expanded test-layer test-agent-confidence msc6-examples sortdemo-selftest monkeytype-trace monkeytype-stubs monkeytype-apply decomp-opt-regression decomp-opt-regression-inputs decomp-opt-regression-suite decomp-opt-regression-thread types

quality: linters type-ratchet-changed decompiler-check decomp-opt-regression-suite

quality-dev: linters-dev type-ratchet-changed decompiler-check-fast decomp-opt-regression-suite

quality-fast: linters type-ratchet-changed decompiler-check-fast decomp-opt-regression-suite

# Hard local/per-PR gate: mandatory practical checks for in-flight development.
quality-hard: linters-hard type-ratchet-changed architecture-check decompiler-check-fast decomp-opt-regression-suite

decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline

decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check test-pipeline-fast

decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded

linters:
	# Keep one bounded job per independent linter.
	$(MAKE) -j$(LINT_JOBS) ruff mypy mypyc vulture unused-python-files lizard PYTHON="$(PYTHON)"

linters-dev:
	# Hard local gate: practical and reproducible per file-level mypyc scope.
	$(MAKE) -j$(LINT_JOBS) ruff mypy-dev mypyc vulture unused-python-files lizard-dev PYTHON="$(PYTHON)"

linters-dev-locked:
	# Serial for deterministic CI-noise-free smoke checks.
	$(MAKE) ruff mypy-dev mypyc vulture unused-python-files lizard-dev PYTHON="$(PYTHON)"

linters-hard:
	# Mandatory development hard gate.
	$(MAKE) linters-dev-locked

.PHONY: lint-iteration
lint-iteration:
	@test -n "$(strip $(FILES))" || { echo 'lint-iteration: explicit FILES required'; exit 2; }
	@if [ -n "$(strip $(PY_FILES))" ]; then \
		$(PYTHON) -m ruff check --fix $(RUFF_OUTPUT_FLAGS) $(PY_FILES) && \
		$(PYTHON) scripts/check_changed_non_test_types.py $(PY_FILES); \
	else \
		echo 'lint-iteration: no Python files selected'; \
	fi

linters-files:
	$(MAKE) ruff-files PYTHON="$(PYTHON)" FILES="$(FILES)"
	$(MAKE) -j$(LINT_JOBS) mypy-files type-ratchet-files PYTHON="$(PYTHON)" FILES="$(FILES)"

check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files

check-all: ruff-all pyright-all type-ratchet-changed architecture-check agent-context-check test-ownership-check pytest-all
	$(MAKE) ruff-all
	$(MAKE) pyright-all
	$(MAKE) mypy-all
	$(MAKE) mypyc
	$(MAKE) type-ratchet-changed architecture-check agent-context-check test-ownership-check pytest-all

QA_TYPED_FILES := \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_load_origins.py \
	angr_platforms/angr_platforms/X86_16/ir/instruction_origin.py \
	angr_platforms/angr_platforms/X86_16/ir/constant_flow.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_value_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_inventory.py \
	angr_platforms/angr_platforms/X86_16/lowering/codegen_return_origin.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_restore_state.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_definition_return.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_local_return.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_local_reload.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_allocation.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_call_preservation.py \
	angr_platforms/angr_platforms/X86_16/ir/register_live_in.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_object_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_call_results.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_semantic_gap.py \
	scripts/makefile_inventory.py \
	angr_platforms/angr_platforms/X86_16/ir/function_ir_registry.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_constant_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_register_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_carrier_liveness.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_frame.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_frame_arguments.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_register_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_projections.py \
	angr_platforms/angr_platforms/X86_16/callsite_setup_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/consumed_stack_address_setup.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_entry_overwrite.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_value_preservation.py \
	angr_platforms/angr_platforms/X86_16/synthetic_call_stub_evidence.py \
	monkeytype_config.py \
	angr_platforms/angr_platforms/X86_16/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias_domains.py \
	angr_platforms/angr_platforms/X86_16/alias_state.py \
	angr_platforms/angr_platforms/X86_16/alias_transfer.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model_impl.py \
	angr_platforms/angr_platforms/X86_16/alias/callsite_stack_merge.py \
	angr_platforms/angr_platforms/X86_16/alias/register_reaching_source.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_definition.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_register_expression.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_break_topology.py \
	angr_platforms/angr_platforms/X86_16/alias/partial_register_address_break.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_classification.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_program.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_liveness.py \
	angr_platforms/angr_platforms/X86_16/alias/domains.py \
	angr_platforms/angr_platforms/X86_16/alias/state.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/alias/segment_stack_fragments.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_pointer_snapshots.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_byte_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_bytes.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_pointer_snapshots.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_operation_membership.py \
	angr_platforms/tests/entry_stack_byte_test_support.py \
	angr_platforms/angr_platforms/X86_16/alias/segment_stack_restore.py \
	angr_platforms/angr_platforms/X86_16/alias/bp_preservation.py \
	angr_platforms/angr_platforms/X86_16/alias/logical_stack_memory_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_memory_access_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_address_escape.py \
	angr_platforms/angr_platforms/X86_16/alias/private_stack_writes.py \
	angr_platforms/angr_platforms/X86_16/alias/transfer.py \
	angr_platforms/angr_platforms/X86_16/analysis/__init__.py \
	angr_platforms/angr_platforms/X86_16/analysis/alias.py \
	angr_platforms/angr_platforms/X86_16/analysis/stack_frame_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/frame_memory_accesses.py \
	angr_platforms/angr_platforms/X86_16/analysis_helpers.py \
	angr_platforms/angr_platforms/X86_16/arch_86_16.py \
	angr_platforms/angr_platforms/X86_16/access.py \
	angr_platforms/angr_platforms/X86_16/addressing_helpers.py \
	angr_platforms/angr_platforms/X86_16/capstone_memory_segment.py \
	angr_platforms/angr_platforms/X86_16/decoded_memory_width.py \
	angr_platforms/angr_platforms/X86_16/address_ir.py \
	angr_platforms/angr_platforms/X86_16/alu_helpers.py \
	angr_platforms/angr_platforms/X86_16/annotations.py \
	angr_platforms/angr_platforms/X86_16/borrow_verification.py \
	angr_platforms/angr_platforms/X86_16/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/condition_trace.py \
	angr_platforms/angr_platforms/X86_16/condition_call_effects.py \
	angr_platforms/angr_platforms/X86_16/function_evidence_inventory.py \
	angr_platforms/angr_platforms/X86_16/helper_abi.py \
	angr_platforms/angr_platforms/X86_16/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/__init__.py \
	angr_platforms/angr_platforms/X86_16/ir/address_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_register_bindings.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_value_extensions.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_fingerprint_masks.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_fingerprint_syntax.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/core.py \
	angr_platforms/angr_platforms/X86_16/ir/block_ownership.py \
	angr_platforms/angr_platforms/X86_16/ir/block_successor_chain.py \
	angr_platforms/angr_platforms/X86_16/ir/effects.py \
	angr_platforms/angr_platforms/X86_16/ir/function_artifact.py \
	angr_platforms/angr_platforms/X86_16/ir/function_condition_artifact.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_lift_capture.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_access_normalization.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_pipeline.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidate_helpers.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_induction_write_census.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidates.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_witnesses.py \
	angr_platforms/angr_platforms/X86_16/ir/ir_canonicalize_8616.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_capture.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_matching.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_rebase.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_resolution.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_value_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_write_value.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_constant_word_receipt.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_word_call_window.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_word_call_binding.py \
	angr_platforms/angr_platforms/X86_16/ir/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_definitions.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_sources.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/affine_indexed_address.py \
	angr_platforms/angr_platforms/X86_16/ir/affine_induction_role.py \
	angr_platforms/angr_platforms/X86_16/ir/frame_register_reaching_definition.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_binary_cfg.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_cfg_projection.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_lift_context.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_lift_codec.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_contract.py \
	angr_platforms/angr_platforms/X86_16/segment_function_summary.py \
	angr_platforms/angr_platforms/X86_16/segment_offset_execution.py \
	angr_platforms/angr_platforms/X86_16/segment_program_layout.py \
	angr_platforms/angr_platforms/X86_16/segment_program_layout_codec.py \
	angr_platforms/angr_platforms/X86_16/segment_program_layout_contract.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state_solver.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state_transfer.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_function.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_cfg.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_cfg_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory_call_liveness.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory_ranges.py \
	angr_platforms/angr_platforms/X86_16/ir/stack_range_overlap.py \
	angr_platforms/angr_platforms/X86_16/lowering/native_integer_constants.py \
	angr_platforms/angr_platforms/X86_16/lowering/native_integer_operations.py \
	angr_platforms/angr_platforms/X86_16/lowering/native_terminal_return_values.py \
	angr_platforms/angr_platforms/X86_16/ir/string_effects.py \
	angr_platforms/angr_platforms/X86_16/ir/value_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_addressing.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_demand.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_transport.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_control_flow.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_terminal_jump.py \
	angr_platforms/angr_platforms/X86_16/ir/entry_jump_domain.py \
	angr_platforms/angr_platforms/X86_16/ir/real16_invocation_domain.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_import.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_integer_displacement.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_bit_source.py \
	angr_platforms/angr_platforms/X86_16/direction_step.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_types.py \
	angr_platforms/angr_platforms/X86_16/function_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_family_routing.py \
	angr_platforms/angr_platforms/X86_16/function_interface_surface.py \
	angr_platforms/angr_platforms/X86_16/function_summary.py \
	angr_platforms/angr_platforms/X86_16/function_state_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_target_inventory.py \
	angr_platforms/angr_platforms/X86_16/semantics/callsite_summary_request.py \
	angr_platforms/angr_platforms/X86_16/caller_return_use_contracts.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_register_provenance.py \
	angr_platforms/angr_platforms/X86_16/register_source_block_inventory.py \
	angr_platforms/angr_platforms/X86_16/call_target_identity.py \
	angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py \
	angr_platforms/angr_platforms/X86_16/stack_probe_fact_trace.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_condition_context.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_frame_spills.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py \
	angr_platforms/angr_platforms/X86_16/validation_goto_target_identity.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_generation.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_generation_atoms.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_ast_generation.py \
	angr_platforms/angr_platforms/X86_16/pipeline/result_contracts.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_assignment_index.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_ast_query_index.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_validation_policy.py \
	angr_platforms/angr_platforms/X86_16/postprocess/bootstrap_orchestration.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_runtime.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_transaction.py \
	angr_platforms/angr_platforms/X86_16/postprocess/runtime_configuration.py \
	angr_platforms/angr_platforms/X86_16/postprocess/rollback_snapshot_cache.py \
	angr_platforms/angr_platforms/X86_16/postprocess/validation_contracts.py \
	angr_platforms/angr_platforms/X86_16/validation/control_flow_ast_index.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_routing.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_selector_returns.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_stack_policy.py \
	angr_platforms/angr_platforms/X86_16/targeted_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/layer_module_status.py \
	angr_platforms/angr_platforms/X86_16/coverage_manifest.py \
	angr_platforms/angr_platforms/X86_16/corpus_scan.py \
	angr_platforms/angr_platforms/X86_16/milestone_report.py \
	angr_platforms/angr_platforms/X86_16/exact_region_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/frontend_cfg_direct_jump.py \
	angr_platforms/angr_platforms/X86_16/frontend_cfg_direct_call.py \
	angr_platforms/angr_platforms/X86_16/frontend_cfg_direct_jobs.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_boundary.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_boundary_index.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_block_decode.py \
	angr_platforms/angr_platforms/X86_16/frontend_capstone_block.py \
	angr_platforms/angr_platforms/X86_16/frontend_block_inventory.py \
	angr_platforms/angr_platforms/X86_16/frontend_capstone_decode.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_instructions.py \
	angr_platforms/angr_platforms/X86_16/frontend_caller_return_use_program.py \
	angr_platforms/angr_platforms/X86_16/frontend_direct_callsite_index.py \
	angr_platforms/angr_platforms/X86_16/frontend_instruction_kinds.py \
	angr_platforms/angr_platforms/X86_16/frontend_instruction_reachability.py \
	angr_platforms/angr_platforms/X86_16/recovery_instruction_coverage.py \
	angr_platforms/angr_platforms/X86_16/flair_extract.py \
	angr_platforms/angr_platforms/X86_16/fast_tracer.py \
	angr_platforms/angr_platforms/X86_16/jcc_condition.py \
	angr_platforms/angr_platforms/X86_16/jcc_result_condition.py \
	angr_platforms/angr_platforms/X86_16/lift_86_16.py \
	angr_platforms/angr_platforms/X86_16/lifter_backend.py \
	angr_platforms/angr_platforms/X86_16/lifter_backend_selection.py \
	angr_platforms/angr_platforms/X86_16/semantics/status_flag_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/status_flag_cfg_liveness.py \
	angr_platforms/angr_platforms/X86_16/semantics/status_flag_liveness.py \
	angr_platforms/angr_platforms/X86_16/load_dos_mz.py \
	angr_platforms/angr_platforms/X86_16/load_dos_ne.py \
	angr_platforms/angr_platforms/X86_16/lst_extract.py \
	angr_platforms/angr_platforms/X86_16/ne_exe_parse.py \
	angr_platforms/angr_platforms/X86_16/ne_resources.py \
	angr_platforms/angr_platforms/X86_16/recovery_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifacts.py \
	angr_platforms/angr_platforms/X86_16/recovery_confidence.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_cache.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_writer.py \
	angr_platforms/angr_platforms/X86_16/corpus_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/confidence_and_assumptions.py \
	angr_platforms/angr_platforms/X86_16/ir_recovery_summary.py \
	angr_platforms/angr_platforms/X86_16/ir_readiness.py \
	angr_platforms/angr_platforms/X86_16/ir_confidence_markers.py \
	angr_platforms/angr_platforms/X86_16/runtime_trace_refinement.py \
	angr_platforms/angr_platforms/X86_16/structuring_ir_hints.py \
	angr_platforms/angr_platforms/X86_16/structuring_abnormal_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_analysis.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_indirect.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py \
	angr_platforms/angr_platforms/X86_16/structuring_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_snapshot.py \
	angr_platforms/angr_platforms/X86_16/structuring_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_region.py \
	angr_platforms/angr_platforms/X86_16/structuring_codegen.py \
	angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_pass.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_units.py \
	angr_platforms/angr_platforms/X86_16/structured_function_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_artifact.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_lowering.py \
	angr_platforms/angr_platforms/X86_16/string_codegen_override.py \
	angr_platforms/angr_platforms/X86_16/type_array_matching.py \
	angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py \
	angr_platforms/angr_platforms/X86_16/type_structure_merging.py \
	angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py \
	angr_platforms/angr_platforms/X86_16/bootstrap.py \
	angr_platforms/angr_platforms/X86_16/cod_comment_emitter.py \
	angr_platforms/angr_platforms/X86_16/cod_analysis_image.py \
	angr_platforms/angr_platforms/X86_16/cod_extract.py \
	angr_platforms/angr_platforms/X86_16/interrupt_contract.py \
	angr_platforms/angr_platforms/X86_16/cod_known_objects.py \
	angr_platforms/angr_platforms/X86_16/cod_source_rewrites.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb00.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb02_nb04.py \
	angr_platforms/angr_platforms/X86_16/codegen_metadata.py \
	angr_platforms/angr_platforms/X86_16/compiler_helpers.py \
	angr_platforms/angr_platforms/X86_16/cr.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_globals.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_utils.py \
	angr_platforms/angr_platforms/X86_16/compat.py \
	angr_platforms/angr_platforms/X86_16/call_frame_compat.py \
	angr_platforms/angr_platforms/X86_16/call_cleanup_compat.py \
	angr_platforms/angr_platforms/X86_16/ir/stack_pointer_provenance.py \
	angr_platforms/angr_platforms/X86_16/ir/stack_extent_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/ail_register_displacement.py \
	angr_platforms/angr_platforms/X86_16/ail_displacement_compat.py \
	angr_platforms/angr_platforms/X86_16/ail_remainder_compat.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_reference_offsets.py \
	angr_platforms/angr_platforms/X86_16/variable_recovery_compat.py \
	angr_platforms/angr_platforms/X86_16/ir/ail_remainder.py \
	angr_platforms/angr_platforms/X86_16/codegen_parentheses.py \
	angr_platforms/angr_platforms/X86_16/stack_anchor_compat.py \
	angr_platforms/angr_platforms/X86_16/ir/native_stack_anchor.py \
	angr_platforms/angr_platforms/X86_16/ir/native_segment_live_out.py \
	angr_platforms/angr_platforms/X86_16/lowering/store_projection_width.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_push_carrier.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_segment.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_return_contract.py \
	angr_platforms/angr_platforms/X86_16/calling_convention_compat.py \
	angr_platforms/angr_platforms/X86_16/calling_convention_seed_cache.py \
	angr_platforms/angr_platforms/X86_16/render_compat.py \
	angr_platforms/angr_platforms/X86_16/patch_dirty.py \
	angr_platforms/angr_platforms/X86_16/c_ast_utils.py \
	angr_platforms/angr_platforms/X86_16/callee_name_normalization.py \
	angr_platforms/angr_platforms/X86_16/low_memory_regions.py \
	angr_platforms/angr_platforms/X86_16/simos_86_16.py \
	angr_platforms/angr_platforms/X86_16/exception.py \
	angr_platforms/angr_platforms/X86_16/hardware.py \
	angr_platforms/angr_platforms/X86_16/simprocs_io.py \
	angr_platforms/angr_platforms/X86_16/debug.py \
	angr_platforms/angr_platforms/X86_16/exepack.py \
	angr_platforms/angr_platforms/X86_16/mz_image.py \
	angr_platforms/angr_platforms/X86_16/mz_load_source.py \
	angr_platforms/angr_platforms/X86_16/mz_invocation_source.py \
	angr_platforms/angr_platforms/X86_16/packed_mz.py \
	angr_platforms/angr_platforms/X86_16/pklite.py \
	inertia_decompiler/catalog_policy.py \
	angr_platforms/angr_platforms/X86_16/dev_io.py \
	angr_platforms/angr_platforms/X86_16/io.py \
	angr_platforms/angr_platforms/X86_16/instruction.py \
	angr_platforms/angr_platforms/X86_16/instr_base.py \
	angr_platforms/angr_platforms/X86_16/vex_value_contract.py \
	angr_platforms/angr_platforms/X86_16/instr16.py \
	angr_platforms/angr_platforms/X86_16/instr32.py \
	angr_platforms/angr_platforms/X86_16/parse.py \
	angr_platforms/angr_platforms/X86_16/exec.py \
	angr_platforms/angr_platforms/X86_16/emu.py \
	angr_platforms/angr_platforms/X86_16/emulator.py \
	angr_platforms/angr_platforms/X86_16/eflags.py \
	angr_platforms/angr_platforms/X86_16/memory.py \
	angr_platforms/angr_platforms/X86_16/processor.py \
	angr_platforms/angr_platforms/X86_16/interrupt.py \
	angr_platforms/angr_platforms/X86_16/stack_compat.py \
	angr_platforms/angr_platforms/X86_16/load_propagation.py \
	angr_platforms/angr_platforms/X86_16/stack_tracker_allocation.py \
	angr_platforms/angr_platforms/X86_16/stack_tracker_return_segment.py \
	angr_platforms/angr_platforms/X86_16/stack_value_use.py \
	angr_platforms/angr_platforms/X86_16/typehoon_compat.py \
	angr_platforms/angr_platforms/X86_16/type_clinic_return_compat.py \
	angr_platforms/angr_platforms/X86_16/stack_helpers.py \
	angr_platforms/angr_platforms/X86_16/control_coordinates.py \
	angr_platforms/angr_platforms/X86_16/relative_control_edge.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_relative_edge.py \
	angr_platforms/angr_platforms/X86_16/correctness_goals.py \
	angr_platforms/angr_platforms/X86_16/readability_set.py \
	angr_platforms/angr_platforms/X86_16/readability_goals.py \
	angr_platforms/angr_platforms/X86_16/quality.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_flags.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_jcc.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_loads.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_simplify.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_typed_conditions.py \
	angr_platforms/angr_platforms/X86_16/decompiler_return_compat.py \
	angr_platforms/angr_platforms/X86_16/ailment_variant_access.py \
	angr_platforms/angr_platforms/X86_16/tail_validation.py \
	angr_platforms/angr_platforms/X86_16/validation_manifest.py \
	angr_platforms/angr_platforms/X86_16/validation_helper_report.py \
	angr_platforms/angr_platforms/X86_16/validation_summary.py \
	angr_platforms/angr_platforms/X86_16/validation_calls.py \
	angr_platforms/angr_platforms/X86_16/validation_call_multiplicity.py \
	angr_platforms/angr_platforms/X86_16/validation_call_argument_sources.py \
	angr_platforms/angr_platforms/X86_16/validation_call_return_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_stack_projection.py \
	angr_platforms/angr_platforms/X86_16/validation_branch_conditions.py \
	angr_platforms/angr_platforms/X86_16/validation_materialized_condition_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_identity.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_coverage.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_storage_views.py \
	angr_platforms/angr_platforms/X86_16/validation_control_flow.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_precision.py \
	angr_platforms/angr_platforms/X86_16/validation_control_condition_delta.py \
	angr_platforms/angr_platforms/X86_16/validation_terminal_returns.py \
	angr_platforms/angr_platforms/X86_16/validation_switch_loop_tail_breaks.py \
	angr_platforms/angr_platforms/X86_16/validation_control_flow_obligations.py \
	angr_platforms/angr_platforms/X86_16/validation_dataflow.py \
	angr_platforms/angr_platforms/X86_16/validation_identical_return_guards.py \
	angr_platforms/angr_platforms/X86_16/validation_semantic_failures.py \
	angr_platforms/angr_platforms/X86_16/validation_predicates.py \
	angr_platforms/angr_platforms/X86_16/validation_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_aggregate_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_additive_terms.py \
	angr_platforms/angr_platforms/X86_16/validation_required_memory_effects.py \
	angr_platforms/angr_platforms/X86_16/validation_semantics.py \
	angr_platforms/angr_platforms/X86_16/verification_80286.py \
	angr_platforms/angr_platforms/X86_16/turbo_debug_tdinfo.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cases.py \
	angr_platforms/angr_platforms/X86_16/recompilable_checks.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cli_bridge.py \
	angr_platforms/angr_platforms/X86_16/recompilable_source_evidence.py \
	angr_platforms/angr_platforms/X86_16/recompilable_subset.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_fallback.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map_producer.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_objects.py \
	angr_platforms/angr_platforms/X86_16/structuring_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouping_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_refusal_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_cross_entry.py \
	angr_platforms/angr_platforms/X86_16/structuring_sequences.py \
	angr_platforms/angr_platforms/X86_16/lowering/__init__.py \
	angr_platforms/angr_platforms/X86_16/lowering/annotated_global_refs.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape_publication.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_arity_ownership.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_expression.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_semantic_token.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_state.py \
	angr_platforms/angr_platforms/X86_16/callsite_argument_value_sources.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_runtime.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_object_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/authoritative_function_prototypes.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_return_address_arguments.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_consumer_generation.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_local_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_variable_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_address_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_reload_consumers.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_storage_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_bindings.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_stores.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_cleanup_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_segment_access.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_memory_helpers.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_abi.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_globals.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/named_type_definitions.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_seeding.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_pointer_tables.py \
	angr_platforms/angr_platforms/X86_16/lowering/signed_global_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_signedness.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_census.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_count_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_width_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/function_ssa_registry.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_object_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_validation.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_function_solver.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_paths.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_slot_join.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_pipeline.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_application.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_source_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_condition_graph.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_caller_context.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_block.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_stack.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_witness.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_expression_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_target_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_targets.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_type_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_physical_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_input_preflight.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_solver.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_simtypes.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_transaction.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_interface.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_object_program_requirement.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_interface.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_sources.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_object_source_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_type_surface.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_codec.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_codec.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_program.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_program_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_range_callsite_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_callee_callsite_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_object_source_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_global_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_collector_parity.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/helper_call_interfaces.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_constant_segmented_store.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_index_binding.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_type.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_cache.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_fact_arbitration.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_argument_type_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_argument_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_scalar_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_stack_operands.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_stack_value.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_stack_projection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/assignment_lvalue_casts.py \
	angr_platforms/angr_platforms/X86_16/lowering/c_runtime_header.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_saved_frame.py \
	angr_platforms/angr_platforms/X86_16/lowering/dead_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/explicit_char_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/fixed_stack_probe_frames.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_probe_callsite_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_prologue_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_carrier_liveness.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_overwrite_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/fact_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameter_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameters.py \
	angr_platforms/angr_platforms/X86_16/lowering/cod_global_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/bounded_global_array_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_declaration_extents.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_symbol_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py \
	angr_platforms/angr_platforms/X86_16/lowering/physical_registers.py \
	angr_platforms/angr_platforms/X86_16/lowering/positive_bp_argument_plan.py \
	angr_platforms/angr_platforms/X86_16/lowering/positive_bp_arguments.py \
	angr_platforms/angr_platforms/X86_16/lowering/live_stack_word_inputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py \
	angr_platforms/angr_platforms/X86_16/lowering/linear_global_decomposition_cache.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_coordinate_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/instruction_bp_stack_access.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_coordinate_rebinding.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/machine_stack_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_function_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_display_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_candidate.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_inventory_presence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_segment_provenance.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_access_coverage.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_codegen_access_provenance.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_access_policy.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_global_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/semantic_cast.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_operand_views.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_liveness_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/unobserved_call_results.py \
	angr_platforms/angr_platforms/X86_16/lowering/unobserved_returns.py \
	angr_platforms/angr_platforms/X86_16/lowering/unused_void_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/scalar_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_register_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_load_subviews.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_global_loads.py \
	angr_platforms/angr_platforms/X86_16/lowering/aggregate_byte_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_value_casts.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_memory_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_store_consumption.py \
	angr_platforms/angr_platforms/X86_16/lowering/ir_segmented_load_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_indirect_call_targets.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_pointer_snapshot.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_argument_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_declaration_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_stack_sources.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/structured_intrinsics.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_call_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_values.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_return_expressions.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_return_render_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_calls.py \
	angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_status_outputs.py \
	angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_c_ast_matching.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_from_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_ast.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_placement.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_predicate.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_scope.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_values.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_stack_storage.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_ast.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_placement.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignments.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_return_recombine.py \
	angr_platforms/angr_platforms/X86_16/lowering/straight_line_placement.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_projection_retirement.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_impl.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_stack_argument_views.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/storage_identity_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/ss_bp_substitution.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_result.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_binding.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_stack_pair_evidence.py \
	angr_platforms/angr_platforms/X86_16/pipeline/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/affine_compound_assignment.py \
	angr_platforms/angr_platforms/X86_16/postprocess/call_argument_transaction.py \
	angr_platforms/angr_platforms/X86_16/postprocess/cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/flag_dead_definitions.py \
	angr_platforms/angr_platforms/X86_16/postprocess/simplify.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/const_prop.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_noop_conditionals.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_purity.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_walk.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_liveness.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_read_keys.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_declarations.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_setup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_condition_carriers.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/pass_driver.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/structured_braces.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/trivial_copy.py \
	angr_platforms/angr_platforms/X86_16/semantics/__init__.py \
	angr_platforms/angr_platforms/X86_16/semantics/alias_query.py \
	angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/immediate_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/binary_call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/branch_target_return.py \
	angr_platforms/angr_platforms/X86_16/semantics/return_effect_operands.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_pipeline.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_provenance.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_destinations.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_sources.py \
	angr_platforms/angr_platforms/X86_16/alias/storage_fact_join.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_cfg.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_links.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_ssa.py \
	angr_platforms/angr_platforms/X86_16/semantics/condition_recovery.py \
	angr_platforms/angr_platforms/X86_16/semantics/evidence_cache.py \
	angr_platforms/angr_platforms/X86_16/semantics/expression_analysis.py \
	angr_platforms/angr_platforms/X86_16/semantics/flag_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/direct_call_result_storage.py \
	angr_platforms/angr_platforms/X86_16/semantics/direct_global_ordering.py \
	angr_platforms/angr_platforms/X86_16/semantics/memory_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/software_interrupt_inputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_call_paths.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_return_passthrough.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_register_restore.py \
	angr_platforms/angr_platforms/X86_16/semantics/return_register_preservation.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_register_returns.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_return_storage.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_value_roles.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_stack_cleanup.py \
	angr_platforms/angr_platforms/X86_16/structuring/branch_return_expressions.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_path_preservation.py \
	angr_platforms/angr_platforms/X86_16/structuring/tagged_terminal_return_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/identical_return_guards.py \
	angr_platforms/angr_platforms/X86_16/structuring/multi_arm_return_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/total_return_suffixes.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_loop_tail_breaks.py \
	angr_platforms/angr_platforms/X86_16/structuring/compare32_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_join_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_joins.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/bound_call_condition.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_register_index.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_register_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_store_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_assignment_ast.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_contracts.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_occurrences.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_assignments.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_registers.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_return_early_exit.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_return_operands.py \
	angr_platforms/angr_platforms/X86_16/structuring/control_flow.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_materialization.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_exit_normalization.py \
	angr_platforms/angr_platforms/X86_16/structuring/tagged_subtree_projection.py \
	angr_platforms/angr_platforms/X86_16/structuring/single_branch_return_orientation.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_call_occurrence_finalization.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_call_result_aliases.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_tail_call_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_tail_cfg_topology.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_tail_structured_ancestry.py \
	angr_platforms/angr_platforms/X86_16/structuring/multi_arm_condition_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/local_condition_regions.py \
	angr_platforms/angr_platforms/X86_16/structuring/clinic_option_policy.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_condition_materialization.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_condition_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_update_scope_guard.py \
	angr_platforms/angr_platforms/X86_16/structuring/instruction_fragment_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_condition_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_binding.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_provenance.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/composite_pretest_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/existing_loop_exit_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/terminal_loop_exit_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_condition_binding.py \
	angr_platforms/angr_platforms/X86_16/validation_terminal_wide_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/symbolic_condition_origin.py \
	angr_platforms/angr_platforms/X86_16/structuring/symbolic_ite.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_zero_input.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_loop_exit.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_loop_exit_publication.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_replay.py \
	angr_platforms/angr_platforms/X86_16/structuring/expression_substitution.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_call_return_guard_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_condition_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_condition_ordering.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_condition_source.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_condition_capture.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_call_condition_plan.py \
	angr_platforms/angr_platforms/X86_16/structuring/local_wide_stack_condition_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_predicate_graphs.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_return_predicates.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_single_branches.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_binary_value.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py \
	angr_platforms/angr_platforms/X86_16/structuring/unused_call_result_self_xor.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_stack_views.py \
	angr_platforms/angr_platforms/X86_16/structuring/indexed_condition_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_rendering.py \
	angr_platforms/angr_platforms/X86_16/structuring/indexed_stack_ranges.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_branches.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_entries.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_immediate_loop_entries.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_linear_prefix_cfg.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_linear_prefixes.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_body.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_body_evidence.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_evidence.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_sites.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_initializers.py \
	angr_platforms/angr_platforms/X86_16/structuring/pretest_initializer_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_tail_replay.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_refresh.py \
	angr_platforms/angr_platforms/X86_16/structuring/canonical_for_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring/induction_comparisons.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_body_repair.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_break_jcc.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_exit_return_guards.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/natural_loop_topology.py \
	angr_platforms/angr_platforms/X86_16/structuring/register_dependencies.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chain_condition_selection.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/guard_decisions.py \
	angr_platforms/angr_platforms/X86_16/structuring/pass_effects.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_storage_identity.py \
	angr_platforms/angr_platforms/X86_16/structuring/surplus_guard_contracts.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chain_integrity.py \
	angr_platforms/angr_platforms/X86_16/structuring/selector_return_projection.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_carried_terminal_return_contracts.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_carried_terminal_returns.py \
	angr_platforms/angr_platforms/X86_16/structuring/terminal_register_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/software_interrupt_returns.py \
	angr_platforms/angr_platforms/X86_16/structuring/scalar_return_evidence.py \
	angr_platforms/angr_platforms/X86_16/structuring/simple_loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_artifact_identity.py \
	angr_platforms/angr_platforms/X86_16/structuring/typed_switch_seqnode.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_selector_binding.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_definition_coverage.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_return_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/canonicalize.py \
	angr_platforms/angr_platforms/X86_16/validation/callsite_completeness.py \
	angr_platforms/angr_platforms/X86_16/validation/status_flag_preservation.py \
	angr_platforms/angr_platforms/X86_16/validation_interrupt_calls.py \
	angr_platforms/angr_platforms/X86_16/widening_alias.py \
	angr_platforms/angr_platforms/X86_16/widening_model.py \
	angr_platforms/angr_platforms/X86_16/widening/__init__.py \
	angr_platforms/angr_platforms/X86_16/widening/global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/widening/direct_global_object_layout_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/global_object_layout_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_range_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_ranges.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_layouts.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_recovery.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_solver.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_ranges.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/widening/register_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_identity.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_argument_widths.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_word_register_transfers.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_expression.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_projection.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_proof.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_coordinates.py \
	angr_platforms/angr_platforms/X86_16/widening/store_width.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_pipeline.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_storage.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_values.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_memory_output_views.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_views.py \
	angr_platforms/angr_platforms/X86_16/widening/word_projection_recomposition.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_copyprop_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_memory_fold_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_rules.py \
	angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/contracts.py \
	angr_platforms/angr_platforms/X86_16/pipeline/errors.py \
	angr_platforms/angr_platforms/X86_16/pipeline/invariants.py \
	angr_platforms/angr_platforms/X86_16/pipeline/linear_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/recovery_coverage_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/render_authority.py \
	inertia_decompiler/__init__.py \
	inertia_decompiler/acceptance_scorecard.py \
	inertia_decompiler/analysis_timeout.py \
	inertia_decompiler/architecture_import_attestation.py \
	inertia_decompiler/architecture_runtime_guard.py \
	inertia_decompiler/project_evidence_transport.py \
	inertia_decompiler/indexed_global_object_cache.py \
	inertia_decompiler/direct_global_object_cache.py \
	inertia_decompiler/direct_global_object_context.py \
	inertia_decompiler/serial_clean_worker_evidence.py \
	inertia_decompiler/cod_module_caller_evidence.py \
	inertia_decompiler/c_text_cleanup.py \
	inertia_decompiler/cache.py \
	inertia_decompiler/cache_io.py \
	inertia_decompiler/cache_lock.py \
	inertia_decompiler/cache_runtime_contract.py \
	inertia_decompiler/cache_source_manifest.py \
	inertia_decompiler/function_ir_ssa_source_scope.py \
	inertia_decompiler/program_callsite_cache.py \
	inertia_decompiler/direct_request_cache.py \
	inertia_decompiler/direct_request_fast_path.py \
	inertia_decompiler/direct_request_identity.py \
	inertia_decompiler/cli.py \
	inertia_decompiler/cli_core.py \
	inertia_decompiler/indexed_alias_program_context.py \
	inertia_decompiler/indexed_alias_program_publication.py \
	inertia_decompiler/indexed_alias_program_recovery.py \
	inertia_decompiler/indexed_alias_program_parallel.py \
	inertia_decompiler/project_argument_evidence_ranges.py \
	inertia_decompiler/serial_clean_worker_cli.py \
	inertia_decompiler/serial_worker_cache.py \
	inertia_decompiler/discovery_cache_contract.py \
	inertia_decompiler/segment_program_layout_reporting.py \
	inertia_decompiler/function_worker_policy.py \
	inertia_decompiler/generated_c_artifacts.py \
	inertia_decompiler/cli_batch_c_output.py \
	inertia_decompiler/generated_external_function_contracts.py \
	inertia_decompiler/generated_c_function_extraction.py \
	inertia_decompiler/generated_translation_unit_assembly.py \
	inertia_decompiler/cli_decompilation.py \
	inertia_decompiler/cli_c_ast_rewrites.py \
	inertia_decompiler/cli_c_text_postprocess.py \
	inertia_decompiler/cli_fallback_decompilation.py \
	inertia_decompiler/cli_function_discovery.py \
	inertia_decompiler/function_graph_extent_repair.py \
	inertia_decompiler/cli_access_object_hints.py \
	inertia_decompiler/cli_access_profiles.py \
	inertia_decompiler/cli_access_traits.py \
	inertia_decompiler/cli_access_trait_rewrite.py \
	inertia_decompiler/cli_access_rewrite_artifact.py \
	inertia_decompiler/cli_arg_parser.py \
	inertia_decompiler/cli_cod_global_statements.py \
	inertia_decompiler/cli_cod_globals.py \
	inertia_decompiler/cli_dead_local_prune.py \
	inertia_decompiler/cli_semantic_rollback.py \
	inertia_decompiler/cli_helper_modeling.py \
	inertia_decompiler/cli_interrupt_modeling.py \
	inertia_decompiler/cli_linear_aliases.py \
	inertia_decompiler/cli_induction_rewrite.py \
	inertia_decompiler/cli_linear_recurrence.py \
	inertia_decompiler/cli_linear_recurrence_rules.py \
	inertia_decompiler/cli_linear_recurrence_state.py \
	inertia_decompiler/cli_mkfp_simplify.py \
	inertia_decompiler/cli_memory_prune.py \
	inertia_decompiler/cli_local_prune.py \
	inertia_decompiler/cli_local_rewrites.py \
	inertia_decompiler/cli_far_pointer_stack.py \
	inertia_decompiler/cli_segmented.py \
	inertia_decompiler/cli_segmented_compare.py \
	inertia_decompiler/cli_segmented_elision.py \
	inertia_decompiler/cli_segmented_load_coalesce.py \
	inertia_decompiler/cli_segmented_lowering.py \
	inertia_decompiler/cli_segmented_store_coalesce.py \
	inertia_decompiler/cli_stack_coalesce.py \
	inertia_decompiler/cli_stack_cvars.py \
	inertia_decompiler/cli_stack_byte_offsets.py \
	inertia_decompiler/cli_stack_locals.py \
	inertia_decompiler/cli_storage_objects.py \
	inertia_decompiler/cli_string_timeout_fallback.py \
	inertia_decompiler/cli_timeout.py \
	inertia_decompiler/cli_output.py \
	inertia_decompiler/cli_word_loads.py \
	inertia_decompiler/cli_word_global_helpers.py \
	inertia_decompiler/default_signature_catalog.py \
	inertia_decompiler/decompile_file_summary.py \
	inertia_decompiler/decompilation_quality.py \
	inertia_decompiler/direct_addr_failure_family.py \
	inertia_decompiler/direct_addr_stage_bundle.py \
	inertia_decompiler/discovery_evidence_project.py \
	inertia_decompiler/disassembly_helpers.py \
	inertia_decompiler/flair_paths.py \
	inertia_decompiler/fork_timeout.py \
	inertia_decompiler/function_cache_context.py \
	inertia_decompiler/gdb_client.py \
	inertia_decompiler/gdb_tui.py \
	inertia_decompiler/library_function_classifier.py \
	inertia_decompiler/debug_dos.py \
	inertia_decompiler/debugger_gdb.py \
	inertia_decompiler/signature_matching_policy.py \
	inertia_decompiler/msc51_local_hash.py \
	inertia_decompiler/non_optimized_fallback.py \
	inertia_decompiler/packer_detect.py \
	inertia_decompiler/project_loading.py \
	inertia_decompiler/prefork_job_pool.py \
	inertia_decompiler/rizin_evidence.py \
	inertia_decompiler/rizin_discovery.py \
	inertia_decompiler/recompile_check.py \
	inertia_decompiler/recompile_check_contract.py \
	inertia_decompiler/cli_terminal_status.py \
	inertia_decompiler/runtime_support.py \
	inertia_decompiler/sidecar_cache.py \
	inertia_decompiler/sidecar_metadata.py \
	inertia_decompiler/sidecar_policy.py \
	inertia_decompiler/sidecar_parsers.py \
	inertia_decompiler/slice_recovery.py \
	inertia_decompiler/source_sidecar.py \
	inertia_decompiler/tail_validation.py \
	inertia_decompiler/telemetry.py \
	inertia_decompiler/tui_widgets.py \
	inertia_decompiler/variable_recovery_sub_guard.py \
	inertia_decompiler/work_items.py \
	inertia_decompiler/x86_16_exact_slice.py \
	inertia_decompiler/monkeytype_tools.py \
	scripts/collect_monkeytype_pytest.py \
	scripts/apply_monkeytype_annotations.py \
	scripts/export_monkeytype_stubs.py \
	scripts/build_mypyc.py \
	scripts/build_cython_vex.py \
	scripts/benchmark_cython_vex.py \
	scripts/report_cython_vex.py \
	scripts/mypyc_build_cache.py \
	scripts/agent_context_check.py \
	scripts/agent_test_focus.py \
	scripts/batch_decompile_procs.py \
	scripts/build_debug_info_corpus.py \
	scripts/build_msc6_examples.py \
	scripts/msc6_compat_headers.py \
	scripts/msc6_entrypoint.py \
	scripts/msc6_function_targets.py \
	scripts/msc6_runtime_gate_artifacts.py \
	scripts/verify_msc_example_runtime_gate.py \
	scripts/compare_ghidra_function_coverage.py \
	scripts/check_sortd_sidecar_free.py \
	scripts/sortd_function_gate.py \
	scripts/runmenu_behavior.py \
	scripts/indexed_address_parity_inventory.py \
	scripts/check_generated_translation_unit.py \
	scripts/generated_translation_unit_assembly.py \
	scripts/check_sortd_generated_sort_core.py \
	scripts/check_decompiler_architecture.py \
	scripts/generated_c_contracts.py \
	scripts/generated_c_indexed_argument_contract.py \
	scripts/generated_c_return_contract.py \
	scripts/import_ultra_quickc_fixtures.py \
	scripts/msc6_toolchain_lock.py \
	scripts/pytest_profile.py \
	scripts/pytest_assertion_facts.py \
	scripts/pytest_call_hints.py \
	scripts/pytest_cache_events.py \
	scripts/pytest_inventory_review.py \
	scripts/pytest_inventory_check.py \
	scripts/pytest_partition_execution.py \
	scripts/pytest_dynamic_schedule.py \
	scripts/pytest_partition_plugin.py \
	scripts/pytest_partitioned.py \
	scripts/pytest_test_inventory.py \
	scripts/pytest_test_record.py \
	scripts/pytest_process_metrics.py \
	scripts/pytest_resource_history.py \
	scripts/pytest_resource_scheduler.py \
	scripts/pytest_profile_merge.py \
	scripts/pytest_profile_rankings.py \
	scripts/pytest_source_state.py \
	scripts/pytest_source_index.py \
	scripts/pytest_source_structure.py \
	scripts/pytest_source_structure_cache.py \
	scripts/test_pipeline.py \
	scripts/cod_stability_sweep.py \
	scripts/test_ownership_manifest.py \
	scripts/check_changed_non_test_types.py \
	scripts/sortdemo_decompiler_status.py \
	inertia_decompiler/accepted_payload_integrity.py \
	inertia_decompiler/angr_codegen_tags.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_bindings.py \
	angr_platforms/angr_platforms/X86_16/callsite_register_instruction_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/consumed_call_push_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_instruction_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/structured_tags.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_branch_carriers.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_joins.py \
	angr_platforms/angr_platforms/X86_16/verification_80386.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_layout.py \
	angr_platforms/angr_platforms/X86_16/msvc_x87_interrupts.py \
	angr_platforms/angr_platforms/X86_16/structuring/boolean_condition_ites.py \
	angr_platforms/angr_platforms/X86_16/alias/logical_stack_storage_identity.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_scalar_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_global_register_updates.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_global_register_update_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_segmented_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/logical_word_memory_copy_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_frame_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_recomposition.py \
	angr_platforms/angr_platforms/X86_16/widening/logical_word_memory_copies.py \
	angr_platforms/angr_platforms/X86_16/frontend_indirect_jump_targets.py \
	angr_platforms/angr_platforms/X86_16/lowering/balanced_memory_stack_restore.py \
	angr_platforms/angr_platforms/X86_16/lowering/caller_observed_byte_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/control_stack_escape.py \
	angr_platforms/angr_platforms/X86_16/lowering/direction_flag_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/packed_flags_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/packed_flags_liveness.py \
	angr_platforms/angr_platforms/X86_16/lowering/packed_flags_calls.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_return_boundary_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_stack_restore_carriers.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_chain_provenance.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_evidence_closure.py \
	angr_platforms/angr_platforms/X86_16/structuring/pretest_condition_surface.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_closure_delta.py \
	angr_platforms/angr_platforms/X86_16/validation_observable_compaction.py \
	angr_platforms/angr_platforms/X86_16/validation_pointer_parameter_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/validation_pointer_parameter_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_restore.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_restore_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_value_projection.py \
	angr_platforms/angr_platforms/X86_16/validation/entry_stack_ranges.py \
	inertia_decompiler/cache_file_digest.py \
	inertia_decompiler/direct_indexed_alias_local_cache.py \
	inertia_decompiler/function_ir_ssa_cache.py \
	inertia_decompiler/function_ir_ssa_cache_codec.py \
	inertia_decompiler/function_ir_ssa_cache_identity.py \
	decompile.py

QA_RUFF_TARGETS := \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_load_origins.py \
	angr_platforms/tests/test_x86_16_segmented_load_origins.py \
	angr_platforms/tests/test_x86_16_envsize_behavior.py \
	angr_platforms/angr_platforms/X86_16/ir/instruction_origin.py \
	angr_platforms/tests/test_x86_16_ir_instruction_origin.py \
	angr_platforms/angr_platforms/X86_16/ir/constant_flow.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_value_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_inventory.py \
	angr_platforms/angr_platforms/X86_16/lowering/codegen_return_origin.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_restore_state.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_definition_return.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_local_return.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_local_reload.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_allocation.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_call_preservation.py \
	angr_platforms/angr_platforms/X86_16/ir/register_live_in.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_object_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_call_results.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_semantic_gap.py \
	scripts/makefile_inventory.py \
	angr_platforms/angr_platforms/X86_16/ir/function_ir_registry.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_constant_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_register_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_carrier_liveness.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_frame.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_frame_arguments.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_register_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_projections.py \
	angr_platforms/angr_platforms/X86_16/callsite_setup_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/consumed_stack_address_setup.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_entry_overwrite.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_value_preservation.py \
	angr_platforms/angr_platforms/X86_16/synthetic_call_stub_evidence.py \
	monkeytype_config.py \
	angr_platforms/angr_platforms/X86_16/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias/__init__.py \
	angr_platforms/angr_platforms/X86_16/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias_domains.py \
	angr_platforms/angr_platforms/X86_16/alias_state.py \
	angr_platforms/angr_platforms/X86_16/alias_transfer.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model.py \
	angr_platforms/angr_platforms/X86_16/alias/alias_model_impl.py \
	angr_platforms/angr_platforms/X86_16/alias/callsite_stack_merge.py \
	angr_platforms/angr_platforms/X86_16/alias/register_reaching_source.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_definition.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_register_expression.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_break_topology.py \
	angr_platforms/angr_platforms/X86_16/alias/partial_register_address_break.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_classification.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_program.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_liveness.py \
	angr_platforms/angr_platforms/X86_16/alias/domains.py \
	angr_platforms/angr_platforms/X86_16/alias/state.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/alias/segment_stack_fragments.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_pointer_snapshots.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_byte_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_bytes.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_pointer_snapshots.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_operation_membership.py \
	angr_platforms/tests/entry_stack_byte_test_support.py \
	angr_platforms/angr_platforms/X86_16/alias/segment_stack_restore.py \
	angr_platforms/angr_platforms/X86_16/alias/bp_preservation.py \
	angr_platforms/angr_platforms/X86_16/alias/logical_stack_memory_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_memory_access_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_address_escape.py \
	angr_platforms/angr_platforms/X86_16/alias/private_stack_writes.py \
	angr_platforms/angr_platforms/X86_16/alias/transfer.py \
	angr_platforms/angr_platforms/X86_16/analysis/__init__.py \
	angr_platforms/angr_platforms/X86_16/analysis/alias.py \
	angr_platforms/angr_platforms/X86_16/analysis/stack_frame_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/frame_memory_accesses.py \
	angr_platforms/angr_platforms/X86_16/analysis_helpers.py \
	angr_platforms/angr_platforms/X86_16/arch_86_16.py \
	angr_platforms/angr_platforms/X86_16/access.py \
	angr_platforms/angr_platforms/X86_16/addressing_helpers.py \
	angr_platforms/angr_platforms/X86_16/capstone_memory_segment.py \
	angr_platforms/angr_platforms/X86_16/decoded_memory_width.py \
	angr_platforms/angr_platforms/X86_16/address_ir.py \
	angr_platforms/angr_platforms/X86_16/alu_helpers.py \
	angr_platforms/angr_platforms/X86_16/annotations.py \
	angr_platforms/angr_platforms/X86_16/borrow_verification.py \
	angr_platforms/angr_platforms/X86_16/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/condition_trace.py \
	angr_platforms/angr_platforms/X86_16/condition_call_effects.py \
	angr_platforms/angr_platforms/X86_16/function_evidence_inventory.py \
	angr_platforms/angr_platforms/X86_16/helper_abi.py \
	angr_platforms/angr_platforms/X86_16/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/__init__.py \
	angr_platforms/angr_platforms/X86_16/ir/address_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_register_bindings.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_value_extensions.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_fingerprint_masks.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_fingerprint_syntax.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/core.py \
	angr_platforms/angr_platforms/X86_16/ir/block_ownership.py \
	angr_platforms/angr_platforms/X86_16/ir/block_successor_chain.py \
	angr_platforms/angr_platforms/X86_16/ir/effects.py \
	angr_platforms/angr_platforms/X86_16/ir/function_artifact.py \
	angr_platforms/angr_platforms/X86_16/ir/function_condition_artifact.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_lift_capture.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_access_normalization.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_pipeline.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidate_helpers.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_induction_write_census.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidates.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_witnesses.py \
	angr_platforms/angr_platforms/X86_16/ir/ir_canonicalize_8616.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_capture.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_matching.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_rebase.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_resolution.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_value_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_write_value.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_constant_word_receipt.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_word_call_window.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_word_call_binding.py \
	angr_platforms/angr_platforms/X86_16/ir/regs.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_definitions.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_sources.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_affine_trace.py \
	angr_platforms/angr_platforms/X86_16/ir/affine_indexed_address.py \
	angr_platforms/angr_platforms/X86_16/ir/affine_induction_role.py \
	angr_platforms/angr_platforms/X86_16/ir/frame_register_reaching_definition.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_binary_cfg.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_cfg_projection.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_lift_context.py \
	angr_platforms/angr_platforms/X86_16/ir/status_flag_lift_codec.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_contract.py \
	angr_platforms/angr_platforms/X86_16/segment_function_summary.py \
	angr_platforms/angr_platforms/X86_16/segment_offset_execution.py \
	angr_platforms/angr_platforms/X86_16/segment_program_layout.py \
	angr_platforms/angr_platforms/X86_16/segment_program_layout_codec.py \
	angr_platforms/angr_platforms/X86_16/segment_program_layout_contract.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state_solver.py \
	angr_platforms/angr_platforms/X86_16/ir/segment_state_transfer.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_function.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_cfg.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_cfg_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory_call_liveness.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_memory_ranges.py \
	angr_platforms/angr_platforms/X86_16/ir/stack_range_overlap.py \
	angr_platforms/angr_platforms/X86_16/lowering/native_integer_constants.py \
	angr_platforms/angr_platforms/X86_16/lowering/native_integer_operations.py \
	angr_platforms/angr_platforms/X86_16/lowering/native_terminal_return_values.py \
	angr_platforms/angr_platforms/X86_16/ir/string_effects.py \
	angr_platforms/angr_platforms/X86_16/ir/value_ir.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_addressing.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_demand.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_condition_transport.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_control_flow.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_terminal_jump.py \
	angr_platforms/angr_platforms/X86_16/ir/entry_jump_domain.py \
	angr_platforms/angr_platforms/X86_16/ir/real16_invocation_domain.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_import.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_integer_displacement.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_bit_source.py \
	angr_platforms/angr_platforms/X86_16/direction_step.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_types.py \
	angr_platforms/angr_platforms/X86_16/function_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_effect_summary.py \
	angr_platforms/angr_platforms/X86_16/helper_family_routing.py \
	angr_platforms/angr_platforms/X86_16/function_interface_surface.py \
	angr_platforms/angr_platforms/X86_16/function_summary.py \
	angr_platforms/angr_platforms/X86_16/function_state_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_target_inventory.py \
	angr_platforms/angr_platforms/X86_16/semantics/callsite_summary_request.py \
	angr_platforms/angr_platforms/X86_16/caller_return_use_contracts.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary.py \
	angr_platforms/angr_platforms/X86_16/callsite_register_provenance.py \
	angr_platforms/angr_platforms/X86_16/register_source_block_inventory.py \
	angr_platforms/angr_platforms/X86_16/call_target_identity.py \
	angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py \
	angr_platforms/angr_platforms/X86_16/stack_probe_fact_trace.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_condition_context.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_frame_spills.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py \
	angr_platforms/angr_platforms/X86_16/validation_goto_target_identity.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_generation.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_generation_atoms.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_ast_generation.py \
	angr_platforms/angr_platforms/X86_16/pipeline/result_contracts.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_assignment_index.py \
	angr_platforms/angr_platforms/X86_16/pipeline/structured_ast_query_index.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_validation_policy.py \
	angr_platforms/angr_platforms/X86_16/postprocess/bootstrap_orchestration.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_runtime.py \
	angr_platforms/angr_platforms/X86_16/postprocess/pass_transaction.py \
	angr_platforms/angr_platforms/X86_16/postprocess/runtime_configuration.py \
	angr_platforms/angr_platforms/X86_16/postprocess/rollback_snapshot_cache.py \
	angr_platforms/angr_platforms/X86_16/postprocess/validation_contracts.py \
	angr_platforms/angr_platforms/X86_16/validation/control_flow_ast_index.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_routing.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_selector_returns.py \
	angr_platforms/angr_platforms/X86_16/tail_validation_stack_policy.py \
	angr_platforms/angr_platforms/X86_16/targeted_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/layer_module_status.py \
	angr_platforms/angr_platforms/X86_16/coverage_manifest.py \
	angr_platforms/angr_platforms/X86_16/corpus_scan.py \
	angr_platforms/angr_platforms/X86_16/milestone_report.py \
	angr_platforms/angr_platforms/X86_16/exact_region_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/frontend_cfg_direct_jump.py \
	angr_platforms/angr_platforms/X86_16/frontend_cfg_direct_call.py \
	angr_platforms/angr_platforms/X86_16/frontend_cfg_direct_jobs.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_boundary.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_boundary_index.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_block_decode.py \
	angr_platforms/angr_platforms/X86_16/frontend_capstone_block.py \
	angr_platforms/angr_platforms/X86_16/frontend_block_inventory.py \
	angr_platforms/angr_platforms/X86_16/frontend_capstone_decode.py \
	angr_platforms/angr_platforms/X86_16/frontend_function_instructions.py \
	angr_platforms/angr_platforms/X86_16/frontend_caller_return_use_program.py \
	angr_platforms/angr_platforms/X86_16/frontend_direct_callsite_index.py \
	angr_platforms/angr_platforms/X86_16/frontend_instruction_kinds.py \
	angr_platforms/angr_platforms/X86_16/frontend_instruction_reachability.py \
	angr_platforms/angr_platforms/X86_16/recovery_instruction_coverage.py \
	angr_platforms/angr_platforms/X86_16/flair_extract.py \
	angr_platforms/angr_platforms/X86_16/fast_tracer.py \
	angr_platforms/angr_platforms/X86_16/jcc_condition.py \
	angr_platforms/angr_platforms/X86_16/jcc_result_condition.py \
	angr_platforms/angr_platforms/X86_16/lift_86_16.py \
	angr_platforms/angr_platforms/X86_16/lifter_backend.py \
	angr_platforms/angr_platforms/X86_16/lifter_backend_selection.py \
	angr_platforms/angr_platforms/X86_16/semantics/status_flag_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/status_flag_cfg_liveness.py \
	angr_platforms/angr_platforms/X86_16/semantics/status_flag_liveness.py \
	angr_platforms/angr_platforms/X86_16/load_dos_mz.py \
	angr_platforms/angr_platforms/X86_16/load_dos_ne.py \
	angr_platforms/angr_platforms/X86_16/lst_extract.py \
	angr_platforms/angr_platforms/X86_16/ne_exe_parse.py \
	angr_platforms/angr_platforms/X86_16/ne_resources.py \
	angr_platforms/angr_platforms/X86_16/recovery_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifacts.py \
	angr_platforms/angr_platforms/X86_16/recovery_confidence.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_cache.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_manifest.py \
	angr_platforms/angr_platforms/X86_16/recovery_artifact_writer.py \
	angr_platforms/angr_platforms/X86_16/corpus_recovery_artifact.py \
	angr_platforms/angr_platforms/X86_16/confidence_and_assumptions.py \
	angr_platforms/angr_platforms/X86_16/ir_recovery_summary.py \
	angr_platforms/angr_platforms/X86_16/ir_readiness.py \
	angr_platforms/angr_platforms/X86_16/ir_confidence_markers.py \
	angr_platforms/angr_platforms/X86_16/runtime_trace_refinement.py \
	angr_platforms/angr_platforms/X86_16/structuring_ir_hints.py \
	angr_platforms/angr_platforms/X86_16/structuring_abnormal_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_analysis.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_indirect.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py \
	angr_platforms/angr_platforms/X86_16/structuring_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring_cfg_snapshot.py \
	angr_platforms/angr_platforms/X86_16/structuring_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_graph_builder.py \
	angr_platforms/angr_platforms/X86_16/structuring_region.py \
	angr_platforms/angr_platforms/X86_16/structuring_codegen.py \
	angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_pass.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_units.py \
	angr_platforms/angr_platforms/X86_16/structured_function_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_helpers.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_artifact.py \
	angr_platforms/angr_platforms/X86_16/string_instruction_lowering.py \
	angr_platforms/angr_platforms/X86_16/string_codegen_override.py \
	angr_platforms/angr_platforms/X86_16/type_array_matching.py \
	angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py \
	angr_platforms/angr_platforms/X86_16/type_structure_merging.py \
	angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py \
	angr_platforms/angr_platforms/X86_16/bootstrap.py \
	angr_platforms/angr_platforms/X86_16/cod_comment_emitter.py \
	angr_platforms/angr_platforms/X86_16/cod_analysis_image.py \
	angr_platforms/angr_platforms/X86_16/cod_extract.py \
	angr_platforms/angr_platforms/X86_16/interrupt_contract.py \
	angr_platforms/angr_platforms/X86_16/cod_known_objects.py \
	angr_platforms/angr_platforms/X86_16/cod_source_rewrites.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb00.py \
	angr_platforms/angr_platforms/X86_16/codeview_nb02_nb04.py \
	angr_platforms/angr_platforms/X86_16/codegen_metadata.py \
	angr_platforms/angr_platforms/X86_16/compiler_helpers.py \
	angr_platforms/angr_platforms/X86_16/cr.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_globals.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_utils.py \
	angr_platforms/angr_platforms/X86_16/compat.py \
	angr_platforms/angr_platforms/X86_16/call_frame_compat.py \
	angr_platforms/angr_platforms/X86_16/call_cleanup_compat.py \
	angr_platforms/angr_platforms/X86_16/ir/stack_pointer_provenance.py \
	angr_platforms/angr_platforms/X86_16/ir/stack_extent_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/ail_register_displacement.py \
	angr_platforms/angr_platforms/X86_16/ail_displacement_compat.py \
	angr_platforms/angr_platforms/X86_16/ail_remainder_compat.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_reference_offsets.py \
	angr_platforms/angr_platforms/X86_16/variable_recovery_compat.py \
	angr_platforms/angr_platforms/X86_16/ir/ail_remainder.py \
	angr_platforms/angr_platforms/X86_16/codegen_parentheses.py \
	angr_platforms/angr_platforms/X86_16/stack_anchor_compat.py \
	angr_platforms/angr_platforms/X86_16/ir/native_stack_anchor.py \
	angr_platforms/angr_platforms/X86_16/ir/native_segment_live_out.py \
	angr_platforms/angr_platforms/X86_16/lowering/store_projection_width.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_push_carrier.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_return_segment.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_return_contract.py \
	angr_platforms/angr_platforms/X86_16/calling_convention_compat.py \
	angr_platforms/angr_platforms/X86_16/calling_convention_seed_cache.py \
	angr_platforms/angr_platforms/X86_16/render_compat.py \
	angr_platforms/angr_platforms/X86_16/patch_dirty.py \
	angr_platforms/angr_platforms/X86_16/c_ast_utils.py \
	angr_platforms/angr_platforms/X86_16/callee_name_normalization.py \
	angr_platforms/angr_platforms/X86_16/low_memory_regions.py \
	angr_platforms/angr_platforms/X86_16/simos_86_16.py \
	angr_platforms/angr_platforms/X86_16/exception.py \
	angr_platforms/angr_platforms/X86_16/hardware.py \
	angr_platforms/angr_platforms/X86_16/simprocs_io.py \
	angr_platforms/angr_platforms/X86_16/debug.py \
	angr_platforms/angr_platforms/X86_16/exepack.py \
	angr_platforms/angr_platforms/X86_16/mz_image.py \
	angr_platforms/angr_platforms/X86_16/mz_load_source.py \
	angr_platforms/angr_platforms/X86_16/mz_invocation_source.py \
	angr_platforms/angr_platforms/X86_16/packed_mz.py \
	angr_platforms/angr_platforms/X86_16/dev_io.py \
	angr_platforms/angr_platforms/X86_16/io.py \
	angr_platforms/angr_platforms/X86_16/instruction.py \
	angr_platforms/angr_platforms/X86_16/instr_base.py \
	angr_platforms/angr_platforms/X86_16/vex_value_contract.py \
	angr_platforms/angr_platforms/X86_16/instr16.py \
	angr_platforms/angr_platforms/X86_16/instr32.py \
	angr_platforms/angr_platforms/X86_16/parse.py \
	angr_platforms/angr_platforms/X86_16/exec.py \
	angr_platforms/angr_platforms/X86_16/emu.py \
	angr_platforms/angr_platforms/X86_16/emulator.py \
	angr_platforms/angr_platforms/X86_16/eflags.py \
	angr_platforms/angr_platforms/X86_16/memory.py \
	angr_platforms/angr_platforms/X86_16/processor.py \
	angr_platforms/angr_platforms/X86_16/interrupt.py \
	angr_platforms/angr_platforms/X86_16/stack_compat.py \
	angr_platforms/angr_platforms/X86_16/load_propagation.py \
	angr_platforms/angr_platforms/X86_16/stack_tracker_allocation.py \
	angr_platforms/angr_platforms/X86_16/stack_tracker_return_segment.py \
	angr_platforms/angr_platforms/X86_16/stack_value_use.py \
	angr_platforms/angr_platforms/X86_16/typehoon_compat.py \
	angr_platforms/angr_platforms/X86_16/type_clinic_return_compat.py \
	angr_platforms/angr_platforms/X86_16/stack_helpers.py \
	angr_platforms/angr_platforms/X86_16/control_coordinates.py \
	angr_platforms/angr_platforms/X86_16/relative_control_edge.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_relative_edge.py \
	angr_platforms/angr_platforms/X86_16/correctness_goals.py \
	angr_platforms/angr_platforms/X86_16/readability_set.py \
	angr_platforms/angr_platforms/X86_16/readability_goals.py \
	angr_platforms/angr_platforms/X86_16/quality.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_flags.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_jcc.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_loads.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_simplify.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py \
	angr_platforms/angr_platforms/X86_16/decompiler_postprocess_typed_conditions.py \
	angr_platforms/angr_platforms/X86_16/decompiler_return_compat.py \
	angr_platforms/angr_platforms/X86_16/ailment_variant_access.py \
	angr_platforms/angr_platforms/X86_16/tail_validation.py \
	angr_platforms/angr_platforms/X86_16/validation_manifest.py \
	angr_platforms/angr_platforms/X86_16/validation_helper_report.py \
	angr_platforms/angr_platforms/X86_16/validation_summary.py \
	angr_platforms/angr_platforms/X86_16/validation_calls.py \
	angr_platforms/angr_platforms/X86_16/validation_call_multiplicity.py \
	angr_platforms/angr_platforms/X86_16/validation_call_argument_sources.py \
	angr_platforms/angr_platforms/X86_16/validation_call_return_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_stack_projection.py \
	angr_platforms/angr_platforms/X86_16/validation_branch_conditions.py \
	angr_platforms/angr_platforms/X86_16/validation_materialized_condition_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_identity.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_coverage.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_storage_views.py \
	angr_platforms/angr_platforms/X86_16/validation_control_flow.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_precision.py \
	angr_platforms/angr_platforms/X86_16/validation_control_condition_delta.py \
	angr_platforms/angr_platforms/X86_16/validation_terminal_returns.py \
	angr_platforms/angr_platforms/X86_16/validation_switch_loop_tail_breaks.py \
	angr_platforms/angr_platforms/X86_16/validation_control_flow_obligations.py \
	angr_platforms/angr_platforms/X86_16/validation_dataflow.py \
	angr_platforms/angr_platforms/X86_16/validation_identical_return_guards.py \
	angr_platforms/angr_platforms/X86_16/validation_semantic_failures.py \
	angr_platforms/angr_platforms/X86_16/validation_predicates.py \
	angr_platforms/angr_platforms/X86_16/validation_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_aggregate_storage.py \
	angr_platforms/angr_platforms/X86_16/validation_additive_terms.py \
	angr_platforms/angr_platforms/X86_16/validation_required_memory_effects.py \
	angr_platforms/angr_platforms/X86_16/validation_semantics.py \
	angr_platforms/angr_platforms/X86_16/verification_80286.py \
	angr_platforms/angr_platforms/X86_16/turbo_debug_tdinfo.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cases.py \
	angr_platforms/angr_platforms/X86_16/recompilable_checks.py \
	angr_platforms/angr_platforms/X86_16/recompilable_cli_bridge.py \
	angr_platforms/angr_platforms/X86_16/recompilable_source_evidence.py \
	angr_platforms/angr_platforms/X86_16/recompilable_subset.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_fallback.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_map_producer.py \
	angr_platforms/angr_platforms/X86_16/recompilable_storage_objects.py \
	angr_platforms/angr_platforms/X86_16/structuring_diagnostics.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouping_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_grouped_refusal_report.py \
	angr_platforms/angr_platforms/X86_16/structuring_cross_entry.py \
	angr_platforms/angr_platforms/X86_16/structuring_sequences.py \
	angr_platforms/angr_platforms/X86_16/lowering/__init__.py \
	angr_platforms/angr_platforms/X86_16/lowering/annotated_global_refs.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape_publication.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_arity_ownership.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_expression.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_semantic_token.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_state.py \
	angr_platforms/angr_platforms/X86_16/callsite_argument_value_sources.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_runtime.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_object_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/authoritative_function_prototypes.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_return_address_arguments.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_consumer_generation.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_local_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_variable_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_address_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_reload_consumers.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_storage_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_bindings.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_stores.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_cleanup_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_segment_access.py \
	angr_platforms/angr_platforms/X86_16/lowering/runtime_memory_helpers.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_abi.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_globals.py \
	angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/named_type_definitions.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_seeding.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_pointer_tables.py \
	angr_platforms/angr_platforms/X86_16/lowering/signed_global_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_signedness.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_census.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_count_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_width_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/function_ssa_registry.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_object_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_validation.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_function_solver.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_paths.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_slot_join.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_pipeline.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_application.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_source_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_condition_graph.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_caller_context.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_block.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_flow.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_stack.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_witness.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_expression_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_target_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_targets.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_type_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_physical_defs.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_input_preflight.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_solver.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_simtypes.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_transaction.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_argument_interface.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_object_program_requirement.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_interface.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_sources.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_object_source_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_type_surface.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_codec.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_codec.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_program.py \
	angr_platforms/angr_platforms/X86_16/callsite_summary_program_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_codec.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_range_callsite_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_callee_callsite_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_object_source_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_global_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_collector_parity.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/helper_call_interfaces.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_constant_segmented_store.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_index_binding.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_type.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_cache.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_fact_arbitration.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_argument_type_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_argument_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_scalar_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_stack_operands.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_stack_value.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_stack_projection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/assignment_lvalue_casts.py \
	angr_platforms/angr_platforms/X86_16/lowering/c_runtime_header.py \
	angr_platforms/angr_platforms/X86_16/lowering/callee_saved_frame.py \
	angr_platforms/angr_platforms/X86_16/lowering/dead_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/explicit_char_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/fixed_stack_probe_frames.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_probe_callsite_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_prologue_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_carrier_liveness.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_overwrite_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/fact_transfer.py \
	angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameter_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameters.py \
	angr_platforms/angr_platforms/X86_16/lowering/cod_global_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/bounded_global_array_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_declaration_extents.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_declarations.py \
	angr_platforms/angr_platforms/X86_16/lowering/global_symbol_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py \
	angr_platforms/angr_platforms/X86_16/lowering/physical_registers.py \
	angr_platforms/angr_platforms/X86_16/lowering/positive_bp_argument_plan.py \
	angr_platforms/angr_platforms/X86_16/lowering/positive_bp_arguments.py \
	angr_platforms/angr_platforms/X86_16/lowering/live_stack_word_inputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/project_global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py \
	angr_platforms/angr_platforms/X86_16/lowering/linear_global_decomposition_cache.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_coordinate_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/instruction_bp_stack_access.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_coordinate_rebinding.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/machine_stack_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_function_coordinates.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_display_names.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_candidate.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_inventory_presence.py \
	angr_platforms/angr_platforms/X86_16/lowering/callsite_segment_provenance.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_access_coverage.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_codegen_access_provenance.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_access_policy.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_global_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/semantic_cast.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_operand_views.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/return_liveness_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/unobserved_call_results.py \
	angr_platforms/angr_platforms/X86_16/lowering/unobserved_returns.py \
	angr_platforms/angr_platforms/X86_16/lowering/unused_void_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/scalar_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_register_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/indexed_load_subviews.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_global_loads.py \
	angr_platforms/angr_platforms/X86_16/lowering/aggregate_byte_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/condition_value_casts.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/segmented_memory_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/pointer_store_consumption.py \
	angr_platforms/angr_platforms/X86_16/lowering/ir_segmented_load_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/register_indirect_call_targets.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_pointer_snapshot.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_argument_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_declaration_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_argument_stack_sources.py \
	angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/structured_intrinsics.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_call_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_values.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_return_expressions.py \
	angr_platforms/angr_platforms/X86_16/lowering/terminal_return_render_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_calls.py \
	angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_status_outputs.py \
	angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_objects.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_c_ast_matching.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_from_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_ast.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_placement.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_predicate.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_scope.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_values.py \
	angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_stack_storage.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_ast.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_placement.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_replay.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignments.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_return_recombine.py \
	angr_platforms/angr_platforms/X86_16/lowering/straight_line_placement.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_projection_retirement.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_impl.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_stack_argument_views.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/storage_identity_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/ss_bp_substitution.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_result.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_variable_binding.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_stack_pair_evidence.py \
	angr_platforms/angr_platforms/X86_16/pipeline/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/__init__.py \
	angr_platforms/angr_platforms/X86_16/postprocess/affine_compound_assignment.py \
	angr_platforms/angr_platforms/X86_16/postprocess/call_argument_transaction.py \
	angr_platforms/angr_platforms/X86_16/postprocess/cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/flag_dead_definitions.py \
	angr_platforms/angr_platforms/X86_16/postprocess/simplify.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/const_prop.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_noop_conditionals.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_purity.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_walk.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_liveness.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_read_keys.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_declarations.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_setup.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_condition_carriers.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/pass_driver.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/structured_braces.py \
	angr_platforms/angr_platforms/X86_16/postprocess/optimization/trivial_copy.py \
	angr_platforms/angr_platforms/X86_16/semantics/__init__.py \
	angr_platforms/angr_platforms/X86_16/semantics/alias_query.py \
	angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/immediate_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/binary_call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/branch_target_return.py \
	angr_platforms/angr_platforms/X86_16/semantics/return_effect_operands.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_pipeline.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_effects.py \
	angr_platforms/angr_platforms/X86_16/semantics/call_stack_provenance.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_destinations.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_projection.py \
	angr_platforms/angr_platforms/X86_16/alias/carry_borrow_sources.py \
	angr_platforms/angr_platforms/X86_16/alias/storage_fact_join.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_cfg.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_links.py \
	angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_ssa.py \
	angr_platforms/angr_platforms/X86_16/semantics/condition_recovery.py \
	angr_platforms/angr_platforms/X86_16/semantics/evidence_cache.py \
	angr_platforms/angr_platforms/X86_16/semantics/expression_analysis.py \
	angr_platforms/angr_platforms/X86_16/semantics/flag_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/direct_call_result_storage.py \
	angr_platforms/angr_platforms/X86_16/semantics/direct_global_ordering.py \
	angr_platforms/angr_platforms/X86_16/semantics/memory_semantics.py \
	angr_platforms/angr_platforms/X86_16/semantics/software_interrupt_inputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_call_paths.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_outputs.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_return_passthrough.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_register_restore.py \
	angr_platforms/angr_platforms/X86_16/semantics/return_register_preservation.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_register_returns.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_return_storage.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_value_roles.py \
	angr_platforms/angr_platforms/X86_16/semantics/terminal_stack_cleanup.py \
	angr_platforms/angr_platforms/X86_16/structuring/branch_return_expressions.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_path_preservation.py \
	angr_platforms/angr_platforms/X86_16/structuring/tagged_terminal_return_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/identical_return_guards.py \
	angr_platforms/angr_platforms/X86_16/structuring/multi_arm_return_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/total_return_suffixes.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_loop_tail_breaks.py \
	angr_platforms/angr_platforms/X86_16/structuring/compare32_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_join_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_joins.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/bound_call_condition.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_register_index.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_register_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_return_store_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_assignment_ast.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_contracts.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_occurrences.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_assignments.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_registers.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_return_early_exit.py \
	angr_platforms/angr_platforms/X86_16/structuring/stored_call_return_operands.py \
	angr_platforms/angr_platforms/X86_16/structuring/control_flow.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_materialization.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_exit_normalization.py \
	angr_platforms/angr_platforms/X86_16/structuring/tagged_subtree_projection.py \
	angr_platforms/angr_platforms/X86_16/structuring/single_branch_return_orientation.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_call_occurrence_finalization.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_call_result_aliases.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_tail_call_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_tail_cfg_topology.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_tail_structured_ancestry.py \
	angr_platforms/angr_platforms/X86_16/structuring/multi_arm_condition_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/local_condition_regions.py \
	angr_platforms/angr_platforms/X86_16/structuring/clinic_option_policy.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_condition_materialization.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_condition_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_update_scope_guard.py \
	angr_platforms/angr_platforms/X86_16/structuring/instruction_fragment_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_condition_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_binding.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_provenance.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/composite_pretest_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/existing_loop_exit_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/terminal_loop_exit_conditions.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_condition_binding.py \
	angr_platforms/angr_platforms/X86_16/validation_terminal_wide_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/symbolic_condition_origin.py \
	angr_platforms/angr_platforms/X86_16/structuring/symbolic_ite.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_zero_input.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_loop_exit.py \
	angr_platforms/angr_platforms/X86_16/structuring/shared_loop_exit_publication.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_replay.py \
	angr_platforms/angr_platforms/X86_16/structuring/expression_substitution.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_call_return_guard_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_condition_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_condition_ordering.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_condition_source.py \
	angr_platforms/angr_platforms/X86_16/lowering/wide_call_condition_capture.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_call_condition_plan.py \
	angr_platforms/angr_platforms/X86_16/structuring/local_wide_stack_condition_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_predicate_graphs.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_return_predicates.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_stack_single_branches.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_binary_value.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py \
	angr_platforms/angr_platforms/X86_16/structuring/unused_call_result_self_xor.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_stack_views.py \
	angr_platforms/angr_platforms/X86_16/structuring/indexed_condition_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_rendering.py \
	angr_platforms/angr_platforms/X86_16/structuring/indexed_stack_ranges.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_branches.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_ownership.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_entries.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_immediate_loop_entries.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_linear_prefix_cfg.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_linear_prefixes.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_body.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_body_evidence.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_evidence.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_sites.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_initializers.py \
	angr_platforms/angr_platforms/X86_16/structuring/pretest_initializer_placement.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_tail_replay.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_refresh.py \
	angr_platforms/angr_platforms/X86_16/structuring/canonical_for_loops.py \
	angr_platforms/angr_platforms/X86_16/structuring/induction_comparisons.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_body_repair.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_break_jcc.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_exit_return_guards.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/natural_loop_topology.py \
	angr_platforms/angr_platforms/X86_16/structuring/register_dependencies.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chain_condition_selection.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chains.py \
	angr_platforms/angr_platforms/X86_16/structuring/guard_decisions.py \
	angr_platforms/angr_platforms/X86_16/structuring/pass_effects.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_storage_identity.py \
	angr_platforms/angr_platforms/X86_16/structuring/surplus_guard_contracts.py \
	angr_platforms/angr_platforms/X86_16/structuring/return_chain_integrity.py \
	angr_platforms/angr_platforms/X86_16/structuring/selector_return_projection.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_carried_terminal_return_contracts.py \
	angr_platforms/angr_platforms/X86_16/structuring/loop_carried_terminal_returns.py \
	angr_platforms/angr_platforms/X86_16/structuring/terminal_register_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/software_interrupt_returns.py \
	angr_platforms/angr_platforms/X86_16/structuring/scalar_return_evidence.py \
	angr_platforms/angr_platforms/X86_16/structuring/simple_loop_recovery.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_artifact_identity.py \
	angr_platforms/angr_platforms/X86_16/structuring/typed_switch_seqnode.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_selector_binding.py \
	angr_platforms/angr_platforms/X86_16/structuring/switch_definition_coverage.py \
	angr_platforms/angr_platforms/X86_16/structuring/wide_return_values.py \
	angr_platforms/angr_platforms/X86_16/structuring/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/__init__.py \
	angr_platforms/angr_platforms/X86_16/validation/canonicalize.py \
	angr_platforms/angr_platforms/X86_16/validation/callsite_completeness.py \
	angr_platforms/angr_platforms/X86_16/validation/status_flag_preservation.py \
	angr_platforms/angr_platforms/X86_16/validation_interrupt_calls.py \
	angr_platforms/angr_platforms/X86_16/widening_alias.py \
	angr_platforms/angr_platforms/X86_16/widening_model.py \
	angr_platforms/angr_platforms/X86_16/widening/__init__.py \
	angr_platforms/angr_platforms/X86_16/widening/global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/widening/direct_global_object_layout_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/global_object_layout_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_range_codec.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_ranges.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_layouts.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_recovery.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_solver.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_ranges.py \
	angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_layout.py \
	angr_platforms/angr_platforms/X86_16/widening/register_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_identity.py \
	angr_platforms/angr_platforms/X86_16/widening/segmented_load_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_argument_widths.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_word_register_transfers.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_widening.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_expression.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_projection.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_proof.py \
	angr_platforms/angr_platforms/X86_16/widening/stack_subview_coordinates.py \
	angr_platforms/angr_platforms/X86_16/widening/store_width.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_pipeline.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_storage.py \
	angr_platforms/angr_platforms/X86_16/widening/carry_borrow_values.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_memory_output_views.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_views.py \
	angr_platforms/angr_platforms/X86_16/widening/word_projection_recomposition.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_copyprop_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_memory_fold_8616.py \
	angr_platforms/angr_platforms/X86_16/widening/widening_rules.py \
	angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/contracts.py \
	angr_platforms/angr_platforms/X86_16/pipeline/errors.py \
	angr_platforms/angr_platforms/X86_16/pipeline/invariants.py \
	angr_platforms/angr_platforms/X86_16/pipeline/linear_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/recovery_coverage_guard.py \
	angr_platforms/angr_platforms/X86_16/pipeline/render_authority.py \
	inertia_decompiler/__init__.py \
	inertia_decompiler/acceptance_scorecard.py \
	inertia_decompiler/analysis_timeout.py \
	inertia_decompiler/architecture_import_attestation.py \
	inertia_decompiler/architecture_runtime_guard.py \
	inertia_decompiler/project_evidence_transport.py \
	inertia_decompiler/indexed_global_object_cache.py \
	inertia_decompiler/direct_global_object_cache.py \
	inertia_decompiler/direct_global_object_context.py \
	inertia_decompiler/serial_clean_worker_evidence.py \
	inertia_decompiler/cod_module_caller_evidence.py \
	inertia_decompiler/c_text_cleanup.py \
	inertia_decompiler/cache.py \
	inertia_decompiler/cache_io.py \
	inertia_decompiler/cache_lock.py \
	inertia_decompiler/cache_runtime_contract.py \
	inertia_decompiler/cache_source_manifest.py \
	inertia_decompiler/function_ir_ssa_source_scope.py \
	inertia_decompiler/program_callsite_cache.py \
	inertia_decompiler/direct_request_cache.py \
	inertia_decompiler/direct_request_fast_path.py \
	inertia_decompiler/direct_request_identity.py \
	inertia_decompiler/cli.py \
	inertia_decompiler/cli_core.py \
	inertia_decompiler/indexed_alias_program_context.py \
	inertia_decompiler/indexed_alias_program_publication.py \
	inertia_decompiler/indexed_alias_program_recovery.py \
	inertia_decompiler/indexed_alias_program_parallel.py \
	inertia_decompiler/project_argument_evidence_ranges.py \
	inertia_decompiler/serial_clean_worker_cli.py \
	inertia_decompiler/serial_worker_cache.py \
	inertia_decompiler/discovery_cache_contract.py \
	inertia_decompiler/segment_program_layout_reporting.py \
	inertia_decompiler/generated_c_artifacts.py \
	inertia_decompiler/cli_batch_c_output.py \
	inertia_decompiler/generated_external_function_contracts.py \
	inertia_decompiler/generated_c_function_extraction.py \
	inertia_decompiler/generated_translation_unit_assembly.py \
	inertia_decompiler/cli_decompilation.py \
	inertia_decompiler/cli_c_ast_rewrites.py \
	inertia_decompiler/cli_c_text_postprocess.py \
	inertia_decompiler/cli_fallback_decompilation.py \
	inertia_decompiler/cli_function_discovery.py \
	inertia_decompiler/function_graph_extent_repair.py \
	inertia_decompiler/cli_access_object_hints.py \
	inertia_decompiler/cli_access_profiles.py \
	inertia_decompiler/cli_access_traits.py \
	inertia_decompiler/cli_access_trait_rewrite.py \
	inertia_decompiler/cli_access_rewrite_artifact.py \
	inertia_decompiler/cli_arg_parser.py \
	inertia_decompiler/cli_cod_global_statements.py \
	inertia_decompiler/cli_cod_globals.py \
	inertia_decompiler/cli_dead_local_prune.py \
	inertia_decompiler/cli_semantic_rollback.py \
	inertia_decompiler/cli_helper_modeling.py \
	inertia_decompiler/cli_interrupt_modeling.py \
	inertia_decompiler/cli_linear_aliases.py \
	inertia_decompiler/cli_induction_rewrite.py \
	inertia_decompiler/cli_linear_recurrence.py \
	inertia_decompiler/cli_linear_recurrence_rules.py \
	inertia_decompiler/cli_linear_recurrence_state.py \
	inertia_decompiler/cli_mkfp_simplify.py \
	inertia_decompiler/cli_memory_prune.py \
	inertia_decompiler/cli_local_prune.py \
	inertia_decompiler/cli_local_rewrites.py \
	inertia_decompiler/cli_far_pointer_stack.py \
	inertia_decompiler/cli_segmented.py \
	inertia_decompiler/cli_segmented_compare.py \
	inertia_decompiler/cli_segmented_elision.py \
	inertia_decompiler/cli_segmented_load_coalesce.py \
	inertia_decompiler/cli_segmented_lowering.py \
	inertia_decompiler/cli_segmented_store_coalesce.py \
	inertia_decompiler/cli_stack_coalesce.py \
	inertia_decompiler/cli_stack_cvars.py \
	inertia_decompiler/cli_stack_byte_offsets.py \
	inertia_decompiler/cli_stack_locals.py \
	inertia_decompiler/cli_storage_objects.py \
	inertia_decompiler/cli_string_timeout_fallback.py \
	inertia_decompiler/cli_timeout.py \
	inertia_decompiler/cli_output.py \
	inertia_decompiler/cli_word_loads.py \
	inertia_decompiler/cli_word_global_helpers.py \
	inertia_decompiler/default_signature_catalog.py \
	inertia_decompiler/decompile_file_summary.py \
	inertia_decompiler/decompilation_quality.py \
	inertia_decompiler/direct_addr_failure_family.py \
	inertia_decompiler/direct_addr_stage_bundle.py \
	inertia_decompiler/discovery_evidence_project.py \
	inertia_decompiler/disassembly_helpers.py \
	inertia_decompiler/flair_paths.py \
	inertia_decompiler/fork_timeout.py \
	inertia_decompiler/function_cache_context.py \
	inertia_decompiler/gdb_client.py \
	inertia_decompiler/gdb_tui.py \
	inertia_decompiler/library_function_classifier.py \
	inertia_decompiler/debug_dos.py \
	inertia_decompiler/debugger_gdb.py \
	inertia_decompiler/signature_matching_policy.py \
	inertia_decompiler/msc51_local_hash.py \
	inertia_decompiler/non_optimized_fallback.py \
	inertia_decompiler/packer_detect.py \
	inertia_decompiler/project_loading.py \
	inertia_decompiler/prefork_job_pool.py \
	inertia_decompiler/rizin_evidence.py \
	inertia_decompiler/rizin_discovery.py \
	inertia_decompiler/recompile_check.py \
	inertia_decompiler/recompile_check_contract.py \
	inertia_decompiler/cli_terminal_status.py \
	inertia_decompiler/runtime_support.py \
	inertia_decompiler/sidecar_cache.py \
	inertia_decompiler/sidecar_metadata.py \
	inertia_decompiler/sidecar_policy.py \
	inertia_decompiler/sidecar_parsers.py \
	inertia_decompiler/slice_recovery.py \
	inertia_decompiler/source_sidecar.py \
	inertia_decompiler/tail_validation.py \
	inertia_decompiler/telemetry.py \
	inertia_decompiler/work_items.py \
	inertia_decompiler/tui_widgets.py \
	inertia_decompiler/variable_recovery_sub_guard.py \
	inertia_decompiler/x86_16_exact_slice.py \
	inertia_decompiler/monkeytype_tools.py \
	scripts/collect_monkeytype_pytest.py \
	scripts/apply_monkeytype_annotations.py \
	scripts/export_monkeytype_stubs.py \
	scripts/build_mypyc.py \
	scripts/build_cython_vex.py \
	scripts/benchmark_cython_vex.py \
	scripts/report_cython_vex.py \
	scripts/mypyc_build_cache.py \
	scripts/agent_context_check.py \
	scripts/agent_test_focus.py \
	scripts/batch_decompile_procs.py \
	scripts/build_debug_info_corpus.py \
	scripts/build_msc6_examples.py \
	scripts/msc6_compat_headers.py \
	scripts/msc6_entrypoint.py \
	scripts/msc6_function_targets.py \
	scripts/msc6_runtime_gate_artifacts.py \
	scripts/verify_msc_example_runtime_gate.py \
	scripts/compare_ghidra_function_coverage.py \
	scripts/check_changed_non_test_types.py \
	scripts/check_decompiler_architecture.py \
	scripts/check_sortd_sidecar_free.py \
	scripts/sortd_function_gate.py \
	scripts/runmenu_behavior.py \
	scripts/indexed_address_parity_inventory.py \
	scripts/check_generated_translation_unit.py \
	scripts/generated_translation_unit_assembly.py \
	scripts/check_sortd_generated_sort_core.py \
	scripts/generated_c_contracts.py \
	scripts/generated_c_indexed_argument_contract.py \
	scripts/generated_c_return_contract.py \
	scripts/import_ultra_quickc_fixtures.py \
	scripts/msc6_toolchain_lock.py \
	scripts/pytest_profile.py \
	scripts/pytest_assertion_facts.py \
	scripts/pytest_call_hints.py \
	scripts/pytest_cache_events.py \
	scripts/pytest_inventory_review.py \
	scripts/pytest_inventory_check.py \
	scripts/pytest_partition_execution.py \
	scripts/pytest_dynamic_schedule.py \
	scripts/pytest_partition_plugin.py \
	scripts/pytest_partitioned.py \
	scripts/pytest_test_inventory.py \
	scripts/pytest_test_record.py \
	scripts/pytest_process_metrics.py \
	scripts/pytest_resource_history.py \
	scripts/pytest_resource_scheduler.py \
	scripts/pytest_profile_merge.py \
	scripts/pytest_profile_rankings.py \
	scripts/pytest_source_state.py \
	scripts/pytest_source_index.py \
	scripts/pytest_source_structure.py \
	scripts/pytest_source_structure_cache.py \
	scripts/sortdemo_decompiler_status.py \
	scripts/test_pipeline.py \
	scripts/cod_stability_sweep.py \
	scripts/test_ownership_manifest.py \
	decompile.py \
	angr_platforms/tests/test_agent_context_check.py \
	angr_platforms/tests/test_cache_lock.py \
	angr_platforms/tests/test_function_ir_ssa_source_scope.py \
	angr_platforms/tests/test_x86_16_indexed_alias_cache_layers.py \
	angr_platforms/tests/test_program_callsite_cache.py \
	angr_platforms/tests/test_x86_16_gp_register_state.py \
	angr_platforms/tests/test_x86_16_gp_pointer_values.py \
	angr_platforms/tests/test_x86_16_pointer_fill_behavior.py \
	angr_platforms/tests/test_x86_16_pointer_sum_behavior.py \
	angr_platforms/tests/test_check_changed_non_test_types.py \
	angr_platforms/tests/test_cli_core_clinic_policy.py \
	angr_platforms/tests/test_fork_timeout.py \
	angr_platforms/tests/test_function_cache_context.py \
	angr_platforms/tests/test_cli_batch_c_output.py \
	angr_platforms/tests/test_x86_16_cli.py \
	angr_platforms/tests/test_x86_16_cr.py \
	angr_platforms/tests/test_x86_16_exception.py \
	angr_platforms/tests/test_x86_16_hardware.py \
	angr_platforms/tests/test_x86_16_simprocs_io.py \
	angr_platforms/tests/test_x86_16_debug_info_real_compilers.py \
	angr_platforms/tests/test_x86_16_debug.py \
	angr_platforms/tests/test_recompile_check_contract.py \
	angr_platforms/tests/test_x86_16_packed_mz.py \
	angr_platforms/tests/test_x86_16_pklite.py \
	angr_platforms/tests/test_cli_catalog_budget.py \
	angr_platforms/tests/test_missing_dos_toolchain.py \
	angr_platforms/tests/test_x86_16_dev_io.py \
	angr_platforms/tests/test_x86_16_io.py \
	angr_platforms/tests/test_x86_16_emulator.py \
	angr_platforms/tests/test_x86_16_pyvex_compat.py \
	angr_platforms/tests/test_x86_16_memory.py \
	angr_platforms/tests/test_x86_16_interrupt.py \
	angr_platforms/tests/test_x86_16_lowered_register_carriers.py \
		angr_platforms/tests/test_x86_16_stack_compat.py \
		angr_platforms/tests/test_x86_16_load_propagation.py \
		angr_platforms/tests/test_x86_16_stack_tracker_allocation.py \
		angr_platforms/tests/test_x86_16_stack_tracker_return_segment.py \
		angr_platforms/tests/test_x86_16_stack_address_operand_roles.py \
		angr_platforms/tests/test_x86_16_numeric_sp_call_return.py \
		angr_platforms/tests/test_x86_16_call_frame_compat.py \
		angr_platforms/tests/test_x86_16_callee_cleanup_compat.py \
		angr_platforms/tests/test_x86_16_stack_pointer_provenance.py \
		angr_platforms/tests/test_x86_16_ail_register_displacement.py \
		angr_platforms/tests/test_x86_16_codegen_parentheses.py \
		angr_platforms/tests/test_x86_16_local_declarations.py \
		angr_platforms/tests/test_x86_16_terminal_call_return_types.py \
		angr_platforms/tests/test_x86_16_seed_calling_dependencies.py \
		angr_platforms/tests/test_x86_16_stack_value_owner_identity.py \
		angr_platforms/tests/test_x86_16_tagged_terminal_return_values.py \
		angr_platforms/tests/test_recompile_check.py \
		angr_platforms/tests/test_msc6_runtime_state.py \
		angr_platforms/tests/test_x86_16_telemetry_support.py \
		angr_platforms/tests/test_x86_16_switch_segment_diagnostics.py \
		angr_platforms/tests/test_x86_16_codegen_metadata.py \
	angr_platforms/tests/test_x86_16_call_return_segment.py \
	angr_platforms/tests/test_x86_16_stack_pointer_width.py \
	angr_platforms/tests/test_x86_16_lifted_integer_constants.py \
	angr_platforms/tests/test_x86_16_correctness_goals.py \
	angr_platforms/tests/test_x86_16_readability_set.py \
	angr_platforms/tests/test_x86_16_readability_goals.py \
	angr_platforms/tests/test_x86_16_alias_domains.py \
	angr_platforms/tests/test_x86_16_condition_register_carriers.py \
	angr_platforms/tests/test_x86_16_semantics_exports.py \
	angr_platforms/tests/test_x86_16_alias_stack_lowering.py \
		angr_platforms/tests/test_x86_16_alias_state_transfer.py \
		angr_platforms/tests/test_x86_16_c_runtime_header.py \
		angr_platforms/tests/test_x86_16_object_lowering.py \
		angr_platforms/tests/test_x86_16_semantics_alias_query.py \
		angr_platforms/tests/test_x86_16_semantics_evidence_cache.py \
		angr_platforms/tests/test_x86_16_semantics_expression_analysis.py \
		angr_platforms/tests/test_x86_16_vex_logical_memory_accesses.py \
		angr_platforms/tests/x86_16_logical_memory_fixtures.py \
		angr_platforms/tests/test_x86_16_address_ir.py \
	angr_platforms/tests/test_x86_16_segment_contract.py \
	angr_platforms/tests/test_x86_16_segment_address_policy.py \
	angr_platforms/tests/test_x86_16_segment_access_coverage.py \
	angr_platforms/tests/test_x86_16_segment_access_policy.py \
	angr_platforms/tests/test_x86_16_segment_function_summary.py \
	angr_platforms/tests/test_x86_16_segment_program_layout.py \
	angr_platforms/tests/test_segment_program_layout_reporting.py \
	angr_platforms/tests/test_x86_16_stack_restore_constants.py \
	angr_platforms/tests/test_x86_16_ir_constant_known_lanes.py \
	angr_platforms/tests/test_x86_16_ir_constant_flow_refusals.py \
	angr_platforms/tests/test_x86_16_scalar_value_projection.py \
	angr_platforms/tests/test_x86_16_gp_restore_word_views.py \
	angr_platforms/tests/test_x86_16_gp_constant_restore.py \
	angr_platforms/tests/test_x86_16_segment_stack_restore.py \
	angr_platforms/tests/test_x86_16_stack_restore_ss_identity.py \
	angr_platforms/tests/test_x86_16_bp_preservation.py \
	angr_platforms/tests/test_x86_16_stack_restore_loops.py \
	angr_platforms/tests/test_x86_16_gp_restore_binding.py \
	angr_platforms/tests/test_x86_16_gp_stack_restore.py \
	angr_platforms/tests/test_segment_register_membership.py \
	angr_platforms/tests/test_x86_16_stack_memory_ssa_alias.py \
	angr_platforms/tests/test_x86_16_stack_address_escape.py \
	angr_platforms/tests/test_x86_16_private_stack_writes.py \
	angr_platforms/tests/test_x86_16_logical_frame_accesses.py \
	angr_platforms/tests/test_serial_clean_worker_cache.py \
	angr_platforms/tests/test_direct_request_cache.py \
	angr_platforms/tests/test_discovery_cache_contract.py \
	angr_platforms/tests/test_x86_16_segment_state.py \
	angr_platforms/tests/test_x86_16_segment_state_call_boundary.py \
	angr_platforms/tests/test_x86_16_segment_state_call_outputs.py \
	angr_platforms/tests/test_x86_16_vex_import.py \
	angr_platforms/tests/test_x86_16_entry_jump_domain.py \
	angr_platforms/tests/test_x86_16_invocation_domain.py \
	angr_platforms/tests/test_x86_16_invocation_domain_boundaries.py \
	angr_platforms/tests/test_x86_16_invocation_partition_census.py \
	angr_platforms/tests/test_x86_16_boot_call_prefix.py \
	angr_platforms/tests/test_x86_16_invocation_unused_premise.py \
	angr_platforms/tests/test_optimization_quality_guard_diagnostics.py \
	angr_platforms/tests/test_x86_16_vex_direct_constants.py \
	angr_platforms/tests/test_x86_16_vex_integer_displacement.py \
	angr_platforms/tests/test_x86_16_vex_bit_source.py \
	angr_platforms/tests/test_x86_16_vex_import_hot_path.py \
	angr_platforms/tests/test_x86_16_vex_import_cfg_successors.py \
	angr_platforms/tests/test_x86_16_sortd_indexed_loop_topology.py \
	angr_platforms/tests/test_x86_16_ssa_cfg.py \
	angr_platforms/tests/test_x86_16_logical_memory_write_value.py \
	angr_platforms/tests/test_x86_16_logical_constant_word_receipt.py \
	angr_platforms/tests/test_x86_16_stack_word_call_window.py \
	angr_platforms/tests/test_x86_16_stack_word_call_binding.py \
	angr_platforms/tests/test_x86_16_vex_memory_access_fidelity.py \
	angr_platforms/tests/test_x86_16_condition_rendering.py \
	angr_platforms/tests/test_x86_16_ir_readiness.py \
	angr_platforms/tests/test_x86_16_layer_module_status.py \
	angr_platforms/tests/test_x86_16_coverage_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifacts.py \
	angr_platforms/tests/test_x86_16_function_effect_summary.py \
	angr_platforms/tests/test_x86_16_function_graph_extent_repair.py \
	angr_platforms/tests/test_x86_16_graph_repair_leaders.py \
	angr_platforms/tests/test_x86_16_return_ip_provenance.py \
	angr_platforms/tests/test_x86_16_clinic_variable_recovery_contract.py \
	angr_platforms/tests/test_x86_16_ir_memory_call_liveness.py \
	angr_platforms/tests/test_x86_16_helper_effect_summary.py \
	angr_platforms/tests/test_x86_16_helper_family_routing.py \
	angr_platforms/tests/test_x86_16_function_interface_surface.py \
	angr_platforms/tests/test_x86_16_function_state_summary.py \
	angr_platforms/tests/test_x86_16_recovery_confidence_helper_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_cache.py \
	angr_platforms/tests/test_x86_16_ir_recovery_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_writer.py \
	angr_platforms/tests/test_x86_16_targeted_recovery_artifact.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsite_prototypes.py \
	inertia_decompiler/function_worker_policy.py \
	angr_platforms/tests/test_decompile_entrypoint_determinism.py \
	angr_platforms/tests/test_import_ultra_quickc_fixtures.py \
	angr_platforms/tests/test_generated_c_indexed_argument_contract.py \
	angr_platforms/tests/test_project_loading_cache.py \
	angr_platforms/tests/test_project_loading_diagnostics.py \
	angr_platforms/tests/test_cli_interrupt_call_boundary.py \
	angr_platforms/tests/test_function_work_item_contract.py \
	angr_platforms/tests/test_pytest_profile.py \
	angr_platforms/tests/test_parallel_job_defaults.py \
	angr_platforms/tests/test_pytest_partitioned.py \
	angr_platforms/tests/test_pytest_dynamic_schedule.py \
	angr_platforms/tests/test_pytest_process_metrics.py \
	angr_platforms/tests/test_pytest_resource_scheduler.py \
	angr_platforms/tests/test_pytest_source_state.py \
	angr_platforms/tests/test_pytest_source_index.py \
	angr_platforms/tests/test_decompiler_architecture_check.py \
	angr_platforms/tests/test_rizin_discovery.py \
		angr_platforms/tests/test_decompilation_quality.py \
		angr_platforms/tests/test_cli_regeneration.py \
		angr_platforms/tests/test_cli_segment_replay.py \
		angr_platforms/tests/test_agent_test_focus.py \
		angr_platforms/tests/test_test_ownership_manifest.py \
		angr_platforms/tests/test_test_ownership_validation.py \
		angr_platforms/tests/test_x86_16_carry_borrow_cfg.py \
		angr_platforms/tests/test_x86_16_carry_borrow_call_output.py \
		angr_platforms/tests/test_x86_16_wide_call_output_assignments.py \
		angr_platforms/tests/test_x86_16_carry_borrow_sources.py \
		angr_platforms/tests/test_x86_16_carry_borrow_stack_storage.py \
		angr_platforms/tests/test_x86_16_carry_borrow_widening.py \
		angr_platforms/tests/test_x86_16_call_outputs.py \
		angr_platforms/tests/test_x86_16_call_stack_effects.py \
		angr_platforms/tests/test_x86_16_synthetic_frame_call_effects.py \
		angr_platforms/tests/test_x86_16_call_stack_allocation_guard.py \
		angr_platforms/tests/test_x86_16_call_stack_allocation_proof.py \
		angr_platforms/tests/test_x86_16_stack_frame_register_alias.py \
		angr_platforms/tests/test_x86_16_entry_stack_bytes.py \
		angr_platforms/tests/test_x86_16_entry_stack_byte_refusals.py \
		angr_platforms/tests/test_x86_16_entry_stack_pointer_snapshots.py \
		angr_platforms/tests/test_x86_16_register_definition_return.py \
		angr_platforms/tests/test_x86_16_gp_stack_local_return.py \
		angr_platforms/tests/test_x86_16_codegen_return_origin.py \
		angr_platforms/tests/test_x86_16_callsite_inventory.py \
		angr_platforms/tests/test_x86_16_gp_stack_local_reload.py \
		angr_platforms/tests/test_x86_16_call_stack_logical_width.py \
		angr_platforms/tests/test_x86_16_call_stack_provenance.py \
		angr_platforms/tests/test_x86_16_partial_register_address_break.py \
		angr_platforms/tests/test_x86_16_function_ssa_registry.py \
		angr_platforms/tests/test_x86_16_stack_carrier_delta_cache.py \
		angr_platforms/tests/test_x86_16_instruction_bp_stack_access_index.py \
		angr_platforms/tests/test_x86_16_stack_variable_coordinates.py \
		angr_platforms/tests/test_x86_16_stack_variable_identifier_coordinates.py \
		angr_platforms/tests/test_x86_16_stack_frame_projection.py \
		angr_platforms/tests/test_x86_16_machine_stack_names.py \
		angr_platforms/tests/test_structured_simplifier_identity.py \
		angr_platforms/tests/test_x86_16_cli_c_ast_rewrites.py \
		angr_platforms/tests/test_x86_16_stack_word_load_materialization.py \
		angr_platforms/tests/test_x86_16_call_contracts.py \
		angr_platforms/tests/test_x86_16_calling_convention_compat.py \
		angr_platforms/tests/test_x86_16_call_execution_frame_carriers.py \
		angr_platforms/tests/test_x86_16_call_frame_base_effects.py \
		angr_platforms/tests/test_x86_16_call_output_stack_objects.py \
		angr_platforms/tests/test_x86_16_call_output_object_projection.py \
		angr_platforms/tests/test_x86_16_structuring_call_argument_joins.py \
		angr_platforms/tests/test_x86_16_call_return_conditions.py \
		angr_platforms/tests/test_x86_16_bound_call_condition.py \
		angr_platforms/tests/test_x86_16_call_result_zero_validation.py \
		angr_platforms/tests/test_x86_16_single_branch_return_orientation.py \
		angr_platforms/tests/test_x86_16_callsite_prototype_declarations.py \
		angr_platforms/tests/test_x86_16_call_argument_shape_publication.py \
		angr_platforms/tests/test_x86_16_callsite_pointer_tables.py \
		angr_platforms/tests/test_x86_16_signed_global_declarations.py \
		angr_platforms/tests/test_x86_16_condition_lowering.py \
		angr_platforms/tests/test_x86_16_condition_cache_relift.py \
		angr_platforms/tests/test_x86_16_condition_lift_capture.py \
		angr_platforms/tests/test_x86_16_function_condition_artifact.py \
		angr_platforms/tests/test_x86_16_return_liveness_replay.py \
		angr_platforms/tests/test_x86_16_condition_transfer.py \
		angr_platforms/tests/test_x86_16_condition_sign_extension.py \
		angr_platforms/tests/test_x86_16_condition_full_width_masks.py \
		angr_platforms/tests/test_x86_16_jcc_result_condition.py \
		angr_platforms/tests/test_x86_16_frontend_condition_evidence.py \
		angr_platforms/tests/test_x86_16_stack_condition_access_provenance.py \
		angr_platforms/tests/test_x86_16_frontend_direct_callsite_index.py \
		angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py \
		angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py \
		angr_platforms/tests/test_x86_16_jcc_register_evidence.py \
		angr_platforms/tests/test_x86_16_indexed_stack_ranges.py \
		angr_platforms/tests/test_x86_16_validation_canonicalize.py \
		angr_platforms/tests/test_x86_16_validation_loop_condition_ir.py \
		angr_platforms/tests/test_x86_16_validation_branch_conditions.py \
		angr_platforms/tests/test_x86_16_validation_condition_coverage.py \
		angr_platforms/tests/test_x86_16_composite_pretest_conditions.py \
		angr_platforms/tests/test_x86_16_existing_loop_exit_conditions.py \
		angr_platforms/tests/test_x86_16_terminal_loop_exit_conditions.py \
		angr_platforms/tests/test_x86_16_terminal_wide_validation.py \
		angr_platforms/tests/test_x86_16_render_compat.py \
		angr_platforms/tests/test_x86_16_structuring_condition_processor.py \
		angr_platforms/tests/test_x86_16_structuring_condition_ownership.py \
		angr_platforms/tests/test_x86_16_shared_loop_exit.py \
		angr_platforms/tests/test_x86_16_condition_decrement_fingerprints.py \
		angr_platforms/tests/test_x86_16_storage_or_fingerprints.py \
		angr_platforms/tests/test_x86_16_structured_tag_projection.py \
		angr_platforms/tests/test_x86_16_validation_additive_semantic_casts.py \
		angr_platforms/tests/test_x86_16_validation_control_flow.py \
		angr_platforms/tests/test_x86_16_validation_dataflow.py \
		angr_platforms/tests/test_x86_16_validation_call_multiplicity.py \
		angr_platforms/tests/test_x86_16_validation_semantic_failures.py \
		angr_platforms/tests/test_x86_16_validation_virtual_carriers.py \
		angr_platforms/tests/test_x86_16_validation_predicates.py \
		angr_platforms/tests/test_x86_16_validation_storage.py \
		angr_platforms/tests/test_x86_16_validation_required_memory_effects.py \
		angr_platforms/tests/test_x86_16_runtime_segment_access.py \
		angr_platforms/tests/test_x86_16_sortd_indexed_aggregate_regression.py \
		angr_platforms/tests/test_x86_16_sortd_menu_pointer_table.py \
	angr_platforms/tests/test_x86_16_validation_manifest.py \
	angr_platforms/tests/test_x86_16_validation_helper_report.py \
	angr_platforms/tests/test_x86_16_low_memory_regions.py \
	angr_platforms/tests/test_x86_16_recompilable_source_evidence.py \
	angr_platforms/tests/test_x86_16_recompilable_subset.py \
	angr_platforms/tests/test_x86_16_recompilable_storage_map.py \
		angr_platforms/tests/test_x86_16_recompilable_storage_objects.py \
		angr_platforms/tests/test_x86_16_structuring_grouping_report.py \
		angr_platforms/tests/test_x86_16_structuring_grouped_refusal_report.py \
		angr_platforms/tests/test_x86_16_structuring_condition_materialization.py \
		angr_platforms/tests/test_x86_16_condition_chain_refusal.py \
		angr_platforms/tests/test_x86_16_recorded_return_argument_replay.py \
		angr_platforms/tests/test_x86_16_stack_reload_instruction_ownership.py \
		angr_platforms/tests/test_x86_16_runtime_call_results.py \
		angr_platforms/tests/test_x86_16_inbox_long_live.py \
		angr_platforms/tests/test_x86_16_wide_return_condition_coverage.py \
		angr_platforms/tests/test_x86_16_condition_exit_normalization.py \
		angr_platforms/tests/test_x86_16_structuring_multi_arm_condition_ownership.py \
	angr_platforms/tests/test_x86_16_local_condition_regions.py \
		angr_platforms/tests/test_x86_16_wide_call_return_guard_chains.py \
		angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py \
		angr_platforms/tests/test_x86_16_structuring_sequences.py \
		angr_platforms/tests/test_x86_16_dce_optimization.py \
		angr_platforms/tests/test_x86_16_dce_noop_conditionals.py \
		angr_platforms/tests/test_x86_16_packed_flags_state.py \
		angr_platforms/tests/test_x86_16_flags_physical_register_contract.py \
		angr_platforms/tests/test_x86_16_dce_lvalue_reads.py \
		angr_platforms/tests/test_x86_16_dead_local_prune.py \
		angr_platforms/tests/test_x86_16_dead_local_structured_reads.py \
		angr_platforms/tests/test_x86_16_local_liveness.py \
		angr_platforms/tests/test_cli_semantic_rollback.py \
		angr_platforms/tests/test_x86_16_trivial_copy_optimization.py \
		angr_platforms/tests/test_x86_16_widening_copyprop.py \
		angr_platforms/tests/test_x86_16_widening_copyprop_width.py \
		angr_platforms/tests/test_x86_16_widening_memory_fold.py \
		angr_platforms/tests/test_x86_16_stack_subview_call_writes.py \
		angr_platforms/tests/test_x86_16_stack_subview_projection.py \
		angr_platforms/tests/test_x86_16_stack_subview_coordinates.py \
		angr_platforms/tests/test_x86_16_stack_subview_projection_wide.py \
		angr_platforms/tests/test_x86_16_indexed_load_subviews.py \
		angr_platforms/tests/test_makefile_quiet_output.py \
		angr_platforms/tests/test_x86_16_widening_rules.py \
		angr_platforms/tests/test_x86_16_far_load_access_width.py \
		angr_platforms/tests/test_x86_16_package_exports.py \
		angr_platforms/tests/test_x86_16_bootstrap_import_order.py \
		angr_platforms/tests/test_x86_16_sortd_sleep_regression.py \
		angr_platforms/tests/test_x86_16_pipeline_contracts.py \
	angr_platforms/tests/test_x86_16_rewrite_boundary.py \
	angr_platforms/tests/test_x86_16_heapsort_widening_regression.py \
	angr_platforms/tests/test_x86_16_global_declarations.py \
	angr_platforms/tests/test_x86_16_function_pointer_parameters.py \
	angr_platforms/tests/test_x86_16_callee_global_object_interface.py \
	angr_platforms/tests/test_x86_16_global_object_program_requirement.py \
	angr_platforms/tests/test_x86_16_callee_global_object_sources.py \
	angr_platforms/tests/test_x86_16_global_object_source_codec.py \
	angr_platforms/tests/test_x86_16_callee_pointer_evidence.py \
	angr_platforms/tests/test_x86_16_callee_pointer_codec.py \
	angr_platforms/tests/test_x86_16_callsite_summary_codec.py \
	angr_platforms/tests/test_x86_16_callsite_summary_program.py \
	angr_platforms/tests/test_x86_16_project_callee_callsite_collection.py \
	angr_platforms/tests/test_project_callee_callsite_transport.py \
	angr_platforms/tests/test_serial_clean_worker_callsite_evidence.py \
	angr_platforms/tests/test_project_argument_evidence_ranges.py \
	angr_platforms/tests/test_x86_16_project_global_object_source_collection.py \
	angr_platforms/tests/test_indexed_alias_source_collection_scope.py \
	angr_platforms/tests/test_project_global_source_evidence_transport.py \
	angr_platforms/tests/test_serial_clean_worker_global_source_evidence.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_branches.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_ownership_priority.py \
	angr_platforms/tests/test_x86_16_direct_stack_callsite_ownership.py \
	angr_platforms/tests/test_x86_16_direct_stack_replay.py \
	angr_platforms/tests/test_x86_16_direct_stack_reload_idempotence.py \
	angr_platforms/tests/test_x86_16_structuring_replay_generation.py \
	angr_platforms/tests/test_x86_16_structuring_lowering_order.py \
	angr_platforms/tests/test_x86_16_direct_global_store_prefilter.py \
	angr_platforms/tests/test_x86_16_pipeline_result_contracts.py \
	angr_platforms/tests/test_x86_16_postprocess_validation_policy.py \
	angr_platforms/tests/test_x86_16_postprocess_bootstrap_orchestration.py \
	angr_platforms/tests/test_x86_16_postprocess_pass_transaction.py \
	angr_platforms/tests/test_x86_16_postprocess_runtime_config.py \
	angr_platforms/tests/test_x86_16_postprocess_rollback_snapshot_cache.py \
	angr_platforms/tests/test_x86_16_control_flow_ast_index.py \
	angr_platforms/tests/test_x86_16_register_local_declarations.py \
	angr_platforms/tests/test_x86_16_runtime_memory_helpers.py \
	angr_platforms/tests/test_x86_16_indexed_stack_frame_terms.py \
	angr_platforms/tests/test_x86_16_loop_condition_materialization.py \
	angr_platforms/tests/test_x86_16_pretest_loop_condition_ownership.py \
	angr_platforms/tests/test_x86_16_loop_condition_block_identity.py \
	angr_platforms/tests/test_x86_16_nested_loop_behavior.py \
	angr_platforms/tests/test_x86_16_goto_accumulate_behavior.py \
	angr_platforms/tests/test_x86_16_stack_update_scope_guard.py \
	angr_platforms/tests/test_x86_16_instruction_fragment_placement.py \
	angr_platforms/tests/test_x86_16_call_return_stack_stores.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_loop_entries.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_pretest_body.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_pretest_initializers.py \
	angr_platforms/tests/test_x86_16_stack_probe_local_preservation.py \
	angr_platforms/tests/test_x86_16_casted_loop_induction.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_loops.py \
	angr_platforms/tests/test_x86_16_direct_stack_update_groups.py \
	angr_platforms/tests/test_x86_16_indexed_address_copies.py \
	angr_platforms/tests/test_x86_16_indexed_address_evidence.py \
	angr_platforms/tests/test_x86_16_indexed_address_aliases.py \
	angr_platforms/tests/test_x86_16_indexed_address_range_candidates.py \
	angr_platforms/tests/test_x86_16_indexed_global_object_program_ranges.py \
	angr_platforms/tests/test_x86_16_indexed_global_object_ranges.py \
	angr_platforms/tests/test_x86_16_bounded_global_array_declarations.py \
	angr_platforms/tests/x86_16_indexed_global_object_range_fixtures.py \
	angr_platforms/tests/test_x86_16_indexed_address_collector_parity.py \
		angr_platforms/tests/test_x86_16_indexed_address_parity_inventory.py \
		angr_platforms/tests/test_x86_16_sortd_indexed_address_parity_inventory.py \
		angr_platforms/tests/test_x86_16_alias_global_object_layout.py \
		angr_platforms/tests/test_indexed_alias_program_parallel.py \
		angr_platforms/tests/test_x86_16_global_object_layout.py \
	angr_platforms/tests/test_x86_16_project_type_contracts.py \
	angr_platforms/tests/test_x86_16_cod_global_identity.py \
	angr_platforms/tests/test_x86_16_segmented_global_loads.py \
	angr_platforms/tests/test_x86_16_wide_store_call_preservation.py \
	angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py \
	angr_platforms/tests/test_x86_16_ir_segmented_load_carriers.py \
	angr_platforms/tests/test_x86_16_reload_provenance_boundaries.py \
	angr_platforms/tests/test_generic_annotation_contracts.py \
	angr_platforms/tests/test_access_trait_runtime_factory.py \
	angr_platforms/tests/test_frame_carrier_type_contracts.py \
	angr_platforms/tests/test_makefile_inventory.py \
	angr_platforms/tests/test_mypy_import_contracts.py \
	angr_platforms/tests/test_x86_16_layer_boundaries.py \
	angr_platforms/tests/test_x86_16_pointer_store_fold_safety.py \
	angr_platforms/tests/test_x86_16_near_pointer_argument_evidence.py \
	angr_platforms/tests/test_x86_16_near_pointer_index_binding.py \
	angr_platforms/tests/test_x86_16_annotation_argument_identity.py \
	angr_platforms/tests/test_x86_16_assignment_lvalue_casts.py \
	angr_platforms/tests/test_x86_16_stack_byte_writes.py \
	angr_platforms/tests/test_x86_16_instruction_stack_write_width.py \
	angr_platforms/tests/test_x86_16_semantic_cast.py \
	angr_platforms/tests/test_x86_16_condition_operand_signedness.py \
	angr_platforms/tests/test_x86_16_condition_signedness_storage_width.py \
	angr_platforms/tests/test_x86_16_validation_argument_coordinates.py \
	angr_platforms/tests/test_x86_16_condition_storage_views.py \
	angr_platforms/tests/test_x86_16_wide_stack_pair_coordinates.py \
	angr_platforms/tests/test_x86_16_direct_stack_access_widths.py \
	angr_platforms/tests/test_x86_16_stack_address_coordinates.py \
	angr_platforms/tests/test_x86_16_native_stack_anchor.py \
	angr_platforms/tests/test_x86_16_runtime_push_carrier.py \
	angr_platforms/tests/test_x86_16_storage_prototype_snapshot.py \
	angr_platforms/tests/test_x86_16_frame_prologue_carriers.py \
	angr_platforms/tests/test_x86_16_frame_byte_carriers.py \
	angr_platforms/tests/test_x86_16_native_segment_live_out.py \
	angr_platforms/tests/test_x86_16_native_terminal_return_values.py \
	angr_platforms/tests/test_x86_16_native_unsigned_constant_casts.py \
	angr_platforms/tests/test_x86_16_loadprogram_behavior.py \
	angr_platforms/tests/test_x86_16_configcrts_behavior.py \
	angr_platforms/tests/test_x86_16_mset_pos_behavior.py \
	angr_platforms/tests/test_x86_16_changeweather_behavior.py \
	angr_platforms/tests/test_x86_16_mouse_position_behavior.py \
	angr_platforms/tests/test_x86_16_native_integer_operations.py \
	angr_platforms/tests/test_x86_16_ail_remainder.py \
	angr_platforms/tests/test_x86_16_stack_reference_offsets.py \
	angr_platforms/tests/test_x86_16_les_stack_argument_behavior.py \
	angr_platforms/tests/test_x86_16_segment_stack_restore_carriers.py \
	angr_platforms/tests/test_x86_16_far_return_boundary_carriers.py \
	angr_platforms/tests/test_x86_16_string_corpus_anchors.py \
	angr_platforms/tests/test_x86_16_ss_traversal_contract.py \
	angr_platforms/tests/test_x86_16_stack_prototype_wrapped_locals.py \
	angr_platforms/tests/test_x86_16_ast_traversal_coverage.py \
	angr_platforms/tests/test_x86_16_msetpos_behavior.py \
	angr_platforms/tests/test_x86_16_gp_livein_authority.py \
	angr_platforms/tests/test_x86_16_anonymous_store_width.py \
	angr_platforms/tests/test_x86_16_ssa_register_displacements.py \
	angr_platforms/tests/test_x86_16_stack_coordinate_conflicts.py \
	angr_platforms/tests/test_x86_16_escaped_stack_validation.py \
	angr_platforms/tests/test_x86_16_bios_strict_compilation.py \
	angr_platforms/tests/test_x86_16_rep_store_codegen.py \
	angr_platforms/tests/test_x86_16_runtime_store_scope.py \
	angr_platforms/tests/test_x86_16_string_timeout_fallback.py \
	angr_platforms/tests/test_x86_16_ir_memory_byte_ssa.py \
	angr_platforms/tests/test_x86_16_string_codegen_override.py \
	angr_platforms/tests/test_cli_codegen_policy.py \
	angr_platforms/tests/test_x86_16_segment_call_effects.py \
	angr_platforms/tests/test_x86_16_frame_carrier_liveness.py \
	angr_platforms/tests/test_x86_16_unobserved_return_maker.py \
	angr_platforms/tests/test_x86_16_dosfunc_behavior.py \
	angr_platforms/tests/test_x86_16_heapsort_behavior.py \
	angr_platforms/tests/x86_16_heapsort_behavior.py \
	angr_platforms/tests/test_x86_16_quicksort_behavior.py \
	angr_platforms/tests/x86_16_quicksort_behavior.py \
	angr_platforms/tests/test_x86_16_sleep_behavior.py \
	angr_platforms/tests/test_x86_16_insertionsort_behavior.py \
	angr_platforms/tests/test_x86_16_swapbars_behavior.py \
	angr_platforms/tests/test_x86_16_gp_word_runtime.py \
	angr_platforms/tests/test_x86_16_gp_word_assignment.py \
	angr_platforms/tests/x86_16_swapbars_behavior.py \
	angr_platforms/tests/x86_16_sleep_behavior.py \
	angr_platforms/tests/test_x86_16_reinitbars_execution.py \
	angr_platforms/tests/x86_16_reinitbars_execution.py \
	angr_platforms/tests/x86_16_runmenu_execution.py \
	angr_platforms/tests/test_x86_16_setgear_behavior.py \
	angr_platforms/tests/test_x86_16_tidshowrange_behavior.py \
	angr_platforms/tests/x86_16_tidshowrange_behavior.py \
	angr_platforms/tests/x86_16_setgear_behavior.py \
	angr_platforms/tests/test_x86_16_address_base_snapshots.py \
	angr_platforms/tests/test_x86_16_memory_ssa_address_provenance.py \
	angr_platforms/tests/test_x86_16_ir_stack_frame.py \
	angr_platforms/tests/test_x86_16_consumed_push_lvalues.py \
	angr_platforms/tests/test_x86_16_stack_aggregate_objects.py \
	angr_platforms/tests/test_x86_16_stack_prototype_codegen_api.py \
	angr_platforms/tests/test_x86_16_stack_aggregate_coordinate_replay.py \
	angr_platforms/tests/test_x86_16_positive_bp_argument_plan.py \
	angr_platforms/tests/test_x86_16_stack_argument_identity.py \
	angr_platforms/tests/test_x86_16_projected_stack_argument_identity.py \
	angr_platforms/tests/test_x86_16_stack_declaration_identity.py \
	angr_platforms/tests/test_x86_16_stack_lowering_contracts.py \
	angr_platforms/tests/test_x86_16_stack_memory_object_widening.py \
	angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py \
	angr_platforms/tests/test_x86_16_stack_memory_ssa_safety.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py \
	angr_platforms/tests/test_x86_16_interprocedural_memory_output_objects.py \
	angr_platforms/tests/test_x86_16_interprocedural_memory_output_validation.py \
	angr_platforms/tests/test_x86_16_pointer_parameter_memory_outputs.py \
	angr_platforms/tests/test_x86_16_pointer_parameter_object_types.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_pipeline.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_expression_defs.py \
	angr_platforms/tests/test_x86_16_scalar_affine_trace.py \
	angr_platforms/tests/test_x86_16_affine_indexed_address.py \
	angr_platforms/tests/test_x86_16_affine_induction_role.py \
	angr_platforms/tests/test_x86_16_frame_register_livein.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_defs.py \
	angr_platforms/tests/test_x86_16_call_target_ssa_binding.py \
	angr_platforms/tests/test_x86_16_call_target_evidence_retention.py \
	angr_platforms/tests/test_x86_16_cython_backend.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_passthrough.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_cfg.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_stack.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_split.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py \
	angr_platforms/tests/test_x86_16_return_witness_addresses.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_types.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py \
	angr_platforms/tests/test_x86_16_terminal_memory_outputs.py \
	angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py \
	angr_platforms/tests/test_x86_16_terminal_memory_output_views.py \
	angr_platforms/tests/test_x86_16_terminal_pointer_outputs.py \
	angr_platforms/tests/test_x86_16_conditional_pointer_output_native.py \
	angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py \
	angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py \
	angr_platforms/tests/test_x86_16_terminal_pointer_output_views.py \
	angr_platforms/tests/test_x86_16_unused_void_return_types.py \
	angr_platforms/tests/test_x86_16_decompilation_cache_surface.py \
	angr_platforms/tests/test_check_sortd_sidecar_free.py \
	angr_platforms/tests/test_sortd_drawtime_gate.py \
	angr_platforms/tests/test_runmenu_execution_evidence.py \
	angr_platforms/tests/test_compare_ghidra_function_coverage.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py \
	angr_platforms/tests/test_x86_16_generated_c_acceptance.py \
	angr_platforms/tests/test_x86_16_corpus_scan_timeout.py \
	angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py \
	angr_platforms/tests/test_x86_16_branch_return_expressions.py \
	angr_platforms/tests/test_x86_16_condition_argument_types.py \
	angr_platforms/tests/test_x86_16_typed_condition_side_effect_preservation.py \
	angr_platforms/tests/test_x86_16_validation_condition_precision.py \
	angr_platforms/tests/test_x86_16_msc6_cmp32_regression.py \
	angr_platforms/tests/test_x86_16_msc6_regressions.py \
	angr_platforms/tests/test_x86_16_multi_arm_return_chains.py \
	angr_platforms/tests/test_x86_16_scalar_return_evidence.py \
	angr_platforms/tests/test_x86_16_scalar_return_types.py \
	angr_platforms/tests/test_x86_16_return_chain_condition_selection.py \
	angr_platforms/tests/test_x86_16_structuring_return_chains.py \
	angr_platforms/tests/test_x86_16_selector_return_projection.py \
	angr_platforms/tests/test_x86_16_mask_accumulator_effects.py \
	angr_platforms/tests/test_x86_16_global_sum_effects.py \
	angr_platforms/tests/test_cli_assignment_effect_preservation.py \
	angr_platforms/tests/test_msc_storage_carry_oracle.py \
	angr_platforms/tests/test_x86_16_total_return_suffixes.py \
	angr_platforms/tests/test_x86_16_switch_loop_tail_breaks.py \
	angr_platforms/tests/test_x86_16_wide_stack_condition_chains.py \
	angr_platforms/tests/test_x86_16_wide_condition_ordering.py \
	angr_platforms/tests/test_x86_16_wide_call_condition_source.py \
	angr_platforms/tests/test_x86_16_wide_call_condition_capture.py \
	angr_platforms/tests/test_x86_16_wide_return_type_preservation.py \
	angr_platforms/tests/test_x86_16_positive_bp_wide_arguments.py \
	angr_platforms/tests/test_x86_16_cod_regressions.py \
	angr_platforms/tests/test_x86_16_wide_call_condition_plan.py \
	angr_platforms/tests/test_x86_16_wide_condition_provenance.py \
	inertia_decompiler/accepted_payload_integrity.py \
	inertia_decompiler/angr_codegen_tags.py \
	angr_platforms/angr_platforms/X86_16/alias/condition_register_bindings.py \
	angr_platforms/angr_platforms/X86_16/callsite_register_instruction_facts.py \
	angr_platforms/angr_platforms/X86_16/lowering/consumed_call_push_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_instruction_evidence.py \
	angr_platforms/angr_platforms/X86_16/lowering/frame_register_carriers.py \
	angr_platforms/angr_platforms/X86_16/structured_tags.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_branch_carriers.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_conditions.py \
	angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_joins.py \
	angr_platforms/angr_platforms/X86_16/verification_80386.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_layout.py \
	angr_platforms/angr_platforms/X86_16/msvc_x87_interrupts.py \
	angr_platforms/angr_platforms/X86_16/structuring/boolean_condition_ites.py \
	angr_platforms/angr_platforms/X86_16/alias/logical_stack_storage_identity.py \
	angr_platforms/angr_platforms/X86_16/ir/logical_memory_scalar_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_global_register_updates.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_global_register_update_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/direct_stack_segmented_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/logical_word_memory_copy_materialization.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_frame_projection.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_word_recomposition.py \
	angr_platforms/angr_platforms/X86_16/widening/logical_word_memory_copies.py \
	angr_platforms/tests/test_x86_16_boolean_condition_ites.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_indexed_use.py \
	angr_platforms/tests/test_x86_16_msvc_x87_interrupts.py \
	angr_platforms/tests/test_x86_16_return_stack_address_compat.py \
	angr_platforms/tests/test_x86_16_stack_prototype_layout.py \
	angr_platforms/tests/test_accepted_payload_integrity.py \
	angr_platforms/tests/test_acceptance_scorecard.py \
	angr_platforms/tests/test_tail_validation_display_outcome.py \
	angr_platforms/angr_platforms/X86_16/frontend_indirect_jump_targets.py \
	angr_platforms/angr_platforms/X86_16/lowering/balanced_memory_stack_restore.py \
	angr_platforms/angr_platforms/X86_16/lowering/caller_observed_byte_return_types.py \
	angr_platforms/angr_platforms/X86_16/lowering/control_stack_escape.py \
	angr_platforms/angr_platforms/X86_16/lowering/direction_flag_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_collection.py \
	angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_collection_contracts.py \
	angr_platforms/angr_platforms/X86_16/lowering/packed_flags_state.py \
	angr_platforms/angr_platforms/X86_16/lowering/packed_flags_liveness.py \
	angr_platforms/angr_platforms/X86_16/lowering/packed_flags_calls.py \
	angr_platforms/angr_platforms/X86_16/lowering/far_return_boundary_carriers.py \
	angr_platforms/angr_platforms/X86_16/lowering/segment_stack_restore_carriers.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_chain_provenance.py \
	angr_platforms/angr_platforms/X86_16/structuring/condition_evidence_closure.py \
	angr_platforms/angr_platforms/X86_16/structuring/pretest_condition_surface.py \
	angr_platforms/angr_platforms/X86_16/validation_condition_closure_delta.py \
	angr_platforms/angr_platforms/X86_16/validation_observable_compaction.py \
	angr_platforms/angr_platforms/X86_16/validation_pointer_parameter_output_contracts.py \
	angr_platforms/angr_platforms/X86_16/validation_pointer_parameter_outputs.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_restore.py \
	angr_platforms/angr_platforms/X86_16/lowering/gp_stack_restore_identity.py \
	angr_platforms/angr_platforms/X86_16/lowering/stack_value_projection.py \
	angr_platforms/angr_platforms/X86_16/validation/entry_stack_ranges.py \
	inertia_decompiler/cache_file_digest.py \
	inertia_decompiler/direct_indexed_alias_local_cache.py \
	inertia_decompiler/function_ir_ssa_cache.py \
	inertia_decompiler/function_ir_ssa_cache_codec.py \
	inertia_decompiler/function_ir_ssa_cache_identity.py

QA_RUFF_TARGETS += \
	angr_platforms/tests/test_x86_16_materialized_condition_storage.py \
	angr_platforms/tests/test_x86_16_stored_call_result_assignments.py \
	angr_platforms/tests/test_x86_16_stored_call_result_definitions.py \
	angr_platforms/tests/test_x86_16_clinic_semantic_stages.py

QA_PYTEST_TARGETS := \
	angr_platforms/tests/test_x86_16_gp_constant_restore.py \
	angr_platforms/tests/test_x86_16_segmented_load_origins.py \
	angr_platforms/tests/test_x86_16_envsize_behavior.py \
	angr_platforms/tests/test_x86_16_ir_instruction_origin.py \
	angr_platforms/tests/test_x86_16_stack_restore_constants.py \
	angr_platforms/tests/test_x86_16_ir_constant_known_lanes.py \
	angr_platforms/tests/test_x86_16_ir_constant_flow_refusals.py \
	angr_platforms/tests/test_x86_16_gp_restore_word_views.py \
	angr_platforms/tests/test_x86_16_stored_call_result_assignments.py \
	angr_platforms/tests/test_x86_16_stored_call_result_definitions.py \
	angr_platforms/tests/test_x86_16_gp_partial_live_in.py \
	angr_platforms/tests/test_x86_16_callsite_return_use_zero_idiom.py \
	angr_platforms/tests/test_x86_16_layer_boundaries.py::test_quality_and_diagnostics_modules_are_wired_into_production_paths \
	angr_platforms/tests/test_x86_16_layer_boundaries.py::test_layer_module_admission_status_matches_production_imports \
	angr_platforms/tests/test_x86_16_layer_boundaries.py::test_quality_compatibility_exports_retain_canonical_identity \
	angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_dos_loadprogram_wrapper_keeps_err_guard_and_segment_stores \
	angr_platforms/tests/test_cod_openfilewrapper_consolidation.py \
	angr_platforms/tests/test_function_ir_ssa_source_scope.py \
	angr_platforms/tests/test_x86_16_indexed_alias_cache_layers.py \
	angr_platforms/tests/test_program_callsite_cache.py \
	angr_platforms/tests/test_x86_16_clinic_semantic_stages.py \
	angr_platforms/tests/test_x86_16_gp_register_state.py \
	angr_platforms/tests/test_x86_16_gp_pointer_values.py \
	angr_platforms/tests/test_x86_16_pointer_fill_behavior.py \
	angr_platforms/tests/test_x86_16_pointer_sum_behavior.py \
	angr_platforms/tests/test_agent_context_check.py \
	angr_platforms/tests/test_x86_16_caller_return_use_contracts.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py \
	angr_platforms/tests/test_x86_16_interprocedural_memory_output_objects.py \
	angr_platforms/tests/test_x86_16_interprocedural_memory_output_validation.py \
	angr_platforms/tests/test_x86_16_pointer_parameter_memory_outputs.py \
	angr_platforms/tests/test_x86_16_pointer_parameter_object_types.py \
	angr_platforms/tests/test_x86_16_direct_stack_replay.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_pipeline.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_expression_defs.py \
	angr_platforms/tests/test_x86_16_scalar_affine_trace.py \
	angr_platforms/tests/test_x86_16_affine_indexed_address.py \
	angr_platforms/tests/test_x86_16_affine_induction_role.py \
	angr_platforms/tests/test_x86_16_frame_register_livein.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_defs.py \
	angr_platforms/tests/test_x86_16_call_target_ssa_binding.py \
	angr_platforms/tests/test_x86_16_call_target_evidence_retention.py \
	angr_platforms/tests/test_x86_16_cython_backend.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_passthrough.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_cfg.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_stack.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_split.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py \
	angr_platforms/tests/test_x86_16_return_witness_addresses.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_return_types.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py \
	angr_platforms/tests/test_x86_16_carry_borrow_cfg.py \
	angr_platforms/tests/test_x86_16_carry_borrow_call_output.py \
	angr_platforms/tests/test_x86_16_wide_call_output_assignments.py \
	angr_platforms/tests/test_x86_16_vex_logical_memory_accesses.py \
	angr_platforms/tests/test_x86_16_carry_borrow_sources.py \
	angr_platforms/tests/test_x86_16_carry_borrow_stack_storage.py \
	angr_platforms/tests/test_x86_16_carry_borrow_widening.py \
	angr_platforms/tests/test_x86_16_call_outputs.py \
	angr_platforms/tests/test_x86_16_call_stack_effects.py \
	angr_platforms/tests/test_x86_16_synthetic_frame_call_effects.py \
	angr_platforms/tests/test_x86_16_call_stack_allocation_guard.py \
	angr_platforms/tests/test_x86_16_call_stack_allocation_proof.py \
	angr_platforms/tests/test_x86_16_stack_frame_register_alias.py \
	angr_platforms/tests/test_x86_16_entry_stack_bytes.py \
	angr_platforms/tests/test_x86_16_entry_stack_byte_refusals.py \
	angr_platforms/tests/test_x86_16_entry_stack_pointer_snapshots.py \
	angr_platforms/tests/test_x86_16_register_definition_return.py \
	angr_platforms/tests/test_x86_16_gp_stack_local_return.py \
	angr_platforms/tests/test_x86_16_codegen_return_origin.py \
	angr_platforms/tests/test_x86_16_callsite_inventory.py \
	angr_platforms/tests/test_x86_16_gp_stack_local_reload.py \
	angr_platforms/tests/test_x86_16_call_stack_logical_width.py \
	angr_platforms/tests/test_x86_16_call_stack_provenance.py \
	angr_platforms/tests/test_x86_16_partial_register_address_break.py \
	angr_platforms/tests/test_x86_16_function_ssa_registry.py \
	angr_platforms/tests/test_x86_16_stack_carrier_delta_cache.py \
	angr_platforms/tests/test_x86_16_instruction_bp_stack_access_index.py \
	angr_platforms/tests/test_x86_16_stack_variable_coordinates.py \
	angr_platforms/tests/test_x86_16_stack_variable_identifier_coordinates.py \
	angr_platforms/tests/test_x86_16_stack_frame_projection.py \
	angr_platforms/tests/test_x86_16_machine_stack_names.py \
	angr_platforms/tests/test_structured_simplifier_identity.py \
	angr_platforms/tests/test_x86_16_cli_c_ast_rewrites.py \
	angr_platforms/tests/test_x86_16_stack_word_load_materialization.py \
	angr_platforms/tests/test_x86_16_terminal_memory_outputs.py \
	angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py \
	angr_platforms/tests/test_x86_16_terminal_memory_output_views.py \
	angr_platforms/tests/test_x86_16_terminal_pointer_outputs.py \
	angr_platforms/tests/test_x86_16_conditional_pointer_output_native.py \
	angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::test_every_store_site_binds_to_one_exact_positive_bp_parameter \
	angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::test_unknown_or_non_parameter_source_refuses_atomically \
	angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::test_competing_parameter_sources_refuse_without_partial_fact \
	angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py \
	angr_platforms/tests/test_x86_16_terminal_pointer_output_views.py \
	angr_platforms/tests/test_x86_16_smoketest.py \
	angr_platforms/tests/test_check_changed_non_test_types.py \
	angr_platforms/tests/test_cli_batch_c_output.py \
	angr_platforms/tests/test_cli_direct_argument_evidence_context.py \
	angr_platforms/tests/test_generated_c_artifacts.py \
	angr_platforms/tests/test_generated_translation_unit_assembly.py \
	angr_platforms/tests/test_generated_translation_unit_gate.py \
	angr_platforms/tests/test_x86_16_callee_name_normalization.py \
	angr_platforms/tests/test_x86_16_cr.py \
	angr_platforms/tests/test_x86_16_exception.py \
	angr_platforms/tests/test_x86_16_hardware.py \
	angr_platforms/tests/test_x86_16_simprocs_io.py \
	angr_platforms/tests/test_x86_16_debug.py \
	angr_platforms/tests/test_recompile_check_contract.py \
	angr_platforms/tests/test_x86_16_packed_mz.py \
	angr_platforms/tests/test_x86_16_dev_io.py \
	angr_platforms/tests/test_x86_16_io.py \
	angr_platforms/tests/test_x86_16_emulator.py \
	angr_platforms/tests/test_x86_16_memory.py \
	angr_platforms/tests/test_x86_16_interrupt.py \
	angr_platforms/tests/test_x86_16_stack_compat.py \
	angr_platforms/tests/test_x86_16_load_propagation.py \
	angr_platforms/tests/test_x86_16_stack_tracker_allocation.py \
	angr_platforms/tests/test_x86_16_stack_tracker_return_segment.py \
	angr_platforms/tests/test_x86_16_stack_address_operand_roles.py \
	angr_platforms/tests/test_x86_16_numeric_sp_call_return.py \
	angr_platforms/tests/test_x86_16_call_frame_compat.py \
	angr_platforms/tests/test_x86_16_callee_cleanup_compat.py \
	angr_platforms/tests/test_x86_16_stack_pointer_provenance.py \
	angr_platforms/tests/test_x86_16_stack_extent_evidence.py \
	angr_platforms/tests/test_x86_16_logical_frame_accesses.py \
	angr_platforms/tests/test_x86_16_ir_terminal_control_flow.py \
	angr_platforms/tests/test_x86_16_ail_register_displacement.py \
	angr_platforms/tests/test_x86_16_codegen_parentheses.py \
	angr_platforms/tests/test_x86_16_local_declarations.py \
	angr_platforms/tests/test_x86_16_terminal_call_return_types.py \
	angr_platforms/tests/test_x86_16_seed_calling_dependencies.py \
	angr_platforms/tests/test_x86_16_stack_value_owner_identity.py \
	angr_platforms/tests/test_x86_16_tagged_terminal_return_values.py \
	angr_platforms/tests/test_recompile_check.py \
	angr_platforms/tests/test_msc6_runtime_state.py \
	angr_platforms/tests/test_x86_16_telemetry_support.py \
	angr_platforms/tests/test_x86_16_switch_segment_diagnostics.py \
	angr_platforms/tests/test_x86_16_codegen_metadata.py \
	angr_platforms/tests/test_x86_16_call_return_segment.py \
	angr_platforms/tests/test_x86_16_stack_pointer_width.py \
	angr_platforms/tests/test_x86_16_lifted_integer_constants.py \
	angr_platforms/tests/test_x86_16_correctness_goals.py \
	angr_platforms/tests/test_x86_16_readability_set.py \
	angr_platforms/tests/test_x86_16_readability_goals.py \
	angr_platforms/tests/test_x86_16_alias_domains.py \
	angr_platforms/tests/test_x86_16_condition_register_carriers.py \
	angr_platforms/tests/test_x86_16_semantics_exports.py \
	angr_platforms/tests/test_x86_16_alias_stack_lowering.py \
	angr_platforms/tests/test_x86_16_alias_state_transfer.py \
	angr_platforms/tests/test_x86_16_alu_helpers.py \
	angr_platforms/tests/test_x86_16_c_runtime_header.py \
	angr_platforms/tests/test_x86_16_call_return_selectors.py \
	angr_platforms/tests/test_x86_16_register_local_declarations.py \
	angr_platforms/tests/test_x86_16_object_lowering.py \
	angr_platforms/tests/test_x86_16_semantics_alias_query.py \
	angr_platforms/tests/test_x86_16_semantics_evidence_cache.py \
	angr_platforms/tests/test_x86_16_semantics_expression_analysis.py \
	angr_platforms/tests/test_x86_16_stack_frame_recovery.py \
	angr_platforms/tests/test_x86_16_segmented_lowering.py \
	angr_platforms/tests/test_x86_16_address_ir.py \
	angr_platforms/tests/test_x86_16_segment_contract.py \
	angr_platforms/tests/test_x86_16_segment_address_policy.py \
	angr_platforms/tests/test_x86_16_segment_access_coverage.py \
	angr_platforms/tests/test_x86_16_segment_access_policy.py \
	angr_platforms/tests/test_x86_16_segment_function_summary.py \
	angr_platforms/tests/test_x86_16_segment_program_layout.py \
	angr_platforms/tests/test_segment_program_layout_reporting.py \
	angr_platforms/tests/test_x86_16_segment_stack_restore.py \
	angr_platforms/tests/test_x86_16_stack_restore_ss_identity.py \
	angr_platforms/tests/test_x86_16_bp_preservation.py \
	angr_platforms/tests/test_x86_16_stack_restore_loops.py \
	angr_platforms/tests/test_x86_16_gp_restore_binding.py \
	angr_platforms/tests/test_x86_16_gp_stack_restore.py \
	angr_platforms/tests/test_segment_register_membership.py \
	angr_platforms/tests/test_x86_16_stack_memory_ssa_alias.py \
	angr_platforms/tests/test_x86_16_stack_address_escape.py \
	angr_platforms/tests/test_x86_16_private_stack_writes.py \
	angr_platforms/tests/test_serial_clean_worker_cache.py \
	angr_platforms/tests/test_direct_request_cache.py \
	angr_platforms/tests/test_discovery_cache_contract.py \
	angr_platforms/tests/test_x86_16_segment_state.py \
	angr_platforms/tests/test_x86_16_segment_state_call_boundary.py \
	angr_platforms/tests/test_x86_16_segment_state_call_outputs.py \
	angr_platforms/tests/test_x86_16_vex_import.py \
	angr_platforms/tests/test_x86_16_entry_jump_domain.py \
	angr_platforms/tests/test_x86_16_invocation_domain.py \
	angr_platforms/tests/test_x86_16_invocation_domain_boundaries.py \
	angr_platforms/tests/test_x86_16_invocation_partition_census.py \
	angr_platforms/tests/test_x86_16_boot_call_prefix.py \
	angr_platforms/tests/test_x86_16_invocation_unused_premise.py \
	angr_platforms/tests/test_optimization_quality_guard_diagnostics.py \
	angr_platforms/tests/test_x86_16_vex_direct_constants.py \
	angr_platforms/tests/test_x86_16_vex_integer_displacement.py \
	angr_platforms/tests/test_x86_16_vex_bit_source.py \
	angr_platforms/tests/test_x86_16_vex_import_hot_path.py \
	angr_platforms/tests/test_x86_16_vex_import_cfg_successors.py \
	angr_platforms/tests/test_x86_16_sortd_indexed_loop_topology.py \
	angr_platforms/tests/test_x86_16_ssa_cfg.py \
	angr_platforms/tests/test_x86_16_logical_memory_write_value.py \
	angr_platforms/tests/test_x86_16_logical_constant_word_receipt.py \
	angr_platforms/tests/test_x86_16_stack_word_call_window.py \
	angr_platforms/tests/test_x86_16_stack_word_call_binding.py \
	angr_platforms/tests/test_x86_16_vex_memory_access_fidelity.py \
	angr_platforms/tests/test_x86_16_condition_rendering.py \
	angr_platforms/tests/test_x86_16_ir_readiness.py \
	angr_platforms/tests/test_x86_16_layer_module_status.py \
	angr_platforms/tests/test_x86_16_coverage_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifacts.py \
	angr_platforms/tests/test_x86_16_function_effect_summary.py \
	angr_platforms/tests/test_x86_16_function_graph_extent_repair.py \
	angr_platforms/tests/test_x86_16_graph_repair_leaders.py \
	angr_platforms/tests/test_x86_16_return_ip_provenance.py \
	angr_platforms/tests/test_x86_16_clinic_variable_recovery_contract.py \
	angr_platforms/tests/test_x86_16_ir_memory_call_liveness.py \
	angr_platforms/tests/test_x86_16_helper_effect_summary.py \
	angr_platforms/tests/test_x86_16_helper_family_routing.py \
	angr_platforms/tests/test_x86_16_function_interface_surface.py \
	angr_platforms/tests/test_x86_16_function_state_summary.py \
	angr_platforms/tests/test_x86_16_recovery_confidence_helper_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_cache.py \
	angr_platforms/tests/test_x86_16_ir_recovery_summary.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_manifest.py \
	angr_platforms/tests/test_x86_16_recovery_artifact_writer.py \
	angr_platforms/tests/test_x86_16_targeted_recovery_artifact.py \
	angr_platforms/tests/test_x86_16_corpus_recovery_artifact.py \
	angr_platforms/tests/test_x86_16_corpus_scan_timeout.py \
	angr_platforms/tests/test_build_msc6_examples.py \
	angr_platforms/tests/test_msc6_compat_headers.py \
	angr_platforms/tests/test_msc6_entrypoint.py \
	angr_platforms/tests/test_decompile_entrypoint_determinism.py \
	angr_platforms/tests/test_import_ultra_quickc_fixtures.py \
	angr_platforms/tests/test_generated_c_indexed_argument_contract.py \
	angr_platforms/tests/test_project_loading_cache.py \
	angr_platforms/tests/test_project_loading_diagnostics.py \
	angr_platforms/tests/test_cli_interrupt_call_boundary.py \
	angr_platforms/tests/test_pytest_profile.py \
	angr_platforms/tests/test_generic_annotation_contracts.py \
	angr_platforms/tests/test_access_trait_runtime_factory.py \
	angr_platforms/tests/test_frame_carrier_type_contracts.py \
	angr_platforms/tests/test_makefile_inventory.py \
	angr_platforms/tests/test_mypy_import_contracts.py \
	angr_platforms/tests/test_x86_16_pointer_store_fold_safety.py \
	angr_platforms/tests/test_x86_16_near_pointer_argument_evidence.py \
	angr_platforms/tests/test_x86_16_near_pointer_index_binding.py \
	angr_platforms/tests/test_x86_16_annotation_argument_identity.py \
	angr_platforms/tests/test_parallel_job_defaults.py \
	angr_platforms/tests/test_pytest_partitioned.py \
	angr_platforms/tests/test_pytest_process_metrics.py \
	angr_platforms/tests/test_pytest_resource_scheduler.py \
	angr_platforms/tests/test_pytest_source_index.py \
	angr_platforms/tests/test_omf_pat_lidata.py \
	angr_platforms/tests/test_decompiler_architecture_check.py \
	angr_platforms/tests/test_rizin_discovery.py \
	angr_platforms/tests/test_decompilation_quality.py \
	angr_platforms/tests/test_cli_regeneration.py \
	angr_platforms/tests/test_cli_segment_replay.py \
	angr_platforms/tests/test_check_sortd_sidecar_free.py \
	angr_platforms/tests/test_sortd_drawtime_gate.py \
	angr_platforms/tests/test_runmenu_execution_evidence.py \
	angr_platforms/tests/test_compare_ghidra_function_coverage.py \
	angr_platforms/tests/test_agent_test_focus.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_test_ownership_manifest.py \
	angr_platforms/tests/test_test_ownership_validation.py \
	angr_platforms/tests/test_x86_16_alias_register_mvp.py \
	angr_platforms/tests/test_x86_16_call_contracts.py \
	angr_platforms/tests/test_x86_16_call_execution_frame_carriers.py \
	angr_platforms/tests/test_x86_16_call_frame_base_effects.py \
	angr_platforms/tests/test_x86_16_call_output_stack_objects.py \
	angr_platforms/tests/test_x86_16_call_output_object_projection.py \
	angr_platforms/tests/test_x86_16_structuring_call_argument_joins.py \
	angr_platforms/tests/test_x86_16_call_return_conditions.py \
	angr_platforms/tests/test_x86_16_bound_call_condition.py \
	angr_platforms/tests/test_x86_16_call_result_zero_validation.py \
	angr_platforms/tests/test_x86_16_single_branch_return_orientation.py \
	angr_platforms/tests/test_x86_16_callsite_prototype_declarations.py \
	angr_platforms/tests/test_x86_16_call_argument_shape_publication.py \
	angr_platforms/tests/test_x86_16_callsite_pointer_tables.py \
	angr_platforms/tests/test_x86_16_callsite_replay_safety.py \
	angr_platforms/tests/test_x86_16_signed_global_declarations.py \
	angr_platforms/tests/test_x86_16_sortd_sleep_regression.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py \
	angr_platforms/tests/test_x86_16_protected_call_arguments.py \
	angr_platforms/tests/test_x86_16_call_argument_expression.py \
	angr_platforms/tests/test_x86_16_condition_lowering.py \
	angr_platforms/tests/test_x86_16_condition_cache_relift.py \
	angr_platforms/tests/test_x86_16_condition_lift_capture.py \
	angr_platforms/tests/test_x86_16_function_condition_artifact.py \
	angr_platforms/tests/test_x86_16_return_liveness_replay.py \
	angr_platforms/tests/test_x86_16_lowered_register_carriers.py \
	angr_platforms/tests/test_x86_16_condition_transfer.py \
	angr_platforms/tests/test_x86_16_condition_sign_extension.py \
	angr_platforms/tests/test_x86_16_condition_full_width_masks.py \
	angr_platforms/tests/test_x86_16_jcc_result_condition.py \
	angr_platforms/tests/test_x86_16_frontend_condition_evidence.py \
	angr_platforms/tests/test_x86_16_stack_condition_access_provenance.py \
	angr_platforms/tests/test_x86_16_frontend_direct_callsite_index.py \
	angr_platforms/tests/test_x86_16_wide_call_return_guard_chains.py \
	angr_platforms/tests/test_x86_16_branch_return_expressions.py \
	angr_platforms/tests/test_x86_16_condition_argument_types.py \
	angr_platforms/tests/test_x86_16_typed_condition_side_effect_preservation.py \
	angr_platforms/tests/test_x86_16_validation_condition_precision.py \
	angr_platforms/tests/test_x86_16_msc6_cmp32_regression.py \
	angr_platforms/tests/test_x86_16_multi_arm_return_chains.py \
	angr_platforms/tests/test_x86_16_scalar_return_evidence.py \
	angr_platforms/tests/test_x86_16_scalar_return_types.py \
	angr_platforms/tests/test_x86_16_return_chain_condition_selection.py \
	angr_platforms/tests/test_x86_16_structuring_return_chains.py \
	angr_platforms/tests/test_x86_16_selector_return_projection.py \
	angr_platforms/tests/test_x86_16_mask_accumulator_effects.py \
	angr_platforms/tests/test_x86_16_global_sum_effects.py \
	angr_platforms/tests/test_cli_assignment_effect_preservation.py \
	angr_platforms/tests/test_msc_storage_carry_oracle.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py \
	angr_platforms/tests/test_x86_16_condition_register_definition.py \
	angr_platforms/tests/test_x86_16_runtime_condition_projection.py \
	angr_platforms/tests/test_x86_16_loop_instruction_tags.py \
	angr_platforms/tests/test_x86_16_loop_break_topology.py \
	angr_platforms/tests/test_x86_16_structuring_grouped_pass.py::test_decision_tree_accumulates_unresolved_normalized_affine_producers \
	angr_platforms/tests/test_x86_16_void_return_pass_ownership.py \
	angr_platforms/tests/test_x86_16_stack_prototype_promotion.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py \
	angr_platforms/tests/test_x86_16_jcc_register_evidence.py \
	angr_platforms/tests/test_x86_16_package_exports.py \
	angr_platforms/tests/test_x86_16_bootstrap_import_order.py \
	angr_platforms/tests/test_x86_16_pipeline_contracts.py \
	angr_platforms/tests/test_x86_16_rewrite_boundary.py \
	angr_platforms/tests/test_x86_16_indexed_stack_ranges.py \
	angr_platforms/tests/test_x86_16_validation_canonicalize.py \
	angr_platforms/tests/test_x86_16_call_argument_stack_projection.py \
	angr_platforms/tests/test_x86_16_validation_call_argument_sources.py \
	angr_platforms/tests/test_x86_16_validation_calls.py \
	angr_platforms/tests/test_x86_16_validation_call_multiplicity.py \
	angr_platforms/tests/test_x86_16_validation_loop_condition_ir.py \
	angr_platforms/tests/test_x86_16_validation_branch_conditions.py \
	angr_platforms/tests/test_x86_16_validation_condition_coverage.py \
	angr_platforms/tests/test_x86_16_composite_pretest_conditions.py \
	angr_platforms/tests/test_x86_16_existing_loop_exit_conditions.py \
	angr_platforms/tests/test_x86_16_terminal_loop_exit_conditions.py \
	angr_platforms/tests/test_x86_16_terminal_wide_validation.py \
	angr_platforms/tests/test_x86_16_render_compat.py \
	angr_platforms/tests/test_x86_16_structuring_condition_processor.py \
	angr_platforms/tests/test_x86_16_structuring_condition_ownership.py \
	angr_platforms/tests/test_x86_16_shared_loop_exit.py \
	angr_platforms/tests/test_x86_16_condition_decrement_fingerprints.py \
	angr_platforms/tests/test_x86_16_storage_or_fingerprints.py \
	angr_platforms/tests/test_x86_16_structured_tag_projection.py \
	angr_platforms/tests/test_x86_16_validation_additive_semantic_casts.py \
	angr_platforms/tests/test_x86_16_materialized_condition_storage.py \
	angr_platforms/tests/test_x86_16_validation_control_flow.py \
	angr_platforms/tests/test_x86_16_validation_dataflow.py \
	angr_platforms/tests/test_x86_16_validation_semantic_failures.py \
	angr_platforms/tests/test_x86_16_validation_virtual_carriers.py \
	angr_platforms/tests/test_x86_16_validation_predicates.py \
	angr_platforms/tests/test_x86_16_validation_storage.py \
	angr_platforms/tests/test_x86_16_validation_required_memory_effects.py \
	angr_platforms/tests/test_x86_16_runtime_segment_access.py \
	angr_platforms/tests/test_x86_16_sortd_indexed_aggregate_regression.py \
	angr_platforms/tests/test_x86_16_sortd_menu_pointer_table.py \
	angr_platforms/tests/test_x86_16_validation_manifest.py \
	angr_platforms/tests/test_x86_16_validation_helper_report.py \
	angr_platforms/tests/test_x86_16_low_memory_regions.py \
	angr_platforms/tests/test_x86_16_recompilable_source_evidence.py \
	angr_platforms/tests/test_x86_16_recompilable_subset.py \
	angr_platforms/tests/test_x86_16_recompilable_storage_map.py \
	angr_platforms/tests/test_x86_16_recompilable_storage_objects.py \
	angr_platforms/tests/test_x86_16_array_matching.py \
	angr_platforms/tests/test_x86_16_struct_merging.py \
	angr_platforms/tests/test_x86_16_structuring_condition_materialization.py \
	angr_platforms/tests/test_x86_16_condition_chain_refusal.py \
	angr_platforms/tests/test_x86_16_recorded_return_argument_replay.py \
	angr_platforms/tests/test_x86_16_stack_reload_instruction_ownership.py \
	angr_platforms/tests/test_x86_16_runtime_call_results.py \
	angr_platforms/tests/test_x86_16_inbox_long_live.py \
	angr_platforms/tests/test_x86_16_wide_return_condition_coverage.py \
	angr_platforms/tests/test_x86_16_condition_exit_normalization.py \
	angr_platforms/tests/test_x86_16_structuring_multi_arm_condition_ownership.py \
	angr_platforms/tests/test_x86_16_local_condition_regions.py \
	angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py \
	angr_platforms/tests/test_x86_16_total_return_suffixes.py \
	angr_platforms/tests/test_x86_16_switch_loop_tail_breaks.py \
	angr_platforms/tests/test_x86_16_wide_stack_condition_chains.py \
	angr_platforms/tests/test_x86_16_wide_condition_ordering.py \
	angr_platforms/tests/test_x86_16_wide_call_condition_source.py \
	angr_platforms/tests/test_x86_16_wide_call_condition_capture.py \
	angr_platforms/tests/test_x86_16_wide_return_type_preservation.py \
	angr_platforms/tests/test_x86_16_positive_bp_wide_arguments.py \
	angr_platforms/tests/test_x86_16_cli.py::test_decompile_function_disables_structuring_for_tiny_single_call_helpers \
	angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_runner_hotspots_fall_back_through_scan_safe_classifier \
	angr_platforms/tests/test_x86_16_wide_call_condition_plan.py \
	angr_platforms/tests/test_x86_16_wide_condition_provenance.py \
	angr_platforms/tests/test_x86_16_dce_optimization.py \
	angr_platforms/tests/test_x86_16_dce_noop_conditionals.py \
	angr_platforms/tests/test_x86_16_packed_flags_state.py \
	angr_platforms/tests/test_x86_16_packed_flags_cycles.py \
	angr_platforms/tests/test_x86_16_packed_flags_call_evidence.py \
	angr_platforms/tests/test_x86_16_flags_physical_register_contract.py \
	angr_platforms/tests/test_x86_16_dce_lvalue_reads.py \
	angr_platforms/tests/test_x86_16_dead_local_prune.py \
	angr_platforms/tests/test_x86_16_dead_local_structured_reads.py \
	angr_platforms/tests/test_x86_16_local_liveness.py \
	angr_platforms/tests/test_cli_semantic_rollback.py \
	angr_platforms/tests/test_x86_16_trivial_copy_optimization.py \
	angr_platforms/tests/test_x86_16_widening_copyprop.py \
	angr_platforms/tests/test_x86_16_widening_copyprop_width.py \
	angr_platforms/tests/test_x86_16_linear_global_decomposition_cache.py \
	angr_platforms/tests/test_x86_16_widening_memory_fold.py \
	angr_platforms/tests/test_x86_16_stack_subview_call_writes.py \
	angr_platforms/tests/test_x86_16_stack_subview_projection.py \
	angr_platforms/tests/test_x86_16_stack_subview_coordinates.py \
	angr_platforms/tests/test_x86_16_stack_subview_projection_wide.py \
	angr_platforms/tests/test_x86_16_indexed_load_subviews.py \
	angr_platforms/tests/test_makefile_quiet_output.py \
	angr_platforms/tests/test_x86_16_widening_rules.py \
	angr_platforms/tests/test_x86_16_far_load_access_width.py \
	angr_platforms/tests/test_x86_16_generated_c_acceptance.py \
	angr_platforms/tests/test_x86_16_structuring_grouping_report.py \
	angr_platforms/tests/test_x86_16_structuring_grouped_refusal_report.py \
	angr_platforms/tests/test_x86_16_structuring_sequences.py \
	angr_platforms/tests/test_x86_16_stack_aggregate_objects.py \
	angr_platforms/tests/test_x86_16_stack_prototype_codegen_api.py \
	angr_platforms/tests/test_x86_16_stack_aggregate_coordinate_replay.py \
	angr_platforms/tests/test_x86_16_positive_bp_argument_plan.py \
	angr_platforms/tests/test_x86_16_stack_argument_identity.py \
	angr_platforms/tests/test_x86_16_projected_stack_argument_identity.py \
	angr_platforms/tests/test_x86_16_stack_declaration_identity.py \
	angr_platforms/tests/test_x86_16_stack_lowering_contracts.py \
	angr_platforms/tests/test_x86_16_stack_memory_object_widening.py \
	angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py \
	angr_platforms/tests/test_x86_16_stack_memory_ssa_safety.py \
	angr_platforms/tests/test_x86_16_unused_void_return_types.py \
	angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py \
	angr_platforms/tests/test_x86_16_ir_segmented_load_carriers.py \
	angr_platforms/tests/test_x86_16_reload_provenance_boundaries.py \
	angr_platforms/tests/test_x86_16_assignment_lvalue_casts.py \
	angr_platforms/tests/test_x86_16_stack_byte_writes.py \
	angr_platforms/tests/test_x86_16_instruction_stack_write_width.py \
	angr_platforms/tests/test_x86_16_semantic_cast.py \
	angr_platforms/tests/test_x86_16_condition_operand_signedness.py \
	angr_platforms/tests/test_x86_16_condition_signedness_storage_width.py \
	angr_platforms/tests/test_x86_16_validation_argument_coordinates.py \
	angr_platforms/tests/test_x86_16_condition_storage_views.py \
	angr_platforms/tests/test_x86_16_wide_stack_pair_coordinates.py \
	angr_platforms/tests/test_x86_16_direct_stack_access_widths.py \
	angr_platforms/tests/test_x86_16_stack_address_coordinates.py \
	angr_platforms/tests/test_x86_16_native_stack_anchor.py \
	angr_platforms/tests/test_x86_16_runtime_push_carrier.py \
	angr_platforms/tests/test_x86_16_storage_prototype_snapshot.py \
	angr_platforms/tests/test_x86_16_frame_prologue_carriers.py \
	angr_platforms/tests/test_x86_16_frame_byte_carriers.py \
	angr_platforms/tests/test_x86_16_native_segment_live_out.py \
	angr_platforms/tests/test_x86_16_native_terminal_return_values.py \
	angr_platforms/tests/test_x86_16_native_unsigned_constant_casts.py \
	angr_platforms/tests/test_x86_16_loadprogram_behavior.py \
	angr_platforms/tests/test_x86_16_configcrts_behavior.py \
	angr_platforms/tests/test_x86_16_mset_pos_behavior.py \
	angr_platforms/tests/test_x86_16_changeweather_behavior.py \
	angr_platforms/tests/test_x86_16_mouse_position_behavior.py \
	angr_platforms/tests/test_x86_16_native_integer_operations.py \
	angr_platforms/tests/test_x86_16_ail_remainder.py \
	angr_platforms/tests/test_x86_16_stack_reference_offsets.py \
	angr_platforms/tests/test_x86_16_les_stack_argument_behavior.py \
	angr_platforms/tests/test_x86_16_string_corpus_anchors.py \
	angr_platforms/tests/test_x86_16_segment_stack_restore_carriers.py \
	angr_platforms/tests/test_x86_16_far_return_boundary_carriers.py \
	angr_platforms/tests/test_x86_16_ss_traversal_contract.py \
	angr_platforms/tests/test_x86_16_stack_prototype_wrapped_locals.py \
	angr_platforms/tests/test_x86_16_ast_traversal_coverage.py \
	angr_platforms/tests/test_x86_16_msetpos_behavior.py \
	angr_platforms/tests/test_x86_16_gp_livein_authority.py \
	angr_platforms/tests/test_x86_16_anonymous_store_width.py \
	angr_platforms/tests/test_x86_16_ssa_register_displacements.py \
	angr_platforms/tests/test_x86_16_stack_coordinate_conflicts.py \
	angr_platforms/tests/test_x86_16_escaped_stack_validation.py \
	angr_platforms/tests/test_x86_16_bios_strict_compilation.py \
	angr_platforms/tests/test_x86_16_rep_store_codegen.py \
	angr_platforms/tests/test_x86_16_runtime_store_scope.py \
	angr_platforms/tests/test_x86_16_string_timeout_fallback.py \
	angr_platforms/tests/test_x86_16_ir_memory_byte_ssa.py \
	angr_platforms/tests/test_x86_16_string_codegen_override.py \
	angr_platforms/tests/test_cli_codegen_policy.py \
	angr_platforms/tests/test_x86_16_segment_call_effects.py \
	angr_platforms/tests/test_x86_16_frame_carrier_liveness.py \
	angr_platforms/tests/test_x86_16_unobserved_return_maker.py \
	angr_platforms/tests/test_x86_16_dosfunc_behavior.py \
	angr_platforms/tests/test_x86_16_heapsort_behavior.py \
	angr_platforms/tests/test_x86_16_quicksort_behavior.py \
	angr_platforms/tests/test_x86_16_sleep_behavior.py \
	angr_platforms/tests/test_x86_16_insertionsort_behavior.py \
	angr_platforms/tests/test_x86_16_swapbars_behavior.py \
	angr_platforms/tests/test_x86_16_gp_word_runtime.py \
	angr_platforms/tests/test_x86_16_gp_word_assignment.py \
	angr_platforms/tests/test_x86_16_address_base_snapshots.py \
	angr_platforms/tests/test_x86_16_reinitbars_execution.py \
	angr_platforms/tests/test_x86_16_setgear_behavior.py \
	angr_platforms/tests/test_x86_16_tidshowrange_behavior.py \
	angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_setgear_guard_logic \
	angr_platforms/tests/test_x86_16_memory_ssa_address_provenance.py \
	angr_platforms/tests/test_x86_16_ir_stack_frame.py \
	angr_platforms/tests/test_x86_16_consumed_push_lvalues.py \
	angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py \
	angr_platforms/tests/test_x86_16_heapsort_widening_regression.py \
	angr_platforms/tests/test_x86_16_global_declarations.py \
	angr_platforms/tests/test_x86_16_alias_global_object_layout.py \
	angr_platforms/tests/test_indexed_alias_program_parallel.py \
	angr_platforms/tests/test_x86_16_global_object_layout.py \
	angr_platforms/tests/test_x86_16_project_type_contracts.py \
	angr_platforms/tests/test_x86_16_function_pointer_parameters.py \
	angr_platforms/tests/test_x86_16_callee_global_object_interface.py \
	angr_platforms/tests/test_x86_16_global_object_program_requirement.py \
	angr_platforms/tests/test_x86_16_callee_global_object_sources.py \
	angr_platforms/tests/test_x86_16_global_object_source_codec.py \
	angr_platforms/tests/test_x86_16_callee_pointer_evidence.py \
	angr_platforms/tests/test_x86_16_callee_pointer_codec.py \
	angr_platforms/tests/test_x86_16_callsite_summary_codec.py \
	angr_platforms/tests/test_x86_16_callsite_summary_program.py \
	angr_platforms/tests/test_x86_16_project_callee_callsite_collection.py \
	angr_platforms/tests/test_project_callee_callsite_transport.py \
	angr_platforms/tests/test_serial_clean_worker_callsite_evidence.py \
	angr_platforms/tests/test_project_argument_evidence_ranges.py \
	angr_platforms/tests/test_x86_16_project_global_object_source_collection.py \
	angr_platforms/tests/test_indexed_alias_source_collection_scope.py \
	angr_platforms/tests/test_project_global_source_evidence_transport.py \
	angr_platforms/tests/test_serial_clean_worker_global_source_evidence.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_branches.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_ownership_priority.py \
	angr_platforms/tests/test_x86_16_direct_stack_reload_idempotence.py \
	angr_platforms/tests/test_x86_16_direct_global_store_prefilter.py \
	angr_platforms/tests/test_x86_16_pipeline_result_contracts.py \
	angr_platforms/tests/test_x86_16_postprocess_validation_policy.py \
	angr_platforms/tests/test_x86_16_postprocess_bootstrap_orchestration.py \
	angr_platforms/tests/test_x86_16_postprocess_pass_transaction.py \
	angr_platforms/tests/test_x86_16_postprocess_rollback_snapshot_cache.py \
	angr_platforms/tests/test_x86_16_postprocess_runtime_config.py \
	angr_platforms/tests/test_x86_16_control_flow_ast_index.py \
	angr_platforms/tests/test_x86_16_runtime_memory_helpers.py \
	angr_platforms/tests/test_x86_16_indexed_stack_frame_terms.py \
	angr_platforms/tests/test_x86_16_loop_condition_materialization.py \
	angr_platforms/tests/test_x86_16_pretest_loop_condition_ownership.py \
	angr_platforms/tests/test_x86_16_loop_condition_block_identity.py \
	angr_platforms/tests/test_x86_16_nested_loop_behavior.py \
	angr_platforms/tests/test_x86_16_goto_accumulate_behavior.py \
	angr_platforms/tests/test_x86_16_stack_update_scope_guard.py \
	angr_platforms/tests/test_x86_16_instruction_fragment_placement.py \
	angr_platforms/tests/test_x86_16_call_return_stack_stores.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_loop_entries.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_pretest_body.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_pretest_initializers.py \
	angr_platforms/tests/test_x86_16_stack_probe_local_preservation.py \
	angr_platforms/tests/test_x86_16_casted_loop_induction.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_loops.py \
	angr_platforms/tests/test_x86_16_direct_stack_update_groups.py \
	angr_platforms/tests/test_x86_16_indexed_address_copies.py \
	angr_platforms/tests/test_x86_16_indexed_address_evidence.py \
	angr_platforms/tests/test_x86_16_indexed_address_aliases.py \
	angr_platforms/tests/test_x86_16_indexed_address_range_candidates.py \
	angr_platforms/tests/test_x86_16_indexed_global_object_program_ranges.py \
	angr_platforms/tests/test_x86_16_indexed_global_object_ranges.py \
	angr_platforms/tests/test_x86_16_bounded_global_array_declarations.py \
	angr_platforms/tests/test_x86_16_indexed_address_collector_parity.py \
	angr_platforms/tests/test_x86_16_indexed_address_parity_inventory.py \
	angr_platforms/tests/test_x86_16_sortd_indexed_address_parity_inventory.py \
	angr_platforms/tests/test_x86_16_cod_global_identity.py \
	angr_platforms/tests/test_x86_16_segmented_global_loads.py \
	angr_platforms/tests/test_x86_16_wide_store_call_preservation.py \
	angr_platforms/tests/test_x86_16_decompilation_cache_surface.py \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_heapsort_materializes_call_arguments_without_stack_leaks \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_percolateup_materializes_parent_once_and_preserves_calls \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_reinitbars_preserves_clock_store_loop_and_validation_contract \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_drawtime_materializes_clock_return_to_clfinish_once \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initmenu_pause_zero_guard_has_no_raw_flag_carrier \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_insertionsort_word_stores_materialized_without_raw_high_byte_memory \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_drawbar_word_stride_byte_fields_validate_without_indexed_mem_helper_syntax \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_percolatedown_direct_global_increment_materialized \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swapbars_materializes_arguments_without_dead_setup_artifacts \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swaps_preserves_binary_proven_global_increment_and_pointer_swap \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_bubblesort_sidecar_free_preserves_direct_ds_row_count \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_exchangesort_sidecar_free_folds_alias_proven_high_byte \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawbar_sidecar_free_materializes_stack_buffer_and_conservative_return \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawframe_sidecar_free_materializes_segmented_buffer_calls \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_reinitbars_sidecar_free_materializes_indexed_global_copy \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawtime_sidecar_free_materializes_wide_delay_arguments \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_insertionsort_sidecar_free_splits_header_and_rebases_source \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_initmenu_sidecar_free_preserves_calls_and_compiles \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_runmenu_default_direct_path_validates_without_temp_carrier_fallback \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_runmenu_sidecar_free_preserves_binary_escape_exit \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_sidecar_free_initbars_preserves_binary_stack_array \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_sidecar_free_swapbars_recovers_binary_stack_arguments \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py::test_normalize_call_target_names_drops_detached_angr_callee_func \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py::test_callsite_stats_count_stale_target_rejection \
	angr_platforms/tests/test_x86_16_access_trait_arrays.py \
	angr_platforms/tests/test_x86_16_access_trait_policy.py \
	angr_platforms/tests/test_x86_16_access_trait_strides.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py \
	angr_platforms/tests/test_x86_16_segmented_memory.py \
	angr_platforms/tests/test_x86_16_type_equivalence_classes.py \
	angr_platforms/tests/test_msc6_toolchain_lock.py \
	angr_platforms/tests/test_x86_16_cod_module_caller_evidence.py \
	angr_platforms/tests/test_x86_16_cfg_direct_jump.py \
	angr_platforms/tests/test_x86_16_cfg_direct_call.py \
	angr_platforms/tests/test_x86_16_frontend_function_boundary_index.py \
	angr_platforms/tests/test_x86_16_frontend_instruction_reachability.py \
	angr_platforms/tests/test_x86_16_function_callsite_inventory.py \
	angr_platforms/tests/test_x86_16_return_compat_counters.py \
	angr_platforms/tests/test_x86_16_return_expression_preservation.py \
	angr_platforms/tests/test_x86_16_overlay_return_behavior.py \
	angr_platforms/tests/test_x86_16_boolean_condition_ites.py \
	angr_platforms/tests/test_x86_16_direct_stack_move_indexed_use.py \
	angr_platforms/tests/test_x86_16_msvc_x87_interrupts.py \
	angr_platforms/tests/test_x86_16_return_stack_address_compat.py \
	angr_platforms/tests/test_x86_16_stack_prototype_layout.py \
	angr_platforms/tests/test_accepted_payload_integrity.py \
	angr_platforms/tests/test_acceptance_scorecard.py \
	angr_platforms/tests/test_tail_validation_display_outcome.py

# Focused owner tests are appended while the legacy QA lists remain curated.
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/return_witness_source.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/return_witness_source.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/return_witness_source.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/argument_frame_base.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/argument_frame_base.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/argument_frame_base.py angr_platforms/tests/test_x86_16_argument_frame_base.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_argument_frame_base.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_pointer_type.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_pointer_type.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/far_pointer_type.py
QA_TYPED_FILES += ada.py tools/ada_script/__init__.py tools/ada_script/cli.py tools/ada_script/signatures.py tools/ada_script/vendor_bridge.py
QA_RUFF_TARGETS += ada.py tools/ada_script/__init__.py tools/ada_script/cli.py tools/ada_script/signatures.py tools/ada_script/vendor_bridge.py angr_platforms/tests/test_ada_signature_integration.py

QA_TYPED_FILES += pat_literal_filter.py
QA_RUFF_TARGETS += pat_literal_filter.py angr_platforms/tests/test_pat_literal_prefilter.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pat_literal_prefilter.py
QA_RUFF_TARGETS += angr_platforms/tests/test_pat_catalog_cache_identity.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pat_catalog_cache_identity.py
LINTERS_DEV_MYPY_FILES += scripts/compiler_coverage_cross_unit.py
QA_TYPED_FILES += scripts/compiler_coverage_cross_unit.py
QA_RUFF_TARGETS += scripts/compiler_coverage_cross_unit.py angr_platforms/tests/test_compiler_coverage_cross_unit.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_compiler_coverage_cross_unit.py
LINTERS_DEV_MYPY_FILES += scripts/compiler_coverage_provenance.py scripts/compiler_coverage_runner.py
QA_TYPED_FILES += scripts/compiler_coverage_provenance.py scripts/compiler_coverage_runner.py
QA_RUFF_TARGETS += scripts/compiler_coverage_provenance.py scripts/compiler_coverage_runner.py angr_platforms/tests/test_compiler_coverage_provenance.py angr_platforms/tests/test_compiler_coverage_runner.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_compiler_coverage_provenance.py angr_platforms/tests/test_compiler_coverage_runner.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/logical_word_read_reaching_value.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/logical_word_read_reaching_value.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/logical_word_read_reaching_value.py angr_platforms/tests/test_x86_16_logical_word_read_reaching_value.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_logical_word_read_reaching_value.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_high_byte_remnant_walk.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_high_byte_remnant_walk.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/binary_callback_targets.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/binary_callback_targets.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/binary_callback_targets.py angr_platforms/tests/test_x86_16_binary_callback_targets.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_binary_callback_targets.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_far_callback_call_shape.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_far_callback_call_shape.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_shape.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_shape.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_shape.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_value.py angr_platforms/angr_platforms/X86_16/lowering/binary_far_callback_targets.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_value.py angr_platforms/angr_platforms/X86_16/lowering/binary_far_callback_targets.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_value.py angr_platforms/angr_platforms/X86_16/lowering/binary_far_callback_targets.py angr_platforms/tests/test_x86_16_far_callback_call_value.py angr_platforms/tests/test_x86_16_binary_far_callback_targets.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_far_callback_call_value.py angr_platforms/tests/test_x86_16_binary_far_callback_targets.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_materialization.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_materialization.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/far_callback_call_materialization.py angr_platforms/tests/test_x86_16_far_callback_call_materialization.py angr_platforms/tests/test_x86_16_typed_call_argument_path_conditions.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_far_callback_call_materialization.py angr_platforms/tests/test_x86_16_typed_call_argument_path_conditions.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/semantics/terminal_boundary_paths.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/semantics/terminal_boundary_paths.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/semantics/terminal_boundary_paths.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/frontend_boundary_transport.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/frontend_boundary_transport.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/frontend_boundary_transport.py angr_platforms/tests/test_x86_16_frontend_boundary_transport.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_frontend_boundary_transport.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_discard.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_discard.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_discard.py angr_platforms/tests/test_x86_16_interprocedural_discarded_return.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_interprocedural_discarded_return.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/frontend_caller_entry_identity.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/frontend_caller_entry_identity.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/frontend_caller_entry_identity.py angr_platforms/tests/test_x86_16_frontend_caller_entry_identity.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_frontend_caller_entry_identity.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/gp_register_versions.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/gp_register_versions.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/gp_register_versions.py angr_platforms/tests/test_x86_16_gp_register_versions.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_gp_register_versions.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/validation_indexed_bytes.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/validation_indexed_bytes.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/validation_indexed_bytes.py angr_platforms/tests/test_x86_16_validation_indexed_bytes.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_validation_indexed_bytes.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_stack_restore_value_identity.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_stack_restore_value_identity.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/postprocess/bitwise_terms.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/postprocess/bitwise_terms.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/postprocess/bitwise_terms.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/alias/condition_register_storage.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/alias/condition_register_storage.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_local_array_reads.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_value_identity.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_value_identity.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_local_array_reads.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/alias/condition_register_storage.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_condition_register_source_bindings.py angr_platforms/tests/test_x86_16_condition_register_byte_extension.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_condition_register_source_bindings.py angr_platforms/tests/test_x86_16_condition_register_byte_extension.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_scalar_byte_behavior.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_scalar_byte_behavior.py
QA_RUFF_TARGETS += angr_platforms/tests/test_sortd_generated_sort_core_gate.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_sortd_generated_sort_core_gate.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_dce_purity.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_tail_validation_alias_cycles.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_tail_validation_alias_cycles.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_validation_owned_condition_precision.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_validation_owned_condition_precision.py
QA_RUFF_TARGETS += angr_platforms/tests/test_generated_translation_unit_gate.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_msc6_runtime_gate_artifacts.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_loadprog_preserves_binary_arguments_and_recompiles
QA_RUFF_TARGETS += \
	angr_platforms/tests/test_x86_16_symbolic_value_boundaries.py \
	angr_platforms/tests/test_make_linter_inputs.py \
	angr_platforms/tests/test_x86_16_direction_flag_execution.py \
	angr_platforms/tests/test_x86_16_stack_helpers.py \
	angr_platforms/tests/test_x86_16_structuring_pass_validation.py \
	angr_platforms/tests/test_x86_16_helper_abi.py \
	angr_platforms/tests/test_x86_16_fixed_stack_probe_frames.py \
	angr_platforms/tests/test_x86_16_stack_projection_renaming.py \
	angr_platforms/tests/test_x86_16_tail_validation_projection_coordinates.py \
	angr_platforms/tests/test_x86_16_validation_identical_return_guards.py \
	angr_platforms/tests/test_x86_16_widening_copyprop_returns.py \
	angr_platforms/tests/test_architecture_import_attestation.py \
	angr_platforms/tests/test_x86_16_tagged_subtree_projection.py \
	angr_platforms/tests/test_x86_16_dce_purity.py \
	angr_platforms/tests/test_x86_16_condition_artifact_reuse.py \
	angr_platforms/tests/test_x86_16_indexed_global_stack_coordinates.py \
	angr_platforms/tests/test_x86_16_status_flag_cfg_liveness.py \
	angr_platforms/tests/test_x86_16_status_flag_cfg_projection.py \
	angr_platforms/tests/test_x86_16_typed_switch_seqnode.py \
	angr_platforms/tests/test_x86_16_switch_definition_coverage.py \
	angr_platforms/tests/test_x86_16_status_flag_lift_context.py \
	angr_platforms/tests/test_x86_16_status_flag_liveness.py \
	angr_platforms/tests/test_x86_16_flag_lookahead_boundaries.py \
	angr_platforms/tests/test_x86_16_msc_caller_cleanup.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py \
	angr_platforms/tests/test_x86_16_alu_effect_order.py \
	angr_platforms/tests/test_x86_16_carry_predicate_execution.py \
	angr_platforms/tests/test_x86_16_simple_incdec_value_provenance.py \
	angr_platforms/tests/test_x86_16_concrete_loop_conditions.py \
	angr_platforms/tests/test_x86_16_lifting_opcode_tables.py \
	angr_platforms/tests/test_x86_16_callsite_completeness_validation.py \
	angr_platforms/tests/test_x86_16_direct_global_call_return_materialization.py \
	angr_platforms/tests/test_x86_16_borrow_verification.py \
	angr_platforms/tests/test_build_msc6_artifact_names.py \
	angr_platforms/tests/test_x86_16_call_argument_carrier_liveness.py \
	angr_platforms/tests/test_x86_16_callee_saved_frame.py \
	angr_platforms/tests/test_x86_16_callee_saved_frame_validation.py \
	angr_platforms/tests/test_x86_16_canonical_frame_carriers.py \
	angr_platforms/tests/test_x86_16_canonical_frame_setup_carriers.py \
	angr_platforms/tests/test_x86_16_cod_module_caller_evidence.py \
	angr_platforms/tests/test_msc6_toolchain_lock.py \
	angr_platforms/tests/test_x86_16_return_compat_counters.py \
	angr_platforms/tests/test_x86_16_return_expression_preservation.py \
	angr_platforms/tests/test_x86_16_overlay_return_behavior.py \
	angr_platforms/tests/test_x86_16_cfg_direct_jump.py \
	angr_platforms/tests/test_x86_16_cfg_direct_call.py \
	angr_platforms/tests/test_x86_16_frontend_function_boundary_index.py \
	angr_platforms/tests/test_x86_16_frontend_instruction_reachability.py \
	angr_platforms/tests/test_x86_16_callsite_block_inventory_reuse.py \
	angr_platforms/tests/test_x86_16_function_callsite_inventory.py \
	angr_platforms/tests/test_x86_16_analysis_helper_direct_blocks.py \
	angr_platforms/tests/test_x86_16_stitched_direct_blocks.py \
	angr_platforms/tests/test_cli_decompilation_render_refresh.py \
	angr_platforms/tests/test_project_evidence_transport.py \
	angr_platforms/tests/test_x86_16_condition_fact_arbitration.py \
	angr_platforms/tests/test_x86_16_direct_global_zero_index_replay.py \
	angr_platforms/tests/test_x86_16_direct_stack_immediate_branches.py \
	angr_platforms/tests/test_x86_16_lifter_condition_cache.py \
	angr_platforms/tests/test_x86_16_lifter_cython_dependency.py \
	angr_platforms/tests/test_x86_16_msc6_sort_patterns_regression.py \
	angr_platforms/tests/test_x86_16_stack_pointer_snapshot.py \
	angr_platforms/tests/test_x86_16_cod_extract_control_flow.py \
	angr_platforms/tests/test_x86_16_software_interrupt_pipeline.py \
	angr_platforms/tests/test_x86_16_software_interrupt_validation.py \
	angr_platforms/tests/test_x86_16_terminal_register_return_values.py \
	angr_platforms/tests/test_x86_16_terminal_register_return_semantics.py \
	angr_platforms/tests/test_x86_16_terminal_register_restore.py \
	angr_platforms/tests/test_x86_16_terminal_side_effect_returns.py \
	angr_platforms/tests/test_x86_16_terminal_return_passthrough.py \
	angr_platforms/tests/test_x86_16_terminal_return_expression_scaling.py \
	angr_platforms/tests/test_x86_16_call_return_frame_effects.py \
	angr_platforms/tests/test_x86_16_register_reaching_source.py \
	angr_platforms/tests/test_x86_16_register_source_memory_dependencies.py \
	angr_platforms/tests/test_x86_16_register_source_wide_clobbers.py \
	angr_platforms/tests/test_x86_16_register_entry_overwrite.py \
	angr_platforms/tests/test_x86_16_consumed_stack_address_setup.py \
	angr_platforms/tests/test_x86_16_register_source_block_inventory.py \
	angr_platforms/tests/test_x86_16_patch_direct_calls.py \
	angr_platforms/tests/test_x86_16_stored_call_return_early_exit.py \
	angr_platforms/tests/test_x86_16_validation_call_return_storage.py

QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_make_linter_inputs.py \
	angr_platforms/tests/test_x86_16_symbolic_value_boundaries.py \
	angr_platforms/tests/test_x86_16_direction_flag_execution.py \
	angr_platforms/tests/test_x86_16_stack_helpers.py \
	angr_platforms/tests/test_x86_16_structuring_pass_validation.py \
	angr_platforms/tests/test_x86_16_helper_abi.py \
	angr_platforms/tests/test_x86_16_fixed_stack_probe_frames.py \
	angr_platforms/tests/test_x86_16_register_source_memory_dependencies.py \
	angr_platforms/tests/test_x86_16_tail_callsite_inventory.py \
	angr_platforms/tests/test_x86_16_register_source_wide_clobbers.py \
	angr_platforms/tests/test_x86_16_register_entry_overwrite.py \
	angr_platforms/tests/test_x86_16_consumed_stack_address_setup.py \
	angr_platforms/tests/test_x86_16_stack_projection_renaming.py \
	angr_platforms/tests/test_x86_16_tail_validation_projection_coordinates.py \
	angr_platforms/tests/test_x86_16_validation_identical_return_guards.py \
	angr_platforms/tests/test_x86_16_widening_copyprop_returns.py \
	angr_platforms/tests/test_architecture_import_attestation.py \
	angr_platforms/tests/test_x86_16_tagged_subtree_projection.py \
	angr_platforms/tests/test_x86_16_indexed_global_stack_coordinates.py \
	angr_platforms/tests/test_x86_16_status_flag_cfg_liveness.py \
	angr_platforms/tests/test_x86_16_status_flag_cfg_projection.py \
	angr_platforms/tests/test_x86_16_typed_switch_seqnode.py \
	angr_platforms/tests/test_x86_16_switch_definition_coverage.py \
	angr_platforms/tests/test_x86_16_status_flag_lift_context.py \
	angr_platforms/tests/test_x86_16_status_flag_liveness.py \
	angr_platforms/tests/test_x86_16_flag_lookahead_boundaries.py \
	angr_platforms/tests/test_x86_16_msc_caller_cleanup.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::test_materialize_callsite_stack_arguments_requires_exact_consumed_push_evidence \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::test_materialize_callsite_stack_arguments_keeps_unproven_far_pointer_stores \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::test_materialize_callsite_stack_arguments_keeps_unproven_scalar_byte_pair_stores \
	angr_platforms/tests/test_x86_16_alu_effect_order.py \
	angr_platforms/tests/test_x86_16_carry_predicate_execution.py \
	angr_platforms/tests/test_x86_16_simple_incdec_value_provenance.py \
	angr_platforms/tests/test_x86_16_concrete_loop_conditions.py \
	angr_platforms/tests/test_x86_16_lifting_opcode_tables.py \
	angr_platforms/tests/test_x86_16_callsite_completeness_validation.py \
	angr_platforms/tests/test_x86_16_borrow_verification.py \
	angr_platforms/tests/test_build_msc6_artifact_names.py \
	angr_platforms/tests/test_x86_16_call_argument_carrier_liveness.py \
	angr_platforms/tests/test_x86_16_callee_saved_frame.py \
	angr_platforms/tests/test_x86_16_callsite_block_inventory_reuse.py \
	angr_platforms/tests/test_x86_16_canonical_frame_carriers.py \
	angr_platforms/tests/test_x86_16_canonical_frame_setup_carriers.py \
	angr_platforms/tests/test_x86_16_cod_extract_control_flow.py \
	angr_platforms/tests/test_x86_16_lifter_condition_cache.py \
	angr_platforms/tests/test_x86_16_lifter_cython_dependency.py \
	angr_platforms/tests/test_x86_16_stack_pointer_snapshot.py \
	angr_platforms/tests/test_x86_16_software_interrupt_pipeline.py \
	angr_platforms/tests/test_x86_16_software_interrupt_validation.py \
	angr_platforms/tests/test_x86_16_terminal_register_return_values.py \
	angr_platforms/tests/test_x86_16_terminal_register_return_semantics.py \
	angr_platforms/tests/test_x86_16_terminal_register_restore.py \
	angr_platforms/tests/test_x86_16_terminal_side_effect_returns.py \
	angr_platforms/tests/test_x86_16_terminal_return_passthrough.py \
	angr_platforms/tests/test_x86_16_terminal_return_expression_scaling.py \
	angr_platforms/tests/test_x86_16_call_return_frame_effects.py \
	angr_platforms/tests/test_x86_16_register_reaching_source.py \
	angr_platforms/tests/test_x86_16_patch_direct_calls.py \
	angr_platforms/tests/test_x86_16_stored_call_return_early_exit.py \
	angr_platforms/tests/test_x86_16_validation_call_return_storage.py

QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/pklite.py inertia_decompiler/catalog_policy.py
QA_TYPED_FILES += inertia_decompiler/external_unpacker_cache.py
QA_RUFF_TARGETS += inertia_decompiler/external_unpacker_cache.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_pklite.py angr_platforms/tests/test_cli_catalog_budget.py angr_platforms/tests/test_missing_dos_toolchain.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/structuring/string_io_loop_carriers.py angr_platforms/angr_platforms/X86_16/validation_condition_chains.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/structuring/string_io_loop_carriers.py angr_platforms/angr_platforms/X86_16/validation_condition_chains.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/structuring/string_io_loop_carriers.py angr_platforms/angr_platforms/X86_16/validation_condition_chains.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use.py angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use_contracts.py angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use_flow.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use.py angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use_contracts.py angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use_flow.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use.py angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use_contracts.py angr_platforms/angr_platforms/X86_16/ir/stack_argument_modular_use_flow.py angr_platforms/tests/test_x86_16_stack_argument_modular_use.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_stack_argument_modular_use.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/stack_argument_scaled_return.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/stack_argument_scaled_return.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/stack_argument_scaled_return.py angr_platforms/tests/test_x86_16_stack_argument_scaled_return.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_stack_argument_scaled_return.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/semantics/direct_ret_call_effect.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/semantics/bp_call_preservation.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/semantics/direct_ret_call_effect.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/semantics/bp_call_preservation.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/semantics/direct_ret_call_effect.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/semantics/bp_call_preservation.py angr_platforms/tests/test_x86_16_bp_call_preservation.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_bp_call_preservation.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_far_stack_probe_aggregate.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_far_stack_probe_aggregate.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_census.py angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use.py angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use_contracts.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_census.py angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use.py angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use_contracts.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_census.py angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use.py angr_platforms/angr_platforms/X86_16/lowering/far_return_pointer_use_contracts.py angr_platforms/tests/test_x86_16_far_return_pointer_use.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_far_return_pointer_use.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_return_expression_binding.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/far_return_expression_binding.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/far_return_expression_binding.py angr_platforms/tests/test_x86_16_far_return_expression_binding.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_far_return_expression_binding.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_scaled_return_candidate.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_scaled_return_candidate.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_scaled_return_candidate.py angr_platforms/tests/test_x86_16_near_scaled_return_candidate.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_near_scaled_return_candidate.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_c_ast_congruence.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_c_ast_congruence.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_return_c_ast_congruence.py angr_platforms/tests/test_x86_16_near_return_c_ast_congruence.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_near_return_c_ast_congruence.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_segment_use.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_segment_use.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_return_segment_use.py angr_platforms/tests/test_x86_16_near_return_segment_use.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_near_return_segment_use.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_pointer_stack_input_segment.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_pointer_stack_input_segment.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_pointer_stack_input_segment.py angr_platforms/tests/test_x86_16_near_pointer_stack_input_segment.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_near_pointer_stack_input_segment.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_expression.py angr_platforms/angr_platforms/X86_16/lowering/near_return_selector.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_expression.py angr_platforms/angr_platforms/X86_16/lowering/near_return_selector.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_return_expression.py angr_platforms/angr_platforms/X86_16/lowering/near_return_selector.py angr_platforms/tests/test_x86_16_near_return_expression.py angr_platforms/tests/test_x86_16_near_return_expression_replay.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_near_return_expression.py angr_platforms/tests/test_x86_16_near_return_expression_replay.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_entry_selector.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_entry_selector.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_return_entry_selector.py angr_platforms/tests/test_x86_16_near_return_entry_selector.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_near_return_entry_selector.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_body_preflight.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_return_body_preflight.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_return_body_preflight.py angr_platforms/tests/test_x86_16_near_return_body_preflight.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_near_return_body_preflight.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/storage_word_input_binding.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/storage_word_input_binding.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/storage_word_input_binding.py angr_platforms/tests/test_x86_16_storage_word_input_binding.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_storage_word_input_binding.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_pointer_value_runtime.py angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument_values.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/near_pointer_value_runtime.py angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument_values.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/near_pointer_value_runtime.py angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument_values.py angr_platforms/tests/test_near_pointer_argument_values.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/ir_boundary_cfg.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/ir_boundary_cfg.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/ir_boundary_cfg.py angr_platforms/tests/test_x86_16_ir_boundary_cfg.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_ir_boundary_cfg.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/no_effect_instructions.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/no_effect_instructions.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/no_effect_instructions.py angr_platforms/tests/test_nop_census_8616.py angr_platforms/tests/test_nop_native_binding.py angr_platforms/tests/test_nop_cache_cost.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_nop_census_8616.py angr_platforms/tests/test_nop_native_binding.py angr_platforms/tests/test_nop_cache_cost.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/segment_effect_closure.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/segment_effect_closure.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/segment_effect_closure.py angr_platforms/tests/test_x86_16_segment_effect_closure.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_segment_effect_closure.py
SCOPED_IR_OWNERS := \
	tools/dosunit/real16_scoped_invocation.py \
	angr_platforms/angr_platforms/X86_16/frontend_invocation_inventory.py \
	angr_platforms/angr_platforms/X86_16/ir/entry_domain_call_preservation.py \
	angr_platforms/angr_platforms/X86_16/ir/scoped_function_ir_view.py
SCOPED_IR_CONTRACT_TESTS := \
	angr_platforms/tests/test_x86_16_invocation_inventory_budgets.py \
	angr_platforms/tests/test_x86_16_scoped_ir_view.py \
	angr_platforms/tests/test_x86_16_scoped_ir_view_counters.py \
	angr_platforms/tests/test_x86_16_scoped_ir_coverage.py \
	angr_platforms/tests/test_x86_16_scoped_ir_function_refusals.py \
	angr_platforms/tests/test_x86_16_scoped_segment_state.py \
	angr_platforms/tests/test_x86_16_scoped_resolution_guard.py
SCOPED_IR_NATIVE_TESTS := \
	angr_platforms/tests/test_x86_16_scoped_invocation_adapter.py \
	angr_platforms/tests/test_x86_16_scoped_ir_native_view.py \
	angr_platforms/tests/test_x86_16_scoped_ir_native_import.py \
	angr_platforms/tests/test_x86_16_scoped_ir_native_closure.py \
	angr_platforms/tests/test_x86_16_scoped_ir_native_resolution.py
LINTERS_DEV_MYPY_FILES += $(SCOPED_IR_OWNERS)
# Keep the declared boot/image contracts visible under follow_imports=skip;
# otherwise the adapter's runtime-authenticated ProgramBoot becomes Any.
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_boot.py tools/dosunit/real16_replay_model.py
QA_TYPED_FILES += $(SCOPED_IR_OWNERS)
QA_RUFF_TARGETS += $(SCOPED_IR_OWNERS) $(SCOPED_IR_CONTRACT_TESTS) $(SCOPED_IR_NATIVE_TESTS) angr_platforms/tests/test_x86_16_scoped_native_inputs.py
QA_PYTEST_TARGETS += $(SCOPED_IR_CONTRACT_TESTS)
# Native transport checks have their own serial lane to avoid proof-budget
# contention with the ordinary six-worker unit cohort.
.PHONY: test-scoped-ir-native
test-scoped-ir-native:
	$(PYTHON) -m pytest $(PYTEST_OUTPUT_FLAGS) --durations=10 $(SCOPED_IR_NATIVE_TESTS)
test-pipeline-expanded: test-scoped-ir-native

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/segment_call_preservation.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/segment_call_preservation_stage.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/segment_call_preservation_stage.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/segment_call_preservation_stage.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/segment_call_preservation.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/segment_call_preservation.py angr_platforms/tests/test_x86_16_segment_call_preservation.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_segment_call_preservation.py
QA_RUFF_TARGETS += angr_platforms/tests/segment_nonleaf_test_helpers.py angr_platforms/tests/test_segment_nonleaf_contracts.py angr_platforms/tests/test_segment_nonleaf_budgets.py angr_platforms/tests/test_segment_nonleaf_native.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_segment_nonleaf_contracts.py angr_platforms/tests/test_segment_nonleaf_budgets.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/input_offset_value.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/input_offset_value.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/input_offset_value.py angr_platforms/tests/test_x86_16_input_offset_value.py angr_platforms/tests/x86_16_native_call_fixtures.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_input_offset_value.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry.py angr_platforms/tests/test_x86_16_direct_call_segment_entry.py angr_platforms/tests/test_x86_16_direct_call_segment_entry_integrity.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_direct_call_segment_entry.py angr_platforms/tests/test_x86_16_direct_call_segment_entry_integrity.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry_binding.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry_binding.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_entry_binding.py angr_platforms/tests/test_x86_16_direct_call_segment_entry_provenance.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_direct_call_segment_entry_provenance.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_context.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_context.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/direct_call_segment_context.py angr_platforms/tests/test_x86_16_direct_call_segment_context.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_direct_call_segment_context.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/alias/saved_stack_store_window.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/alias/saved_stack_store_window.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/alias/saved_stack_store_window.py
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/ir/memory_offset_word_value.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/ir/memory_offset_word_value.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/ir/memory_offset_word_value.py angr_platforms/tests/test_x86_16_memory_offset_word_value.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_memory_offset_word_value.py

LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/frontend_block_partition.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/frontend_block_partition.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/frontend_block_partition.py angr_platforms/tests/test_x86_16_frontend_block_partition.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_frontend_block_partition.py

# Keep every exact fast-pipeline pytest target in the hard QA lane as well.
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_x86_16_calling_convention_compat.py \
	angr_platforms/tests/test_fork_timeout.py \
	angr_platforms/tests/test_batch_decompile_procs_runtime.py \
	angr_platforms/tests/test_x86_16_c_ast_utils.py \
	angr_platforms/tests/test_cli_c_text_postprocess.py::test_known_helper_signature_text_preserves_recovered_signature \
	angr_platforms/tests/test_x86_16_cod_samples.py::test_dosfunc_cod_sample_process_helpers_stay_empty \
	angr_platforms/tests/test_cod_stability_sweep.py \
	angr_platforms/tests/test_cli_fallback_slice_entry.py::test_sidecar_slice_refuses_truncated_cfg_ownership \
	angr_platforms/tests/test_x86_16_bounded_linear_instruction_inventory.py::test_bounded_inventory_decodes_to_exact_region_end \
	angr_platforms/tests/test_x86_16_function_pointer_argument_replay.py \
	angr_platforms/tests/test_x86_16_stack_annotation_authority.py \
	angr_platforms/tests/test_msc6_binary_recovery_policy.py \
	angr_platforms/tests/test_x86_16_frontend_capstone_decode.py \
	angr_platforms/tests/test_compiler_coverage_manifest.py \
	angr_platforms/tests/test_compiler_coverage_csmith.py \
	angr_platforms/tests/test_compiler_coverage_pointer_oracle.py \
	angr_platforms/tests/test_msc6_memory_model.py \
	angr_platforms/tests/test_compiler_coverage_result.py \
	angr_platforms/tests/test_compiler_coverage_suite.py \
	angr_platforms/tests/test_x86_16_nested_cdecl_arguments.py \
	angr_platforms/tests/test_omf_pat_fixup_encoding.py \
	angr_platforms/tests/test_msc6_original_evidence.py \
	angr_platforms/tests/test_discovery_pre_entry_order.py \
	angr_platforms/tests/test_signature_catalog_without_flair.py \
	angr_platforms/tests/test_binary_signature_metadata.py \
	angr_platforms/tests/test_signature_match_ambiguity.py \
	angr_platforms/tests/test_ada_signature_integration.py \
	angr_platforms/tests/test_default_signature_provenance.py \
	angr_platforms/tests/test_metadata_evidence.py \
	angr_platforms/tests/test_near_pointer_argument_values.py \
	angr_platforms/tests/test_signature_region_bounds.py \
	angr_platforms/tests/test_discovery_signature_isolation.py \
	angr_platforms/tests/test_discovery_library_boundaries.py \
	angr_platforms/tests/test_discovery_recovery_policy.py \
	angr_platforms/tests/test_callsite_complement_sources.py \
	angr_platforms/tests/test_x86_16_interprocedural_storage_caller_context.py \
	angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_can_extract_and_name_cod_procedure \
	angr_platforms/tests/test_x86_16_far_probe_lifting.py

include scripts/compiler_coverage.mk

QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_far_probe_lifting.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_scalar_value_projection.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_ssa_call_target_inputs.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_ssa_call_target_inputs.py
QA_TYPED_FILES += \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_bits.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_value_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_values.py
QA_RUFF_TARGETS += \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_bits.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_value_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_values.py \
	angr_platforms/tests/test_x86_16_entry_stack_word_bits.py \
	angr_platforms/tests/test_x86_16_entry_stack_word_values.py \
	angr_platforms/tests/test_x86_16_entry_stack_word_boundaries.py \
	angr_platforms/tests/test_x86_16_entry_stack_word_effects.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_x86_16_entry_stack_word_bits.py \
	angr_platforms/tests/test_x86_16_entry_stack_word_values.py \
	angr_platforms/tests/test_x86_16_entry_stack_word_boundaries.py \
	angr_platforms/tests/test_x86_16_entry_stack_word_effects.py

# One typed register-effect owner shared by entry-word value consumers.
ENTRY_WORD_TRANSPORT_TYPED_FILES := \
	angr_platforms/angr_platforms/X86_16/ir/scalar_instruction_effects.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_state.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_flow.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_snapshots.py
QA_TYPED_FILES += \
	angr_platforms/angr_platforms/X86_16/ir/scalar_instruction_effects.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_state.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_flow.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_snapshots.py
QA_RUFF_TARGETS += \
	angr_platforms/angr_platforms/X86_16/ir/scalar_instruction_effects.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_state.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_flow.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_word_transport_snapshots.py \
	angr_platforms/tests/test_x86_16_scalar_instruction_effects.py \
	angr_platforms/tests/test_x86_16_scalar_instruction_effects_emitter.py \
	angr_platforms/tests/test_x86_16_entry_word_transport.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_sites.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_control.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_snapshots.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_snapshot_coherence.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_x86_16_scalar_instruction_effects.py \
	angr_platforms/tests/test_x86_16_scalar_instruction_effects_emitter.py \
	angr_platforms/tests/test_x86_16_entry_word_transport.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_sites.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_control.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_snapshots.py \
	angr_platforms/tests/test_x86_16_entry_word_transport_snapshot_coherence.py

# Binary comparison contracts and independent replay owners.
QA_TYPED_FILES += angr_platforms/angr_platforms/import_identity.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/import_identity.py
QA_TYPED_FILES += \
	tools/dosunit/replay_machine_inputs.py \
	tools/dosunit/replay_capture_model.py \
	tools/dosunit/flat32_memory_permissions.py \
	tools/dosunit/flat32_replay_model.py \
	tools/dosunit/flat32_replay_memory.py \
	angr_platforms/tests/flat32_replay_test_support.py
QA_RUFF_TARGETS += \
	tools/dosunit/replay_machine_inputs.py \
	tools/dosunit/replay_capture_model.py \
	tools/dosunit/flat32_memory_permissions.py \
	tools/dosunit/flat32_replay_model.py \
	tools/dosunit/flat32_replay_memory.py \
	angr_platforms/tests/flat32_replay_test_support.py \
	angr_platforms/tests/test_flat32_file_permissions.py \
	angr_platforms/tests/test_flat32_mapping_contract.py \
	angr_platforms/tests/test_flat32_observation_contract.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_flat32_file_permissions.py \
	angr_platforms/tests/test_flat32_mapping_contract.py \
	angr_platforms/tests/test_flat32_observation_contract.py
QA_TYPED_FILES += scripts/workspace_sandbox.py
QA_TYPED_FILES += tools/dosunit/scc_proof_admission.py
QA_RUFF_TARGETS += tools/dosunit/scc_proof_admission.py angr_platforms/tests/test_ssa_scc_status_admission.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_ssa_scc_status_admission.py
QA_RUFF_TARGETS += scripts/workspace_sandbox.py angr_platforms/tests/test_workspace_sandbox.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_workspace_sandbox.py


# Declared DOS version-query effects and checked public receipts.
QA_TYPED_FILES += tools/dosunit/real16_program_version.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_version.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_version.py angr_platforms/tests/test_real16_program_version.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_version.py
QA_TYPED_FILES += tools/dosunit/real16_program_resize.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_resize.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_resize.py angr_platforms/tests/test_real16_program_resize.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_resize.py
QA_TYPED_FILES += tools/dosunit/real16_program_memory.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_memory.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_memory.py angr_platforms/tests/test_real16_program_memory.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_memory.py
QA_TYPED_FILES += tools/dosunit/real16_program_interrupts.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_interrupts.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_interrupts.py angr_platforms/tests/test_real16_program_interrupts.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_interrupts.py
QA_TYPED_FILES += tools/dosunit/real16_program_vectors.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_vectors.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_vectors.py angr_platforms/tests/test_real16_program_vectors.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_vectors.py
QA_TYPED_FILES += tools/dosunit/real16_program_device_info.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_device_info.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_device_info.py angr_platforms/tests/test_real16_program_device_info.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_device_info.py
QA_TYPED_FILES += tools/dosunit/real16_program_video.py tools/dosunit/real16_program_video_boundary.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_video.py tools/dosunit/real16_program_video_boundary.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_video.py tools/dosunit/real16_program_video_boundary.py angr_platforms/tests/test_real16_program_video.py angr_platforms/tests/test_real16_program_video_policy.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_video.py angr_platforms/tests/test_real16_program_video_policy.py
QA_TYPED_FILES += tools/dosunit/real16_program_video_state.py tools/dosunit/real16_video_state_boundary.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_video_state.py tools/dosunit/real16_video_state_boundary.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_video_state.py tools/dosunit/real16_video_state_boundary.py angr_platforms/tests/test_real16_video_state_policy.py angr_platforms/tests/test_real16_video_state_boundary.py angr_platforms/tests/test_real16_program_video_state.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_video_state_policy.py angr_platforms/tests/test_real16_video_state_boundary.py angr_platforms/tests/test_real16_program_video_state.py
QA_TYPED_FILES += tools/dosunit/real16_program_rom.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_program_rom.py
# SegOffset/LinearRange own the typed coordinates consumed by these contracts;
# MyPy's skipped imports otherwise turn their fields into Any in this lane.
LINTERS_DEV_MYPY_FILES += tools/dosunit/real16_replay_model.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_rom.py angr_platforms/tests/test_real16_program_rom.py angr_platforms/tests/test_real16_program_rom_integration.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_rom.py angr_platforms/tests/test_real16_program_rom_integration.py

# Explicit bounded initialized-program output stream contracts.
QA_TYPED_FILES += tools/dosunit/real16_program_output.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_output.py \
	angr_platforms/tests/test_real16_program_output.py angr_platforms/tests/test_real16_program_output_integration.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_output.py \
	angr_platforms/tests/test_real16_program_output_integration.py

# Declared read-only input file effects and complete cursor receipts.
QA_TYPED_FILES += tools/dosunit/real16_program_input.py tools/dosunit/real16_program_input_manifest.py \
	tools/dosunit/real16_program_file_receipts.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_input.py tools/dosunit/real16_program_input_manifest.py \
	tools/dosunit/real16_program_file_receipts.py \
	angr_platforms/tests/test_real16_program_input.py angr_platforms/tests/test_real16_program_input_integration.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_input.py \
	angr_platforms/tests/test_real16_program_input_integration.py

# Genuine PE32-to-PE32 public branch proof and mutation controls.
QA_RUFF_TARGETS += angr_platforms/tests/test_relational_branch_public32.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_relational_branch_public32.py
QA_RUFF_TARGETS += tools/dosunit/macro_step_contracts.py tools/dosunit/macro_step_pairing.py tools/dosunit/region_path_terms.py tools/dosunit/real16_macro_rows.py tools/dosunit/real16_macro_proof.py tools/dosunit/flat32_macro_terms.py tools/dosunit/flat32_macro_proof.py tools/dosunit/flat32_environment_coverage.py tools/dosunit/real16_macro_retry.py angr_platforms/tests/test_real16_macro_public.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_macro_public.py
QA_TYPED_FILES += tools/dosunit/real16_macro_retry.py
QA_RUFF_TARGETS += tools/dosunit/real16_retry_diagnostics.py angr_platforms/tests/test_real16_retry_budget_diagnostics.py
QA_TYPED_FILES += tools/dosunit/real16_retry_diagnostics.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_retry_budget_diagnostics.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_macro_step_proof.py angr_platforms/tests/test_macro_step_admission.py angr_platforms/tests/test_macro_step_deadlines.py angr_platforms/tests/test_macro_step_concat_exhaustion.py angr_platforms/tests/test_macro_step_return_state.py
QA_RUFF_TARGETS += angr_platforms/tests/test_macro_step_proof.py angr_platforms/tests/test_macro_step_admission.py angr_platforms/tests/test_macro_step_deadlines.py angr_platforms/tests/test_macro_step_concat_exhaustion.py angr_platforms/tests/test_macro_step_return_state.py
QA_RUFF_TARGETS += angr_platforms/tests/test_flat32_macro_retry.py
QA_RUFF_TARGETS += angr_platforms/tests/test_flat32_term_budget.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_flat32_macro_retry.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_flat32_term_budget.py

# Combined initialized-MZ immutable input and bounded output replay.
QA_RUFF_TARGETS += angr_platforms/tests/test_real16_program_file_copy.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_file_copy.py

# Initialized PE32 process contracts, independent of function return replay.
QA_TYPED_FILES += tools/dosunit/pe32_program_boot.py tools/dosunit/pe32_program_replay.py \
	tools/dosunit/pe32_program_manifest.py tools/dosunit/pe32_program_cli.py
QA_RUFF_TARGETS += tools/dosunit/pe32_program_boot.py tools/dosunit/pe32_program_replay.py \
	tools/dosunit/pe32_program_manifest.py tools/dosunit/pe32_program_cli.py \
	angr_platforms/tests/test_pe32_program_boot.py angr_platforms/tests/test_pe32_program_replay.py \
	angr_platforms/tests/test_pe32_program_cli.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pe32_program_boot.py \
	angr_platforms/tests/test_pe32_program_replay.py angr_platforms/tests/test_pe32_program_cli.py

# Literal gate lists are required by the architecture enrollment checker.
QA_TYPED_FILES += tools/dosunit/real16_program_boot.py tools/dosunit/real16_program_model.py \
	tools/dosunit/real16_program_replay.py tools/dosunit/real16_program_manifest.py tools/dosunit/real16_program_cli.py
QA_RUFF_TARGETS += tools/dosunit/real16_program_boot.py tools/dosunit/real16_program_model.py \
	tools/dosunit/real16_program_replay.py tools/dosunit/real16_program_manifest.py tools/dosunit/real16_program_cli.py \
	angr_platforms/tests/test_real16_program_boot.py angr_platforms/tests/test_real16_program_replay.py \
	angr_platforms/tests/test_real16_program_cli.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_program_boot.py \
	angr_platforms/tests/test_real16_program_replay.py angr_platforms/tests/test_real16_program_cli.py
QA_TYPED_FILES += tools/dosunit/binary_callee_intake.py tools/dosunit/binary_callee_discovery.py
QA_RUFF_TARGETS += tools/dosunit/binary_callee_intake.py tools/dosunit/binary_callee_discovery.py \
	angr_platforms/tests/test_binary_callee_intake.py \
	angr_platforms/tests/test_binary_callee_intake_review.py \
	angr_platforms/tests/test_real16_uncatalogued_calls.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_binary_callee_intake.py \
	angr_platforms/tests/test_binary_callee_intake_review.py \
	angr_platforms/tests/test_real16_uncatalogued_calls.py
QA_TYPED_FILES += \
	tools/dosunit/flat32_call_composition.py \
	tools/dosunit/flat32_proof_domain.py \
	tools/dosunit/flat32_proof_domain_cli.py \
	tools/dosunit/flat32_pe_loader.py \
	tools/dosunit/flat32_call_contracts.py \
	tools/dosunit/flat32_call_lowering.py \
	tools/dosunit/flat32_call_execution.py \
	tools/dosunit/flat32_cfg_regions.py \
	tools/dosunit/binary_environment.py \
	tools/dosunit/ordered_io_environment.py \
	tools/dosunit/ssa_io_retention.py \
	tools/dosunit/callee_proof_scope.py \
	tools/dosunit/proof_contracts.py \
	tools/dosunit/proof_public_domain.py \
	tools/dosunit/proof_obligations.py \
	tools/dosunit/proof_serialization.py \
	tools/dosunit/proof_projection.py \
	tools/dosunit/flat32_proof_report.py \
	tools/dosunit/flat32_proof_retry.py \
	tools/dosunit/flat32_replay.py \
	tools/dosunit/flat32_replay_cli.py \
	tools/dosunit/ssa_provenance.py \
	tools/dosunit/real16_binary_compare.py \
	tools/dosunit/real16_proof_evidence.py \
	tools/dosunit/ssa_constant_terms.py \
	tools/dosunit/real16_entry_domain.py \
	tools/dosunit/real16_loop_invariants.py \
	tools/dosunit/repeat_string_contracts.py \
	tools/dosunit/x86_lazy_conditions.py \
	tools/dosunit/real16_call_composition.py \
	tools/dosunit/real16_call_contracts.py \
	tools/dosunit/real16_call_evidence.py \
	tools/dosunit/real16_call_execution.py \
	tools/dosunit/real16_replay_model.py \
	tools/dosunit/real16_mz_load.py \
	tools/dosunit/real16_guest.py \
	tools/dosunit/real16_replay_compare.py \
	tools/dosunit/real16_replay.py \
	tools/dosunit/real16_replay_report.py \
	tools/dosunit/real16_replay_cli.py \
	tools/dosunit/real16_replay_manifest.py \
	tools/dosunit/real16_call_frames.py \
	tools/dosunit/real16_call_boundary.py \
	tools/dosunit/real16_loop_calls.py \
	tools/dosunit/real16_call_control.py \
	tools/dosunit/real16_control_resolution.py \
	tools/dosunit/real16_call_retry.py \
	tools/dosunit/binary_initial_state.py

QA_RUFF_TARGETS += \
	tools/dosunit/flat32_call_composition.py \
	tools/dosunit/flat32_proof_domain.py \
	tools/dosunit/flat32_proof_domain_cli.py \
	tools/dosunit/flat32_pe_loader.py \
	tools/dosunit/flat32_call_contracts.py \
	tools/dosunit/flat32_call_lowering.py \
	tools/dosunit/flat32_call_execution.py \
	tools/dosunit/flat32_cfg_regions.py \
	tools/dosunit/binary_environment.py \
	tools/dosunit/ordered_io_environment.py \
	tools/dosunit/ssa_io_retention.py \
	tools/dosunit/callee_proof_scope.py \
	tools/dosunit/proof_contracts.py \
	tools/dosunit/proof_public_domain.py \
	tools/dosunit/proof_obligations.py \
	tools/dosunit/proof_serialization.py \
	tools/dosunit/proof_projection.py \
	tools/dosunit/flat32_proof_report.py \
	tools/dosunit/flat32_proof_retry.py \
	tools/dosunit/flat32_replay.py \
	tools/dosunit/flat32_replay_cli.py \
	tools/dosunit/ssa_provenance.py \
	tools/dosunit/real16_binary_compare.py \
	tools/dosunit/real16_proof_evidence.py \
	tools/dosunit/ssa_constant_terms.py \
	tools/dosunit/real16_entry_domain.py \
	tools/dosunit/real16_loop_invariants.py \
	tools/dosunit/repeat_string_contracts.py \
	tools/dosunit/x86_lazy_conditions.py \
	tools/dosunit/real16_call_composition.py \
	tools/dosunit/real16_call_contracts.py \
	tools/dosunit/real16_call_evidence.py \
	tools/dosunit/real16_call_execution.py \
	tools/dosunit/real16_replay_model.py \
	tools/dosunit/real16_mz_load.py \
	tools/dosunit/real16_guest.py \
	tools/dosunit/real16_replay_compare.py \
	tools/dosunit/real16_replay.py \
	tools/dosunit/real16_replay_report.py \
	tools/dosunit/real16_replay_cli.py \
	tools/dosunit/real16_replay_manifest.py \
	tools/dosunit/real16_call_frames.py \
	tools/dosunit/real16_call_boundary.py \
	tools/dosunit/real16_loop_calls.py \
	tools/dosunit/real16_call_control.py \
	tools/dosunit/real16_control_resolution.py \
	angr_platforms/tests/test_real16_symbolic_call_control.py \
	angr_platforms/tests/test_real16_symbolic_successors.py \
	angr_platforms/tests/test_x86_16_relative_control_edge.py \
	angr_platforms/tests/test_x86_16_relative_condition_producers.py \
	tools/dosunit/real16_call_retry.py \
	tools/dosunit/binary_initial_state.py \
	angr_platforms/tests/test_dosunit_initial_image_relation.py \
	angr_platforms/tests/test_dosunit_proof_contracts.py \
	angr_platforms/tests/test_dosunit_public_domain.py \
	angr_platforms/tests/test_dosunit_public_domain_integration.py \
	angr_platforms/tests/test_dosunit_proof_projection.py \
	angr_platforms/tests/test_ssa_array_input_substitution.py \
	angr_platforms/tests/test_flat32_comparator_lane.py \
	angr_platforms/tests/test_flat32_loop_controls.py \
	angr_platforms/tests/test_flat32_stack_domain.py \
	angr_platforms/tests/test_flat32_stack_domain_cli.py \
	angr_platforms/tests/test_flat32_tail_transfer.py \
	angr_platforms/tests/test_flat32_compose_total_budget.py \
	angr_platforms/tests/test_flat32_tail_retry_projection.py \
	angr_platforms/tests/test_flat32_conditional_boundaries.py \
	angr_platforms/tests/test_flat32_loaded_byte_boundaries.py \
	angr_platforms/tests/test_flat32_concrete_replay.py \
	angr_platforms/tests/test_dosunit_guarded_capture.py \
	angr_platforms/tests/test_flat32_replay_cli.py \
	angr_platforms/tests/test_flat32_replay_full_state.py \
	angr_platforms/tests/test_dosunit_binary_environment.py \
	angr_platforms/tests/test_ordered_io_environment.py \
	angr_platforms/tests/test_ordered_io_native.py \
	angr_platforms/tests/test_ordered_io_native_extended.py \
	angr_platforms/tests/test_x86_16_immediate_port.py \
	angr_platforms/tests/test_x86_16_immediate_port_vex.py \
	angr_platforms/tests/test_dosunit_ssa_provenance.py \
	angr_platforms/tests/test_dosunit_callee_scope.py \
	angr_platforms/tests/test_dosunit_induction_soundness.py \
	angr_platforms/tests/test_real16_binary_compare.py \
	angr_platforms/tests/test_real16_self_lowering_reuse.py \
	angr_platforms/tests/test_real16_call_composition.py \
	angr_platforms/tests/test_real16_argument_controls.py \
	angr_platforms/tests/test_real16_repeat_summary_contract.py \
	angr_platforms/tests/test_dosunit_x86_lazy_conditions.py \
	angr_platforms/tests/test_dosunit_x86_carry_helper.py \
	angr_platforms/tests/test_x86_16_import_identity.py \
	angr_platforms/tests/test_real16_ail_control_contract.py \
	angr_platforms/tests/test_real16_call_admission.py \
	angr_platforms/tests/test_real16_public_calls.py \
	angr_platforms/tests/test_real16_concrete_replay.py \
	angr_platforms/tests/test_real16_replay_observations.py

QA_RUFF_TARGETS += \
	angr_platforms/tests/test_real16_control_domain.py \
	angr_platforms/tests/test_real16_return_coordinates.py \
	angr_platforms/tests/test_real16_operand_call_composition.py \
	angr_platforms/tests/test_real16_replay_snapshot.py \
	angr_platforms/tests/test_real16_replay_cli.py \
	angr_platforms/tests/test_real16_loop_calls.py \
	angr_platforms/tests/test_real16_far_loop_controls.py \
	angr_platforms/tests/test_real16_far_call_composition.py

QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_real16_control_domain.py \
	angr_platforms/tests/test_real16_return_coordinates.py \
	angr_platforms/tests/test_real16_operand_call_composition.py \
	angr_platforms/tests/test_real16_replay_snapshot.py \
	angr_platforms/tests/test_dosunit_initial_image_relation.py \
	angr_platforms/tests/test_dosunit_proof_contracts.py \
	angr_platforms/tests/test_dosunit_public_domain.py \
	angr_platforms/tests/test_dosunit_public_domain_integration.py \
	angr_platforms/tests/test_dosunit_proof_projection.py \
	angr_platforms/tests/test_ssa_array_input_substitution.py \
	angr_platforms/tests/test_flat32_comparator_lane.py \
	angr_platforms/tests/test_flat32_loop_controls.py \
	angr_platforms/tests/test_flat32_stack_domain.py \
	angr_platforms/tests/test_flat32_stack_domain_cli.py \
	angr_platforms/tests/test_flat32_tail_transfer.py \
	angr_platforms/tests/test_flat32_compose_total_budget.py \
	angr_platforms/tests/test_flat32_tail_retry_projection.py \
	angr_platforms/tests/test_flat32_conditional_boundaries.py \
	angr_platforms/tests/test_flat32_loaded_byte_boundaries.py \
	angr_platforms/tests/test_flat32_concrete_replay.py \
	angr_platforms/tests/test_dosunit_guarded_capture.py \
	angr_platforms/tests/test_flat32_replay_cli.py \
	angr_platforms/tests/test_flat32_replay_full_state.py \
	angr_platforms/tests/test_dosunit_binary_environment.py \
	angr_platforms/tests/test_ordered_io_environment.py \
	angr_platforms/tests/test_ordered_io_native.py \
	angr_platforms/tests/test_ordered_io_native_extended.py \
	angr_platforms/tests/test_x86_16_immediate_port.py \
	angr_platforms/tests/test_x86_16_immediate_port_vex.py \
	angr_platforms/tests/test_dosunit_ssa_provenance.py \
	angr_platforms/tests/test_dosunit_callee_scope.py \
	angr_platforms/tests/test_dosunit_induction_soundness.py \
	angr_platforms/tests/test_real16_binary_compare.py \
	angr_platforms/tests/test_real16_self_lowering_reuse.py \
	angr_platforms/tests/test_real16_call_composition.py \
	angr_platforms/tests/test_real16_argument_controls.py \
	angr_platforms/tests/test_real16_repeat_summary_contract.py \
	angr_platforms/tests/test_dosunit_x86_lazy_conditions.py \
	angr_platforms/tests/test_dosunit_x86_carry_helper.py \
	angr_platforms/tests/test_real16_ail_control_contract.py \
	angr_platforms/tests/test_real16_call_admission.py \
	angr_platforms/tests/test_real16_public_calls.py \
	angr_platforms/tests/test_real16_concrete_replay.py \
	angr_platforms/tests/test_real16_replay_observations.py

QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_real16_replay_cli.py \
	angr_platforms/tests/test_real16_loop_calls.py \
	angr_platforms/tests/test_real16_far_loop_controls.py \
	angr_platforms/tests/test_real16_far_call_composition.py

QA_TYPED_FILES += \
	tools/dosunit/paired_region_graph.py \
	tools/dosunit/ssa_control_flow.py \
	tools/dosunit/real16_region_transitions.py \
	tools/dosunit/real16_region_proof.py
QA_RUFF_TARGETS += \
	tools/dosunit/paired_region_graph.py \
	tools/dosunit/ssa_control_flow.py \
	angr_platforms/tests/test_dosunit_ssa_versions.py \
	tools/dosunit/real16_region_transitions.py \
	tools/dosunit/real16_region_proof.py \
	angr_platforms/tests/test_paired_region_graph.py \
	angr_platforms/tests/test_real16_region_proof.py \
	angr_platforms/tests/test_real16_region_public.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_dosunit_ssa_versions.py \
	angr_platforms/tests/test_paired_region_graph.py \
	angr_platforms/tests/test_real16_region_proof.py \
	angr_platforms/tests/test_real16_region_public.py

QA_TYPED_FILES += \
	tools/dosunit/register_state_relations.py \
	tools/dosunit/proof_scope.py
QA_RUFF_TARGETS += \
	tools/dosunit/register_state_relations.py \
	tools/dosunit/proof_scope.py \
	angr_platforms/tests/test_register_state_relations.py \
	angr_platforms/tests/test_proof_scope.py \
	angr_platforms/tests/test_real16_register_regions.py \
	angr_platforms/tests/test_real16_register_public.py \
	angr_platforms/tests/test_flat32_register_regions.py \
	angr_platforms/tests/test_flat32_register_replay.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_register_state_relations.py \
	angr_platforms/tests/test_proof_scope.py \
	angr_platforms/tests/test_real16_register_regions.py \
	angr_platforms/tests/test_real16_register_public.py \
	angr_platforms/tests/test_flat32_register_regions.py \
	angr_platforms/tests/test_flat32_register_replay.py

QA_TYPED_FILES += \
	tools/dosunit/register_affine_relations.py \
	tools/dosunit/flat32_cfg_lifting.py
QA_RUFF_TARGETS += \
	tools/dosunit/register_affine_relations.py \
	tools/dosunit/flat32_cfg_lifting.py \
	angr_platforms/tests/test_real16_affine_regions.py \
	angr_platforms/tests/test_flat32_affine_regions.py \
	angr_platforms/tests/test_register_affine_relations.py \
	angr_platforms/tests/test_affine_concrete_replay.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_real16_affine_regions.py \
	angr_platforms/tests/test_flat32_affine_regions.py \
	angr_platforms/tests/test_register_affine_relations.py \
	angr_platforms/tests/test_affine_concrete_replay.py

# Finite-cover and memory-invariant relations require complete state proofs.
QA_TYPED_FILES += tools/dosunit/region_branch_pairing.py
QA_RUFF_TARGETS += \
	tools/dosunit/region_branch_pairing.py \
	angr_platforms/tests/test_region_branch_pairing.py \
	angr_platforms/tests/test_branch_pairing_oracle.py \
	angr_platforms/tests/test_region_pairing_reporting.py \
	angr_platforms/tests/test_real16_branch_regions.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_region_branch_pairing.py \
	angr_platforms/tests/test_branch_pairing_oracle.py \
	angr_platforms/tests/test_region_pairing_reporting.py \
	angr_platforms/tests/test_real16_branch_regions.py
QA_TYPED_FILES += \
	tools/dosunit/cutpoint_state_relations.py \
	tools/dosunit/finite_region_cover.py \
	tools/dosunit/flat32_invariant_proof.py \
	tools/dosunit/flat32_invariant_retry.py \
	tools/dosunit/flat32_region_attempts.py \
	tools/dosunit/flat32_relation_evidence.py \
	tools/dosunit/memory_invariant_obligations.py \
	tools/dosunit/memory_invariant_priority.py \
	tools/dosunit/memory_invariant_proposals.py \
	tools/dosunit/memory_relation_proposals.py \
	tools/dosunit/memory_state_invariants.py \
	tools/dosunit/memory_state_relations.py \
	tools/dosunit/real16_memory_relations.py \
	tools/dosunit/region_pairing.py
QA_RUFF_TARGETS += \
	tools/dosunit/cutpoint_state_relations.py \
	tools/dosunit/finite_region_cover.py \
	tools/dosunit/flat32_invariant_proof.py \
	tools/dosunit/flat32_invariant_retry.py \
	tools/dosunit/flat32_region_attempts.py \
	tools/dosunit/flat32_relation_evidence.py \
	tools/dosunit/memory_invariant_obligations.py \
	tools/dosunit/memory_invariant_priority.py \
	tools/dosunit/memory_invariant_proposals.py \
	tools/dosunit/memory_relation_proposals.py \
	tools/dosunit/memory_state_invariants.py \
	tools/dosunit/memory_state_relations.py \
	tools/dosunit/real16_memory_relations.py \
	tools/dosunit/region_pairing.py \
	angr_platforms/tests/test_region_cover.py \
	angr_platforms/tests/test_region_composition_admission.py \
	angr_platforms/tests/test_memory_state_relations.py \
	angr_platforms/tests/test_memory_relation_proposals.py \
	angr_platforms/tests/test_memory_invariant_obligations.py \
	angr_platforms/tests/test_memory_invariant_proposals.py \
	angr_platforms/tests/test_memory_state_invariants.py \
	angr_platforms/tests/test_invariant_retry_contracts.py \
	angr_platforms/tests/test_flat32_source_closure.py \
	angr_platforms/tests/test_real16_rotation_regions.py \
	angr_platforms/tests/test_flat32_rotation_regions.py \
	angr_platforms/tests/test_rotation_concrete_replay.py \
	angr_platforms/tests/test_relational_rotation_public32.py \
	angr_platforms/tests/test_relational_saved_public32.py \
	angr_platforms/tests/test_relational_saved_public16.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_region_cover.py \
	angr_platforms/tests/test_region_composition_admission.py \
	angr_platforms/tests/test_memory_state_relations.py \
	angr_platforms/tests/test_memory_relation_proposals.py \
	angr_platforms/tests/test_memory_invariant_obligations.py \
	angr_platforms/tests/test_memory_invariant_proposals.py \
	angr_platforms/tests/test_memory_state_invariants.py \
	angr_platforms/tests/test_invariant_retry_contracts.py \
	angr_platforms/tests/test_flat32_source_closure.py \
	angr_platforms/tests/test_real16_rotation_regions.py \
	angr_platforms/tests/test_flat32_rotation_regions.py \
	angr_platforms/tests/test_rotation_concrete_replay.py \
	angr_platforms/tests/test_relational_rotation_public32.py \
	angr_platforms/tests/test_relational_saved_public32.py \
	angr_platforms/tests/test_relational_saved_public16.py

# Declared candidate scopes retain external obligations without binary expansion.
QA_TYPED_FILES += tools/dosunit/ssa_lowering_scope.py
QA_RUFF_TARGETS += tools/dosunit/ssa_lowering_scope.py angr_platforms/tests/test_ssa_declared_scope.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_ssa_declared_scope.py

# Complete SSA array-output lemmas retain scalar/flag/memory mutations and
# unknown-lemma refusals in the normal comparator regression lane.
QA_TYPED_FILES += \
	tools/dosunit/ssa_output_lemmas.py
QA_RUFF_TARGETS += \
	tools/dosunit/ssa_output_lemmas.py \
	angr_platforms/tests/test_ssa_output_lemmas.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_ssa_output_lemmas.py

# Exact generation comparison has a bounded pure-DAG regression and native
# subclass/depth/hash controls; keep these in both routine entry points.
QA_RUFF_TARGETS += \
	angr_platforms/tests/test_x86_16_tail_validation_generation_atoms.py \
	angr_platforms/tests/test_x86_16_tail_validation_generation_equality.py \
	angr_platforms/tests/test_x86_16_validation_goto_target_identity.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_x86_16_tail_validation_generation_atoms.py \
	angr_platforms/tests/test_x86_16_tail_validation_generation_equality.py \
	angr_platforms/tests/test_x86_16_validation_goto_target_identity.py

# Real nonzero-base MZs pin absolute bounds and relative Clemory counts.
QA_RUFF_TARGETS += \
	angr_platforms/tests/test_x86_16_image_extent_projection.py \
	angr_platforms/tests/test_cli_loader_memory_boundary.py \
	angr_platforms/tests/test_cli_core_isolated_recovery.py \
	angr_platforms/tests/test_cli_function_discovery_regions.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_x86_16_image_extent_projection.py \
	angr_platforms/tests/test_cli_loader_memory_boundary.py \
	angr_platforms/tests/test_cli_core_isolated_recovery.py \
	angr_platforms/tests/test_cli_function_discovery_regions.py

# The final direct clean-worker snapshot retains selected/neighbor/UNKNOWN
# evidence across same-project and rebased payload boundaries.
QA_RUFF_TARGETS += \
	angr_platforms/tests/test_cli_direct_caller_return_snapshot.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_cli_direct_caller_return_snapshot.py

# Callee-bound modular input typing must retain foreign-callee, unknown SSA,
# pointer/condition-conflict and five-stage evidence refusal controls.
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/modular_argument_type_facts.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/modular_argument_type_facts.py
QA_RUFF_TARGETS += \
	angr_platforms/angr_platforms/X86_16/lowering/modular_argument_type_facts.py \
	angr_platforms/tests/test_x86_16_modular_input_type_join.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_x86_16_modular_input_type_join.py

# Optional signatures must not truncate independently closed binary callers;
# unknown bodies and genuine neighboring library boundaries remain refused.
LINTERS_DEV_MYPY_FILES += inertia_decompiler/discovery_candidate_ranges.py
QA_TYPED_FILES += inertia_decompiler/discovery_candidate_ranges.py
QA_RUFF_TARGETS += \
	inertia_decompiler/discovery_candidate_ranges.py \
	angr_platforms/tests/test_cli_caller_range_binary_bounds.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_cli_caller_range_binary_bounds.py

# Native near-pointer ABI execution is default-only; lint it in the regular gate.
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_near_pointer_native_runtime.py

# Logical PUSH transport is a typed input contract, not pointer or segment proof.
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_logical_input_contracts.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_logical_input_contracts.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_logical_input_contracts.py

# Disposable focused-job concurrency keeps serial IPC and per-job budgets.
LINTERS_DEV_MYPY_FILES += scripts/batch_decompile_scheduler.py
QA_TYPED_FILES += scripts/batch_decompile_scheduler.py
QA_RUFF_TARGETS += \
	scripts/batch_decompile_scheduler.py \
	angr_platforms/tests/test_batch_decompile_scheduler.py \
	angr_platforms/tests/test_batch_decompile_frame_deadline.py \
	angr_platforms/tests/test_batch_decompile_result_contract.py \
	angr_platforms/tests/test_msc6_batch_worker_budget.py
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_batch_decompile_scheduler.py \
	angr_platforms/tests/test_batch_decompile_frame_deadline.py \
	angr_platforms/tests/test_batch_decompile_result_contract.py \
	angr_platforms/tests/test_msc6_batch_worker_budget.py

# Binary-bound recursive component contracts; unresolved model scope stays conditional.
LINTERS_DEV_MYPY_FILES += tools/dosunit/recursive_proofs/real16_normal_outcome_scope.py
QA_TYPED_FILES += tools/dosunit/recursive_proofs/real16_normal_outcome_scope.py
QA_RUFF_TARGETS += tools/dosunit/recursive_proofs/real16_normal_outcome_scope.py angr_platforms/tests/test_real16_normal_outcome_scope.py
QA_TYPED_FILES += \
	tools/dosunit/recursive_proofs/__init__.py \
	tools/dosunit/recursive_proofs/stack/__init__.py \
	tools/dosunit/recursive_proofs/loaded_byte_image_binding.py \
	tools/dosunit/recursive_proofs/loaded_byte_native_transition.py \
	tools/dosunit/recursive_proofs/loaded_byte_relation.py \
	tools/dosunit/recursive_proofs/loaded_byte_relation_proof.py \
	tools/dosunit/recursive_proofs/native_effect_equality.py \
	tools/dosunit/recursive_proofs/native_model_hash_snapshot.py \
	tools/dosunit/recursive_proofs/real16_bound_control_scope.py \
	tools/dosunit/recursive_proofs/real16_domain_dispatch.py \
	tools/dosunit/recursive_proofs/real16_native_control_scope.py \
	tools/dosunit/recursive_proofs/real16_bound_operand_scope.py \
	tools/dosunit/recursive_proofs/real16_code_byte_oracle.py \
	tools/dosunit/recursive_proofs/real16_code_prefix_proof.py \
	tools/dosunit/recursive_proofs/real16_entry_domain.py \
	tools/dosunit/recursive_proofs/real16_entry_domain_proof.py \
	tools/dosunit/recursive_proofs/real16_entry_frame.py \
	tools/dosunit/recursive_proofs/real16_fetch_scope.py \
	tools/dosunit/recursive_proofs/real16_fetched_code_intake.py \
	tools/dosunit/recursive_proofs/real16_fetched_code_invariant.py \
	tools/dosunit/recursive_proofs/real16_image_bound_domain.py \
	tools/dosunit/recursive_proofs/real16_image_bound_domain_consumer.py \
	tools/dosunit/recursive_proofs/real16_image_bound_joint_proof.py \
	tools/dosunit/recursive_proofs/real16_image_bound_native_proof.py \
	tools/dosunit/recursive_proofs/real16_native_effect_binding.py \
	tools/dosunit/recursive_proofs/real16_native_memory_access.py \
	tools/dosunit/recursive_proofs/real16_operand_access.py \
	tools/dosunit/recursive_proofs/real16_operand_scope_proof.py \
	tools/dosunit/recursive_proofs/real16_physical_access_bounds.py \
	tools/dosunit/recursive_proofs/recursive_call_components.py \
	tools/dosunit/recursive_proofs/recursive_call_continuation.py \
	tools/dosunit/recursive_proofs/recursive_joint_admission.py \
	tools/dosunit/recursive_proofs/recursive_joint_contracts.py \
	tools/dosunit/recursive_proofs/recursive_joint_identity.py \
	tools/dosunit/recursive_proofs/recursive_joint_proof.py \
	tools/dosunit/recursive_proofs/recursive_static_control.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_address_comparisons.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_clauses.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_domains.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_proofs.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_scalar_lemmas.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_store_coordinates.py
QA_RUFF_TARGETS += angr_platforms/tests/test_dosunit_ssa_source_identity_paths.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_dosunit_ssa_source_identity_paths.py
QA_RUFF_TARGETS += \
	tools/dosunit/recursive_proofs/__init__.py \
	tools/dosunit/recursive_proofs/stack/__init__.py \
	tools/dosunit/recursive_proofs/loaded_byte_image_binding.py \
	tools/dosunit/recursive_proofs/loaded_byte_native_transition.py \
	tools/dosunit/recursive_proofs/loaded_byte_relation.py \
	tools/dosunit/recursive_proofs/loaded_byte_relation_proof.py \
	tools/dosunit/recursive_proofs/native_effect_equality.py \
	tools/dosunit/recursive_proofs/native_model_hash_snapshot.py \
	tools/dosunit/recursive_proofs/real16_bound_control_scope.py \
	tools/dosunit/recursive_proofs/real16_domain_dispatch.py \
	tools/dosunit/recursive_proofs/real16_native_control_scope.py \
	tools/dosunit/recursive_proofs/real16_bound_operand_scope.py \
	tools/dosunit/recursive_proofs/real16_code_byte_oracle.py \
	tools/dosunit/recursive_proofs/real16_code_prefix_proof.py \
	tools/dosunit/recursive_proofs/real16_entry_domain.py \
	tools/dosunit/recursive_proofs/real16_entry_domain_proof.py \
	tools/dosunit/recursive_proofs/real16_entry_frame.py \
	tools/dosunit/recursive_proofs/real16_fetch_scope.py \
	tools/dosunit/recursive_proofs/real16_fetched_code_intake.py \
	tools/dosunit/recursive_proofs/real16_fetched_code_invariant.py \
	tools/dosunit/recursive_proofs/real16_image_bound_domain.py \
	tools/dosunit/recursive_proofs/real16_image_bound_domain_consumer.py \
	tools/dosunit/recursive_proofs/real16_image_bound_joint_proof.py \
	tools/dosunit/recursive_proofs/real16_image_bound_native_proof.py \
	tools/dosunit/recursive_proofs/real16_native_effect_binding.py \
	tools/dosunit/recursive_proofs/real16_native_memory_access.py \
	tools/dosunit/recursive_proofs/real16_operand_access.py \
	tools/dosunit/recursive_proofs/real16_operand_scope_proof.py \
	tools/dosunit/recursive_proofs/real16_physical_access_bounds.py \
	tools/dosunit/recursive_proofs/recursive_call_components.py \
	tools/dosunit/recursive_proofs/recursive_call_continuation.py \
	tools/dosunit/recursive_proofs/recursive_joint_admission.py \
	tools/dosunit/recursive_proofs/recursive_joint_contracts.py \
	tools/dosunit/recursive_proofs/recursive_joint_identity.py \
	tools/dosunit/recursive_proofs/recursive_joint_proof.py \
	tools/dosunit/recursive_proofs/recursive_static_control.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_address_comparisons.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_clauses.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_domains.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_proofs.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_scalar_lemmas.py \
	tools/dosunit/recursive_proofs/stack/recursive_stack_store_coordinates.py \
	angr_platforms/tests/test_recursive_joint_deadlines.py \
	angr_platforms/tests/test_real16_domain_dispatch.py \
	angr_platforms/tests/test_recursive_fetched_code_composition.py \
	angr_platforms/tests/test_recursive_native_deadlines.py \
	angr_platforms/tests/test_recursive_entry_deadlines.py \
	angr_platforms/tests/test_recursive_entry_layout_deadlines.py \
	angr_platforms/tests/test_recursive_domain_deadlines.py \
	angr_platforms/tests/test_recursive_consumer_model_refresh.py \
	angr_platforms/tests/test_real16_address_final_seal.py \
	angr_platforms/tests/test_recursive_loaded_memory_seed.py \
	angr_platforms/tests/test_recursive_joint_actual_binary.py \
	angr_platforms/tests/test_recursive_call_continuation_binding.py \
	angr_platforms/tests/test_recursive_call_continuation_contracts.py \
	angr_platforms/tests/test_recursive_fetched_code_invariant.py \
	angr_platforms/tests/recursive_proof_fixtures
QA_PYTEST_TARGETS += \
	angr_platforms/tests/test_recursive_joint_deadlines.py \
	angr_platforms/tests/test_real16_domain_dispatch.py \
	angr_platforms/tests/test_recursive_call_continuation_contracts.py \
	angr_platforms/tests/test_recursive_fetched_code_composition.py \
	angr_platforms/tests/test_recursive_native_deadlines.py \
	angr_platforms/tests/test_recursive_entry_deadlines.py \
	angr_platforms/tests/test_recursive_entry_layout_deadlines.py \
	angr_platforms/tests/test_recursive_domain_deadlines.py \
	angr_platforms/tests/test_recursive_consumer_model_refresh.py \
	angr_platforms/tests/test_real16_address_final_seal.py \
	angr_platforms/tests/test_recursive_loaded_memory_seed.py


# PE32 binary-bound recursive component prerequisites (conditional scope).
QA_TYPED_FILES += tools/dosunit/recursive_proofs/flat32_image_bound_domain.py tools/dosunit/recursive_proofs/flat32_image_bound_joint_proof.py tools/dosunit/recursive_proofs/flat32_native_effect_binding.py tools/dosunit/recursive_proofs/flat32_pe_component.py
QA_RUFF_TARGETS += tools/dosunit/recursive_proofs/flat32_image_bound_domain.py tools/dosunit/recursive_proofs/flat32_image_bound_joint_proof.py tools/dosunit/recursive_proofs/flat32_native_effect_binding.py tools/dosunit/recursive_proofs/flat32_pe_component.py angr_platforms/tests/test_flat32_pe32_recursive_joint.py angr_platforms/tests/test_flat32_model_namespaces.py angr_platforms/tests/test_flat32_code_write_domain.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_flat32_pe32_recursive_joint.py angr_platforms/tests/test_flat32_model_namespaces.py angr_platforms/tests/test_flat32_code_write_domain.py

# Public initialized-entry real16 recursive comparison and intake guards.
QA_TYPED_FILES += tools/dosunit/real16_call_graph_admission.py tools/dosunit/recursive_proofs/real16_joint_construction.py tools/dosunit/real16_recursive_compare.py
QA_RUFF_TARGETS += tools/dosunit/real16_call_graph_admission.py tools/dosunit/recursive_proofs/real16_joint_construction.py tools/dosunit/real16_recursive_compare.py angr_platforms/tests/test_real16_recursive_public.py angr_platforms/tests/test_real16_recursive_intake_controls.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_recursive_public.py angr_platforms/tests/test_real16_recursive_intake_controls.py

# Public PE32 recursive component reports; ordinary member verdicts stay separate.
QA_TYPED_FILES += tools/dosunit/pe32_recursive_compare.py
QA_RUFF_TARGETS += tools/dosunit/pe32_recursive_compare.py angr_platforms/tests/test_pe32_recursive_public.py angr_platforms/tests/test_pe32_recursive_report_contracts.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pe32_recursive_public.py angr_platforms/tests/test_pe32_recursive_report_contracts.py

# Bounded real16 indirect-call composition and complete target coverage.
QA_TYPED_FILES += tools/dosunit/real16_call_indirect.py
QA_RUFF_TARGETS += tools/dosunit/real16_call_indirect.py angr_platforms/tests/test_real16_indirect_call_composition.py angr_platforms/tests/test_real16_indirect_call_budgets.py angr_platforms/tests/test_real16_indirect_call_multiarm.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_indirect_call_composition.py angr_platforms/tests/test_real16_indirect_call_budgets.py angr_platforms/tests/test_real16_indirect_call_multiarm.py

# Shared symbolic terminal-service proof and public scope schema.
QA_TYPED_FILES += tools/dosunit/terminal_fault.py
QA_RUFF_TARGETS += tools/dosunit/terminal_fault.py angr_platforms/tests/test_symbolic_terminal_faults.py angr_platforms/tests/test_symbolic_terminal_signed_divmod.py angr_platforms/tests/test_dosunit_signed_divmod.py angr_platforms/tests/test_flat32_loop_call_failure_report.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_symbolic_terminal_faults.py angr_platforms/tests/test_symbolic_terminal_signed_divmod.py angr_platforms/tests/test_dosunit_signed_divmod.py angr_platforms/tests/test_flat32_loop_call_failure_report.py
QA_TYPED_FILES += tools/dosunit/symbolic_terminal_cli.py tools/dosunit/flat32_lifting.py tools/dosunit/symbolic_terminal.py tools/dosunit/terminal_memory_effects.py
QA_TYPED_FILES += tools/dosunit/symbolic_terminal_real16_services.py tools/dosunit/terminal_native_decode.py
QA_TYPED_FILES += tools/dosunit/pe32_import_service.py
QA_RUFF_TARGETS += angr_platforms/tests/test_pe32_import_service_cli.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pe32_import_service_cli.py
QA_RUFF_TARGETS += tools/dosunit/pe32_import_service.py angr_platforms/tests/test_pe32_import_service.py angr_platforms/tests/test_pe32_import_service_schema.py angr_platforms/tests/test_symbolic_terminal_configured_limits.py angr_platforms/tests/test_symbolic_terminal_pe32_thunk_census.py angr_platforms/tests/test_symbolic_terminal_ivt_precision.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pe32_import_service.py angr_platforms/tests/test_pe32_import_service_schema.py angr_platforms/tests/test_symbolic_terminal_configured_limits.py angr_platforms/tests/test_symbolic_terminal_pe32_thunk_census.py angr_platforms/tests/test_symbolic_terminal_ivt_precision.py
QA_RUFF_TARGETS += tools/dosunit/symbolic_terminal_real16_services.py tools/dosunit/terminal_native_decode.py angr_platforms/tests/test_symbolic_terminal_services.py angr_platforms/tests/test_symbolic_terminal_service_census.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_symbolic_terminal_services.py angr_platforms/tests/test_symbolic_terminal_service_census.py
QA_RUFF_TARGETS += tools/dosunit/symbolic_terminal_cli.py angr_platforms/tests/test_symbolic_terminal_cli.py tools/dosunit/flat32_lifting.py tools/dosunit/symbolic_terminal.py tools/dosunit/terminal_memory_effects.py angr_platforms/tests/test_symbolic_terminal.py angr_platforms/tests/test_symbolic_terminal_read_permissions.py angr_platforms/tests/test_symbolic_terminal_partial_pe_data.py angr_platforms/tests/test_symbolic_terminal_output_coverage.py angr_platforms/tests/test_symbolic_terminal_read_audit_lifetime.py angr_platforms/tests/test_real16_recursive_report_schema.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_symbolic_terminal_cli.py angr_platforms/tests/test_symbolic_terminal.py angr_platforms/tests/test_symbolic_terminal_read_permissions.py angr_platforms/tests/test_symbolic_terminal_partial_pe_data.py angr_platforms/tests/test_symbolic_terminal_output_coverage.py angr_platforms/tests/test_symbolic_terminal_read_audit_lifetime.py angr_platforms/tests/test_real16_recursive_report_schema.py

# Source-bound callee region candidate scanner and contracts.
QA_TYPED_FILES += tools/dosunit/binary_callee_region_contracts.py tools/dosunit/binary_callee_region_scan.py tools/dosunit/binary_callee_control_target.py tools/dosunit/binary_callee_region_split.py
QA_RUFF_TARGETS += tools/dosunit/binary_callee_region_contracts.py tools/dosunit/binary_callee_region_scan.py tools/dosunit/binary_callee_control_target.py tools/dosunit/binary_callee_region_split.py angr_platforms/tests/test_binary_callee_region_scan.py angr_platforms/tests/test_binary_callee_control_target.py angr_platforms/tests/test_binary_callee_leader_split.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_binary_callee_region_scan.py angr_platforms/tests/test_binary_callee_control_target.py angr_platforms/tests/test_binary_callee_leader_split.py

QA_TYPED_FILES += tools/dosunit/binary_callee_region_intake.py
QA_RUFF_TARGETS += tools/dosunit/binary_callee_region_intake.py angr_platforms/tests/test_binary_callee_region_intake.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_binary_callee_region_intake.py

QA_TYPED_FILES += tools/dosunit/binary_callee_region_lowering.py
QA_TYPED_FILES += tools/dosunit/binary_callee_region_pending.py
QA_RUFF_TARGETS += tools/dosunit/binary_callee_region_pending.py angr_platforms/tests/test_binary_callee_repeat_intake.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_binary_callee_repeat_intake.py
QA_RUFF_TARGETS += tools/dosunit/binary_callee_region_lowering.py

# Native-bound real16 symbolic-control proofs and closed evidence budgets.
QA_TYPED_FILES += tools/dosunit/real16_control_targets.py tools/dosunit/real16_control_boundary.py
QA_RUFF_TARGETS += tools/dosunit/real16_control_targets.py tools/dosunit/real16_control_boundary.py \
	angr_platforms/tests/test_real16_control_boundary.py angr_platforms/tests/test_real16_control_target_proof.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_control_boundary.py angr_platforms/tests/test_real16_control_target_proof.py

# Source-bound native lifter bundles and initialized MZ boot provenance.
QA_RUFF_TARGETS += angr_platforms/tests/test_mypyc_vex_bundle.py angr_platforms/tests/test_real16_boot_provenance.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_mypyc_vex_bundle.py angr_platforms/tests/test_real16_boot_provenance.py

# Checked flat32 call-loop owner and bounded capture controls.
QA_TYPED_FILES += tools/dosunit/flat32_loop_calls.py
QA_RUFF_TARGETS += angr_platforms/tests/test_native_effect_environment_guards.py
QA_RUFF_TARGETS += angr_platforms/tests/test_dosunit_io_read_state.py
QA_RUFF_TARGETS += tools/dosunit/flat32_loop_calls.py angr_platforms/tests/test_flat32_loop_calls.py angr_platforms/tests/test_flat32_loop_calls_public.py angr_platforms/tests/test_flat32_dependency_cache.py angr_platforms/tests/test_replay_capture_vectors.py angr_platforms/tests/test_replay_capture_cohorts.py angr_platforms/tests/test_flat32_indirect_callbacks.py angr_platforms/tests/test_flat32_indirect_callback_effects.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_flat32_loop_calls.py angr_platforms/tests/test_replay_capture_vectors.py

QA_RUFF_TARGETS += angr_platforms/tests/test_m4_exit_controls.py
QA_RUFF_TARGETS += angr_platforms/tests/test_m4_pe32_relations.py

# Actual PE32 public relational proofs and independent execution controls.
QA_RUFF_TARGETS += angr_platforms/tests/test_relational_pe32_public.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_relational_pe32_public.py

QA_RUFF_TARGETS += angr_platforms/tests/test_mz_invocation_source.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_mz_invocation_source.py

# Full-selector control proof shared by real16 region and macro transitions.
QA_RUFF_TARGETS += tools/dosunit/real16_region_control.py angr_platforms/tests/test_real16_region_control.py
QA_TYPED_FILES += tools/dosunit/real16_region_control.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_region_control.py

# Isolated native DOS worker; actual KVM execution stays in the native lane.
KVIKDOS_WORKER_TESTS := angr_platforms/tests/test_dosunit_kvikdos_worker.py \
	angr_platforms/tests/test_dosunit_kvikdos_memory_range.py \
	angr_platforms/tests/test_dosunit_kvikdos_protocol_errors.py \
	angr_platforms/tests/test_dosunit_kvikdos_snapshot_registry.py
QA_TYPED_FILES += tools/dosunit/kvikdos_vm_worker.py tools/dosunit/kvikdos_backend.py
QA_RUFF_TARGETS += tools/dosunit/kvikdos_vm_worker.py tools/dosunit/kvikdos_backend.py \
	$(KVIKDOS_WORKER_TESTS) angr_platforms/tests/dosunit_kvikdos_fake_worker.py \
	angr_platforms/tests/dosunit_kvikdos_test_support.py \
	angr_platforms/tests/test_dosunit_kvikdos_worker_native.py
QA_PYTEST_TARGETS += $(KVIKDOS_WORKER_TESTS)

QA_TYPED_FILES += scripts/pytest_directory_cache.py
QA_TYPED_FILES += scripts/compact_paths.py
QA_RUFF_TARGETS += scripts/compact_paths.py angr_platforms/tests/test_compact_paths.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_compact_paths.py
QA_RUFF_TARGETS += scripts/pytest_directory_cache.py angr_platforms/tests/test_pytest_directory_cache.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pytest_directory_cache.py
QA_TYPED_FILES += scripts/pytest_live_failures.py
QA_RUFF_TARGETS += scripts/pytest_live_failures.py angr_platforms/tests/test_pytest_live_failures.py angr_platforms/tests/test_native_relift_scope.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_pytest_live_failures.py angr_platforms/tests/test_native_relift_scope.py

# Inventory additions must precede the eager scoped-selector assignments.
QA_RUFF_TARGETS += angr_platforms/tests/test_flat32_contextual_calls.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_flat32_contextual_calls.py
QA_RUFF_TARGETS += angr_platforms/tests/test_flat32_proof_seal.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_flat32_proof_seal.py
QA_RUFF_TARGETS += angr_platforms/tests/test_real16_public_accounting.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_public_accounting.py
QA_TYPED_FILES += tools/dosunit/vex_cache_identity.py
QA_RUFF_TARGETS += tools/dosunit/vex_cache_identity.py angr_platforms/tests/test_dosunit_vex_cache_identity.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_dosunit_vex_cache_identity.py
QA_RUFF_TARGETS += angr_platforms/tests/test_dosunit_transitive_callees.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_dosunit_transitive_callees.py
QA_RUFF_TARGETS += angr_platforms/tests/test_dosunit_alarm_boundary.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_dosunit_alarm_boundary.py

QA_TYPED_FILES += tools/dosunit/ssa_selection.py
QA_RUFF_TARGETS += tools/dosunit/ssa_selection.py angr_platforms/tests/test_real16_selected_lowering.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_real16_selected_lowering.py
PYRIGHT_SELECTED_FILES := $(filter $(QA_TYPED_FILES),$(PY_FILES))
PYRIGHT_SKIPPED_FILES := $(filter-out $(QA_TYPED_FILES),$(PY_FILES))
MYPY_SELECTED_FILES := $(filter $(QA_TYPED_FILES),$(PY_FILES))
# Keep the worker facade's owned error and integer-parsing contracts visible.
ifneq ($(filter tools/dosunit/kvikdos_backend.py tools/dosunit/kvikdos_vm_worker.py,$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) tools/dosunit/model.py \
	tools/dosunit/kvikdos_vm_worker.py tools/dosunit/kvikdos_backend.py)
endif
# With follow_imports=skip, the entry-byte subclass needs its shared base and
# owned IR contracts selected explicitly; checking an Any base is not proof.
ENTRY_STACK_BYTE_MYPY_COHORT := \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_byte_contracts.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_bytes.py \
	angr_platforms/angr_platforms/X86_16/alias/entry_stack_pointer_snapshots.py \
	angr_platforms/angr_platforms/X86_16/ir/vex_operation_membership.py \
	angr_platforms/angr_platforms/X86_16/alias/stack_pointer_snapshots.py \
	angr_platforms/angr_platforms/X86_16/ir/core.py
ifneq ($(filter $(ENTRY_STACK_BYTE_MYPY_COHORT) angr_platforms/tests/entry_stack_byte_test_support.py,$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(ENTRY_STACK_BYTE_MYPY_COHORT))
endif
# Select owned contracts with their consumers, not skipped-import Any values.
IR_SCALAR_VALUE_MYPY_COHORT := \
	angr_platforms/angr_platforms/X86_16/ir/constant_flow.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_value_projection.py \
	angr_platforms/angr_platforms/X86_16/ir/core.py
ifneq ($(filter $(IR_SCALAR_VALUE_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(IR_SCALAR_VALUE_MYPY_COHORT))
endif
MYPY_SKIPPED_FILES := $(filter-out $(QA_TYPED_FILES),$(PY_FILES))
# Range consumers need their owned SSA/condition providers, not skipped Any.
INDEXED_LOOP_RANGE_MYPY_COHORT := \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidates.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_evidence.py \
	angr_platforms/angr_platforms/X86_16/ir/indexed_induction_write_census.py \
	angr_platforms/angr_platforms/X86_16/ir/function_condition_artifact.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_contracts.py \
	angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_cache.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa_function.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa.py
# The development gate needs the same owned-provider closure as scoped checks.
LINTERS_DEV_MYPY_FILES += $(INDEXED_LOOP_RANGE_MYPY_COHORT)
ifneq ($(filter $(INDEXED_LOOP_RANGE_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(INDEXED_LOOP_RANGE_MYPY_COHORT))
endif
# Widening consumes owned contracts, never skipped-import Any values.
ENTRY_STACK_WORD_MYPY_COHORT := \
	$(ENTRY_STACK_BYTE_MYPY_COHORT) \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_bits.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_value_contracts.py \
	angr_platforms/angr_platforms/X86_16/widening/entry_stack_word_values.py \
	angr_platforms/angr_platforms/X86_16/ir/function_artifact.py \
	angr_platforms/angr_platforms/X86_16/ir/scalar_value_projection.py \
	angr_platforms/angr_platforms/X86_16/ir/ssa.py \
	angr_platforms/angr_platforms/X86_16/semantics/register_value_preservation.py
ifneq ($(filter $(ENTRY_STACK_WORD_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(ENTRY_STACK_WORD_MYPY_COHORT))
endif
ENTRY_WORD_TRANSPORT_MYPY_COHORT := \
	$(ENTRY_STACK_WORD_MYPY_COHORT) \
	$(ENTRY_WORD_TRANSPORT_TYPED_FILES) \
	angr_platforms/angr_platforms/X86_16/ir/ssa_function.py
ifneq ($(filter $(ENTRY_WORD_TRANSPORT_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(ENTRY_WORD_TRANSPORT_MYPY_COHORT))
endif
RUFF_SELECTED_FILES := $(filter $(QA_RUFF_TARGETS),$(PY_FILES))
RUFF_SKIPPED_FILES := $(filter-out $(QA_RUFF_TARGETS),$(PY_FILES))

QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))
# FunctionCtx and ComposeSession remain typed when selecting one call consumer.
REAL16_CALL_MYPY_CONSUMERS := \
	tools/dosunit/real16_call_indirect.py \
	tools/dosunit/real16_region_control.py \
	tools/dosunit/real16_call_execution.py \
	tools/dosunit/real16_call_control.py \
	tools/dosunit/real16_control_resolution.py \
	tools/dosunit/real16_call_boundary.py \
	tools/dosunit/real16_call_composition.py \
	tools/dosunit/real16_loop_calls.py \
	tools/dosunit/real16_loop_invariants.py \
	tools/dosunit/real16_region_transitions.py \
	tools/dosunit/real16_region_proof.py
ifneq ($(filter $(REAL16_CALL_MYPY_CONSUMERS),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) tools/dosunit/real16_call_contracts.py)
endif
# Proof adapters need the owned status/state and serialization contracts typed together.
REGISTER_PROOF_MYPY_CONSUMERS := \
	tools/dosunit/ssa_output_lemmas.py \
	tools/dosunit/register_state_relations.py \
	tools/dosunit/proof_scope.py \
	tools/dosunit/real16_region_proof.py \
	tools/dosunit/flat32_cfg_regions.py
ifneq ($(filter $(REGISTER_PROOF_MYPY_CONSUMERS),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) \
	tools/dosunit/proof_contracts.py tools/dosunit/proof_obligations.py \
	tools/dosunit/proof_serialization.py tools/dosunit/register_state_relations.py \
	tools/dosunit/register_affine_relations.py)
endif
TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)

# Early comparator admission gate: reuse existing positive/corruption controls
# before the full decompiler suite. This is not M0-M7 release acceptance.
COMPARATOR_ADMISSION_TESTS := \
	angr_platforms/tests/test_ordered_io_environment.py \
	angr_platforms/tests/test_x86_16_immediate_port.py \
	angr_platforms/tests/test_flat32_indirect_callbacks.py \
	angr_platforms/tests/test_flat32_indirect_callback_effects.py \
	angr_platforms/tests/test_flat32_loop_calls_public.py \
	angr_platforms/tests/test_flat32_loop_calls.py \
	angr_platforms/tests/test_replay_capture_vectors.py \
	angr_platforms/tests/test_binary_callee_control_target.py \
	angr_platforms/tests/test_real16_uncatalogued_calls.py::test_public_uncatalogued_direct_leaf \
	angr_platforms/tests/test_dosunit_guarded_capture.py \
	angr_platforms/tests/test_real16_argument_controls.py \
	angr_platforms/tests/test_real16_far_loop_controls.py \
	angr_platforms/tests/test_dosunit_alarm_boundary.py \
	angr_platforms/tests/test_dosunit_transitive_callees.py \
	angr_platforms/tests/test_dosunit_vex_cache_identity.py \
	angr_platforms/tests/test_real16_public_accounting.py \
	angr_platforms/tests/test_real16_selected_lowering.py \
	angr_platforms/tests/test_real16_self_lowering_reuse.py \
	angr_platforms/tests/test_dosunit_ssa_source_identity_paths.py \
	angr_platforms/tests/test_flat32_proof_seal.py \
	angr_platforms/tests/test_flat32_contextual_calls.py \
	angr_platforms/tests/test_real16_program_interrupts.py \
	angr_platforms/tests/test_real16_program_vectors.py \
	angr_platforms/tests/test_real16_program_device_info.py \
	angr_platforms/tests/test_real16_program_video.py \
	angr_platforms/tests/test_real16_program_video_policy.py \
	angr_platforms/tests/test_real16_video_state_policy.py \
	angr_platforms/tests/test_real16_video_state_boundary.py \
	angr_platforms/tests/test_real16_program_video_state.py \
	angr_platforms/tests/test_real16_program_rom.py \
	angr_platforms/tests/test_real16_program_rom_integration.py \
	angr_platforms/tests/test_pytest_directory_cache.py \
	angr_platforms/tests/test_batch_decompile_scheduler.py::test_scheduler_incomplete_eof_waits_for_actual_exit \
	angr_platforms/tests/test_batch_decompile_scheduler.py::test_scheduler_incomplete_eof_keeps_deadline_without_polling_closed_fd \
	angr_platforms/tests/test_x86_16_bp_preservation.py \
	angr_platforms/tests/test_x86_16_ir_boundary_cfg.py \
	angr_platforms/tests/test_x86_16_segment_function_summary.py \
	angr_platforms/tests/test_dosunit_proof_contracts.py \
	angr_platforms/tests/test_dosunit_public_domain.py \
	angr_platforms/tests/test_dosunit_public_domain_integration.py \
	angr_platforms/tests/test_dosunit_ssa_provenance.py \
	angr_platforms/tests/test_real16_control_target_proof.py \
	angr_platforms/tests/test_real16_control_boundary.py \
	angr_platforms/tests/test_x86_16_aam_fault.py \
	angr_platforms/tests/test_native_effect_environment_guards.py \
	angr_platforms/tests/test_dosunit_io_read_state.py \
	angr_platforms/tests/test_nop_native_binding.py \
	angr_platforms/tests/test_nop_cache_cost.py \
	angr_platforms/tests/test_segment_call_binding_regression.py \
	angr_platforms/tests/test_native_relift_scope.py \
	angr_platforms/tests/test_direct_near_call_target_binding.py \
	angr_platforms/tests/test_x86_16_native_helper_call_retention.py \
	angr_platforms/tests/test_flat32_comparator_lane.py \
	angr_platforms/tests/test_flat32_loop_controls.py \
	angr_platforms/tests/test_flat32_compose_total_budget.py \
	angr_platforms/tests/test_relational_pe32_public.py

.PHONY: comparator-check-fast
# A dependency edge, rather than sibling prerequisites, also serializes these
# pytest pools under make -j. Keep the shared six-worker allowance bounded.
comparator-check-fast: override PYTEST_WORKERS := $(COMPARATOR_PYTEST_WORKERS)
comparator-check-fast: decompiler-contracts
	$(Q)$(PYTHON) -m pytest -q $(PYTEST_ARGS) --maxfail=1 $(COMPARATOR_ADMISSION_TESTS)

pytest:
	$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FOCUSED_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) -m pytest -q $(PYTEST_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)" $(QA_PYTEST_TARGETS)

pytest-profile:
	$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FULL_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) scripts/pytest_profile.py $(PYTEST_PROFILE_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)" --profile-json $(PYTEST_PROFILE_JSON) $(PYTEST_PROFILE_TARGETS)

pytest-inventory:
	$(PYTHON) scripts/pytest_profile.py --profile-json $(PYTEST_INVENTORY_JSON) --collect-only -q >/dev/null
	$(PYTHON) scripts/pytest_inventory_check.py $(PYTEST_INVENTORY_JSON)
	@echo "pytest inventory: $(PYTEST_INVENTORY_JSON)"

pytest-inventory-check:
	$(PYTHON) scripts/pytest_inventory_check.py $(PYTEST_INVENTORY_JSON)

pytest-files:
	@manifest_tests="$$( $(PYTHON) scripts/test_ownership_manifest.py $(PY_FILES) )"; \
	selected_tests="$$( \
		for test_target in $$manifest_tests $(PYTEST_FILES); do \
			printf '%s\n' "$$test_target"; \
		done | sort -u | tr '\n' ' ' \
	)"; \
	if [ -n "$$(echo "$$selected_tests" | tr -d '[:space:]')" ]; then \
		INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FOCUSED_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) -m pytest -q $(PYTEST_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)" $$selected_tests; \
	else \
		echo "pytest-files: no test files selected"; \
	fi

pytest-all: pytest-inventory
	$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FULL_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) scripts/pytest_partitioned.py \
		--inventory-json $(PYTEST_INVENTORY_JSON) \
		--history-json $(PYTEST_ALL_SUMMARY_JSON) \
		--summary-json $(PYTEST_ALL_SUMMARY_JSON) \
		--workers $(PYTEST_ALL_WORKERS) \
		--heavy-workers $(PYTEST_ALL_HEAVY_WORKERS) \
		--heavy-shards $(PYTEST_ALL_HEAVY_SHARDS) \
		--max-rss-mib $(PYTEST_ALL_MAX_RSS_MIB)

architecture-check:
	$(PYTHON) scripts/check_decompiler_architecture.py

architecture-check-fast:
	$(PYTHON) -m scripts.check_decompiler_architecture --startup-only

agent-context-check:
	$(Q)$(PYTHON) scripts/agent_context_check.py --compact

test-ownership-check:
	$(PYTHON) scripts/test_ownership_manifest.py --check

ruff:
	$(Q)$(PYTHON) -m ruff check --fix $(RUFF_OUTPUT_FLAGS) $(QA_RUFF_TARGETS)

ruff-files:
	@test -n "$(strip $(PY_FILES))" || (echo 'ruff-files: no Python files selected'; exit 0)
	@if [ -n "$(strip $(RUFF_SELECTED_FILES))" ]; then \
		$(PYTHON) -m ruff check --fix $(RUFF_OUTPUT_FLAGS) $(RUFF_SELECTED_FILES); \
	else \
		echo "ruff-files: no promoted Ruff files selected"; \
	fi
	@if [ -n "$(strip $(RUFF_SKIPPED_FILES))" ]; then \
		echo "ruff-files: skipped legacy files not in QA_RUFF_TARGETS: $(RUFF_SKIPPED_FILES)"; \
	fi

ruff-all:
	$(Q)$(PYTHON) -m ruff check --fix $(RUFF_OUTPUT_FLAGS) $(PY_FILES_ALL)

pyright:
	$(Q)$(PYRIGHT_CMD_BASE) $(wordlist 1,55,$(wildcard angr_platforms/angr_platforms/X86_16/*.py))
	$(Q)$(PYRIGHT_CMD_BASE) $(wordlist 56,110,$(wildcard angr_platforms/angr_platforms/X86_16/*.py))
	$(Q)$(PYRIGHT_CMD_BASE) $(wordlist 111,10000,$(wildcard angr_platforms/angr_platforms/X86_16/*.py))
	$(Q)$(PYRIGHT_CMD_BASE) angr_platforms/angr_platforms/X86_16/alias angr_platforms/angr_platforms/X86_16/analysis angr_platforms/angr_platforms/X86_16/ir angr_platforms/angr_platforms/X86_16/pipeline
	$(Q)$(PYRIGHT_CMD_BASE) angr_platforms/angr_platforms/X86_16/lowering
	$(Q)$(PYRIGHT_CMD_BASE) $(filter-out angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py,$(wildcard angr_platforms/angr_platforms/X86_16/postprocess/*.py) $(wildcard angr_platforms/angr_platforms/X86_16/postprocess/optimization/*.py))
	# Legacy hardening check expects this exact DCE command form in makefile text.
	$(Q)$(if $(strip $(PYRIGHT_WATCH_FLAG)),,$(TIMEOUT) --foreground $(PYRIGHT_DCE_TIMEOUT) $(PYTHON) -m pyright angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py $(PYRIGHT_OUTPUT_FLAGS) --pythonpath $(PYRIGHT_PYTHON_PATH)) || { \
		status=$$?; \
		if [ $$status -eq 124 ]; then echo "pyright: DCE batch exceeded $(PYRIGHT_DCE_TIMEOUT)s; split its oversized function instead of suppressing types"; fi; \
		exit $$status; \
	}
	$(Q)$(PYRIGHT_CMD_BASE) angr_platforms/angr_platforms/X86_16/semantics
	$(Q)$(PYRIGHT_CMD_BASE) angr_platforms/angr_platforms/X86_16/structuring
	$(Q)$(PYRIGHT_CMD_BASE) angr_platforms/angr_platforms/X86_16/validation
	$(Q)$(PYRIGHT_CMD_BASE) angr_platforms/angr_platforms/X86_16/widening
	$(Q)$(PYRIGHT_CMD_BASE) inertia_decompiler $(filter-out angr_platforms/angr_platforms/X86_16/% inertia_decompiler/%,$(QA_TYPED_FILES))

pyright-files:
	@test -n "$(strip $(PY_FILES))" || (echo 'pyright-files: no Python files selected'; exit 0)
	@if [ -n "$(strip $(PYRIGHT_SELECTED_FILES))" ]; then \
		$(PYRIGHT_CMD_BASE) $(PYRIGHT_SELECTED_FILES); \
	else \
		echo "pyright-files: no promoted typed files selected"; \
	fi
	@if [ -n "$(strip $(PYRIGHT_SKIPPED_FILES))" ]; then \
		echo "pyright-files: skipped legacy files not in QA_TYPED_FILES: $(PYRIGHT_SKIPPED_FILES)"; \
	fi

type-ratchet-files:
	@if [ -z "$(strip $(PY_FILES))" ]; then \
		echo 'type-ratchet-files: no Python files selected'; \
	else \
		$(PYTHON) scripts/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES); \
	fi

type-ratchet-changed:
	@if [ -n "$(strip $(QA_CHANGED_TYPED_FILES))" ]; then \
		$(PYTHON) scripts/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES); \
	else \
		echo "type-ratchet-changed: no changed promoted typed Python files selected"; \
	fi

pyright-all:
	$(Q)$(PYRIGHT_CMD_BASE)

mypy:
	$(Q)$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS) --cache-dir .mypy_cache --config-file pyproject.toml $(QA_TYPED_FILES)

mypy-dev:
	$(Q)$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS) --cache-dir .mypy_cache --config-file pyproject.toml $(sort $(LINTERS_DEV_MYPY_FILES))

mypy-files:
	@test -n "$(strip $(PY_FILES))" || (echo 'mypy-files: no Python files selected'; exit 0)
	@if [ -n "$(strip $(MYPY_SELECTED_FILES))" ]; then \
		$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS) --cache-dir .mypy_cache --config-file pyproject.toml $(MYPY_SELECTED_FILES); \
	else \
		echo "mypy-files: no promoted typed files selected"; \
	fi
	@if [ -n "$(strip $(MYPY_SKIPPED_FILES))" ]; then \
		echo "mypy-files: skipped legacy files not in QA_TYPED_FILES: $(MYPY_SKIPPED_FILES)"; \
	fi

mypy-all:
	$(Q)$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS) --cache-dir .mypy_cache --config-file pyproject.toml

mypyc:
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) scripts/build_mypyc.py --jobs $(MYPYC_JOBS)

mypyc-smoke:
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) scripts/build_mypyc.py --jobs $(MYPYC_JOBS)

vulture:
	$(Q)$(PYTHON) -m vulture $(QA_TYPED_FILES)

# Scan the angr_platforms parent so basta's tests/ directory conventions
# classify test-support modules as test code; passing angr_platforms/tests
# as a scan root loses that classification and reports every helper.
# --entry marks modules reachable only from repo-root entry scripts that
# stay outside the lint scan scope: decompile.py (the [project.scripts]
# console entry) imports inertia_decompiler/direct_request_fast_path.py,
# and dump_debug_info.py imports X86_16/borland_mangling.py. Scanning those
# scripts directly is not viable: it activates repo-root Makefile/path-name
# reachability, which collapses the report to almost nothing.
unused-python-files:
	$(Q)npm_config_cache="$(CURDIR)/.cache/npm-cache" $(BASTA) --categories unused-file --workers 3 --no-colors \
		--entry '**/direct_request_fast_path.py' \
		--entry '**/borland_mangling.py' \
		--entry '**/pytest_directory_cache.py' \
		--entry '**/pytest_live_failures.py' \
		scripts inertia_decompiler angr_platforms

lizard:
	$(Q)$(PYTHON) -m lizard $(LIZARD_OUTPUT_FLAGS) -l python -C 10 -i -1 scripts inertia_decompiler

lizard-dev:
	$(Q)$(PYTHON) -m lizard $(LIZARD_OUTPUT_FLAGS) -l python -C 10 -i -1 $(LINTERS_DEV_LIZARD_PATHS)

.PHONY: decompiler-contracts
# This small cohort is dominated by worker imports: two workers measured
# 15.05s versus 28.68s with six. Preserve serial requests and cap only this
# precheck; the following comparator/decompiler suites retain the requested pool.
decompiler-contracts: override PYTEST_WORKERS := $(if $(filter 1,$(PYTEST_WORKERS)),1,2)
decompiler-contracts:
	$(Q)PYTHON_JIT=1 $(PYTHON) -m pytest -q $(PYTEST_ARGS) --durations=10 \
		angr_platforms/tests/test_x86_16_c_ast_utils.py \
		angr_platforms/tests/test_x86_16_ast_traversal_coverage.py \
		angr_platforms/tests/test_x86_16_ss_traversal_contract.py \
		angr_platforms/tests/test_x86_16_stack_prototype_wrapped_locals.py \
		angr_platforms/tests/test_x86_16_validation_entry_stack_ranges.py \
		angr_platforms/tests/test_x86_16_far_return_boundary_carriers.py \
		angr_platforms/tests/test_x86_16_stack_reference_offsets.py


test-pipeline: decompiler-contracts
	mkdir -p "$(dir $(TEST_PIPELINE_LOCK))"
	flock "$(TEST_PIPELINE_LOCK)" $(PYTHON) scripts/test_pipeline.py --require-external --pytest-workers $(PYTEST_WORKERS) --msc6-workers $(PIPELINE_WORKERS)

test-pipeline-fast: comparator-check-fast
	mkdir -p "$(dir $(TEST_PIPELINE_LOCK))"
	flock "$(TEST_PIPELINE_LOCK)" $(PYTHON) scripts/test_pipeline.py --tier fast --require-external --pytest-workers $(PYTEST_WORKERS) --msc6-workers $(PIPELINE_WORKERS)

test-pipeline-expanded: decompiler-contracts
	mkdir -p "$(dir $(TEST_PIPELINE_LOCK))"
	flock "$(TEST_PIPELINE_LOCK)" $(PYTHON) scripts/test_pipeline.py --tier expanded --require-external --pytest-workers $(PYTEST_WORKERS) --msc6-workers $(PIPELINE_WORKERS)

test-layer:
	$(PYTHON) scripts/agent_test_focus.py \
		$(if $(strip $(LAYER)),--layer $(LAYER),) \
		$(if $(strip $(FILES)),--files $(FILES),$(if $(strip $(LAYER)),--no-infer-changed,)) \
		$(if $(strip $(MAX_TESTS)),--max-tests $(MAX_TESTS),) \
		$(if $(strip $(AGENT_TEST_JSON)),--json,) \
		$(if $(strip $(AGENT_TEST_JSON_ONLY)),--json-only,) \
		$(if $(strip $(NO_SHARED)),--no-shared,) \
		$(if $(filter 1,$(RUN)),--run)

test-agent-confidence:
	$(PYTHON) scripts/agent_test_focus.py --run \
		$(if $(strip $(MAX_TESTS)),--max-tests $(MAX_TESTS),) \
		$(if $(strip $(AGENT_TEST_JSON)),--json,) \
		$(if $(strip $(AGENT_TEST_JSON_ONLY)),--json-only,) \
		$(if $(strip $(NO_SHARED)),--no-shared,)

msc6-examples:
	INERTIA_ENABLE_TAIL_VALIDATION=1 INERTIA_DISABLE_TIMING=1 $(PYTHON) scripts/build_msc6_examples.py --skip-constructs medium_structs,enum_union --decompile-mode functions --decompile-max-functions 0 --decompile-timeout 60 --decompile-run-timeout 600

sortdemo-selftest:
	$(PYTHON) scripts/build_sortdemo_selftest.py --clean

# Compare one deterministic validated artifact per corpus binary. Functional
# coverage belongs to test-pipeline; this gate isolates pure-Python vs mypyc quality.
DECOMP_OPT_REGRESSION_ARGS ?= --max-functions 1 -q
DECOMP_OPT_REGRESSION_TIMEOUT ?= 180
DECOMP_OPT_REGRESSION_BINARIES ?= \
	examples/build_msc6_tiny/CMP16.EXE \
	examples/build_msc6_tiny/LOOPS.EXE \
	examples/build_msc6_tiny/FPTR.EXE
DECOMP_OPT_REGRESSION_CONSTRUCTS ?= compare16,loops_jumps,function_pointers

decomp-opt-regression-inputs:
	@missing=0; \
	for binary in $(DECOMP_OPT_REGRESSION_BINARIES); do \
		test -f "$$binary" || missing=1; \
	done; \
	if test "$$missing" -eq 1; then \
		$(PYTHON) scripts/build_msc6_examples.py \
			--out-dir examples/build_msc6_tiny \
			--only-constructs $(DECOMP_OPT_REGRESSION_CONSTRUCTS) \
			--skip-constructs $(DECOMP_OPT_REGRESSION_CONSTRUCTS) \
			--harvest-success-code 255; \
	fi

decomp-opt-regression:
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) scripts/benchmark_optimization_quality_guard.py examples/build_msc6/CMP16.EXE -- $(DECOMP_OPT_REGRESSION_ARGS)

decomp-opt-regression-suite: decomp-opt-regression-inputs
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	@for binary in $(DECOMP_OPT_REGRESSION_BINARIES); do \
		echo "/* decompilation quality guard: $$binary */"; \
		flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) scripts/benchmark_optimization_quality_guard.py "$$binary" \
			--mode-timeout $(DECOMP_OPT_REGRESSION_TIMEOUT) \
			-- $(DECOMP_OPT_REGRESSION_ARGS) \
			|| exit $$?; \
	done

decomp-opt-regression-thread:
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	@for binary in $(DECOMP_OPT_REGRESSION_BINARIES); do \
		echo "/* decompilation quality guard (thread timeout lanes): $$binary */"; \
		INERTIA_FORCE_TIMEOUT_LANES_THREAD=1 flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) scripts/benchmark_optimization_quality_guard.py "$$binary" \
			--mode-timeout $(DECOMP_OPT_REGRESSION_TIMEOUT) \
			-- $(DECOMP_OPT_REGRESSION_ARGS) \
			|| exit $$?; \
	done

monkeytype-trace:
	$(PYTHON) scripts/collect_monkeytype_pytest.py

monkeytype-stubs:
	$(PYTHON) scripts/export_monkeytype_stubs.py

monkeytype-apply:
	$(PYTHON) scripts/apply_monkeytype_annotations.py

types: monkeytype-trace monkeytype-apply

# Source-bound native terminal targets at the Clinic conversion boundary.
LINTERS_DEV_MYPY_FILES += angr_platforms/angr_platforms/X86_16/clinic_terminal_control.py
QA_TYPED_FILES += angr_platforms/angr_platforms/X86_16/clinic_terminal_control.py
QA_RUFF_TARGETS += angr_platforms/angr_platforms/X86_16/clinic_terminal_control.py angr_platforms/tests/test_x86_16_clinic_terminal_control.py
QA_RUFF_TARGETS += angr_platforms/tests/test_x86_16_clinic_binary_terminal_control.py
QA_PYTEST_TARGETS += angr_platforms/tests/test_x86_16_clinic_terminal_control.py
