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
PYTEST_ARGS ?= $(PYTEST_OUTPUT_FLAGS) -p tools.dev.pytest_directory_cache -n $(PYTEST_WORKERS) --dist loadgroup --durations=5
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
PYTEST_FILES := $(filter tests/%.py,$(PY_FILES)) $(foreach f,$(filter tools/%.py,$(PY_FILES)),$(if $(findstring /tests/,$(f)),$(f)))
PY_CHANGED_FILES := $(shell { git diff --name-only -- '*.py'; git ls-files --others --exclude-standard -- '*.py'; } | sort -u)
LINT_JOBS ?= $(PARALLEL_JOBS)
MYPYC_JOBS ?= $(PARALLEL_JOBS)
MYPYC_ARTIFACT_LOCK ?= $(CURDIR)/.cache/locks/mypyc-artifacts.lock
TEST_PIPELINE_LOCK ?= $(CURDIR)/.cache/locks/test-pipeline.lock
PIPELINE_WORKERS ?= $(PARALLEL_JOBS)
INERTIA_ALLOW_PARALLEL_MSC6_WORKERS ?= 1
export INERTIA_ALLOW_PARALLEL_MSC6_WORKERS
LINTERS_DEV_MYPY_FILES ?= \
	inertia/lowering/callsite_inventory.py \
	inertia/lowering/codegen_return_origin.py \
	inertia/alias/stack_restore_state.py \
	inertia/semantics/register_definition_return.py \
	inertia/lowering/gp_stack_local_return.py \
	inertia/lowering/gp_stack_local_reload.py \
	inertia/semantics/call_stack_allocation.py \
	inertia/ir/register_live_in.py \
	inertia/lowering/call_output_object_projection.py \
	inertia/lowering/runtime_call_results.py \
	inertia/lowering/call_argument_semantic_gap.py \
	inertia/ir/function_ir_registry.py \
	inertia/lowering/gp_register_state.py \
	inertia/lowering/software_interrupt_status_outputs.py \
	inertia/lowering/far_pointer_constant_flow.py \
	inertia/cli/cache.py \
	inertia/cli/cache_file_digest.py \
	inertia/cli/cache_source_manifest.py \
	inertia/cli/function_ir_ssa_source_scope.py \
	inertia/cli/decompile_file_summary.py \
	inertia/cli/direct_indexed_alias_local_cache.py \
	inertia/cli/indexed_alias_program_context.py \
	inertia/cli/indexed_alias_program_parallel.py \
	inertia/cli/program_callsite_cache.py \
	inertia/cli/project_argument_evidence_ranges.py \
	inertia/cli/indexed_global_object_cache.py \
	inertia/cli/serial_clean_worker_evidence.py \
	inertia/lowering/callsite_prototype_declarations.py \
	inertia/lowering/callsite_prototype_seeding.py \
	inertia/lowering/helper_call_interfaces.py \
	inertia/lowering/far_pointer_segmented_load_evidence.py \
	inertia/lowering/far_pointer_segmented_load_materialization.py \
	inertia/lowering/register_constant_segmented_store.py \
	inertia/lowering/stack_prototype_materialization.py \
	inertia/lowering/authoritative_function_prototypes.py \
	inertia/lowering/positive_bp_argument_plan.py \
	inertia/lowering/near_return_address_arguments.py \
	inertia/lowering/direct_stack_replay.py \
	inertia/lowering/direct_stack_consumer_generation.py \
	inertia/lowering/direct_stack_replay_contracts.py \
	inertia/lowering/register_local_declarations.py \
	inertia/lowering/register_variable_identity.py \
	inertia/frontend/x86_16/frontend_caller_return_use_program.py \
	inertia/frontend/x86_16/frontend_direct_callsite_index.py \
	inertia/pipeline/result_contracts.py \
	inertia/pipeline/structured_assignment_index.py \
	inertia/pipeline/structured_ast_query_index.py \
	inertia/postprocess/pass_validation_policy.py \
	inertia/postprocess/bootstrap_orchestration.py \
	inertia/postprocess/pass_runtime.py \
	inertia/postprocess/pass_transaction.py \
	inertia/postprocess/runtime_configuration.py \
	inertia/postprocess/rollback_snapshot_cache.py \
	inertia/postprocess/validation_contracts.py \
	inertia/validation/control_flow_ast_index.py \
	inertia/lowering/stack_address_coordinates.py \
	inertia/lowering/stack_storage_evidence.py \
	inertia/lowering/linear_global_decomposition_cache.py \
	inertia/lowering/terminal_return_expressions.py \
	inertia/lowering/terminal_return_render_projection.py \
	inertia/lowering/terminal_call_return_types.py \
	inertia/lowering/terminal_register_return_types.py \
	inertia/lowering/terminal_register_return_values.py \
	inertia/lowering/unused_void_return_types.py \
	inertia/lowering/call_return_stack_conditions.py \
	inertia/lowering/callee_saved_frame.py \
	inertia/lowering/real_mode_linear.py \
	inertia/alias/stack_coordinate_projection.py \
	inertia/lowering/instruction_bp_stack_access.py \
	inertia/lowering/stack_coordinate_rebinding.py \
	inertia/lowering/stack_variable_coordinates.py \
	inertia/lowering/machine_stack_names.py \
	inertia/lowering/stack_function_coordinates.py \
	inertia/lowering/stack_variable_display_names.py \
	inertia/lowering/stack_word_load_candidate.py \
	inertia/lowering/stack_word_load_materialization.py \
	inertia/lowering/stack_word_load_projection.py \
	inertia/lowering/stack_word_projection.py \
	inertia/lowering/stack_prototype_layout.py \
	inertia/frontend/x86_16/msvc_x87_interrupts.py \
	inertia/lowering/structured_tags.py \
	inertia/structuring/boolean_condition_ites.py \
	inertia/structuring/call_return_conditions.py \
	inertia/structuring/bound_call_condition.py \
	inertia/structuring/call_return_register_index.py \
	inertia/structuring/call_return_register_placement.py \
	inertia/structuring/call_return_store_placement.py \
	inertia/structuring/shared_call_result_aliases.py \
	inertia/structuring/stored_call_return_early_exit.py \
	inertia/structuring/decompiler_structuring_stage.py \
	inertia/validation/tail_validation_frame_spills.py \
	inertia/validation/validation_call_return_storage.py \
	inertia/lowering/call_argument_shape.py \
	inertia/lowering/call_argument_shape_publication.py \
	inertia/lowering/call_argument_arity_ownership.py \
	inertia/lowering/call_argument_expression.py \
	inertia/lowering/call_argument_semantic_token.py \
	inertia/lowering/call_argument_state.py \
	inertia/lowering/call_return_selectors.py \
	inertia/lowering/call_return_stack_bindings.py \
	inertia/lowering/call_return_stack_stores.py \
	inertia/validation/validation_calls.py \
	inertia/validation/validation_call_multiplicity.py \
	inertia/validation/validation_dataflow.py \
	inertia/lowering/return_type_evidence.py \
	inertia/lowering/return_liveness_replay.py \
	inertia/validation/validation_predicates.py \
	inertia/validation/validation_control_flow.py \
	inertia/validation/validation_condition_storage_views.py \
	inertia/validation/validation_required_memory_effects.py \
	inertia/lowering/callee_pointer_evidence.py \
	inertia/lowering/callee_pointer_contracts.py \
	inertia/lowering/callee_pointer_codec.py \
	inertia/semantics/callsite_summary_codec.py \
	inertia/semantics/callsite_summary_program.py \
	inertia/semantics/callsite_summary_program_codec.py \
	inertia/lowering/callee_callsite_contracts.py \
	inertia/lowering/callee_callsite_codec.py \
	inertia/lowering/callee_range_callsite_facts.py \
	inertia/lowering/project_callee_callsite_collection.py \
	inertia/lowering/project_global_object_source_collection.py \
	inertia/semantics/caller_return_use_contracts.py \
	inertia/lowering/callee_callsite_census.py \
	inertia/lowering/callee_argument_count_evidence.py \
	inertia/lowering/callee_argument_width_evidence.py \
	inertia/ir/block_ownership.py \
	inertia/ir/block_successor_chain.py \
	inertia/ir/condition_fingerprint_masks.py \
	inertia/ir/condition_fingerprint_syntax.py \
	inertia/ir/function_ssa_registry.py \
	inertia/lowering/interprocedural_memory_output_object_contracts.py \
	inertia/lowering/interprocedural_memory_output_objects.py \
	inertia/lowering/interprocedural_memory_output_validation.py \
	inertia/lowering/interprocedural_storage_collection_contracts.py \
	inertia/lowering/interprocedural_storage_contracts.py \
	inertia/lowering/interprocedural_storage_function_solver.py \
	inertia/lowering/interprocedural_storage_live_out.py \
	inertia/lowering/interprocedural_storage_live_out_contracts.py \
	inertia/lowering/interprocedural_storage_live_out_flow.py \
	inertia/lowering/interprocedural_storage_live_out_paths.py \
	inertia/lowering/interprocedural_storage_slot_join.py \
	inertia/lowering/interprocedural_storage_pipeline.py \
	inertia/lowering/pointer_parameter_output_contracts.py \
	inertia/lowering/pointer_parameter_outputs.py \
	inertia/lowering/interprocedural_storage_prototype_application.py \
	inertia/lowering/interprocedural_storage_prototype_types.py \
	inertia/lowering/interprocedural_storage_reaching_contracts.py \
	inertia/lowering/interprocedural_storage_source_defs.py \
	inertia/lowering/interprocedural_storage_return_defs.py \
	inertia/lowering/interprocedural_storage_return_passthrough_contracts.py \
	inertia/lowering/interprocedural_storage_return_passthrough.py \
	inertia/lowering/interprocedural_storage_return_type_contracts.py \
	inertia/lowering/interprocedural_storage_return_split_condition_graph.py \
	inertia/lowering/interprocedural_storage_return_split_conditions.py \
	inertia/lowering/interprocedural_storage_return_split.py \
	inertia/lowering/interprocedural_storage_return_collection_contracts.py \
	inertia/lowering/interprocedural_storage_return_trial_materialization.py \
	inertia/lowering/interprocedural_storage_caller_context.py \
	inertia/lowering/interprocedural_storage_return_trial_collection.py \
	inertia/lowering/interprocedural_storage_return_pointer.py \
	inertia/lowering/interprocedural_storage_return_pointer_block.py \
	inertia/lowering/interprocedural_storage_return_pointer_flow.py \
	inertia/lowering/interprocedural_storage_return_pointer_stack.py \
	inertia/lowering/interprocedural_storage_return_pointer_witness.py \
	inertia/lowering/interprocedural_storage_return_types.py \
	inertia/lowering/interprocedural_storage_reaching_defs.py \
	inertia/lowering/interprocedural_storage_expression_defs.py \
	inertia/lowering/pointer_parameter_caller_target_contracts.py \
	inertia/lowering/pointer_parameter_caller_targets.py \
	inertia/lowering/pointer_parameter_memory_output_contracts.py \
	inertia/lowering/pointer_parameter_memory_outputs.py \
	inertia/lowering/pointer_parameter_object_type_contracts.py \
	inertia/lowering/pointer_parameter_object_types.py \
	inertia/lowering/interprocedural_storage_physical_defs.py \
	inertia/lowering/interprocedural_storage_trial_types.py \
	inertia/lowering/interprocedural_storage_input_preflight.py \
	inertia/lowering/interprocedural_storage_trial_collection.py \
	inertia/lowering/interprocedural_storage_solver.py \
	inertia/lowering/interprocedural_storage_simtypes.py \
	inertia/lowering/interprocedural_storage_transaction.py \
	inertia/lowering/callee_global_object_type_surface.py \
	inertia/lowering/callee_argument_interface.py \
	inertia/semantics/function_evidence_inventory.py \
	inertia/semantics/helper_abi.py \
	inertia/lowering/near_pointer_argument.py \
	inertia/lowering/near_pointer_index_binding.py \
	inertia/lowering/near_pointer_type.py \
	inertia/lowering/carry_borrow_stack_storage.py \
	inertia/lowering/wide_call_output_assignment_ast.py \
	inertia/lowering/wide_call_output_assignment_carriers.py \
	inertia/lowering/wide_call_output_assignment_contracts.py \
	inertia/lowering/wide_call_output_assignment_evidence.py \
	inertia/lowering/wide_call_output_assignment_placement.py \
	inertia/lowering/wide_call_output_assignment_replay.py \
	inertia/lowering/wide_call_output_assignments.py \
	inertia/alias/carry_borrow_contracts.py \
	inertia/alias/carry_borrow_destinations.py \
	inertia/alias/carry_borrow_projection.py \
	inertia/alias/carry_borrow_sources.py \
	inertia/alias/partial_register_address_break.py \
	inertia/alias/indexed_address_access_classification.py \
	inertia/alias/indexed_address_access_contracts.py \
	inertia/alias/indexed_address_contracts.py \
	inertia/alias/indexed_address_copy_contracts.py \
	inertia/alias/indexed_address_copy_projection.py \
	inertia/alias/indexed_address_projection.py \
	inertia/alias/indexed_address_program.py \
	inertia/alias/indexed_address_range_contracts.py \
	inertia/alias/indexed_address_range_projection.py \
	inertia/alias/storage_fact_join.py \
	inertia/alias/terminal_memory_outputs.py \
	inertia/alias/terminal_pointer_output_contracts.py \
	inertia/alias/terminal_pointer_outputs.py \
	inertia/ir/indexed_address_copy_contracts.py \
	inertia/ir/indexed_address_copy_evidence.py \
	inertia/ir/indexed_address_copy_trace.py \
	inertia/ir/function_condition_artifact.py \
	inertia/ir/condition_lift_capture.py \
	inertia/ir/condition_cache_relift.py \
	inertia/ir/condition_cache_relift_cache.py \
	inertia/ir/condition_cache_relift_contracts.py \
	inertia/ir/ssa_cfg.py \
	inertia/ir/ssa_cfg_contracts.py \
	inertia/ir/indexed_address_pipeline.py \
	inertia/ir/indexed_address_range_candidate_helpers.py \
	inertia/ir/indexed_induction_write_census.py \
	inertia/ir/indexed_address_range_candidates.py \
	inertia/ir/indexed_address_range_contracts.py \
	inertia/ir/indexed_address_range_evidence.py \
	inertia/ir/indexed_address_range_witnesses.py \
	inertia/ir/logical_memory_register_transfer.py \
	inertia/ir/logical_memory_register_transfer_contracts.py \
	inertia/ir/logical_memory_write_value.py \
	inertia/ir/logical_constant_word_receipt.py \
	inertia/alias/stack_word_call_window.py \
	inertia/alias/stack_word_call_binding.py \
	inertia/ir/scalar_definitions.py \
	inertia/ir/scalar_affine_contracts.py \
	inertia/ir/scalar_affine_sources.py \
	inertia/ir/scalar_affine_trace.py \
	inertia/ir/affine_indexed_address.py \
	inertia/ir/affine_induction_role.py \
	inertia/ir/frame_register_reaching_definition.py \
	inertia/lowering/indexed_address_collector_parity.py \
	inertia/lowering/indexed_address_parity_inventory.py \
	inertia/lowering/indexed_address_parity_inventory_contracts.py \
	inertia/lowering/bounded_global_array_declarations.py \
	inertia/lowering/global_declaration_extents.py \
	inertia/lowering/project_global_object_layout.py \
	inertia/semantics/carry_borrow_cfg.py \
	inertia/semantics/carry_borrow_contracts.py \
	inertia/semantics/carry_borrow_links.py \
	inertia/semantics/carry_borrow_ssa.py \
	inertia/semantics/call_output_contracts.py \
	inertia/semantics/call_outputs.py \
	inertia/semantics/call_stack_effect_contracts.py \
	inertia/semantics/call_stack_effect_pipeline.py \
	inertia/semantics/call_stack_effects.py \
	inertia/semantics/call_stack_provenance.py \
	inertia/semantics/terminal_memory_output_contracts.py \
	inertia/semantics/terminal_memory_outputs.py \
	inertia/semantics/terminal_pointer_output_contracts.py \
	inertia/semantics/terminal_pointer_outputs.py \
	inertia/widening/carry_borrow_pipeline.py \
	inertia/widening/carry_borrow_storage.py \
	inertia/widening/carry_borrow_values.py \
	inertia/widening/global_object_layout.py \
	inertia/widening/global_object_layout_codec.py \
	inertia/widening/indexed_global_object_program_range_codec.py \
	inertia/widening/indexed_global_object_program_ranges.py \
	inertia/widening/indexed_global_object_range_layouts.py \
	inertia/widening/indexed_global_object_range_recovery.py \
	inertia/widening/indexed_global_object_range_solver.py \
	inertia/widening/indexed_global_object_ranges.py \
	inertia/widening/indexed_global_object_layout.py \
	inertia/widening/stack_word_register_transfers.py \
	inertia/widening/terminal_memory_output_views.py \
	inertia/widening/terminal_pointer_output_contracts.py \
	inertia/widening/terminal_pointer_output_views.py

LINTERS_DEV_MYPY_FILES += \
	inertia/cli/accepted_payload_integrity.py \
	inertia/cli/angr_codegen_tags.py \
	inertia/frontend/x86_16/borrow_verification.py \
	inertia/alias/condition_register_bindings.py \
	inertia/semantics/callsite_register_instruction_facts.py \
	inertia/lowering/consumed_call_push_evidence.py \
	inertia/lowering/frame_instruction_evidence.py \
	inertia/lowering/frame_register_carriers.py \
	inertia/structuring/call_argument_branch_carriers.py \
	inertia/structuring/call_argument_path_conditions.py \
	inertia/structuring/call_argument_path_joins.py \
	inertia/frontend/x86_16/verification_80386.py \
	inertia/lowering/call_argument_carrier_liveness.py \
	inertia/lowering/call_return_frame.py \
	inertia/semantics/call_register_effects.py \
	inertia/semantics/call_return_frame_effects.py \
	inertia/semantics/call_return_frame_projections.py \
	inertia/semantics/callsite_setup_evidence.py \
	inertia/lowering/consumed_stack_address_setup.py \
	inertia/semantics/register_entry_overwrite.py \
	inertia/semantics/register_value_preservation.py \
	inertia/frontend/x86_16/synthetic_call_stub_evidence.py

LINTERS_DEV_LIZARD_PATHS ?= inertia/cli/decompile_file_summary.py
BASTA ?= npx --yes basta@0.3.0

.PHONY: quality quality-dev quality-fast quality-hard decompiler-check decompiler-check-fast decompiler-check-expanded architecture-check architecture-check-fast agent-context-check test-ownership-check linters linters-hard linters-dev linters-dev-locked linters-files check-files check-all pytest pytest-profile pytest-inventory pytest-inventory-check pytest-files pytest-all ruff ruff-files ruff-all pyright pyright-files pyright-all mypy mypy-dev mypy-files mypy-all mypyc mypyc-smoke type-ratchet-files type-ratchet-changed vulture unused-python-files lizard lizard-dev test-pipeline test-pipeline-fast test-pipeline-expanded test-layer test-agent-confidence msc6-examples sortdemo-selftest monkeytype-trace monkeytype-stubs monkeytype-apply decomp-opt-regression decomp-opt-regression-inputs decomp-opt-regression-suite decomp-opt-regression-thread types

quality: linters type-ratchet-changed decompiler-check decomp-opt-regression-suite

quality-dev: linters-dev type-ratchet-changed decompiler-check-fast decomp-opt-regression-suite

quality-fast: linters type-ratchet-changed decompiler-check-fast decomp-opt-regression-suite

# Hard local/per-PR gate: mandatory practical checks for in-flight development.
quality-hard: linters-hard type-ratchet-changed architecture-check decompiler-check-fast decomp-opt-regression-suite

decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline

decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast

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
		$(PYTHON) tools/dev/check_changed_non_test_types.py $(PY_FILES); \
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
	inertia/lowering/segmented_load_origins.py \
	inertia/ir/instruction_origin.py \
	inertia/ir/constant_flow.py \
	inertia/ir/scalar_value_projection.py \
	inertia/lowering/callsite_inventory.py \
	inertia/lowering/codegen_return_origin.py \
	inertia/lowering/gp_stack_local_return.py \
	inertia/lowering/gp_stack_local_reload.py \
	inertia/lowering/call_argument_call_preservation.py \
	inertia/ir/register_live_in.py \
	inertia/lowering/call_output_object_projection.py \
	inertia/lowering/runtime_call_results.py \
	inertia/lowering/call_argument_semantic_gap.py \
	tools/dev/makefile_inventory.py \
	inertia/ir/function_ir_registry.py \
	inertia/lowering/far_pointer_constant_flow.py \
	inertia/lowering/gp_register_state.py \
	inertia/lowering/call_argument_carrier_liveness.py \
	inertia/lowering/call_return_frame.py \
	inertia/lowering/call_return_frame_arguments.py \
	inertia/semantics/callsite_setup_evidence.py \
	inertia/lowering/consumed_stack_address_setup.py \
	inertia/frontend/x86_16/synthetic_call_stub_evidence.py \
	monkeytype_config.py \
	inertia/frontend/x86_16/public_api.py \
	inertia/ir/vex_operation_membership.py \
	tests/fixtures/entry_stack_byte_test_support.py \
	inertia/ir/analysis/alias.py \
	inertia/ir/analysis/stack_frame_ir.py \
	inertia/ir/frame_memory_accesses.py \
	inertia/lowering/analysis_helpers.py \
	inertia/frontend/x86_16/access.py \
	inertia/frontend/x86_16/addressing_helpers.py \
	inertia/frontend/x86_16/capstone_memory_segment.py \
	inertia/frontend/x86_16/decoded_memory_width.py \
	inertia/ir/address_ir_8616.py \
	inertia/lowering/annotations.py \
	inertia/frontend/x86_16/borrow_verification.py \
	inertia/ir/condition_ir.py \
	inertia/structuring/condition_trace.py \
	inertia/structuring/condition_call_effects.py \
	inertia/semantics/function_evidence_inventory.py \
	inertia/semantics/helper_abi.py \
	inertia/frontend/x86_16/regs.py \
	inertia/ir/__init__.py \
	inertia/ir/address_ir.py \
	inertia/ir/condition_register_bindings.py \
	inertia/ir/condition_value_extensions.py \
	inertia/ir/condition_fingerprint_masks.py \
	inertia/ir/condition_fingerprint_syntax.py \
	inertia/ir/core.py \
	inertia/ir/block_ownership.py \
	inertia/ir/block_successor_chain.py \
	inertia/ir/effects.py \
	inertia/ir/function_artifact.py \
	inertia/ir/function_condition_artifact.py \
	inertia/ir/condition_lift_capture.py \
	inertia/ir/indexed_address_access_normalization.py \
	inertia/ir/indexed_address_contracts.py \
	inertia/ir/indexed_address_copy_contracts.py \
	inertia/ir/indexed_address_copy_evidence.py \
	inertia/ir/indexed_address_copy_trace.py \
	inertia/ir/indexed_address_evidence.py \
	inertia/ir/indexed_address_pipeline.py \
	inertia/ir/indexed_address_range_candidate_helpers.py \
	inertia/ir/indexed_induction_write_census.py \
	inertia/ir/indexed_address_range_candidates.py \
	inertia/ir/indexed_address_range_contracts.py \
	inertia/ir/indexed_address_range_evidence.py \
	inertia/ir/indexed_address_range_witnesses.py \
	inertia/ir/ir_canonicalize_8616.py \
	inertia/ir/logical_memory_capture.py \
	inertia/ir/logical_memory_contracts.py \
	inertia/ir/logical_memory_matching.py \
	inertia/ir/logical_memory_rebase.py \
	inertia/ir/logical_memory_resolution.py \
	inertia/ir/logical_memory_register_transfer.py \
	inertia/ir/logical_memory_register_transfer_contracts.py \
	inertia/ir/logical_memory_value_trace.py \
	inertia/ir/logical_memory_write_value.py \
	inertia/ir/logical_constant_word_receipt.py \
	inertia/ir/regs.py \
	inertia/ir/scalar_definitions.py \
	inertia/ir/scalar_affine_contracts.py \
	inertia/ir/scalar_affine_sources.py \
	inertia/ir/scalar_affine_trace.py \
	inertia/ir/affine_indexed_address.py \
	inertia/ir/affine_induction_role.py \
	inertia/ir/frame_register_reaching_definition.py \
	inertia/ir/status_flag_binary_cfg.py \
	inertia/ir/status_flag_cfg_projection.py \
	inertia/ir/status_flag_lift_context.py \
	inertia/ir/status_flag_lift_codec.py \
	inertia/ir/segment_contract.py \
	inertia/semantics/segment_function_summary.py \
	inertia/frontend/x86_16/segment_offset_execution.py \
	inertia/semantics/segment_program_layout.py \
	inertia/semantics/segment_program_layout_codec.py \
	inertia/semantics/segment_program_layout_contract.py \
	inertia/ir/segment_state.py \
	inertia/ir/segment_state_solver.py \
	inertia/ir/segment_state_transfer.py \
	inertia/ir/ssa.py \
	inertia/ir/ssa_function.py \
	inertia/ir/ssa_cfg.py \
	inertia/ir/ssa_cfg_contracts.py \
	inertia/ir/ssa_memory.py \
	inertia/ir/ssa_memory_call_liveness.py \
	inertia/ir/ssa_memory_contracts.py \
	inertia/ir/ssa_memory_ranges.py \
	inertia/ir/stack_range_overlap.py \
	inertia/lowering/native_integer_constants.py \
	inertia/lowering/native_integer_operations.py \
	inertia/lowering/native_terminal_return_values.py \
	inertia/ir/string_effects.py \
	inertia/ir/value_ir.py \
	inertia/ir/vex_addressing.py \
	inertia/ir/vex_condition_demand.py \
	inertia/ir/vex_condition_lifting.py \
	inertia/ir/vex_condition_transport.py \
	inertia/ir/vex_control_flow.py \
	inertia/ir/vex_terminal_jump.py \
	inertia/ir/entry_jump_domain.py \
	inertia/ir/real16_invocation_domain.py \
	inertia/ir/real16_edge_feasibility8616.py \
	inertia/ir/vex_import.py \
	inertia/ir/vex_integer_displacement.py \
	inertia/ir/vex_types.py \
	inertia/semantics/function_effect_summary.py \
	inertia/semantics/helper_effect_summary.py \
	inertia/semantics/helper_family_routing.py \
	inertia/semantics/function_interface_surface.py \
	inertia/semantics/function_summary.py \
	inertia/semantics/function_state_summary.py \
	inertia/semantics/callsite_target_inventory.py \
	inertia/semantics/caller_return_use_contracts.py \
	inertia/semantics/callsite_summary.py \
	inertia/semantics/callsite_register_provenance.py \
	inertia/semantics/register_source_block_inventory.py \
	inertia/semantics/call_target_identity.py \
	inertia/postprocess/callsite_stack_metadata.py \
	inertia/semantics/stack_probe_fact_trace.py \
	inertia/validation/tail_validation_condition_context.py \
	inertia/validation/tail_validation_frame_spills.py \
	inertia/validation/tail_validation_fingerprint.py \
	inertia/validation/validation_goto_target_identity.py \
	inertia/validation/tail_validation_generation.py \
	inertia/validation/tail_validation_generation_atoms.py \
	inertia/pipeline/structured_ast_generation.py \
	inertia/pipeline/result_contracts.py \
	inertia/pipeline/structured_assignment_index.py \
	inertia/pipeline/structured_ast_query_index.py \
	inertia/validation/control_flow_ast_index.py \
	inertia/validation/tail_validation_routing.py \
	inertia/validation/tail_validation_selector_returns.py \
	inertia/validation/tail_validation_stack_policy.py \
	inertia/cli/targeted_recovery_artifact.py \
	inertia/cli/layer_module_status.py \
	inertia/frontend/x86_16/coverage_manifest.py \
	inertia/cli/corpus_scan.py \
	inertia/cli/milestone_report.py \
	inertia/cli/exact_region_diagnostics.py \
	inertia/frontend/x86_16/frontend_cfg_direct_jump.py \
	inertia/frontend/x86_16/frontend_cfg_direct_call.py \
	inertia/frontend/x86_16/frontend_cfg_direct_jobs.py \
	inertia/frontend/x86_16/frontend_function_boundary.py \
	inertia/frontend/x86_16/frontend_function_boundary_index.py \
	inertia/frontend/x86_16/frontend_function_block_decode.py \
	inertia/frontend/x86_16/frontend_capstone_block.py \
	inertia/frontend/x86_16/frontend_block_inventory.py \
	inertia/frontend/x86_16/frontend_capstone_decode.py \
	inertia/frontend/x86_16/frontend_function_instructions.py \
	inertia/frontend/x86_16/frontend_caller_return_use_program.py \
	inertia/frontend/x86_16/frontend_direct_callsite_index.py \
	inertia/frontend/x86_16/frontend_instruction_kinds.py \
	inertia/frontend/x86_16/frontend_instruction_reachability.py \
	inertia/cli/recovery_instruction_coverage.py \
	inertia/cli/flair_extract.py \
	inertia/cli/fast_tracer.py \
	inertia/frontend/x86_16/jcc_condition.py \
	inertia/frontend/x86_16/jcc_result_condition.py \
	inertia/frontend/x86_16/lift_86_16.py \
	inertia/frontend/x86_16/lifter_backend_selection.py \
	inertia/cli/lst_extract.py \
	inertia/frontend/x86_16/ne_exe_parse.py \
	inertia/cli/recovery_manifest.py \
	inertia/cli/recovery_artifacts.py \
	inertia/validation/recovery_confidence.py \
	inertia/cli/recovery_artifact_cache.py \
	inertia/cli/recovery_artifact_manifest.py \
	inertia/cli/recovery_artifact_writer.py \
	inertia/cli/corpus_recovery_artifact.py \
	inertia/structuring/confidence_and_assumptions.py \
	inertia/structuring/confidence_evidence.py \
	inertia/structuring/ir_recovery_summary.py \
	inertia/structuring/ir_readiness.py \
	inertia/structuring/ir_confidence_markers.py \
	inertia/cli/runtime_trace_refinement.py \
	inertia/structuring/structuring_ir_hints.py \
	inertia/structuring/structuring_abnormal_loops.py \
	inertia/structuring/structuring_analysis.py \
	inertia/structuring/structuring_cfg_ownership.py \
	inertia/structuring/structuring_cfg_indirect.py \
	inertia/structuring/structuring_cfg_grouping.py \
	inertia/structuring/structuring_loops.py \
	inertia/structuring/structuring_cfg_snapshot.py \
	inertia/structuring/structuring_graph_builder.py \
	inertia/structuring/structuring_grouped_graph_builder.py \
	inertia/structuring/structuring_region.py \
	inertia/structuring/structuring_codegen.py \
	inertia/structuring/decompiler_structuring_stage.py \
	inertia/structuring/structuring_grouped_pass.py \
	inertia/structuring/structuring_grouped_units.py \
	inertia/cli/structured_function_helpers.py \
	inertia/frontend/x86_16/string_helpers.py \
	inertia/semantics/string_instruction_artifact.py \
	inertia/lowering/string_instruction_lowering.py \
	inertia/structuring/string_codegen_override.py \
	inertia/lowering/type_array_matching.py \
	inertia/lowering/type_equivalence_classes.py \
	inertia/lowering/type_structure_merging.py \
	inertia/lowering/type_storage_object_bridge.py \
	inertia/frontend/x86_16/bootstrap.py \
	inertia/cli/cod_comment_emitter.py \
	inertia/frontend/x86_16/cod_analysis_image.py \
	inertia/frontend/x86_16/cod_extract.py \
	inertia/frontend/x86_16/cod_known_objects.py \
	inertia/cli/cod_source_rewrites.py \
	inertia/cli/codeview_nb00.py \
	inertia/cli/codeview_nb02_nb04.py \
	inertia/lowering/codegen_metadata.py \
	inertia/semantics/compiler_helpers.py \
	inertia/frontend/x86_16/cr.py \
	inertia/postprocess/decompiler_postprocess_inventory.py \
	inertia/postprocess/decompiler_postprocess_globals.py \
	inertia/postprocess/decompiler_postprocess_utils.py \
	inertia/frontend/x86_16/compat.py \
	inertia/frontend/x86_16/call_frame_compat.py \
	inertia/frontend/x86_16/call_cleanup_compat.py \
	inertia/ir/stack_pointer_provenance.py \
	inertia/ir/stack_extent_evidence.py \
	inertia/ir/ail_register_displacement.py \
	inertia/frontend/x86_16/ail_displacement_compat.py \
	inertia/frontend/x86_16/ail_remainder_compat.py \
	inertia/frontend/x86_16/variable_recovery_compat.py \
	inertia/ir/ail_remainder.py \
	inertia/postprocess/codegen_parentheses.py \
	inertia/frontend/x86_16/stack_anchor_compat.py \
	inertia/ir/native_stack_anchor.py \
	inertia/ir/native_segment_live_out.py \
	inertia/lowering/store_projection_width.py \
	inertia/lowering/runtime_push_carrier.py \
	inertia/frontend/x86_16/calling_convention_compat.py \
	inertia/lowering/calling_convention_seed_cache.py \
	inertia/frontend/x86_16/render_compat.py \
	inertia/frontend/x86_16/patch_dirty.py \
	inertia/lowering/c_ast_utils.py \
	inertia/semantics/callee_name_normalization.py \
	inertia/frontend/x86_16/low_memory_regions.py \
	inertia/frontend/x86_16/exception.py \
	inertia/frontend/x86_16/hardware.py \
	inertia/frontend/x86_16/simprocs_io.py \
	inertia/frontend/x86_16/debug.py \
	inertia/frontend/x86_16/exepack.py \
	inertia/frontend/x86_16/mz_image.py \
	inertia/frontend/x86_16/mz_load_source.py \
	inertia/frontend/x86_16/mz_invocation_source.py \
	inertia/frontend/x86_16/packed_mz.py \
	inertia/frontend/x86_16/pklite.py \
	inertia/cli/catalog_policy.py \
	inertia/frontend/x86_16/dev_io.py \
	inertia/frontend/x86_16/io.py \
	inertia/frontend/x86_16/instruction.py \
	inertia/frontend/x86_16/instr_base.py \
	inertia/frontend/x86_16/instr16.py \
	inertia/frontend/x86_16/instr32.py \
	inertia/frontend/x86_16/parse.py \
	inertia/frontend/x86_16/exec.py \
	inertia/frontend/x86_16/emu.py \
	inertia/frontend/x86_16/emulator.py \
	inertia/frontend/x86_16/eflags.py \
	inertia/frontend/x86_16/memory.py \
	inertia/frontend/x86_16/processor.py \
	inertia/frontend/x86_16/interrupt.py \
	inertia/frontend/x86_16/stack_compat.py \
	inertia/frontend/x86_16/load_propagation.py \
	inertia/frontend/x86_16/stack_tracker_allocation.py \
	inertia/frontend/x86_16/stack_tracker_return_segment.py \
	inertia/frontend/x86_16/stack_value_use.py \
	inertia/frontend/x86_16/typehoon_compat.py \
	inertia/lowering/type_clinic_return_compat.py \
	inertia/frontend/x86_16/stack_helpers.py \
	inertia/frontend/x86_16/relative_control_edge.py \
	inertia/ir/condition_relative_edge.py \
	inertia/cli/correctness_goals.py \
	inertia/cli/readability_set.py \
	inertia/cli/readability_goals.py \
	inertia/cli/acceptance_scorecard.py \
	inertia/postprocess/decompiler_postprocess.py \
	inertia/postprocess/decompiler_postprocess_calls.py \
	inertia/postprocess/decompiler_postprocess_jcc.py \
	inertia/postprocess/decompiler_postprocess_loads.py \
	inertia/postprocess/decompiler_postprocess_simplify.py \
	inertia/postprocess/decompiler_postprocess_stage.py \
	inertia/postprocess/decompiler_postprocess_typed_conditions.py \
	inertia/frontend/x86_16/decompiler_return_compat.py \
	inertia/frontend/x86_16/ailment_variant_access.py \
	inertia/validation/tail_validation.py \
	inertia/validation/validation_manifest.py \
	inertia/validation/validation_helper_report.py \
	inertia/validation/validation_summary.py \
	inertia/validation/validation_calls.py \
	inertia/validation/validation_call_multiplicity.py \
	inertia/validation/validation_call_argument_sources.py \
	inertia/validation/validation_call_return_storage.py \
	inertia/validation/validation_stack_projection.py \
	inertia/validation/validation_branch_conditions.py \
	inertia/validation/validation_materialized_condition_storage.py \
	inertia/validation/validation_condition_identity.py \
	inertia/validation/validation_condition_coverage.py \
	inertia/validation/validation_condition_storage_views.py \
	inertia/validation/validation_control_flow.py \
	inertia/validation/validation_condition_precision.py \
	inertia/validation/validation_control_condition_delta.py \
	inertia/validation/validation_terminal_returns.py \
	inertia/validation/validation_switch_loop_tail_breaks.py \
	inertia/validation/validation_control_flow_obligations.py \
	inertia/validation/validation_dataflow.py \
	inertia/validation/validation_identical_return_guards.py \
	inertia/validation/validation_semantic_failures.py \
	inertia/validation/validation_predicates.py \
	inertia/validation/validation_storage.py \
	inertia/validation/validation_aggregate_storage.py \
	inertia/validation/validation_additive_terms.py \
	inertia/validation/validation_required_memory_effects.py \
	inertia/validation/validation_semantics.py \
	inertia/frontend/x86_16/verification_80286.py \
	inertia/cli/turbo_debug_tdinfo.py \
	inertia/cli/recompilable_cases.py \
	inertia/cli/recompilable_checks.py \
	inertia/cli/recompilable_cli_bridge.py \
	inertia/cli/recompilable_source_evidence.py \
	inertia/cli/recompilable_subset.py \
	inertia/cli/recompilable_storage_alias.py \
	inertia/cli/recompilable_storage_fallback.py \
	inertia/cli/recompilable_storage_map.py \
	inertia/cli/recompilable_storage_map_producer.py \
	inertia/cli/recompilable_storage_objects.py \
	inertia/structuring/structuring_diagnostics.py \
	inertia/structuring/structuring_grouping_report.py \
	inertia/structuring/structuring_grouped_refusal_report.py \
	inertia/structuring/structuring_cross_entry.py \
	inertia/structuring/structuring_sequences.py \
	inertia/lowering/__init__.py \
	inertia/lowering/annotated_global_refs.py \
	inertia/lowering/call_argument_shape.py \
	inertia/lowering/call_argument_shape_publication.py \
	inertia/lowering/call_argument_arity_ownership.py \
	inertia/lowering/call_argument_expression.py \
	inertia/lowering/call_argument_semantic_token.py \
	inertia/lowering/call_argument_state.py \
	inertia/semantics/callsite_argument_value_sources.py \
	inertia/lowering/call_execution_frame_carriers.py \
	inertia/lowering/call_execution_frame_replay.py \
	inertia/lowering/call_execution_frame_runtime.py \
	inertia/lowering/call_output_stack_object_replay.py \
	inertia/lowering/call_output_stack_objects.py \
	inertia/lowering/authoritative_function_prototypes.py \
	inertia/lowering/near_return_address_arguments.py \
	inertia/lowering/direct_stack_replay.py \
	inertia/lowering/direct_stack_consumer_generation.py \
	inertia/lowering/direct_stack_replay_contracts.py \
	inertia/lowering/register_local_declarations.py \
	inertia/lowering/register_variable_identity.py \
	inertia/lowering/stack_address_coordinates.py \
	inertia/lowering/register_reload_consumers.py \
	inertia/lowering/stack_storage_evidence.py \
	inertia/lowering/call_return_selectors.py \
	inertia/lowering/call_return_stack_bindings.py \
	inertia/lowering/call_return_stack_stores.py \
	inertia/lowering/call_cleanup_carriers.py \
	inertia/lowering/runtime_segment_access.py \
	inertia/lowering/runtime_memory_helpers.py \
	inertia/lowering/callsite_prototype_declarations.py \
	inertia/lowering/dos_interrupt_abi.py \
	inertia/lowering/dos_interrupt_aggregate_evidence.py \
	inertia/lowering/dos_interrupt_aggregate_globals.py \
	inertia/lowering/dos_interrupt_aggregate_projection.py \
	inertia/lowering/named_type_definitions.py \
	inertia/lowering/callsite_prototype_seeding.py \
	inertia/lowering/callsite_pointer_tables.py \
	inertia/lowering/signed_global_declarations.py \
	inertia/lowering/project_global_signedness.py \
	inertia/lowering/callee_callsite_census.py \
	inertia/lowering/callee_argument_count_evidence.py \
	inertia/lowering/callee_argument_width_evidence.py \
	inertia/ir/function_ssa_registry.py \
	inertia/lowering/interprocedural_memory_output_object_contracts.py \
	inertia/lowering/interprocedural_memory_output_objects.py \
	inertia/lowering/interprocedural_memory_output_validation.py \
	inertia/lowering/interprocedural_storage_collection_contracts.py \
	inertia/lowering/interprocedural_storage_contracts.py \
	inertia/lowering/interprocedural_storage_function_solver.py \
	inertia/lowering/interprocedural_storage_live_out.py \
	inertia/lowering/interprocedural_storage_live_out_contracts.py \
	inertia/lowering/interprocedural_storage_live_out_flow.py \
	inertia/lowering/interprocedural_storage_live_out_paths.py \
	inertia/lowering/interprocedural_storage_slot_join.py \
	inertia/lowering/interprocedural_storage_pipeline.py \
	inertia/lowering/pointer_parameter_output_contracts.py \
	inertia/lowering/pointer_parameter_outputs.py \
	inertia/lowering/interprocedural_storage_prototype_application.py \
	inertia/lowering/interprocedural_storage_prototype_types.py \
	inertia/lowering/interprocedural_storage_reaching_contracts.py \
	inertia/lowering/interprocedural_storage_source_defs.py \
	inertia/lowering/interprocedural_storage_return_defs.py \
	inertia/lowering/interprocedural_storage_return_passthrough_contracts.py \
	inertia/lowering/interprocedural_storage_return_passthrough.py \
	inertia/lowering/interprocedural_storage_return_type_contracts.py \
	inertia/lowering/interprocedural_storage_return_split_condition_graph.py \
	inertia/lowering/interprocedural_storage_return_split_conditions.py \
	inertia/lowering/interprocedural_storage_return_split.py \
	inertia/lowering/interprocedural_storage_return_collection_contracts.py \
	inertia/lowering/interprocedural_storage_return_trial_materialization.py \
	inertia/lowering/interprocedural_storage_caller_context.py \
	inertia/lowering/interprocedural_storage_return_trial_collection.py \
	inertia/lowering/interprocedural_storage_return_pointer.py \
	inertia/lowering/interprocedural_storage_return_pointer_block.py \
	inertia/lowering/interprocedural_storage_return_pointer_flow.py \
	inertia/lowering/interprocedural_storage_return_pointer_stack.py \
	inertia/lowering/interprocedural_storage_return_pointer_witness.py \
	inertia/lowering/interprocedural_storage_return_types.py \
	inertia/lowering/interprocedural_storage_reaching_defs.py \
	inertia/lowering/interprocedural_storage_expression_defs.py \
	inertia/lowering/pointer_parameter_caller_target_contracts.py \
	inertia/lowering/pointer_parameter_caller_targets.py \
	inertia/lowering/pointer_parameter_memory_output_contracts.py \
	inertia/lowering/pointer_parameter_memory_outputs.py \
	inertia/lowering/pointer_parameter_object_type_contracts.py \
	inertia/lowering/pointer_parameter_object_types.py \
	inertia/lowering/interprocedural_storage_physical_defs.py \
	inertia/lowering/interprocedural_storage_trial_types.py \
	inertia/lowering/interprocedural_storage_input_preflight.py \
	inertia/lowering/interprocedural_storage_trial_collection.py \
	inertia/lowering/interprocedural_storage_solver.py \
	inertia/lowering/interprocedural_storage_simtypes.py \
	inertia/lowering/interprocedural_storage_transaction.py \
	inertia/lowering/callee_argument_interface.py \
	inertia/lowering/callee_global_object_collection.py \
	inertia/lowering/callee_global_object_evidence.py \
	inertia/lowering/global_object_program_requirement.py \
	inertia/lowering/callee_global_object_interface.py \
	inertia/lowering/callee_global_object_sources.py \
	inertia/lowering/global_object_source_codec.py \
	inertia/lowering/callee_global_object_type_surface.py \
	inertia/lowering/callee_pointer_evidence.py \
	inertia/lowering/callee_pointer_contracts.py \
	inertia/lowering/callee_pointer_codec.py \
	inertia/semantics/callsite_summary_codec.py \
	inertia/semantics/callsite_summary_program.py \
	inertia/semantics/callsite_summary_program_codec.py \
	inertia/lowering/callee_callsite_contracts.py \
	inertia/lowering/callee_callsite_codec.py \
	inertia/lowering/callee_range_callsite_facts.py \
	inertia/lowering/project_callee_callsite_collection.py \
	inertia/lowering/project_global_object_source_collection.py \
	inertia/lowering/indexed_global_evidence.py \
	inertia/lowering/indexed_address_collector_parity.py \
	inertia/lowering/indexed_address_parity_inventory.py \
	inertia/lowering/indexed_address_parity_inventory_contracts.py \
	inertia/lowering/helper_call_interfaces.py \
	inertia/lowering/far_pointer_segmented_load_evidence.py \
	inertia/lowering/far_pointer_segmented_load_materialization.py \
	inertia/lowering/register_constant_segmented_store.py \
	inertia/lowering/near_pointer_argument.py \
	inertia/lowering/near_pointer_index_binding.py \
	inertia/lowering/near_pointer_type.py \
	inertia/ir/condition_cache_relift.py \
	inertia/ir/condition_cache_relift_cache.py \
	inertia/ir/condition_cache_relift_contracts.py \
	inertia/lowering/condition_transfer.py \
	inertia/lowering/condition_fact_arbitration.py \
	inertia/lowering/condition_argument_type_facts.py \
	inertia/lowering/condition_argument_types.py \
	inertia/lowering/condition_scalar_types.py \
	inertia/lowering/condition_stack_operands.py \
	inertia/lowering/condition_stack_value.py \
	inertia/lowering/condition_stack_projection_contracts.py \
	inertia/lowering/assignment_lvalue_casts.py \
	inertia/lowering/c_runtime_header.py \
	inertia/lowering/callee_saved_frame.py \
	inertia/lowering/dead_register_carriers.py \
	inertia/lowering/explicit_char_types.py \
	inertia/lowering/fixed_stack_probe_frames.py \
	inertia/lowering/stack_probe_callsite_lowering.py \
	inertia/lowering/frame_prologue_carriers.py \
	inertia/lowering/frame_carrier_liveness.py \
	inertia/lowering/register_overwrite_evidence.py \
	inertia/lowering/fact_transfer.py \
	inertia/lowering/function_pointer_parameter_evidence.py \
	inertia/lowering/function_pointer_parameters.py \
	inertia/lowering/cod_global_identity.py \
	inertia/lowering/bounded_global_array_declarations.py \
	inertia/lowering/global_declaration_extents.py \
	inertia/lowering/global_declarations.py \
	inertia/lowering/global_symbol_names.py \
	inertia/lowering/object_lowering.py \
	inertia/lowering/pointer_memory_idioms.py \
	inertia/lowering/physical_registers.py \
	inertia/lowering/positive_bp_argument_plan.py \
	inertia/lowering/positive_bp_arguments.py \
	inertia/lowering/live_stack_word_inputs.py \
	inertia/lowering/project_global_object_layout.py \
	inertia/lowering/real_mode_linear.py \
	inertia/lowering/linear_global_decomposition_cache.py \
	inertia/lowering/instruction_bp_stack_access.py \
	inertia/lowering/stack_coordinate_rebinding.py \
	inertia/lowering/stack_variable_coordinates.py \
	inertia/lowering/machine_stack_names.py \
	inertia/lowering/stack_function_coordinates.py \
	inertia/lowering/stack_variable_display_names.py \
	inertia/lowering/stack_word_load_candidate.py \
	inertia/lowering/stack_word_load_materialization.py \
	inertia/lowering/stack_word_load_projection.py \
	inertia/lowering/stack_word_projection.py \
	inertia/lowering/callsite_inventory_presence.py \
	inertia/lowering/callsite_segment_provenance.py \
	inertia/lowering/segment_access_coverage.py \
	inertia/lowering/segment_codegen_access_provenance.py \
	inertia/lowering/segment_access_policy.py \
	inertia/lowering/segment_global_materialization.py \
	inertia/lowering/semantic_cast.py \
	inertia/lowering/condition_operand_views.py \
	inertia/lowering/return_type_evidence.py \
	inertia/lowering/return_liveness_replay.py \
	inertia/lowering/unobserved_call_results.py \
	inertia/lowering/unobserved_returns.py \
	inertia/lowering/unused_void_return_types.py \
	inertia/lowering/scalar_return_types.py \
	inertia/lowering/segment_register_state.py \
	inertia/lowering/indexed_load_subviews.py \
	inertia/lowering/segmented_global_loads.py \
	inertia/lowering/aggregate_byte_projection.py \
	inertia/lowering/condition_value_casts.py \
	inertia/lowering/segmented_lowering.py \
	inertia/lowering/segmented_memory_lowering.py \
	inertia/lowering/pointer_store_consumption.py \
	inertia/lowering/ir_segmented_load_carriers.py \
	inertia/lowering/register_indirect_call_targets.py \
	inertia/lowering/stack_pointer_snapshot.py \
	inertia/lowering/stack_argument_identity.py \
	inertia/lowering/stack_declaration_identity.py \
	inertia/lowering/call_argument_stack_sources.py \
	inertia/lowering/call_return_stack_conditions.py \
	inertia/lowering/structured_intrinsics.py \
	inertia/lowering/terminal_call_return_types.py \
	inertia/lowering/terminal_register_return_values.py \
	inertia/lowering/terminal_register_return_types.py \
	inertia/lowering/terminal_return_expressions.py \
	inertia/lowering/terminal_return_render_projection.py \
	inertia/lowering/software_interrupt_calls.py \
	inertia/lowering/software_interrupt_status_outputs.py \
	inertia/lowering/segmented_memory_reasoning.py \
	inertia/lowering/stack_aggregate_objects.py \
	inertia/lowering/stack_aggregate_projection.py \
	inertia/lowering/stack_c_ast_matching.py \
	inertia/lowering/stack_lowering.py \
	inertia/lowering/stack_lowering_from_facts.py \
	inertia/lowering/carry_borrow_bit_ast.py \
	inertia/lowering/carry_borrow_bit_contracts.py \
	inertia/lowering/carry_borrow_bit_placement.py \
	inertia/lowering/carry_borrow_bit_predicate.py \
	inertia/lowering/carry_borrow_bit_scope.py \
	inertia/lowering/carry_borrow_bit_values.py \
	inertia/lowering/carry_borrow_stack_storage.py \
	inertia/lowering/wide_call_output_assignment_ast.py \
	inertia/lowering/wide_call_output_assignment_carriers.py \
	inertia/lowering/wide_call_output_assignment_contracts.py \
	inertia/lowering/wide_call_output_assignment_evidence.py \
	inertia/lowering/wide_call_output_assignment_placement.py \
	inertia/lowering/wide_call_output_assignment_replay.py \
	inertia/lowering/wide_call_output_assignments.py \
	inertia/lowering/wide_call_return_recombine.py \
	inertia/lowering/straight_line_placement.py \
	inertia/lowering/stack_memory_ssa.py \
	inertia/lowering/stack_memory_ssa_contracts.py \
	inertia/lowering/stack_projection_retirement.py \
	inertia/lowering/stack_lowering_impl.py \
	inertia/lowering/stack_prototype_materialization.py \
	inertia/lowering/wide_stack_argument_views.py \
	inertia/lowering/stack_probe_return_facts.py \
	inertia/lowering/storage_identity_facts.py \
	inertia/lowering/ss_bp_substitution.py \
	inertia/lowering/stack_lowering_result.py \
	inertia/lowering/stack_variable_binding.py \
	inertia/lowering/wide_stack_pair_evidence.py \
	inertia/lowering/stack_update_scope_guard.py \
	inertia/lowering/wide_call_condition_binding.py \
	inertia/validation/validation_terminal_wide_conditions.py \
	inertia/ir/condition_zero_input.py \
	inertia/lowering/wide_call_condition_source.py \
	inertia/lowering/wide_call_condition_capture.py \
	inertia/validation/__init__.py \
	inertia/validation/canonicalize.py \
	inertia/validation/callsite_completeness.py \
	inertia/validation/status_flag_preservation.py \
	inertia/validation/validation_interrupt_calls.py \
	inertia/widening/widening_model.py \
	inertia/pipeline/architecture_guard.py \
	inertia/pipeline/contracts.py \
	inertia/pipeline/errors.py \
	inertia/pipeline/invariants.py \
	inertia/pipeline/linear_guard.py \
	inertia/pipeline/recovery_coverage_guard.py \
	inertia/pipeline/render_authority.py \
	inertia/cli/__init__.py \
	inertia/cli/analysis_timeout.py \
	inertia/cli/architecture_import_attestation.py \
	inertia/cli/architecture_runtime_guard.py \
	inertia/cli/project_evidence_transport.py \
	inertia/cli/indexed_global_object_cache.py \
	inertia/cli/direct_global_object_cache.py \
	inertia/cli/direct_global_object_context.py \
	inertia/cli/serial_clean_worker_evidence.py \
	inertia/cli/cod_module_caller_evidence.py \
	inertia/cli/c_text_cleanup.py \
	inertia/cli/cache.py \
	inertia/cli/cache_io.py \
	inertia/cli/cache_lock.py \
	inertia/cli/cache_runtime_contract.py \
	inertia/cli/cache_source_manifest.py \
	inertia/cli/function_ir_ssa_source_scope.py \
	inertia/cli/program_callsite_cache.py \
	inertia/cli/direct_request_cache.py \
	inertia/cli/direct_request_fast_path.py \
	inertia/cli/direct_request_identity.py \
	inertia/cli/cli.py \
	inertia/cli/cli_core.py \
	inertia/cli/indexed_alias_program_context.py \
	inertia/cli/indexed_alias_program_publication.py \
	inertia/cli/indexed_alias_program_recovery.py \
	inertia/cli/indexed_alias_program_parallel.py \
	inertia/cli/project_argument_evidence_ranges.py \
	inertia/cli/serial_clean_worker_cli.py \
	inertia/cli/serial_worker_cache.py \
	inertia/cli/discovery_cache_contract.py \
	inertia/cli/segment_program_layout_reporting.py \
	inertia/cli/function_worker_policy.py \
	inertia/cli/generated_c_artifacts.py \
	inertia/cli/cli_batch_c_output.py \
	inertia/cli/generated_external_function_contracts.py \
	inertia/cli/generated_c_function_extraction.py \
	inertia/cli/generated_translation_unit_assembly.py \
	inertia/cli/cli_decompilation.py \
	inertia/cli/cli_c_ast_rewrites.py \
	inertia/cli/cli_c_text_postprocess.py \
	inertia/cli/cli_fallback_decompilation.py \
	inertia/cli/cli_function_discovery.py \
	inertia/cli/function_graph_extent_repair.py \
	inertia/cli/cli_access_profiles.py \
	inertia/cli/cli_access_traits.py \
	inertia/cli/cli_access_trait_rewrite.py \
	inertia/cli/cli_access_rewrite_artifact.py \
	inertia/cli/cli_arg_parser.py \
	inertia/cli/cli_cod_global_statements.py \
	inertia/cli/cli_cod_globals.py \
	inertia/cli/cli_dead_local_prune.py \
	inertia/cli/cli_semantic_rollback.py \
	inertia/cli/cli_rollback_snapshot_8616.py \
	inertia/cli/cli_helper_modeling.py \
	inertia/cli/cli_interrupt_modeling.py \
	inertia/cli/cli_linear_aliases.py \
	inertia/cli/cli_induction_rewrite.py \
	inertia/cli/cli_linear_recurrence.py \
	inertia/cli/cli_linear_recurrence_rules.py \
	inertia/cli/cli_linear_recurrence_state.py \
	inertia/cli/cli_mkfp_simplify.py \
	inertia/cli/cli_memory_prune.py \
	inertia/cli/cli_local_prune.py \
	inertia/cli/cli_local_rewrites.py \
	inertia/cli/cli_far_pointer_stack.py \
	inertia/cli/cli_segmented_compare.py \
	inertia/cli/cli_segmented_elision.py \
	inertia/cli/cli_segmented_load_coalesce.py \
	inertia/cli/cli_stack_byte_offsets.py \
	inertia/cli/cli_stack_locals.py \
	inertia/cli/cli_storage_objects.py \
	inertia/cli/cli_string_timeout_fallback.py \
	inertia/cli/cli_timeout.py \
	inertia/cli/cli_output.py \
	inertia/cli/cli_word_global_helpers.py \
	inertia/cli/default_signature_catalog.py \
	inertia/cli/decompile_file_summary.py \
	inertia/cli/decompilation_quality.py \
	inertia/cli/direct_addr_failure_family.py \
	inertia/cli/direct_addr_stage_bundle.py \
	inertia/cli/discovery_evidence_project.py \
	inertia/cli/disassembly_helpers.py \
	inertia/cli/fork_timeout.py \
	inertia/cli/function_cache_context.py \
	inertia/cli/library_function_classifier.py \
	inertia/cli/debug_dos.py \
	inertia/cli/debugger_gdb.py \
	inertia/cli/msc51_local_hash.py \
	inertia/cli/non_optimized_fallback.py \
	inertia/cli/packer_detect.py \
	inertia/cli/project_loading.py \
	inertia/cli/prefork_job_pool.py \
	inertia/cli/rizin_evidence.py \
	inertia/cli/rizin_discovery.py \
	inertia/cli/recompile_check.py \
	inertia/cli/recompile_check_contract.py \
	inertia/cli/cli_terminal_status.py \
	inertia/cli/runtime_support.py \
	inertia/cli/sidecar_cache.py \
	inertia/cli/sidecar_metadata.py \
	inertia/cli/sidecar_policy.py \
	inertia/cli/sidecar_parsers.py \
	inertia/cli/slice_recovery.py \
	inertia/cli/source_sidecar.py \
	inertia/cli/tail_validation.py \
	inertia/cli/telemetry.py \
	inertia/cli/variable_recovery_sub_guard.py \
	inertia/cli/work_items.py \
	inertia/cli/x86_16_exact_slice.py \
	inertia/cli/monkeytype_tools.py \
	tools/dev/collect_monkeytype_pytest.py \
	tools/dev/apply_monkeytype_annotations.py \
	tools/dev/export_monkeytype_stubs.py \
	tools/dev/build_mypyc.py \
	tools/dev/build_cython_vex.py \
	tools/dev/benchmark_cython_vex.py \
	tools/dev/mypyc_build_cache.py \
	tools/dev/agent_context_check.py \
	tools/dev/agent_test_focus.py \
	tools/dev/batch_decompile_procs.py \
	tools/compiler_toolchain/build_debug_info_corpus.py \
	tools/compiler_toolchain/verify_msc_example_runtime_gate.py \
	tools/dev/compare_ghidra_function_coverage.py \
	tools/dev/check_sortd_sidecar_free.py \
	tools/dev/sortd_function_gate.py \
	tools/dev/runmenu_behavior.py \
	tools/dev/indexed_address_parity_inventory.py \
	tools/dev/check_generated_translation_unit.py \
	tools/dev/check_sortd_generated_sort_core.py \
	tools/dev/check_decompiler_architecture.py \
	tools/dev/test_pipeline.py \
	tools/dev/cod_stability_sweep.py \
	tools/dev/test_ownership_manifest.py \
	tools/dev/check_changed_non_test_types.py \
	tools/dev/sortdemo_decompiler_status.py \
	inertia/cli/accepted_payload_integrity.py \
	inertia/cli/angr_codegen_tags.py \
	inertia/semantics/callsite_register_instruction_facts.py \
	inertia/lowering/consumed_call_push_evidence.py \
	inertia/lowering/frame_instruction_evidence.py \
	inertia/lowering/frame_register_carriers.py \
	inertia/lowering/structured_tags.py \
	inertia/frontend/x86_16/verification_80386.py \
	inertia/lowering/stack_prototype_layout.py \
	inertia/frontend/x86_16/msvc_x87_interrupts.py \
	inertia/ir/logical_memory_scalar_projection.py \
	inertia/lowering/direct_global_register_updates.py \
	inertia/lowering/direct_global_register_update_contracts.py \
	inertia/lowering/direct_stack_segmented_projection.py \
	inertia/lowering/logical_word_memory_copy_materialization.py \
	inertia/lowering/stack_frame_projection.py \
	inertia/lowering/stack_word_recomposition.py \
	inertia/frontend/x86_16/frontend_indirect_jump_targets.py \
	inertia/lowering/balanced_memory_stack_restore.py \
	inertia/lowering/caller_observed_byte_return_types.py \
	inertia/lowering/control_stack_escape.py \
	inertia/lowering/direction_flag_state.py \
	inertia/lowering/interprocedural_storage_return_type_collection.py \
	inertia/lowering/interprocedural_storage_return_type_collection_contracts.py \
	inertia/lowering/packed_flags_state.py \
	inertia/lowering/packed_flags_liveness.py \
	inertia/lowering/packed_flags_calls.py \
	inertia/lowering/far_return_boundary_carriers.py \
	inertia/lowering/segment_stack_restore_carriers.py \
	inertia/validation/validation_condition_closure_delta.py \
	inertia/validation/validation_observable_compaction.py \
	inertia/validation/validation_pointer_parameter_output_contracts.py \
	inertia/validation/validation_pointer_parameter_outputs.py \
	inertia/lowering/gp_stack_restore.py \
	inertia/lowering/gp_stack_restore_identity.py \
	inertia/lowering/stack_value_projection.py \
	inertia/validation/entry_stack_ranges.py \
	inertia/cli/cache_file_digest.py \
	inertia/cli/direct_indexed_alias_local_cache.py \
	inertia/cli/function_ir_ssa_cache.py \
	inertia/cli/function_ir_ssa_cache_codec.py \
	inertia/cli/function_ir_ssa_cache_identity.py \
	decompile.py

QA_RUFF_TARGETS := \
	inertia/lowering/segmented_load_origins.py \
	tests/widening/test_x86_16_segmented_load_origins.py \
	tests/cli/test_x86_16_envsize_behavior.py \
	inertia/ir/instruction_origin.py \
	tests/ir/test_x86_16_ir_instruction_origin.py \
	inertia/ir/constant_flow.py \
	inertia/ir/scalar_value_projection.py \
	inertia/lowering/callsite_inventory.py \
	inertia/lowering/codegen_return_origin.py \
	inertia/lowering/gp_stack_local_return.py \
	inertia/lowering/gp_stack_local_reload.py \
	inertia/lowering/call_argument_call_preservation.py \
	inertia/ir/register_live_in.py \
	inertia/lowering/call_output_object_projection.py \
	inertia/lowering/runtime_call_results.py \
	inertia/lowering/call_argument_semantic_gap.py \
	tools/dev/makefile_inventory.py \
	inertia/ir/function_ir_registry.py \
	inertia/lowering/far_pointer_constant_flow.py \
	inertia/lowering/gp_register_state.py \
	inertia/lowering/call_argument_carrier_liveness.py \
	inertia/lowering/call_return_frame.py \
	inertia/lowering/call_return_frame_arguments.py \
	inertia/semantics/callsite_setup_evidence.py \
	inertia/lowering/consumed_stack_address_setup.py \
	inertia/frontend/x86_16/synthetic_call_stub_evidence.py \
	monkeytype_config.py \
	inertia/frontend/x86_16/public_api.py \
	inertia/ir/vex_operation_membership.py \
	tests/fixtures/entry_stack_byte_test_support.py \
	inertia/ir/analysis/alias.py \
	inertia/ir/analysis/stack_frame_ir.py \
	inertia/ir/frame_memory_accesses.py \
	inertia/lowering/analysis_helpers.py \
	inertia/frontend/x86_16/access.py \
	inertia/frontend/x86_16/addressing_helpers.py \
	inertia/frontend/x86_16/capstone_memory_segment.py \
	inertia/frontend/x86_16/decoded_memory_width.py \
	inertia/ir/address_ir_8616.py \
	inertia/lowering/annotations.py \
	inertia/frontend/x86_16/borrow_verification.py \
	inertia/ir/condition_ir.py \
	inertia/structuring/condition_trace.py \
	inertia/structuring/condition_call_effects.py \
	inertia/semantics/function_evidence_inventory.py \
	inertia/semantics/helper_abi.py \
	inertia/frontend/x86_16/regs.py \
	inertia/ir/__init__.py \
	inertia/ir/address_ir.py \
	inertia/ir/condition_register_bindings.py \
	inertia/ir/condition_value_extensions.py \
	inertia/ir/condition_fingerprint_masks.py \
	inertia/ir/condition_fingerprint_syntax.py \
	inertia/ir/core.py \
	inertia/ir/block_ownership.py \
	inertia/ir/block_successor_chain.py \
	inertia/ir/effects.py \
	inertia/ir/function_artifact.py \
	inertia/ir/function_condition_artifact.py \
	inertia/ir/condition_lift_capture.py \
	inertia/ir/indexed_address_access_normalization.py \
	inertia/ir/indexed_address_contracts.py \
	inertia/ir/indexed_address_copy_contracts.py \
	inertia/ir/indexed_address_copy_evidence.py \
	inertia/ir/indexed_address_copy_trace.py \
	inertia/ir/indexed_address_evidence.py \
	inertia/ir/indexed_address_pipeline.py \
	inertia/ir/indexed_address_range_candidate_helpers.py \
	inertia/ir/indexed_induction_write_census.py \
	inertia/ir/indexed_address_range_candidates.py \
	inertia/ir/indexed_address_range_contracts.py \
	inertia/ir/indexed_address_range_evidence.py \
	inertia/ir/indexed_address_range_witnesses.py \
	inertia/ir/ir_canonicalize_8616.py \
	inertia/ir/logical_memory_capture.py \
	inertia/ir/logical_memory_contracts.py \
	inertia/ir/logical_memory_matching.py \
	inertia/ir/logical_memory_rebase.py \
	inertia/ir/logical_memory_resolution.py \
	inertia/ir/logical_memory_register_transfer.py \
	inertia/ir/logical_memory_register_transfer_contracts.py \
	inertia/ir/logical_memory_value_trace.py \
	inertia/ir/logical_memory_write_value.py \
	inertia/ir/logical_constant_word_receipt.py \
	inertia/ir/regs.py \
	inertia/ir/scalar_definitions.py \
	inertia/ir/scalar_affine_contracts.py \
	inertia/ir/scalar_affine_sources.py \
	inertia/ir/scalar_affine_trace.py \
	inertia/ir/affine_indexed_address.py \
	inertia/ir/affine_induction_role.py \
	inertia/ir/frame_register_reaching_definition.py \
	inertia/ir/status_flag_binary_cfg.py \
	inertia/ir/status_flag_cfg_projection.py \
	inertia/ir/status_flag_lift_context.py \
	inertia/ir/status_flag_lift_codec.py \
	inertia/ir/segment_contract.py \
	inertia/semantics/segment_function_summary.py \
	inertia/frontend/x86_16/segment_offset_execution.py \
	inertia/semantics/segment_program_layout.py \
	inertia/semantics/segment_program_layout_codec.py \
	inertia/semantics/segment_program_layout_contract.py \
	inertia/ir/segment_state.py \
	inertia/ir/segment_state_solver.py \
	inertia/ir/segment_state_transfer.py \
	inertia/ir/ssa.py \
	inertia/ir/ssa_function.py \
	inertia/ir/ssa_cfg.py \
	inertia/ir/ssa_cfg_contracts.py \
	inertia/ir/ssa_memory.py \
	inertia/ir/ssa_memory_call_liveness.py \
	inertia/ir/ssa_memory_contracts.py \
	inertia/ir/ssa_memory_ranges.py \
	inertia/ir/stack_range_overlap.py \
	inertia/lowering/native_integer_constants.py \
	inertia/lowering/native_integer_operations.py \
	inertia/lowering/native_terminal_return_values.py \
	inertia/ir/string_effects.py \
	inertia/ir/value_ir.py \
	inertia/ir/vex_addressing.py \
	inertia/ir/vex_condition_demand.py \
	inertia/ir/vex_condition_lifting.py \
	inertia/ir/vex_condition_transport.py \
	inertia/ir/vex_control_flow.py \
	inertia/ir/vex_terminal_jump.py \
	inertia/ir/entry_jump_domain.py \
	inertia/ir/real16_invocation_domain.py \
	inertia/ir/real16_edge_feasibility8616.py \
	inertia/ir/vex_import.py \
	inertia/ir/vex_integer_displacement.py \
	inertia/ir/vex_types.py \
	inertia/semantics/function_effect_summary.py \
	inertia/semantics/helper_effect_summary.py \
	inertia/semantics/helper_family_routing.py \
	inertia/semantics/function_interface_surface.py \
	inertia/semantics/function_summary.py \
	inertia/semantics/function_state_summary.py \
	inertia/semantics/callsite_target_inventory.py \
	inertia/semantics/caller_return_use_contracts.py \
	inertia/semantics/callsite_summary.py \
	inertia/semantics/callsite_register_provenance.py \
	inertia/semantics/register_source_block_inventory.py \
	inertia/semantics/call_target_identity.py \
	inertia/postprocess/callsite_stack_metadata.py \
	inertia/semantics/stack_probe_fact_trace.py \
	inertia/validation/tail_validation_condition_context.py \
	inertia/validation/tail_validation_frame_spills.py \
	inertia/validation/tail_validation_fingerprint.py \
	inertia/validation/validation_goto_target_identity.py \
	inertia/validation/tail_validation_generation.py \
	inertia/validation/tail_validation_generation_atoms.py \
	inertia/pipeline/structured_ast_generation.py \
	inertia/pipeline/result_contracts.py \
	inertia/pipeline/structured_assignment_index.py \
	inertia/pipeline/structured_ast_query_index.py \
	inertia/validation/control_flow_ast_index.py \
	inertia/validation/tail_validation_routing.py \
	inertia/validation/tail_validation_selector_returns.py \
	inertia/validation/tail_validation_stack_policy.py \
	inertia/cli/targeted_recovery_artifact.py \
	inertia/cli/layer_module_status.py \
	inertia/frontend/x86_16/coverage_manifest.py \
	inertia/cli/corpus_scan.py \
	inertia/cli/milestone_report.py \
	inertia/cli/exact_region_diagnostics.py \
	inertia/frontend/x86_16/frontend_cfg_direct_jump.py \
	inertia/frontend/x86_16/frontend_cfg_direct_call.py \
	inertia/frontend/x86_16/frontend_cfg_direct_jobs.py \
	inertia/frontend/x86_16/frontend_function_boundary.py \
	inertia/frontend/x86_16/frontend_function_boundary_index.py \
	inertia/frontend/x86_16/frontend_function_block_decode.py \
	inertia/frontend/x86_16/frontend_capstone_block.py \
	inertia/frontend/x86_16/frontend_block_inventory.py \
	inertia/frontend/x86_16/frontend_capstone_decode.py \
	inertia/frontend/x86_16/frontend_function_instructions.py \
	inertia/frontend/x86_16/frontend_caller_return_use_program.py \
	inertia/frontend/x86_16/frontend_direct_callsite_index.py \
	inertia/frontend/x86_16/frontend_instruction_kinds.py \
	inertia/frontend/x86_16/frontend_instruction_reachability.py \
	inertia/cli/recovery_instruction_coverage.py \
	inertia/cli/flair_extract.py \
	inertia/cli/fast_tracer.py \
	inertia/frontend/x86_16/jcc_condition.py \
	inertia/frontend/x86_16/jcc_result_condition.py \
	inertia/frontend/x86_16/lift_86_16.py \
	inertia/frontend/x86_16/lifter_backend_selection.py \
	inertia/cli/lst_extract.py \
	inertia/frontend/x86_16/ne_exe_parse.py \
	inertia/cli/recovery_manifest.py \
	inertia/cli/recovery_artifacts.py \
	inertia/validation/recovery_confidence.py \
	inertia/cli/recovery_artifact_cache.py \
	inertia/cli/recovery_artifact_manifest.py \
	inertia/cli/recovery_artifact_writer.py \
	inertia/cli/corpus_recovery_artifact.py \
	inertia/structuring/confidence_and_assumptions.py \
	inertia/structuring/confidence_evidence.py \
	inertia/structuring/ir_recovery_summary.py \
	inertia/structuring/ir_readiness.py \
	inertia/structuring/ir_confidence_markers.py \
	inertia/cli/runtime_trace_refinement.py \
	inertia/structuring/structuring_ir_hints.py \
	inertia/structuring/structuring_abnormal_loops.py \
	inertia/structuring/structuring_analysis.py \
	inertia/structuring/structuring_cfg_ownership.py \
	inertia/structuring/structuring_cfg_indirect.py \
	inertia/structuring/structuring_cfg_grouping.py \
	inertia/structuring/structuring_loops.py \
	inertia/structuring/structuring_cfg_snapshot.py \
	inertia/structuring/structuring_graph_builder.py \
	inertia/structuring/structuring_grouped_graph_builder.py \
	inertia/structuring/structuring_region.py \
	inertia/structuring/structuring_codegen.py \
	inertia/structuring/decompiler_structuring_stage.py \
	inertia/structuring/structuring_grouped_pass.py \
	inertia/structuring/structuring_grouped_units.py \
	inertia/cli/structured_function_helpers.py \
	inertia/frontend/x86_16/string_helpers.py \
	inertia/semantics/string_instruction_artifact.py \
	inertia/lowering/string_instruction_lowering.py \
	inertia/structuring/string_codegen_override.py \
	inertia/lowering/type_array_matching.py \
	inertia/lowering/type_equivalence_classes.py \
	inertia/lowering/type_structure_merging.py \
	inertia/lowering/type_storage_object_bridge.py \
	inertia/frontend/x86_16/bootstrap.py \
	inertia/cli/cod_comment_emitter.py \
	inertia/frontend/x86_16/cod_analysis_image.py \
	inertia/frontend/x86_16/cod_extract.py \
	inertia/frontend/x86_16/cod_known_objects.py \
	inertia/cli/cod_source_rewrites.py \
	inertia/cli/codeview_nb00.py \
	inertia/cli/codeview_nb02_nb04.py \
	inertia/lowering/codegen_metadata.py \
	inertia/semantics/compiler_helpers.py \
	inertia/frontend/x86_16/cr.py \
	inertia/postprocess/decompiler_postprocess_inventory.py \
	inertia/postprocess/decompiler_postprocess_globals.py \
	inertia/postprocess/decompiler_postprocess_utils.py \
	inertia/frontend/x86_16/compat.py \
	inertia/frontend/x86_16/call_frame_compat.py \
	inertia/frontend/x86_16/call_cleanup_compat.py \
	inertia/ir/stack_pointer_provenance.py \
	inertia/ir/stack_extent_evidence.py \
	inertia/ir/ail_register_displacement.py \
	inertia/frontend/x86_16/ail_displacement_compat.py \
	inertia/frontend/x86_16/ail_remainder_compat.py \
	inertia/frontend/x86_16/variable_recovery_compat.py \
	inertia/ir/ail_remainder.py \
	inertia/postprocess/codegen_parentheses.py \
	inertia/frontend/x86_16/stack_anchor_compat.py \
	inertia/ir/native_stack_anchor.py \
	inertia/ir/native_segment_live_out.py \
	inertia/lowering/store_projection_width.py \
	inertia/lowering/runtime_push_carrier.py \
	inertia/frontend/x86_16/calling_convention_compat.py \
	inertia/lowering/calling_convention_seed_cache.py \
	inertia/frontend/x86_16/render_compat.py \
	inertia/frontend/x86_16/patch_dirty.py \
	inertia/lowering/c_ast_utils.py \
	inertia/semantics/callee_name_normalization.py \
	inertia/frontend/x86_16/low_memory_regions.py \
	inertia/frontend/x86_16/exception.py \
	inertia/frontend/x86_16/hardware.py \
	inertia/frontend/x86_16/simprocs_io.py \
	inertia/frontend/x86_16/debug.py \
	inertia/frontend/x86_16/exepack.py \
	inertia/frontend/x86_16/mz_image.py \
	inertia/frontend/x86_16/mz_load_source.py \
	inertia/frontend/x86_16/mz_invocation_source.py \
	inertia/frontend/x86_16/packed_mz.py \
	inertia/frontend/x86_16/dev_io.py \
	inertia/frontend/x86_16/io.py \
	inertia/frontend/x86_16/instruction.py \
	inertia/frontend/x86_16/instr_base.py \
	inertia/frontend/x86_16/instr16.py \
	inertia/frontend/x86_16/instr32.py \
	inertia/frontend/x86_16/parse.py \
	inertia/frontend/x86_16/exec.py \
	inertia/frontend/x86_16/emu.py \
	inertia/frontend/x86_16/emulator.py \
	inertia/frontend/x86_16/eflags.py \
	inertia/frontend/x86_16/memory.py \
	inertia/frontend/x86_16/processor.py \
	inertia/frontend/x86_16/interrupt.py \
	inertia/frontend/x86_16/stack_compat.py \
	inertia/frontend/x86_16/load_propagation.py \
	inertia/frontend/x86_16/stack_tracker_allocation.py \
	inertia/frontend/x86_16/stack_tracker_return_segment.py \
	inertia/frontend/x86_16/stack_value_use.py \
	inertia/frontend/x86_16/typehoon_compat.py \
	inertia/lowering/type_clinic_return_compat.py \
	inertia/frontend/x86_16/stack_helpers.py \
	inertia/frontend/x86_16/relative_control_edge.py \
	inertia/ir/condition_relative_edge.py \
	inertia/cli/correctness_goals.py \
	inertia/cli/readability_set.py \
	inertia/cli/readability_goals.py \
	inertia/cli/acceptance_scorecard.py \
	inertia/postprocess/decompiler_postprocess.py \
	inertia/postprocess/decompiler_postprocess_calls.py \
	inertia/postprocess/decompiler_postprocess_jcc.py \
	inertia/postprocess/decompiler_postprocess_loads.py \
	inertia/postprocess/decompiler_postprocess_simplify.py \
	inertia/postprocess/decompiler_postprocess_stage.py \
	inertia/postprocess/decompiler_postprocess_typed_conditions.py \
	inertia/frontend/x86_16/decompiler_return_compat.py \
	inertia/frontend/x86_16/ailment_variant_access.py \
	inertia/validation/tail_validation.py \
	inertia/validation/validation_manifest.py \
	inertia/validation/validation_helper_report.py \
	inertia/validation/validation_summary.py \
	inertia/validation/validation_calls.py \
	inertia/validation/validation_call_multiplicity.py \
	inertia/validation/validation_call_argument_sources.py \
	inertia/validation/validation_call_return_storage.py \
	inertia/validation/validation_stack_projection.py \
	inertia/validation/validation_branch_conditions.py \
	inertia/validation/validation_materialized_condition_storage.py \
	inertia/validation/validation_condition_identity.py \
	inertia/validation/validation_condition_coverage.py \
	inertia/validation/validation_condition_storage_views.py \
	inertia/validation/validation_control_flow.py \
	inertia/validation/validation_condition_precision.py \
	inertia/validation/validation_control_condition_delta.py \
	inertia/validation/validation_terminal_returns.py \
	inertia/validation/validation_switch_loop_tail_breaks.py \
	inertia/validation/validation_control_flow_obligations.py \
	inertia/validation/validation_dataflow.py \
	inertia/validation/validation_identical_return_guards.py \
	inertia/validation/validation_semantic_failures.py \
	inertia/validation/validation_predicates.py \
	inertia/validation/validation_storage.py \
	inertia/validation/validation_aggregate_storage.py \
	inertia/validation/validation_additive_terms.py \
	inertia/validation/validation_required_memory_effects.py \
	inertia/validation/validation_semantics.py \
	inertia/frontend/x86_16/verification_80286.py \
	inertia/cli/turbo_debug_tdinfo.py \
	inertia/cli/recompilable_cases.py \
	inertia/cli/recompilable_checks.py \
	inertia/cli/recompilable_cli_bridge.py \
	inertia/cli/recompilable_source_evidence.py \
	inertia/cli/recompilable_subset.py \
	inertia/cli/recompilable_storage_alias.py \
	inertia/cli/recompilable_storage_fallback.py \
	inertia/cli/recompilable_storage_map.py \
	inertia/cli/recompilable_storage_map_producer.py \
	inertia/cli/recompilable_storage_objects.py \
	inertia/structuring/structuring_diagnostics.py \
	inertia/structuring/structuring_grouping_report.py \
	inertia/structuring/structuring_grouped_refusal_report.py \
	inertia/structuring/structuring_cross_entry.py \
	inertia/structuring/structuring_sequences.py \
	inertia/lowering/__init__.py \
	inertia/lowering/annotated_global_refs.py \
	inertia/lowering/call_argument_shape.py \
	inertia/lowering/call_argument_shape_publication.py \
	inertia/lowering/call_argument_arity_ownership.py \
	inertia/lowering/call_argument_expression.py \
	inertia/lowering/call_argument_semantic_token.py \
	inertia/lowering/call_argument_state.py \
	inertia/semantics/callsite_argument_value_sources.py \
	inertia/lowering/call_execution_frame_carriers.py \
	inertia/lowering/call_execution_frame_replay.py \
	inertia/lowering/call_execution_frame_runtime.py \
	inertia/lowering/call_output_stack_object_replay.py \
	inertia/lowering/call_output_stack_objects.py \
	inertia/lowering/authoritative_function_prototypes.py \
	inertia/lowering/near_return_address_arguments.py \
	inertia/lowering/direct_stack_replay.py \
	inertia/lowering/direct_stack_consumer_generation.py \
	inertia/lowering/direct_stack_replay_contracts.py \
	inertia/lowering/register_local_declarations.py \
	inertia/lowering/register_variable_identity.py \
	inertia/lowering/stack_address_coordinates.py \
	inertia/lowering/register_reload_consumers.py \
	inertia/lowering/stack_storage_evidence.py \
	inertia/lowering/call_return_selectors.py \
	inertia/lowering/call_return_stack_bindings.py \
	inertia/lowering/call_return_stack_stores.py \
	inertia/lowering/call_cleanup_carriers.py \
	inertia/lowering/runtime_segment_access.py \
	inertia/lowering/runtime_memory_helpers.py \
	inertia/lowering/callsite_prototype_declarations.py \
	inertia/lowering/dos_interrupt_abi.py \
	inertia/lowering/dos_interrupt_aggregate_evidence.py \
	inertia/lowering/dos_interrupt_aggregate_globals.py \
	inertia/lowering/dos_interrupt_aggregate_projection.py \
	inertia/lowering/named_type_definitions.py \
	inertia/lowering/callsite_prototype_seeding.py \
	inertia/lowering/callsite_pointer_tables.py \
	inertia/lowering/signed_global_declarations.py \
	inertia/lowering/project_global_signedness.py \
	inertia/lowering/callee_callsite_census.py \
	inertia/lowering/callee_argument_count_evidence.py \
	inertia/lowering/callee_argument_width_evidence.py \
	inertia/ir/function_ssa_registry.py \
	inertia/lowering/interprocedural_memory_output_object_contracts.py \
	inertia/lowering/interprocedural_memory_output_objects.py \
	inertia/lowering/interprocedural_memory_output_validation.py \
	inertia/lowering/interprocedural_storage_collection_contracts.py \
	inertia/lowering/interprocedural_storage_contracts.py \
	inertia/lowering/interprocedural_storage_function_solver.py \
	inertia/lowering/interprocedural_storage_live_out.py \
	inertia/lowering/interprocedural_storage_live_out_contracts.py \
	inertia/lowering/interprocedural_storage_live_out_flow.py \
	inertia/lowering/interprocedural_storage_live_out_paths.py \
	inertia/lowering/interprocedural_storage_slot_join.py \
	inertia/lowering/interprocedural_storage_pipeline.py \
	inertia/lowering/pointer_parameter_output_contracts.py \
	inertia/lowering/pointer_parameter_outputs.py \
	inertia/lowering/interprocedural_storage_prototype_application.py \
	inertia/lowering/interprocedural_storage_prototype_types.py \
	inertia/lowering/interprocedural_storage_reaching_contracts.py \
	inertia/lowering/interprocedural_storage_source_defs.py \
	inertia/lowering/interprocedural_storage_return_defs.py \
	inertia/lowering/interprocedural_storage_return_passthrough_contracts.py \
	inertia/lowering/interprocedural_storage_return_passthrough.py \
	inertia/lowering/interprocedural_storage_return_type_contracts.py \
	inertia/lowering/interprocedural_storage_return_split_condition_graph.py \
	inertia/lowering/interprocedural_storage_return_split_conditions.py \
	inertia/lowering/interprocedural_storage_return_split.py \
	inertia/lowering/interprocedural_storage_return_collection_contracts.py \
	inertia/lowering/interprocedural_storage_return_trial_materialization.py \
	inertia/lowering/interprocedural_storage_caller_context.py \
	inertia/lowering/interprocedural_storage_return_trial_collection.py \
	inertia/lowering/interprocedural_storage_return_pointer.py \
	inertia/lowering/interprocedural_storage_return_pointer_block.py \
	inertia/lowering/interprocedural_storage_return_pointer_flow.py \
	inertia/lowering/interprocedural_storage_return_pointer_stack.py \
	inertia/lowering/interprocedural_storage_return_pointer_witness.py \
	inertia/lowering/interprocedural_storage_return_types.py \
	inertia/lowering/interprocedural_storage_reaching_defs.py \
	inertia/lowering/interprocedural_storage_expression_defs.py \
	inertia/lowering/pointer_parameter_caller_target_contracts.py \
	inertia/lowering/pointer_parameter_caller_targets.py \
	inertia/lowering/pointer_parameter_memory_output_contracts.py \
	inertia/lowering/pointer_parameter_memory_outputs.py \
	inertia/lowering/pointer_parameter_object_type_contracts.py \
	inertia/lowering/pointer_parameter_object_types.py \
	inertia/lowering/interprocedural_storage_physical_defs.py \
	inertia/lowering/interprocedural_storage_trial_types.py \
	inertia/lowering/interprocedural_storage_input_preflight.py \
	inertia/lowering/interprocedural_storage_trial_collection.py \
	inertia/lowering/interprocedural_storage_solver.py \
	inertia/lowering/interprocedural_storage_simtypes.py \
	inertia/lowering/interprocedural_storage_transaction.py \
	inertia/lowering/callee_argument_interface.py \
	inertia/lowering/callee_global_object_collection.py \
	inertia/lowering/callee_global_object_evidence.py \
	inertia/lowering/global_object_program_requirement.py \
	inertia/lowering/callee_global_object_interface.py \
	inertia/lowering/callee_global_object_sources.py \
	inertia/lowering/global_object_source_codec.py \
	inertia/lowering/callee_global_object_type_surface.py \
	inertia/lowering/callee_pointer_evidence.py \
	inertia/lowering/callee_pointer_contracts.py \
	inertia/lowering/callee_pointer_codec.py \
	inertia/semantics/callsite_summary_codec.py \
	inertia/semantics/callsite_summary_program.py \
	inertia/semantics/callsite_summary_program_codec.py \
	inertia/lowering/callee_callsite_contracts.py \
	inertia/lowering/callee_callsite_codec.py \
	inertia/lowering/callee_range_callsite_facts.py \
	inertia/lowering/project_callee_callsite_collection.py \
	inertia/lowering/project_global_object_source_collection.py \
	inertia/lowering/indexed_global_evidence.py \
	inertia/lowering/indexed_address_collector_parity.py \
	inertia/lowering/indexed_address_parity_inventory.py \
	inertia/lowering/indexed_address_parity_inventory_contracts.py \
	inertia/lowering/helper_call_interfaces.py \
	inertia/lowering/far_pointer_segmented_load_evidence.py \
	inertia/lowering/far_pointer_segmented_load_materialization.py \
	inertia/lowering/register_constant_segmented_store.py \
	inertia/lowering/near_pointer_argument.py \
	inertia/lowering/near_pointer_index_binding.py \
	inertia/lowering/near_pointer_type.py \
	inertia/ir/condition_cache_relift.py \
	inertia/ir/condition_cache_relift_cache.py \
	inertia/ir/condition_cache_relift_contracts.py \
	inertia/lowering/condition_transfer.py \
	inertia/lowering/condition_fact_arbitration.py \
	inertia/lowering/condition_argument_type_facts.py \
	inertia/lowering/condition_argument_types.py \
	inertia/lowering/condition_scalar_types.py \
	inertia/lowering/condition_stack_operands.py \
	inertia/lowering/condition_stack_value.py \
	inertia/lowering/condition_stack_projection_contracts.py \
	inertia/lowering/assignment_lvalue_casts.py \
	inertia/lowering/c_runtime_header.py \
	inertia/lowering/callee_saved_frame.py \
	inertia/lowering/dead_register_carriers.py \
	inertia/lowering/explicit_char_types.py \
	inertia/lowering/fixed_stack_probe_frames.py \
	inertia/lowering/stack_probe_callsite_lowering.py \
	inertia/lowering/frame_prologue_carriers.py \
	inertia/lowering/frame_carrier_liveness.py \
	inertia/lowering/register_overwrite_evidence.py \
	inertia/lowering/fact_transfer.py \
	inertia/lowering/function_pointer_parameter_evidence.py \
	inertia/lowering/function_pointer_parameters.py \
	inertia/lowering/cod_global_identity.py \
	inertia/lowering/bounded_global_array_declarations.py \
	inertia/lowering/global_declaration_extents.py \
	inertia/lowering/global_declarations.py \
	inertia/lowering/global_symbol_names.py \
	inertia/lowering/object_lowering.py \
	inertia/lowering/pointer_memory_idioms.py \
	inertia/lowering/physical_registers.py \
	inertia/lowering/positive_bp_argument_plan.py \
	inertia/lowering/positive_bp_arguments.py \
	inertia/lowering/live_stack_word_inputs.py \
	inertia/lowering/project_global_object_layout.py \
	inertia/lowering/real_mode_linear.py \
	inertia/lowering/linear_global_decomposition_cache.py \
	inertia/lowering/instruction_bp_stack_access.py \
	inertia/lowering/stack_coordinate_rebinding.py \
	inertia/lowering/stack_variable_coordinates.py \
	inertia/lowering/machine_stack_names.py \
	inertia/lowering/stack_function_coordinates.py \
	inertia/lowering/stack_variable_display_names.py \
	inertia/lowering/stack_word_load_candidate.py \
	inertia/lowering/stack_word_load_materialization.py \
	inertia/lowering/stack_word_load_projection.py \
	inertia/lowering/stack_word_projection.py \
	inertia/lowering/callsite_inventory_presence.py \
	inertia/lowering/callsite_segment_provenance.py \
	inertia/lowering/segment_access_coverage.py \
	inertia/lowering/segment_codegen_access_provenance.py \
	inertia/lowering/segment_access_policy.py \
	inertia/lowering/segment_global_materialization.py \
	inertia/lowering/semantic_cast.py \
	inertia/lowering/condition_operand_views.py \
	inertia/lowering/return_type_evidence.py \
	inertia/lowering/return_liveness_replay.py \
	inertia/lowering/unobserved_call_results.py \
	inertia/lowering/unobserved_returns.py \
	inertia/lowering/unused_void_return_types.py \
	inertia/lowering/scalar_return_types.py \
	inertia/lowering/segment_register_state.py \
	inertia/lowering/indexed_load_subviews.py \
	inertia/lowering/segmented_global_loads.py \
	inertia/lowering/aggregate_byte_projection.py \
	inertia/lowering/condition_value_casts.py \
	inertia/lowering/segmented_lowering.py \
	inertia/lowering/segmented_memory_lowering.py \
	inertia/lowering/pointer_store_consumption.py \
	inertia/lowering/ir_segmented_load_carriers.py \
	inertia/lowering/register_indirect_call_targets.py \
	inertia/lowering/stack_pointer_snapshot.py \
	inertia/lowering/stack_argument_identity.py \
	inertia/lowering/stack_declaration_identity.py \
	inertia/lowering/call_argument_stack_sources.py \
	inertia/lowering/call_return_stack_conditions.py \
	inertia/lowering/structured_intrinsics.py \
	inertia/lowering/terminal_call_return_types.py \
	inertia/lowering/terminal_register_return_values.py \
	inertia/lowering/terminal_register_return_types.py \
	inertia/lowering/terminal_return_expressions.py \
	inertia/lowering/terminal_return_render_projection.py \
	inertia/lowering/software_interrupt_calls.py \
	inertia/lowering/software_interrupt_status_outputs.py \
	inertia/lowering/segmented_memory_reasoning.py \
	inertia/lowering/stack_aggregate_objects.py \
	inertia/lowering/stack_aggregate_projection.py \
	inertia/lowering/stack_c_ast_matching.py \
	inertia/lowering/stack_lowering.py \
	inertia/lowering/stack_lowering_from_facts.py \
	inertia/lowering/carry_borrow_bit_ast.py \
	inertia/lowering/carry_borrow_bit_contracts.py \
	inertia/lowering/carry_borrow_bit_placement.py \
	inertia/lowering/carry_borrow_bit_predicate.py \
	inertia/lowering/carry_borrow_bit_scope.py \
	inertia/lowering/carry_borrow_bit_values.py \
	inertia/lowering/carry_borrow_stack_storage.py \
	inertia/lowering/wide_call_output_assignment_ast.py \
	inertia/lowering/wide_call_output_assignment_carriers.py \
	inertia/lowering/wide_call_output_assignment_contracts.py \
	inertia/lowering/wide_call_output_assignment_evidence.py \
	inertia/lowering/wide_call_output_assignment_placement.py \
	inertia/lowering/wide_call_output_assignment_replay.py \
	inertia/lowering/wide_call_output_assignments.py \
	inertia/lowering/wide_call_return_recombine.py \
	inertia/lowering/straight_line_placement.py \
	inertia/lowering/stack_memory_ssa.py \
	inertia/lowering/stack_memory_ssa_contracts.py \
	inertia/lowering/stack_projection_retirement.py \
	inertia/lowering/stack_lowering_impl.py \
	inertia/lowering/stack_prototype_materialization.py \
	inertia/lowering/wide_stack_argument_views.py \
	inertia/lowering/stack_probe_return_facts.py \
	inertia/lowering/storage_identity_facts.py \
	inertia/lowering/ss_bp_substitution.py \
	inertia/lowering/stack_lowering_result.py \
	inertia/lowering/stack_variable_binding.py \
	inertia/lowering/wide_stack_pair_evidence.py \
	inertia/lowering/stack_update_scope_guard.py \
	inertia/lowering/wide_call_condition_binding.py \
	inertia/validation/validation_terminal_wide_conditions.py \
	inertia/ir/condition_zero_input.py \
	inertia/lowering/wide_call_condition_source.py \
	inertia/lowering/wide_call_condition_capture.py \
	inertia/validation/__init__.py \
	inertia/validation/canonicalize.py \
	inertia/validation/callsite_completeness.py \
	inertia/validation/status_flag_preservation.py \
	inertia/validation/validation_interrupt_calls.py \
	inertia/widening/widening_model.py \
	inertia/pipeline/architecture_guard.py \
	inertia/pipeline/contracts.py \
	inertia/pipeline/errors.py \
	inertia/pipeline/invariants.py \
	inertia/pipeline/linear_guard.py \
	inertia/pipeline/recovery_coverage_guard.py \
	inertia/pipeline/render_authority.py \
	inertia/cli/__init__.py \
	inertia/cli/analysis_timeout.py \
	inertia/cli/architecture_import_attestation.py \
	inertia/cli/architecture_runtime_guard.py \
	inertia/cli/project_evidence_transport.py \
	inertia/cli/indexed_global_object_cache.py \
	inertia/cli/direct_global_object_cache.py \
	inertia/cli/direct_global_object_context.py \
	inertia/cli/serial_clean_worker_evidence.py \
	inertia/cli/cod_module_caller_evidence.py \
	inertia/cli/c_text_cleanup.py \
	inertia/cli/cache.py \
	inertia/cli/cache_io.py \
	inertia/cli/cache_lock.py \
	inertia/cli/cache_runtime_contract.py \
	inertia/cli/cache_source_manifest.py \
	inertia/cli/function_ir_ssa_source_scope.py \
	inertia/cli/program_callsite_cache.py \
	inertia/cli/direct_request_cache.py \
	inertia/cli/direct_request_fast_path.py \
	inertia/cli/direct_request_identity.py \
	inertia/cli/cli.py \
	inertia/cli/cli_core.py \
	inertia/cli/indexed_alias_program_context.py \
	inertia/cli/indexed_alias_program_publication.py \
	inertia/cli/indexed_alias_program_recovery.py \
	inertia/cli/indexed_alias_program_parallel.py \
	inertia/cli/project_argument_evidence_ranges.py \
	inertia/cli/serial_clean_worker_cli.py \
	inertia/cli/serial_worker_cache.py \
	inertia/cli/discovery_cache_contract.py \
	inertia/cli/segment_program_layout_reporting.py \
	inertia/cli/generated_c_artifacts.py \
	inertia/cli/cli_batch_c_output.py \
	inertia/cli/generated_external_function_contracts.py \
	inertia/cli/generated_c_function_extraction.py \
	inertia/cli/generated_translation_unit_assembly.py \
	inertia/cli/cli_decompilation.py \
	inertia/cli/cli_c_ast_rewrites.py \
	inertia/cli/cli_c_text_postprocess.py \
	inertia/cli/cli_fallback_decompilation.py \
	inertia/cli/cli_function_discovery.py \
	inertia/cli/function_graph_extent_repair.py \
	inertia/cli/cli_access_profiles.py \
	inertia/cli/cli_access_traits.py \
	inertia/cli/cli_access_trait_rewrite.py \
	inertia/cli/cli_access_rewrite_artifact.py \
	inertia/cli/cli_arg_parser.py \
	inertia/cli/cli_cod_global_statements.py \
	inertia/cli/cli_cod_globals.py \
	inertia/cli/cli_dead_local_prune.py \
	inertia/cli/cli_semantic_rollback.py \
	inertia/cli/cli_rollback_snapshot_8616.py \
	inertia/cli/cli_helper_modeling.py \
	inertia/cli/cli_interrupt_modeling.py \
	inertia/cli/cli_linear_aliases.py \
	inertia/cli/cli_induction_rewrite.py \
	inertia/cli/cli_linear_recurrence.py \
	inertia/cli/cli_linear_recurrence_rules.py \
	inertia/cli/cli_linear_recurrence_state.py \
	inertia/cli/cli_mkfp_simplify.py \
	inertia/cli/cli_memory_prune.py \
	inertia/cli/cli_local_prune.py \
	inertia/cli/cli_local_rewrites.py \
	inertia/cli/cli_far_pointer_stack.py \
	inertia/cli/cli_segmented_compare.py \
	inertia/cli/cli_segmented_elision.py \
	inertia/cli/cli_segmented_load_coalesce.py \
	inertia/cli/cli_stack_byte_offsets.py \
	inertia/cli/cli_stack_locals.py \
	inertia/cli/cli_storage_objects.py \
	inertia/cli/cli_string_timeout_fallback.py \
	inertia/cli/cli_timeout.py \
	inertia/cli/cli_output.py \
	inertia/cli/cli_word_global_helpers.py \
	inertia/cli/default_signature_catalog.py \
	inertia/cli/decompile_file_summary.py \
	inertia/cli/decompilation_quality.py \
	inertia/cli/direct_addr_failure_family.py \
	inertia/cli/direct_addr_stage_bundle.py \
	inertia/cli/discovery_evidence_project.py \
	inertia/cli/disassembly_helpers.py \
	inertia/cli/fork_timeout.py \
	inertia/cli/function_cache_context.py \
	inertia/cli/library_function_classifier.py \
	inertia/cli/debug_dos.py \
	inertia/cli/debugger_gdb.py \
	inertia/cli/msc51_local_hash.py \
	inertia/cli/non_optimized_fallback.py \
	inertia/cli/packer_detect.py \
	inertia/cli/project_loading.py \
	inertia/cli/prefork_job_pool.py \
	inertia/cli/rizin_evidence.py \
	inertia/cli/rizin_discovery.py \
	inertia/cli/recompile_check.py \
	inertia/cli/recompile_check_contract.py \
	inertia/cli/cli_terminal_status.py \
	inertia/cli/runtime_support.py \
	inertia/cli/sidecar_cache.py \
	inertia/cli/sidecar_metadata.py \
	inertia/cli/sidecar_policy.py \
	inertia/cli/sidecar_parsers.py \
	inertia/cli/slice_recovery.py \
	inertia/cli/source_sidecar.py \
	inertia/cli/tail_validation.py \
	inertia/cli/telemetry.py \
	inertia/cli/work_items.py \
	inertia/cli/variable_recovery_sub_guard.py \
	inertia/cli/x86_16_exact_slice.py \
	inertia/cli/monkeytype_tools.py \
	tools/dev/collect_monkeytype_pytest.py \
	tools/dev/apply_monkeytype_annotations.py \
	tools/dev/export_monkeytype_stubs.py \
	tools/dev/build_mypyc.py \
	tools/dev/build_cython_vex.py \
	tools/dev/benchmark_cython_vex.py \
	tools/dev/mypyc_build_cache.py \
	tools/dev/agent_context_check.py \
	tools/dev/agent_test_focus.py \
	tools/dev/batch_decompile_procs.py \
	tools/compiler_toolchain/build_debug_info_corpus.py \
	tools/compiler_toolchain/verify_msc_example_runtime_gate.py \
	tools/dev/compare_ghidra_function_coverage.py \
	tools/dev/check_changed_non_test_types.py \
	tools/dev/check_decompiler_architecture.py \
	tools/dev/check_sortd_sidecar_free.py \
	tools/dev/sortd_function_gate.py \
	tools/dev/runmenu_behavior.py \
	tools/dev/indexed_address_parity_inventory.py \
	tools/dev/check_generated_translation_unit.py \
	tools/dev/check_sortd_generated_sort_core.py \
	tools/dev/sortdemo_decompiler_status.py \
	tools/dev/test_pipeline.py \
	tools/dev/cod_stability_sweep.py \
	tools/dev/test_ownership_manifest.py \
	decompile.py \
	tools/dev/tests/test_agent_context_check.py \
	tests/cli/test_cache_lock.py \
	tests/cli/test_function_ir_ssa_source_scope.py \
	tests/cli/test_x86_16_indexed_alias_cache_layers.py \
	tests/cli/test_program_callsite_cache.py \
	tests/lowering/test_x86_16_gp_register_state.py \
	tests/lowering/test_x86_16_gp_pointer_values.py \
	tests/integration/test_x86_16_pointer_fill_behavior.py \
	tests/integration/test_x86_16_pointer_sum_behavior.py \
	tools/dev/tests/test_check_changed_non_test_types.py \
	tests/cli/test_cli_core_clinic_policy.py \
	tools/dev/tests/test_fork_timeout.py \
	tools/dev/tests/test_fork_owner_death.py \
	tests/cli/test_function_cache_context.py \
	tests/cli/test_cli_batch_c_output.py \
	tests/cli/test_x86_16_cli.py \
	tests/frontend/test_x86_16_cr.py \
	tests/frontend/test_x86_16_exception.py \
	tests/frontend/test_x86_16_hardware.py \
	tests/frontend/test_x86_16_simprocs_io.py \
	tests/cli/test_x86_16_debug_info_real_compilers.py \
	tests/frontend/test_x86_16_debug.py \
	tools/compiler_toolchain/tests/test_recompile_check_contract.py \
	tests/frontend/test_x86_16_packed_mz.py \
	tests/cli/test_x86_16_pklite.py \
	tests/cli/test_cli_catalog_budget.py \
	tools/compiler_toolchain/tests/test_missing_dos_toolchain.py \
	tests/frontend/test_x86_16_dev_io.py \
	tests/frontend/test_x86_16_io.py \
	tests/frontend/test_x86_16_emulator.py \
	tests/frontend/test_x86_16_pyvex_compat.py \
	tests/frontend/test_x86_16_memory.py \
	tests/frontend/test_x86_16_interrupt.py \
	tests/lowering/test_x86_16_lowered_register_carriers.py \
		tests/frontend/test_x86_16_stack_compat.py \
		tests/frontend/test_x86_16_load_propagation.py \
		tests/integration/test_x86_16_stack_tracker_allocation.py \
		tests/semantics/test_x86_16_stack_tracker_return_segment.py \
		tests/integration/test_x86_16_stack_address_operand_roles.py \
		tests/frontend/test_x86_16_numeric_sp_call_return.py \
		tests/semantics/test_x86_16_call_frame_compat.py \
		tests/semantics/test_x86_16_callee_cleanup_compat.py \
		tests/ir/test_x86_16_stack_pointer_provenance.py \
		tests/ir/test_x86_16_ail_register_displacement.py \
		tests/postprocess/test_x86_16_codegen_parentheses.py \
		tests/postprocess/test_x86_16_local_declarations.py \
		tests/lowering/test_x86_16_terminal_call_return_types.py \
		tests/integration/test_x86_16_seed_calling_dependencies.py \
		tests/lowering/test_x86_16_stack_value_owner_identity.py \
		tests/structuring/test_x86_16_tagged_terminal_return_values.py \
		tools/compiler_toolchain/tests/test_recompile_check.py \
		tests/integration/test_msc6_runtime_state.py \
		tests/cli/test_x86_16_telemetry_support.py \
		tests/lowering/test_x86_16_switch_segment_diagnostics.py \
		tests/integration/test_x86_16_codegen_metadata.py \
	tests/semantics/test_x86_16_call_return_segment.py \
	tests/frontend/test_x86_16_stack_pointer_width.py \
	tests/frontend/test_x86_16_lifted_integer_constants.py \
	tests/cli/test_x86_16_correctness_goals.py \
	tests/cli/test_x86_16_readability_set.py \
	tests/cli/test_x86_16_readability_goals.py \
	tests/alias/test_x86_16_alias_domains.py \
	tests/alias/test_x86_16_condition_register_carriers.py \
	tests/semantics/test_x86_16_semantics_exports.py \
	tests/alias/test_x86_16_alias_stack_lowering.py \
		tests/alias/test_x86_16_alias_state_transfer.py \
		tests/lowering/test_x86_16_c_runtime_header.py \
		tests/lowering/test_x86_16_object_lowering.py \
		tests/semantics/test_x86_16_semantics_alias_query.py \
		tests/semantics/test_x86_16_semantics_evidence_cache.py \
		tests/semantics/test_x86_16_semantics_expression_analysis.py \
		tests/ir/test_x86_16_vex_logical_memory_accesses.py \
		tests/fixtures/x86_16_logical_memory_fixtures.py \
		tests/ir/test_x86_16_address_ir.py \
	tests/ir/test_x86_16_segment_contract.py \
	tests/lowering/test_x86_16_segment_address_policy.py \
	tests/lowering/test_x86_16_segment_access_coverage.py \
	tests/lowering/test_x86_16_segment_access_policy.py \
	tests/ir/test_x86_16_segment_function_summary.py \
	tests/ir/test_x86_16_segment_program_layout.py \
	tests/ir/test_segment_program_layout_reporting.py \
	tests/alias/test_x86_16_stack_restore_constants.py \
	tests/ir/test_x86_16_ir_constant_known_lanes.py \
	tests/ir/test_x86_16_ir_constant_flow_refusals.py \
	tests/ir/test_x86_16_scalar_value_projection.py \
	tests/lowering/test_x86_16_gp_restore_word_views.py \
	tests/lowering/test_x86_16_gp_constant_restore.py \
	tests/alias/test_x86_16_segment_stack_restore.py \
	tests/alias/test_x86_16_stack_restore_ss_identity.py \
	tests/alias/test_x86_16_bp_preservation.py \
	tests/alias/test_x86_16_stack_restore_loops.py \
	tests/lowering/test_x86_16_gp_restore_binding.py \
	tests/lowering/test_x86_16_gp_stack_restore.py \
	tests/integration/test_segment_register_membership.py \
	tests/alias/test_x86_16_stack_memory_ssa_alias.py \
	tests/alias/test_x86_16_stack_address_escape.py \
	tests/alias/test_x86_16_private_stack_writes.py \
	tests/integration/test_x86_16_logical_frame_accesses.py \
	tests/cli/test_serial_clean_worker_cache.py \
	tests/cli/test_direct_request_cache.py \
	tests/cli/test_discovery_cache_contract.py \
	tests/integration/test_x86_16_segment_state.py \
	tests/ir/test_x86_16_segment_state_call_boundary.py \
	tests/ir/test_x86_16_segment_state_call_outputs.py \
	tests/ir/test_x86_16_vex_import.py \
	tests/ir/test_x86_16_entry_jump_domain.py \
	tests/ir/test_x86_16_invocation_domain.py \
	tests/ir/test_x86_16_invocation_edge_feasibility.py \
	tests/ir/test_x86_16_edge_known_bits_soundness.py \
	tests/ir/test_x86_16_unary_value_contract.py \
	tests/ir/test_x86_16_unary_fold_contract.py \
	tests/ir/test_x86_16_unary_storage_guards.py \
	tests/semantics/test_x86_16_unary_call_binding.py \
	tests/ir/test_x86_16_unary_address_capture.py \
	tests/ir/test_x86_16_unary_constant_flow.py \
	tests/ir/test_x86_16_invocation_domain_boundaries.py \
	tests/ir/test_x86_16_invocation_refusal_site.py \
	tests/ir/test_x86_16_invocation_partition_census.py \
	tests/integration/test_x86_16_boot_call_prefix.py \
	tests/ir/test_x86_16_invocation_unused_premise.py \
	tests/cli/test_optimization_quality_guard_diagnostics.py \
	tests/ir/test_x86_16_vex_direct_constants.py \
	tests/ir/test_x86_16_vex_integer_displacement.py \
	tests/ir/test_x86_16_vex_bit_source.py \
	tests/ir/test_x86_16_vex_import_hot_path.py \
	tests/ir/test_x86_16_vex_import_cfg_successors.py \
	tests/ir/test_x86_16_sortd_indexed_loop_topology.py \
	tests/ir/test_x86_16_ssa_cfg.py \
	tests/ir/test_x86_16_logical_memory_write_value.py \
	tests/ir/test_x86_16_logical_constant_word_receipt.py \
	tests/alias/test_x86_16_stack_word_call_window.py \
	tests/alias/test_x86_16_stack_word_call_binding.py \
	tests/ir/test_x86_16_vex_memory_access_fidelity.py \
	tests/structuring/test_x86_16_condition_rendering.py \
	tests/structuring/test_x86_16_ir_readiness.py \
	tests/cli/test_x86_16_layer_module_status.py \
	tests/frontend/test_x86_16_coverage_manifest.py \
	tests/cli/test_x86_16_recovery_manifest.py \
	tests/cli/test_x86_16_recovery_artifacts.py \
	tests/cli/test_x86_16_function_effect_summary.py \
	tests/cli/test_x86_16_function_graph_extent_repair.py \
	tests/cli/test_x86_16_graph_repair_leaders.py \
	tests/frontend/test_x86_16_return_ip_provenance.py \
	tests/cli/test_x86_16_clinic_variable_recovery_contract.py \
	tests/ir/test_x86_16_ir_memory_call_liveness.py \
	tests/cli/test_x86_16_helper_effect_summary.py \
	tests/cli/test_x86_16_helper_family_routing.py \
	tests/cli/test_x86_16_function_interface_surface.py \
	tests/cli/test_x86_16_function_state_summary.py \
	tests/cli/test_x86_16_recovery_confidence_helper_summary.py \
	tests/cli/test_x86_16_recovery_artifact_cache.py \
	tests/structuring/test_x86_16_ir_recovery_summary.py \
	tests/cli/test_x86_16_recovery_artifact_manifest.py \
	tests/cli/test_x86_16_recovery_artifact_writer.py \
	tests/cli/test_x86_16_targeted_recovery_artifact.py \
	tests/postprocess/test_x86_16_decompiler_postprocess_callsite_prototypes.py \
	inertia/cli/function_worker_policy.py \
	tests/cli/test_decompile_entrypoint_determinism.py \
	tools/compiler_toolchain/tests/test_import_ultra_quickc_fixtures.py \
	tools/compiler_toolchain/tests/test_generated_c_indexed_argument_contract.py \
	tests/cli/test_project_loading_cache.py \
	tests/cli/test_project_loading_diagnostics.py \
	tests/cli/test_cli_interrupt_call_boundary.py \
	tests/cli/test_function_work_item_contract.py \
	tools/dev/tests/test_pytest_profile.py \
	tools/dev/tests/test_parallel_job_defaults.py \
	tools/dev/tests/test_pytest_partitioned.py \
	tools/dev/tests/test_pytest_dynamic_schedule.py \
	tools/dev/tests/test_pytest_process_metrics.py \
	tools/dev/tests/test_pytest_resource_scheduler.py \
	tools/dev/tests/test_pytest_source_state.py \
	tools/dev/tests/test_pytest_source_index.py \
	tools/dev/tests/test_decompiler_architecture_check.py \
	tests/cli/test_rizin_discovery.py \
		tests/cli/test_decompilation_quality.py \
		tests/cli/test_cli_regeneration.py \
		tests/cli/test_cli_segment_replay.py \
		tools/dev/tests/test_agent_test_focus.py \
		tools/dev/tests/test_test_ownership_manifest.py \
		tools/dev/tests/test_test_ownership_validation.py \
		tests/semantics/test_x86_16_carry_borrow_cfg.py \
		tests/semantics/test_x86_16_carry_borrow_call_output.py \
		tests/lowering/test_x86_16_wide_call_output_assignments.py \
		tests/semantics/test_x86_16_carry_borrow_sources.py \
		tests/integration/test_x86_16_carry_borrow_stack_storage.py \
		tests/semantics/test_x86_16_carry_borrow_widening.py \
		tests/semantics/test_x86_16_call_outputs.py \
		tests/semantics/test_x86_16_call_stack_effects.py \
		tests/semantics/test_x86_16_synthetic_frame_call_effects.py \
		tests/semantics/test_x86_16_call_stack_allocation_guard.py \
		tests/integration/test_x86_16_call_stack_allocation_proof.py \
		tests/alias/test_x86_16_stack_frame_register_alias.py \
		tests/alias/test_x86_16_entry_stack_bytes.py \
		tests/alias/test_x86_16_entry_stack_byte_refusals.py \
		tests/alias/test_x86_16_entry_stack_pointer_snapshots.py \
		tests/semantics/test_x86_16_register_definition_return.py \
		tests/lowering/test_x86_16_gp_stack_local_return.py \
		tests/lowering/test_x86_16_codegen_return_origin.py \
		tests/semantics/test_x86_16_callsite_inventory.py \
		tests/lowering/test_x86_16_gp_stack_local_reload.py \
		tests/semantics/test_x86_16_call_stack_logical_width.py \
		tests/semantics/test_x86_16_call_stack_provenance.py \
		tests/alias/test_x86_16_partial_register_address_break.py \
		tests/ir/test_x86_16_function_ssa_registry.py \
		tests/lowering/test_x86_16_stack_carrier_delta_cache.py \
		tests/lowering/test_x86_16_instruction_bp_stack_access_index.py \
		tests/lowering/test_x86_16_stack_variable_coordinates.py \
		tests/lowering/test_x86_16_stack_variable_identifier_coordinates.py \
		tests/lowering/test_x86_16_stack_frame_projection.py \
		tests/lowering/test_x86_16_machine_stack_names.py \
		tests/postprocess/test_structured_simplifier_identity.py \
		tests/cli/test_x86_16_cli_c_ast_rewrites.py \
		tests/lowering/test_x86_16_stack_word_load_materialization.py \
		tests/semantics/test_x86_16_call_contracts.py \
		tests/frontend/test_x86_16_calling_convention_compat.py \
		tests/lowering/test_x86_16_call_execution_frame_carriers.py \
		tests/lowering/test_x86_16_call_frame_base_effects.py \
		tests/lowering/test_x86_16_call_output_stack_objects.py \
		tests/lowering/test_x86_16_call_output_object_projection.py \
		tests/structuring/test_x86_16_structuring_call_argument_joins.py \
		tests/structuring/test_x86_16_call_return_conditions.py \
		tests/structuring/test_x86_16_bound_call_condition.py \
		tests/validation/test_x86_16_call_result_zero_validation.py \
		tests/structuring/test_x86_16_single_branch_return_orientation.py \
		tests/lowering/test_x86_16_callsite_prototype_declarations.py \
		tests/lowering/test_x86_16_call_argument_shape_publication.py \
		tests/lowering/test_x86_16_callsite_pointer_tables.py \
		tests/lowering/test_x86_16_signed_global_declarations.py \
		tests/structuring/test_x86_16_condition_lowering.py \
		tests/frontend/test_x86_16_condition_cache_relift.py \
		tests/frontend/test_x86_16_condition_lift_capture.py \
		tests/ir/test_x86_16_function_condition_artifact.py \
		tests/frontend/test_x86_16_return_liveness_replay.py \
		tests/ir/test_x86_16_condition_transfer.py \
		tests/integration/test_x86_16_condition_sign_extension.py \
		tests/ir/test_x86_16_condition_full_width_masks.py \
		tests/frontend/test_x86_16_jcc_result_condition.py \
		tests/integration/test_x86_16_frontend_condition_evidence.py \
		tests/frontend/test_x86_16_stack_condition_access_provenance.py \
		tests/frontend/test_x86_16_frontend_direct_callsite_index.py \
		tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py \
		tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py \
		tests/frontend/test_x86_16_jcc_register_evidence.py \
		tests/structuring/test_x86_16_indexed_stack_ranges.py \
		tests/validation/test_x86_16_validation_canonicalize.py \
		tests/validation/test_x86_16_validation_loop_condition_ir.py \
		tests/validation/test_x86_16_validation_branch_conditions.py \
		tests/validation/test_x86_16_validation_condition_coverage.py \
		tests/structuring/test_x86_16_composite_pretest_conditions.py \
		tests/structuring/test_x86_16_existing_loop_exit_conditions.py \
		tests/structuring/test_x86_16_terminal_loop_exit_conditions.py \
		tests/integration/test_x86_16_terminal_wide_validation.py \
		tests/frontend/test_x86_16_render_compat.py \
		tests/structuring/test_x86_16_structuring_condition_processor.py \
		tests/structuring/test_x86_16_structuring_condition_ownership.py \
		tests/structuring/test_x86_16_shared_loop_exit.py \
		tests/ir/test_x86_16_condition_decrement_fingerprints.py \
		tests/ir/test_x86_16_storage_or_fingerprints.py \
		tests/structuring/test_x86_16_structured_tag_projection.py \
		tests/validation/test_x86_16_validation_additive_semantic_casts.py \
		tests/validation/test_x86_16_validation_control_flow.py \
		tests/validation/test_x86_16_validation_dataflow.py \
		tests/validation/test_x86_16_validation_call_multiplicity.py \
		tests/validation/test_x86_16_validation_semantic_failures.py \
		tests/validation/test_x86_16_validation_virtual_carriers.py \
		tests/validation/test_x86_16_validation_predicates.py \
		tests/validation/test_x86_16_validation_storage.py \
		tests/validation/test_x86_16_validation_required_memory_effects.py \
		tests/lowering/test_x86_16_runtime_segment_access.py \
		tests/cli/test_x86_16_sortd_indexed_aggregate_regression.py \
		tests/cli/test_x86_16_sortd_menu_pointer_table.py \
	tests/validation/test_x86_16_validation_manifest.py \
	tests/validation/test_x86_16_validation_helper_report.py \
	tests/frontend/test_x86_16_low_memory_regions.py \
	tests/cli/test_x86_16_recompilable_source_evidence.py \
	tests/cli/test_x86_16_recompilable_subset.py \
	tests/cli/test_x86_16_recompilable_storage_map.py \
		tests/cli/test_x86_16_recompilable_storage_objects.py \
		tests/structuring/test_x86_16_structuring_grouping_report.py \
		tests/structuring/test_x86_16_structuring_grouped_refusal_report.py \
		tests/structuring/test_x86_16_structuring_condition_materialization.py \
		tests/ir/test_x86_16_condition_chain_refusal.py \
		tests/frontend/test_x86_16_recorded_return_argument_replay.py \
		tests/lowering/test_x86_16_stack_reload_instruction_ownership.py \
		tests/lowering/test_x86_16_runtime_call_results.py \
		tests/cli/test_x86_16_inbox_long_live.py \
		tests/structuring/test_x86_16_wide_return_condition_coverage.py \
		tests/structuring/test_x86_16_condition_exit_normalization.py \
		tests/structuring/test_x86_16_structuring_multi_arm_condition_ownership.py \
	tests/structuring/test_x86_16_local_condition_regions.py \
		tests/structuring/test_x86_16_wide_call_return_guard_chains.py \
		tests/structuring/test_x86_16_structuring_loop_body_repair.py \
		tests/structuring/test_x86_16_structuring_sequences.py \
		tests/postprocess/test_x86_16_dce_optimization.py \
		tests/postprocess/test_x86_16_dce_noop_conditionals.py \
		tests/frontend/test_x86_16_packed_flags_state.py \
		tests/postprocess/test_x86_16_flags_physical_register_contract.py \
		tests/postprocess/test_x86_16_dce_lvalue_reads.py \
		tests/integration/test_x86_16_dead_local_prune.py \
		tests/integration/test_x86_16_dead_local_structured_reads.py \
		tests/postprocess/test_x86_16_local_liveness.py \
		tests/cli/test_cli_semantic_rollback.py \
		tests/postprocess/test_x86_16_trivial_copy_optimization.py \
		tests/widening/test_x86_16_widening_copyprop.py \
		tests/widening/test_x86_16_widening_copyprop_width.py \
		tests/widening/test_x86_16_widening_memory_fold.py \
		tests/widening/test_x86_16_stack_subview_call_writes.py \
		tests/widening/test_x86_16_stack_subview_projection.py \
		tests/widening/test_x86_16_stack_subview_coordinates.py \
		tests/widening/test_x86_16_stack_subview_projection_wide.py \
		tests/lowering/test_x86_16_indexed_load_subviews.py \
		tools/dev/tests/test_makefile_quiet_output.py \
		tests/widening/test_x86_16_widening_rules.py \
		tests/integration/test_x86_16_far_load_access_width.py \
		tests/integration/test_x86_16_package_exports.py \
		tests/integration/test_x86_16_bootstrap_import_order.py \
		tests/cli/test_x86_16_sortd_sleep_regression.py \
		tests/integration/test_x86_16_pipeline_contracts.py \
	tests/alias/test_x86_16_rewrite_boundary.py \
	tests/cli/test_x86_16_heapsort_widening_regression.py \
	tests/lowering/test_x86_16_global_declarations.py \
	tests/lowering/test_x86_16_function_pointer_parameters.py \
	tests/lowering/test_x86_16_callee_global_object_interface.py \
	tests/lowering/test_x86_16_global_object_program_requirement.py \
	tests/lowering/test_x86_16_callee_global_object_sources.py \
	tests/lowering/test_x86_16_global_object_source_codec.py \
	tests/lowering/test_x86_16_callee_pointer_evidence.py \
	tests/lowering/test_x86_16_callee_pointer_codec.py \
	tests/alias/test_x86_16_callsite_summary_codec.py \
	tests/cli/test_x86_16_callsite_summary_program.py \
	tests/lowering/test_x86_16_project_callee_callsite_collection.py \
	tests/cli/test_project_callee_callsite_transport.py \
	tests/cli/test_serial_clean_worker_callsite_evidence.py \
	tests/cli/test_project_argument_evidence_ranges.py \
	tests/integration/test_x86_16_project_global_object_source_collection.py \
	tests/integration/test_indexed_alias_source_collection_scope.py \
	tests/cli/test_project_global_source_evidence_transport.py \
	tests/cli/test_serial_clean_worker_global_source_evidence.py \
	tests/structuring/test_x86_16_direct_stack_move_branches.py \
	tests/structuring/test_x86_16_direct_stack_move_ownership_priority.py \
	tests/lowering/test_x86_16_direct_stack_callsite_ownership.py \
	tests/frontend/test_x86_16_direct_stack_replay.py \
	tests/lowering/test_x86_16_direct_stack_reload_idempotence.py \
	tests/frontend/test_x86_16_structuring_replay_generation.py \
	tests/structuring/test_x86_16_structuring_lowering_order.py \
	tests/lowering/test_x86_16_direct_global_store_prefilter.py \
	tests/integration/test_x86_16_pipeline_result_contracts.py \
	tests/postprocess/test_x86_16_postprocess_validation_policy.py \
	tests/postprocess/test_x86_16_postprocess_bootstrap_orchestration.py \
	tests/postprocess/test_x86_16_postprocess_pass_transaction.py \
	tests/postprocess/test_x86_16_postprocess_runtime_config.py \
	tests/postprocess/test_x86_16_postprocess_rollback_snapshot_cache.py \
	tests/validation/test_x86_16_control_flow_ast_index.py \
	tests/lowering/test_x86_16_register_local_declarations.py \
	tests/lowering/test_x86_16_runtime_memory_helpers.py \
	tests/integration/test_x86_16_indexed_stack_frame_terms.py \
	tests/structuring/test_x86_16_loop_condition_materialization.py \
	tests/structuring/test_x86_16_pretest_loop_condition_ownership.py \
	tests/structuring/test_x86_16_loop_condition_block_identity.py \
	tests/integration/test_x86_16_nested_loop_behavior.py \
	tests/integration/test_x86_16_goto_accumulate_behavior.py \
	tests/lowering/test_x86_16_stack_update_scope_guard.py \
	tests/structuring/test_x86_16_instruction_fragment_placement.py \
	tests/lowering/test_x86_16_call_return_stack_stores.py \
	tests/structuring/test_x86_16_direct_stack_move_loop_entries.py \
	tests/structuring/test_x86_16_direct_stack_move_pretest_body.py \
	tests/structuring/test_x86_16_direct_stack_move_pretest_initializers.py \
	tests/postprocess/test_x86_16_stack_probe_local_preservation.py \
	tests/structuring/test_x86_16_casted_loop_induction.py \
	tests/structuring/test_x86_16_direct_stack_move_loops.py \
	tests/lowering/test_x86_16_direct_stack_update_groups.py \
	tests/alias/test_x86_16_indexed_address_copies.py \
	tests/integration/test_x86_16_indexed_address_evidence.py \
	tests/alias/test_x86_16_indexed_address_aliases.py \
	tests/ir/test_x86_16_indexed_address_range_candidates.py \
	tests/widening/test_x86_16_indexed_global_object_program_ranges.py \
	tests/widening/test_x86_16_indexed_global_object_ranges.py \
	tests/lowering/test_x86_16_bounded_global_array_declarations.py \
	tests/widening/x86_16_indexed_global_object_range_fixtures.py \
	tests/lowering/test_x86_16_indexed_address_collector_parity.py \
		tests/lowering/test_x86_16_indexed_address_parity_inventory.py \
		tests/cli/test_x86_16_sortd_indexed_address_parity_inventory.py \
		tests/widening/test_x86_16_alias_global_object_layout.py \
		tests/cli/test_indexed_alias_program_parallel.py \
		tests/widening/test_x86_16_global_object_layout.py \
	tests/lowering/test_x86_16_project_type_contracts.py \
	tests/lowering/test_x86_16_cod_global_identity.py \
	tests/lowering/test_x86_16_segmented_global_loads.py \
	tests/lowering/test_x86_16_wide_store_call_preservation.py \
	tests/lowering/test_x86_16_segmented_runtime_lowering.py \
	tests/ir/test_x86_16_ir_segmented_load_carriers.py \
	tests/ir/test_x86_16_reload_provenance_boundaries.py \
	tests/cli/test_generic_annotation_contracts.py \
	tests/cli/test_access_trait_runtime_factory.py \
	tests/lowering/test_frame_carrier_type_contracts.py \
	tools/dev/tests/test_makefile_inventory.py \
	tools/dev/tests/test_mypy_import_contracts.py \
	tests/cli/test_x86_16_layer_boundaries.py \
	tests/lowering/test_x86_16_pointer_store_fold_safety.py \
	tests/lowering/test_x86_16_near_pointer_argument_evidence.py \
	tests/lowering/test_x86_16_near_pointer_index_binding.py \
	tests/lowering/test_x86_16_annotation_argument_identity.py \
	tests/lowering/test_x86_16_assignment_lvalue_casts.py \
	tests/lowering/test_x86_16_stack_byte_writes.py \
	tests/lowering/test_x86_16_instruction_stack_write_width.py \
	tests/lowering/test_x86_16_semantic_cast.py \
	tests/ir/test_x86_16_condition_operand_signedness.py \
	tests/lowering/test_x86_16_condition_signedness_storage_width.py \
	tests/validation/test_x86_16_validation_argument_coordinates.py \
	tests/validation/test_x86_16_condition_storage_views.py \
	tests/lowering/test_x86_16_wide_stack_pair_coordinates.py \
	tests/lowering/test_x86_16_direct_stack_access_widths.py \
	tests/lowering/test_x86_16_stack_address_coordinates.py \
	tests/frontend/test_x86_16_native_stack_anchor.py \
	tests/lowering/test_x86_16_runtime_push_carrier.py \
	tests/lowering/test_x86_16_storage_prototype_snapshot.py \
	tests/lowering/test_x86_16_frame_prologue_carriers.py \
	tests/lowering/test_x86_16_frame_byte_carriers.py \
	tests/frontend/test_x86_16_native_segment_live_out.py \
	tests/frontend/test_x86_16_native_terminal_return_values.py \
	tests/frontend/test_x86_16_native_unsigned_constant_casts.py \
	tests/integration/test_x86_16_loadprogram_behavior.py \
	tests/integration/test_x86_16_configcrts_behavior.py \
	tests/integration/test_x86_16_mset_pos_behavior.py \
	tests/integration/test_x86_16_changeweather_behavior.py \
	tests/integration/test_x86_16_mouse_position_behavior.py \
	tests/frontend/test_x86_16_native_integer_operations.py \
	tests/integration/test_x86_16_ail_remainder.py \
	tests/alias/test_x86_16_stack_reference_offsets.py \
	tests/lowering/test_x86_16_les_stack_argument_behavior.py \
	tests/lowering/test_x86_16_segment_stack_restore_carriers.py \
	tests/lowering/test_x86_16_far_return_boundary_carriers.py \
	tests/lowering/test_x86_16_string_corpus_anchors.py \
	tests/lowering/test_x86_16_ss_traversal_contract.py \
	tests/lowering/test_x86_16_stack_prototype_wrapped_locals.py \
	tests/integration/test_x86_16_ast_traversal_coverage.py \
	tests/cli/test_x86_16_msetpos_behavior.py \
	tests/lowering/test_x86_16_gp_livein_authority.py \
	tests/integration/test_x86_16_anonymous_store_width.py \
	tests/ir/test_x86_16_ssa_register_displacements.py \
	tests/alias/test_x86_16_stack_coordinate_conflicts.py \
	tests/validation/test_x86_16_escaped_stack_validation.py \
	tests/cli/test_x86_16_bios_strict_compilation.py \
	tests/cli/test_x86_16_rep_store_codegen.py \
	tests/lowering/test_x86_16_runtime_store_scope.py \
	tests/cli/test_x86_16_string_timeout_fallback.py \
	tests/ir/test_x86_16_ir_memory_byte_ssa.py \
	tests/lowering/test_x86_16_string_codegen_override.py \
	tests/cli/test_cli_codegen_policy.py \
	tests/cli/test_x86_16_segment_call_effects.py \
	tests/lowering/test_x86_16_frame_carrier_liveness.py \
	tests/semantics/test_x86_16_unobserved_return_maker.py \
	tests/integration/test_x86_16_dosfunc_behavior.py \
	tests/integration/test_x86_16_heapsort_behavior.py \
	tests/fixtures/x86_16_heapsort_behavior.py \
	tests/integration/test_x86_16_quicksort_behavior.py \
	tests/fixtures/x86_16_quicksort_behavior.py \
	tests/integration/test_x86_16_sleep_behavior.py \
	tests/integration/test_x86_16_insertionsort_behavior.py \
	tests/lowering/test_x86_16_swapbars_behavior.py \
	tests/lowering/test_x86_16_gp_word_runtime.py \
	tests/lowering/test_x86_16_gp_word_assignment.py \
	tests/fixtures/x86_16_swapbars_behavior.py \
	tests/fixtures/x86_16_sleep_behavior.py \
	tests/integration/test_x86_16_reinitbars_execution.py \
	tests/fixtures/x86_16_reinitbars_execution.py \
	tests/cli/x86_16_runmenu_execution.py \
	tests/integration/test_x86_16_setgear_behavior.py \
	tests/integration/test_x86_16_tidshowrange_behavior.py \
	tests/fixtures/x86_16_tidshowrange_behavior.py \
	tests/fixtures/x86_16_setgear_behavior.py \
	tests/ir/test_x86_16_address_base_snapshots.py \
	tests/ir/test_x86_16_memory_ssa_address_provenance.py \
	tests/ir/test_x86_16_ir_stack_frame.py \
	tests/integration/test_x86_16_consumed_push_lvalues.py \
	tests/lowering/test_x86_16_stack_aggregate_objects.py \
	tests/lowering/test_x86_16_stack_prototype_codegen_api.py \
	tests/frontend/test_x86_16_stack_aggregate_coordinate_replay.py \
	tests/lowering/test_x86_16_positive_bp_argument_plan.py \
	tests/lowering/test_x86_16_stack_argument_identity.py \
	tests/lowering/test_x86_16_projected_stack_argument_identity.py \
	tests/lowering/test_x86_16_stack_declaration_identity.py \
	tests/lowering/test_x86_16_stack_lowering_contracts.py \
	tests/widening/test_x86_16_stack_memory_object_widening.py \
	tests/lowering/test_x86_16_stack_memory_ssa_lowering.py \
	tests/alias/test_x86_16_stack_memory_ssa_safety.py \
	tests/lowering/test_x86_16_interprocedural_storage_consumers.py \
	tests/lowering/test_x86_16_interprocedural_storage_live_out.py \
	tests/lowering/test_x86_16_interprocedural_memory_output_objects.py \
	tests/lowering/test_x86_16_interprocedural_memory_output_validation.py \
	tests/lowering/test_x86_16_pointer_parameter_memory_outputs.py \
	tests/lowering/test_x86_16_pointer_parameter_object_types.py \
	tests/lowering/test_x86_16_interprocedural_storage_slot_join.py \
	tests/lowering/test_x86_16_interprocedural_storage_pipeline.py \
	tests/lowering/test_x86_16_interprocedural_storage_prototype_application.py \
	tests/lowering/test_x86_16_interprocedural_storage_reaching_defs.py \
	tests/lowering/test_x86_16_interprocedural_storage_expression_defs.py \
	tests/ir/test_x86_16_scalar_affine_trace.py \
	tests/ir/test_x86_16_affine_indexed_address.py \
	tests/ir/test_x86_16_affine_induction_role.py \
	tests/ir/test_x86_16_frame_register_livein.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_defs.py \
	tests/lowering/test_x86_16_call_target_ssa_binding.py \
	tests/semantics/test_x86_16_call_target_evidence_retention.py \
	tests/frontend/test_lifter_backend.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_passthrough.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_pointer.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_pointer_cfg.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_pointer_stack.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_split.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_trial_collection.py \
	tests/integration/test_x86_16_return_witness_addresses.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_types.py \
	tests/lowering/test_x86_16_interprocedural_storage_simtypes.py \
	tests/lowering/test_x86_16_interprocedural_storage_trial_collection.py \
	tests/lowering/test_x86_16_interprocedural_storage_trials.py \
	tests/semantics/test_x86_16_terminal_memory_outputs.py \
	tests/integration/test_x86_16_terminal_memory_output_aliases.py \
	tests/widening/test_x86_16_terminal_memory_output_views.py \
	tests/semantics/test_x86_16_terminal_pointer_outputs.py \
	tests/frontend/test_x86_16_conditional_pointer_output_native.py \
	tests/alias/test_x86_16_terminal_pointer_output_aliases.py \
	tests/lowering/test_x86_16_pointer_parameter_output_pipeline.py \
	tests/widening/test_x86_16_terminal_pointer_output_views.py \
	tests/lowering/test_x86_16_unused_void_return_types.py \
	tests/cli/test_x86_16_decompilation_cache_surface.py \
	tests/cli/test_check_sortd_sidecar_free.py \
	tests/cli/test_sortd_drawtime_gate.py \
	tests/cli/test_runmenu_execution_evidence.py \
	tests/cli/test_compare_ghidra_function_coverage.py \
	tools/dev/tests/test_test_pipeline.py \
	tests/cli/test_x86_16_sortdemo_regressions.py \
	tests/cli/test_x86_16_generated_c_acceptance.py \
	tests/cli/test_x86_16_corpus_scan_timeout.py \
	tests/cli/test_x86_16_sortdemo_decompiler_status.py \
	tests/structuring/test_x86_16_branch_return_expressions.py \
	tests/lowering/test_x86_16_condition_argument_types.py \
	tests/postprocess/test_x86_16_typed_condition_side_effect_preservation.py \
	tests/validation/test_x86_16_validation_condition_precision.py \
	tests/integration/test_x86_16_msc6_cmp32_regression.py \
	tests/cli/test_x86_16_msc6_regressions.py \
	tests/structuring/test_x86_16_multi_arm_return_chains.py \
	tests/structuring/test_x86_16_scalar_return_evidence.py \
	tests/lowering/test_x86_16_scalar_return_types.py \
	tests/structuring/test_x86_16_return_chain_condition_selection.py \
	tests/structuring/test_x86_16_structuring_return_chains.py \
	tests/structuring/test_x86_16_selector_return_projection.py \
	tests/structuring/test_x86_16_mask_accumulator_effects.py \
	tests/integration/test_x86_16_global_sum_effects.py \
	tests/cli/test_cli_assignment_effect_preservation.py \
	tools/compiler_toolchain/tests/test_msc_storage_carry_oracle.py \
	tests/structuring/test_x86_16_total_return_suffixes.py \
	tests/structuring/test_x86_16_switch_loop_tail_breaks.py \
	tests/structuring/test_x86_16_wide_stack_condition_chains.py \
	tests/structuring/test_x86_16_wide_condition_ordering.py \
	tests/lowering/test_x86_16_wide_call_condition_source.py \
	tests/lowering/test_x86_16_wide_call_condition_capture.py \
	tests/integration/test_x86_16_wide_return_type_preservation.py \
	tests/lowering/test_x86_16_positive_bp_wide_arguments.py \
	tests/cli/test_x86_16_cod_regressions.py \
	tests/structuring/test_x86_16_wide_call_condition_plan.py \
	tests/structuring/test_x86_16_wide_condition_provenance.py \
	inertia/cli/accepted_payload_integrity.py \
	inertia/cli/angr_codegen_tags.py \
	inertia/semantics/callsite_register_instruction_facts.py \
	inertia/lowering/consumed_call_push_evidence.py \
	inertia/lowering/frame_instruction_evidence.py \
	inertia/lowering/frame_register_carriers.py \
	inertia/lowering/structured_tags.py \
	inertia/frontend/x86_16/verification_80386.py \
	inertia/lowering/stack_prototype_layout.py \
	inertia/frontend/x86_16/msvc_x87_interrupts.py \
	inertia/ir/logical_memory_scalar_projection.py \
	inertia/lowering/direct_global_register_updates.py \
	inertia/lowering/direct_global_register_update_contracts.py \
	inertia/lowering/direct_stack_segmented_projection.py \
	inertia/lowering/logical_word_memory_copy_materialization.py \
	inertia/lowering/stack_frame_projection.py \
	inertia/lowering/stack_word_recomposition.py \
	tests/structuring/test_x86_16_boolean_condition_ites.py \
	tests/lowering/test_x86_16_direct_stack_move_indexed_use.py \
	tests/frontend/test_x86_16_msvc_x87_interrupts.py \
	tests/semantics/test_x86_16_return_stack_address_compat.py \
	tests/lowering/test_x86_16_stack_prototype_layout.py \
	tests/cli/test_accepted_payload_integrity.py \
	tests/cli/test_acceptance_scorecard.py \
	tests/cli/test_tail_validation_display_outcome.py \
	inertia/frontend/x86_16/frontend_indirect_jump_targets.py \
	inertia/lowering/balanced_memory_stack_restore.py \
	inertia/lowering/caller_observed_byte_return_types.py \
	inertia/lowering/control_stack_escape.py \
	inertia/lowering/direction_flag_state.py \
	inertia/lowering/interprocedural_storage_return_type_collection.py \
	inertia/lowering/interprocedural_storage_return_type_collection_contracts.py \
	inertia/lowering/packed_flags_state.py \
	inertia/lowering/packed_flags_liveness.py \
	inertia/lowering/packed_flags_calls.py \
	inertia/lowering/far_return_boundary_carriers.py \
	inertia/lowering/segment_stack_restore_carriers.py \
	inertia/validation/validation_condition_closure_delta.py \
	inertia/validation/validation_observable_compaction.py \
	inertia/validation/validation_pointer_parameter_output_contracts.py \
	inertia/validation/validation_pointer_parameter_outputs.py \
	inertia/lowering/gp_stack_restore.py \
	inertia/lowering/gp_stack_restore_identity.py \
	inertia/lowering/stack_value_projection.py \
	inertia/validation/entry_stack_ranges.py \
	inertia/cli/cache_file_digest.py \
	inertia/cli/direct_indexed_alias_local_cache.py \
	inertia/cli/function_ir_ssa_cache.py \
	inertia/cli/function_ir_ssa_cache_codec.py \
	inertia/cli/function_ir_ssa_cache_identity.py

QA_RUFF_TARGETS += \
	tests/validation/test_x86_16_materialized_condition_storage.py \
	tests/structuring/test_x86_16_stored_call_result_assignments.py \
	tests/structuring/test_x86_16_stored_call_result_definitions.py \
	tests/cli/test_x86_16_clinic_semantic_stages.py

QA_PYTEST_TARGETS := \
	tests/lowering/test_x86_16_gp_constant_restore.py \
	tests/widening/test_x86_16_segmented_load_origins.py \
	tests/cli/test_x86_16_envsize_behavior.py \
	tests/ir/test_x86_16_ir_instruction_origin.py \
	tests/alias/test_x86_16_stack_restore_constants.py \
	tests/ir/test_x86_16_ir_constant_known_lanes.py \
	tests/ir/test_x86_16_ir_constant_flow_refusals.py \
	tests/lowering/test_x86_16_gp_restore_word_views.py \
	tests/structuring/test_x86_16_stored_call_result_assignments.py \
	tests/structuring/test_x86_16_stored_call_result_definitions.py \
	tests/lowering/test_x86_16_gp_partial_live_in.py \
	tests/alias/test_x86_16_callsite_return_use_zero_idiom.py \
	tests/cli/test_x86_16_layer_boundaries.py::test_quality_and_diagnostics_modules_are_wired_into_production_paths \
	tests/cli/test_x86_16_layer_boundaries.py::test_layer_module_admission_status_matches_production_imports \
	tests/cli/test_x86_16_layer_boundaries.py::test_quality_compatibility_exports_retain_canonical_identity \
	tests/cli/test_x86_16_cod_regressions.py::test_cod_dos_loadprogram_wrapper_keeps_err_guard_and_segment_stores \
	tests/cli/test_cod_openfilewrapper_consolidation.py \
	tests/cli/test_function_ir_ssa_source_scope.py \
	tests/cli/test_x86_16_indexed_alias_cache_layers.py \
	tests/cli/test_program_callsite_cache.py \
	tests/cli/test_x86_16_clinic_semantic_stages.py \
	tests/lowering/test_x86_16_gp_register_state.py \
	tests/lowering/test_x86_16_gp_pointer_values.py \
	tests/integration/test_x86_16_pointer_fill_behavior.py \
	tests/integration/test_x86_16_pointer_sum_behavior.py \
	tools/dev/tests/test_agent_context_check.py \
	tests/semantics/test_x86_16_caller_return_use_contracts.py \
	tests/lowering/test_x86_16_interprocedural_storage_consumers.py \
	tests/lowering/test_x86_16_interprocedural_storage_live_out.py \
	tests/lowering/test_x86_16_interprocedural_memory_output_objects.py \
	tests/lowering/test_x86_16_interprocedural_memory_output_validation.py \
	tests/lowering/test_x86_16_pointer_parameter_memory_outputs.py \
	tests/lowering/test_x86_16_pointer_parameter_object_types.py \
	tests/frontend/test_x86_16_direct_stack_replay.py \
	tests/lowering/test_x86_16_interprocedural_storage_slot_join.py \
	tests/lowering/test_x86_16_interprocedural_storage_pipeline.py \
	tests/lowering/test_x86_16_interprocedural_storage_prototype_application.py \
	tests/lowering/test_x86_16_interprocedural_storage_reaching_defs.py \
	tests/lowering/test_x86_16_interprocedural_storage_expression_defs.py \
	tests/ir/test_x86_16_scalar_affine_trace.py \
	tests/ir/test_x86_16_affine_indexed_address.py \
	tests/ir/test_x86_16_affine_induction_role.py \
	tests/ir/test_x86_16_frame_register_livein.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_defs.py \
	tests/lowering/test_x86_16_call_target_ssa_binding.py \
	tests/semantics/test_x86_16_call_target_evidence_retention.py \
	tests/frontend/test_lifter_backend.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_passthrough.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_pointer.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_pointer_cfg.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_pointer_stack.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_split.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_trial_collection.py \
	tests/integration/test_x86_16_return_witness_addresses.py \
	tests/lowering/test_x86_16_interprocedural_storage_return_types.py \
	tests/lowering/test_x86_16_interprocedural_storage_simtypes.py \
	tests/lowering/test_x86_16_interprocedural_storage_trial_collection.py \
	tests/lowering/test_x86_16_interprocedural_storage_trials.py \
	tests/semantics/test_x86_16_carry_borrow_cfg.py \
	tests/semantics/test_x86_16_carry_borrow_call_output.py \
	tests/lowering/test_x86_16_wide_call_output_assignments.py \
	tests/ir/test_x86_16_vex_logical_memory_accesses.py \
	tests/semantics/test_x86_16_carry_borrow_sources.py \
	tests/integration/test_x86_16_carry_borrow_stack_storage.py \
	tests/semantics/test_x86_16_carry_borrow_widening.py \
	tests/semantics/test_x86_16_call_outputs.py \
	tests/semantics/test_x86_16_call_stack_effects.py \
	tests/semantics/test_x86_16_synthetic_frame_call_effects.py \
	tests/semantics/test_x86_16_call_stack_allocation_guard.py \
	tests/integration/test_x86_16_call_stack_allocation_proof.py \
	tests/alias/test_x86_16_stack_frame_register_alias.py \
	tests/alias/test_x86_16_entry_stack_bytes.py \
	tests/alias/test_x86_16_entry_stack_byte_refusals.py \
	tests/alias/test_x86_16_entry_stack_pointer_snapshots.py \
	tests/semantics/test_x86_16_register_definition_return.py \
	tests/lowering/test_x86_16_gp_stack_local_return.py \
	tests/lowering/test_x86_16_codegen_return_origin.py \
	tests/semantics/test_x86_16_callsite_inventory.py \
	tests/lowering/test_x86_16_gp_stack_local_reload.py \
	tests/semantics/test_x86_16_call_stack_logical_width.py \
	tests/semantics/test_x86_16_call_stack_provenance.py \
	tests/alias/test_x86_16_partial_register_address_break.py \
	tests/ir/test_x86_16_function_ssa_registry.py \
	tests/lowering/test_x86_16_stack_carrier_delta_cache.py \
	tests/lowering/test_x86_16_instruction_bp_stack_access_index.py \
	tests/lowering/test_x86_16_stack_variable_coordinates.py \
	tests/lowering/test_x86_16_stack_variable_identifier_coordinates.py \
	tests/lowering/test_x86_16_stack_frame_projection.py \
	tests/lowering/test_x86_16_machine_stack_names.py \
	tests/postprocess/test_structured_simplifier_identity.py \
	tests/cli/test_x86_16_cli_c_ast_rewrites.py \
	tests/lowering/test_x86_16_stack_word_load_materialization.py \
	tests/semantics/test_x86_16_terminal_memory_outputs.py \
	tests/integration/test_x86_16_terminal_memory_output_aliases.py \
	tests/widening/test_x86_16_terminal_memory_output_views.py \
	tests/semantics/test_x86_16_terminal_pointer_outputs.py \
	tests/frontend/test_x86_16_conditional_pointer_output_native.py \
	tests/alias/test_x86_16_terminal_pointer_output_aliases.py::test_every_store_site_binds_to_one_exact_positive_bp_parameter \
	tests/alias/test_x86_16_terminal_pointer_output_aliases.py::test_unknown_or_non_parameter_source_refuses_atomically \
	tests/alias/test_x86_16_terminal_pointer_output_aliases.py::test_competing_parameter_sources_refuse_without_partial_fact \
	tests/lowering/test_x86_16_pointer_parameter_output_pipeline.py \
	tests/widening/test_x86_16_terminal_pointer_output_views.py \
	tests/frontend/test_x86_16_smoketest.py \
	tools/dev/tests/test_check_changed_non_test_types.py \
	tests/cli/test_cli_batch_c_output.py \
	tests/cli/test_cli_direct_argument_evidence_context.py \
	tests/cli/test_generated_c_artifacts.py \
	tests/cli/test_generated_translation_unit_assembly.py \
	tests/cli/test_generated_translation_unit_gate.py \
	tests/cli/test_x86_16_callee_name_normalization.py \
	tests/frontend/test_x86_16_cr.py \
	tests/frontend/test_x86_16_exception.py \
	tests/frontend/test_x86_16_hardware.py \
	tests/frontend/test_x86_16_simprocs_io.py \
	tests/frontend/test_x86_16_debug.py \
	tools/compiler_toolchain/tests/test_recompile_check_contract.py \
	tests/frontend/test_x86_16_packed_mz.py \
	tests/frontend/test_x86_16_dev_io.py \
	tests/frontend/test_x86_16_io.py \
	tests/frontend/test_x86_16_emulator.py \
	tests/frontend/test_x86_16_memory.py \
	tests/frontend/test_x86_16_interrupt.py \
	tests/frontend/test_x86_16_stack_compat.py \
	tests/frontend/test_x86_16_load_propagation.py \
	tests/integration/test_x86_16_stack_tracker_allocation.py \
	tests/semantics/test_x86_16_stack_tracker_return_segment.py \
	tests/integration/test_x86_16_stack_address_operand_roles.py \
	tests/frontend/test_x86_16_numeric_sp_call_return.py \
	tests/semantics/test_x86_16_call_frame_compat.py \
	tests/semantics/test_x86_16_callee_cleanup_compat.py \
	tests/ir/test_x86_16_stack_pointer_provenance.py \
	tests/ir/test_x86_16_stack_extent_evidence.py \
	tests/integration/test_x86_16_logical_frame_accesses.py \
	tests/ir/test_x86_16_ir_terminal_control_flow.py \
	tests/ir/test_x86_16_ail_register_displacement.py \
	tests/postprocess/test_x86_16_codegen_parentheses.py \
	tests/postprocess/test_x86_16_local_declarations.py \
	tests/lowering/test_x86_16_terminal_call_return_types.py \
	tests/integration/test_x86_16_seed_calling_dependencies.py \
	tests/lowering/test_x86_16_stack_value_owner_identity.py \
	tests/structuring/test_x86_16_tagged_terminal_return_values.py \
	tools/compiler_toolchain/tests/test_recompile_check.py \
	tests/integration/test_msc6_runtime_state.py \
	tests/cli/test_x86_16_telemetry_support.py \
	tests/lowering/test_x86_16_switch_segment_diagnostics.py \
	tests/integration/test_x86_16_codegen_metadata.py \
	tests/semantics/test_x86_16_call_return_segment.py \
	tests/frontend/test_x86_16_stack_pointer_width.py \
	tests/frontend/test_x86_16_lifted_integer_constants.py \
	tests/cli/test_x86_16_correctness_goals.py \
	tests/cli/test_x86_16_readability_set.py \
	tests/cli/test_x86_16_readability_goals.py \
	tests/alias/test_x86_16_alias_domains.py \
	tests/alias/test_x86_16_condition_register_carriers.py \
	tests/semantics/test_x86_16_semantics_exports.py \
	tests/alias/test_x86_16_alias_stack_lowering.py \
	tests/alias/test_x86_16_alias_state_transfer.py \
	tests/semantics/test_x86_16_alu_helpers.py \
	tests/lowering/test_x86_16_c_runtime_header.py \
	tests/lowering/test_x86_16_call_return_selectors.py \
	tests/lowering/test_x86_16_register_local_declarations.py \
	tests/lowering/test_x86_16_object_lowering.py \
	tests/semantics/test_x86_16_semantics_alias_query.py \
	tests/semantics/test_x86_16_semantics_evidence_cache.py \
	tests/semantics/test_x86_16_semantics_expression_analysis.py \
	tests/semantics/test_x86_16_stack_frame_recovery.py \
	tests/lowering/test_x86_16_segmented_lowering.py \
	tests/ir/test_x86_16_address_ir.py \
	tests/ir/test_x86_16_segment_contract.py \
	tests/lowering/test_x86_16_segment_address_policy.py \
	tests/lowering/test_x86_16_segment_access_coverage.py \
	tests/lowering/test_x86_16_segment_access_policy.py \
	tests/ir/test_x86_16_segment_function_summary.py \
	tests/ir/test_x86_16_segment_program_layout.py \
	tests/ir/test_segment_program_layout_reporting.py \
	tests/alias/test_x86_16_segment_stack_restore.py \
	tests/alias/test_x86_16_stack_restore_ss_identity.py \
	tests/alias/test_x86_16_bp_preservation.py \
	tests/alias/test_x86_16_stack_restore_loops.py \
	tests/lowering/test_x86_16_gp_restore_binding.py \
	tests/lowering/test_x86_16_gp_stack_restore.py \
	tests/integration/test_segment_register_membership.py \
	tests/alias/test_x86_16_stack_memory_ssa_alias.py \
	tests/alias/test_x86_16_stack_address_escape.py \
	tests/alias/test_x86_16_private_stack_writes.py \
	tests/cli/test_serial_clean_worker_cache.py \
	tests/cli/test_direct_request_cache.py \
	tests/cli/test_discovery_cache_contract.py \
	tests/integration/test_x86_16_segment_state.py \
	tests/ir/test_x86_16_segment_state_call_boundary.py \
	tests/ir/test_x86_16_segment_state_call_outputs.py \
	tests/ir/test_x86_16_vex_import.py \
	tests/ir/test_x86_16_entry_jump_domain.py \
	tests/ir/test_x86_16_invocation_domain.py \
	tests/ir/test_x86_16_invocation_edge_feasibility.py \
	tests/ir/test_x86_16_edge_known_bits_soundness.py \
	tests/ir/test_x86_16_unary_value_contract.py \
	tests/ir/test_x86_16_unary_fold_contract.py \
	tests/ir/test_x86_16_unary_storage_guards.py \
	tests/semantics/test_x86_16_unary_call_binding.py \
	tests/ir/test_x86_16_unary_address_capture.py \
	tests/ir/test_x86_16_unary_constant_flow.py \
	tests/ir/test_x86_16_invocation_domain_boundaries.py \
	tests/ir/test_x86_16_invocation_refusal_site.py \
	tests/ir/test_x86_16_invocation_partition_census.py \
	tests/integration/test_x86_16_boot_call_prefix.py \
	tests/ir/test_x86_16_invocation_unused_premise.py \
	tests/cli/test_optimization_quality_guard_diagnostics.py \
	tests/ir/test_x86_16_vex_direct_constants.py \
	tests/ir/test_x86_16_vex_integer_displacement.py \
	tests/ir/test_x86_16_vex_bit_source.py \
	tests/ir/test_x86_16_vex_import_hot_path.py \
	tests/ir/test_x86_16_vex_import_cfg_successors.py \
	tests/ir/test_x86_16_sortd_indexed_loop_topology.py \
	tests/ir/test_x86_16_ssa_cfg.py \
	tests/ir/test_x86_16_logical_memory_write_value.py \
	tests/ir/test_x86_16_logical_constant_word_receipt.py \
	tests/alias/test_x86_16_stack_word_call_window.py \
	tests/alias/test_x86_16_stack_word_call_binding.py \
	tests/ir/test_x86_16_vex_memory_access_fidelity.py \
	tests/structuring/test_x86_16_condition_rendering.py \
	tests/structuring/test_x86_16_ir_readiness.py \
	tests/cli/test_x86_16_layer_module_status.py \
	tests/frontend/test_x86_16_coverage_manifest.py \
	tests/cli/test_x86_16_recovery_manifest.py \
	tests/cli/test_x86_16_recovery_artifacts.py \
	tests/cli/test_x86_16_function_effect_summary.py \
	tests/cli/test_x86_16_function_graph_extent_repair.py \
	tests/cli/test_x86_16_graph_repair_leaders.py \
	tests/frontend/test_x86_16_return_ip_provenance.py \
	tests/cli/test_x86_16_clinic_variable_recovery_contract.py \
	tests/ir/test_x86_16_ir_memory_call_liveness.py \
	tests/cli/test_x86_16_helper_effect_summary.py \
	tests/cli/test_x86_16_helper_family_routing.py \
	tests/cli/test_x86_16_function_interface_surface.py \
	tests/cli/test_x86_16_function_state_summary.py \
	tests/cli/test_x86_16_recovery_confidence_helper_summary.py \
	tests/cli/test_x86_16_recovery_artifact_cache.py \
	tests/structuring/test_x86_16_ir_recovery_summary.py \
	tests/cli/test_x86_16_recovery_artifact_manifest.py \
	tests/cli/test_x86_16_recovery_artifact_writer.py \
	tests/cli/test_x86_16_targeted_recovery_artifact.py \
	tests/cli/test_x86_16_corpus_recovery_artifact.py \
	tests/cli/test_x86_16_corpus_scan_timeout.py \
	tests/integration/test_build_msc6_examples.py \
	tests/integration/test_msc6_compat_headers.py \
	tools/compiler_toolchain/tests/test_msc6_entrypoint.py \
	tests/cli/test_decompile_entrypoint_determinism.py \
	tools/compiler_toolchain/tests/test_import_ultra_quickc_fixtures.py \
	tools/compiler_toolchain/tests/test_generated_c_indexed_argument_contract.py \
	tests/cli/test_project_loading_cache.py \
	tests/cli/test_project_loading_diagnostics.py \
	tests/cli/test_cli_interrupt_call_boundary.py \
	tools/dev/tests/test_pytest_profile.py \
	tests/cli/test_generic_annotation_contracts.py \
	tests/cli/test_access_trait_runtime_factory.py \
	tests/lowering/test_frame_carrier_type_contracts.py \
	tools/dev/tests/test_makefile_inventory.py \
	tools/dev/tests/test_mypy_import_contracts.py \
	tests/lowering/test_x86_16_pointer_store_fold_safety.py \
	tests/lowering/test_x86_16_near_pointer_argument_evidence.py \
	tests/lowering/test_x86_16_near_pointer_index_binding.py \
	tests/lowering/test_x86_16_annotation_argument_identity.py \
	tools/dev/tests/test_parallel_job_defaults.py \
	tools/dev/tests/test_pytest_partitioned.py \
	tools/dev/tests/test_pytest_process_metrics.py \
	tools/dev/tests/test_pytest_resource_scheduler.py \
	tools/dev/tests/test_pytest_source_index.py \
	tools/dev/tests/test_decompiler_architecture_check.py \
	tests/cli/test_rizin_discovery.py \
	tests/cli/test_decompilation_quality.py \
	tests/cli/test_cli_regeneration.py \
	tests/cli/test_cli_segment_replay.py \
	tests/cli/test_check_sortd_sidecar_free.py \
	tests/cli/test_sortd_drawtime_gate.py \
	tests/cli/test_runmenu_execution_evidence.py \
	tests/cli/test_compare_ghidra_function_coverage.py \
	tools/dev/tests/test_agent_test_focus.py \
	tools/dev/tests/test_test_pipeline.py \
	tools/dev/tests/test_test_ownership_manifest.py \
	tools/dev/tests/test_test_ownership_validation.py \
	tests/alias/test_x86_16_alias_register_mvp.py \
	tests/semantics/test_x86_16_call_contracts.py \
	tests/lowering/test_x86_16_call_execution_frame_carriers.py \
	tests/lowering/test_x86_16_call_frame_base_effects.py \
	tests/lowering/test_x86_16_call_output_stack_objects.py \
	tests/lowering/test_x86_16_call_output_object_projection.py \
	tests/structuring/test_x86_16_structuring_call_argument_joins.py \
	tests/structuring/test_x86_16_call_return_conditions.py \
	tests/structuring/test_x86_16_bound_call_condition.py \
	tests/validation/test_x86_16_call_result_zero_validation.py \
	tests/structuring/test_x86_16_single_branch_return_orientation.py \
	tests/lowering/test_x86_16_callsite_prototype_declarations.py \
	tests/lowering/test_x86_16_call_argument_shape_publication.py \
	tests/lowering/test_x86_16_callsite_pointer_tables.py \
	tests/frontend/test_x86_16_callsite_replay_safety.py \
	tests/lowering/test_x86_16_signed_global_declarations.py \
	tests/cli/test_x86_16_sortd_sleep_regression.py \
	tests/postprocess/test_x86_16_decompiler_postprocess_callsites.py \
	tests/lowering/test_x86_16_protected_call_arguments.py \
	tests/lowering/test_x86_16_call_argument_expression.py \
	tests/structuring/test_x86_16_condition_lowering.py \
	tests/frontend/test_x86_16_condition_cache_relift.py \
	tests/frontend/test_x86_16_condition_lift_capture.py \
	tests/ir/test_x86_16_function_condition_artifact.py \
	tests/frontend/test_x86_16_return_liveness_replay.py \
	tests/lowering/test_x86_16_lowered_register_carriers.py \
	tests/ir/test_x86_16_condition_transfer.py \
	tests/integration/test_x86_16_condition_sign_extension.py \
	tests/ir/test_x86_16_condition_full_width_masks.py \
	tests/frontend/test_x86_16_jcc_result_condition.py \
	tests/integration/test_x86_16_frontend_condition_evidence.py \
	tests/frontend/test_x86_16_stack_condition_access_provenance.py \
	tests/frontend/test_x86_16_frontend_direct_callsite_index.py \
	tests/structuring/test_x86_16_wide_call_return_guard_chains.py \
	tests/structuring/test_x86_16_branch_return_expressions.py \
	tests/lowering/test_x86_16_condition_argument_types.py \
	tests/postprocess/test_x86_16_typed_condition_side_effect_preservation.py \
	tests/validation/test_x86_16_validation_condition_precision.py \
	tests/integration/test_x86_16_msc6_cmp32_regression.py \
	tests/structuring/test_x86_16_multi_arm_return_chains.py \
	tests/structuring/test_x86_16_scalar_return_evidence.py \
	tests/lowering/test_x86_16_scalar_return_types.py \
	tests/structuring/test_x86_16_return_chain_condition_selection.py \
	tests/structuring/test_x86_16_structuring_return_chains.py \
	tests/structuring/test_x86_16_selector_return_projection.py \
	tests/structuring/test_x86_16_mask_accumulator_effects.py \
	tests/integration/test_x86_16_global_sum_effects.py \
	tests/cli/test_cli_assignment_effect_preservation.py \
	tools/compiler_toolchain/tests/test_msc_storage_carry_oracle.py \
	tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py \
	tests/ir/test_x86_16_condition_register_definition.py \
	tests/integration/test_x86_16_runtime_condition_projection.py \
	tests/structuring/test_x86_16_loop_instruction_tags.py \
	tests/structuring/test_x86_16_loop_break_topology.py \
	tests/structuring/test_x86_16_structuring_grouped_pass.py::test_decision_tree_accumulates_unresolved_normalized_affine_producers \
	tests/frontend/test_x86_16_void_return_pass_ownership.py \
	tests/lowering/test_x86_16_stack_prototype_promotion.py \
	tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py \
	tests/frontend/test_x86_16_jcc_register_evidence.py \
	tests/integration/test_x86_16_package_exports.py \
	tests/integration/test_x86_16_bootstrap_import_order.py \
	tests/integration/test_x86_16_pipeline_contracts.py \
	tests/alias/test_x86_16_rewrite_boundary.py \
	tests/structuring/test_x86_16_indexed_stack_ranges.py \
	tests/validation/test_x86_16_validation_canonicalize.py \
	tests/lowering/test_x86_16_call_argument_stack_projection.py \
	tests/validation/test_x86_16_validation_call_argument_sources.py \
	tests/validation/test_x86_16_validation_calls.py \
	tests/validation/test_x86_16_validation_call_multiplicity.py \
	tests/validation/test_x86_16_validation_loop_condition_ir.py \
	tests/validation/test_x86_16_validation_branch_conditions.py \
	tests/validation/test_x86_16_validation_condition_coverage.py \
	tests/structuring/test_x86_16_composite_pretest_conditions.py \
	tests/structuring/test_x86_16_existing_loop_exit_conditions.py \
	tests/structuring/test_x86_16_terminal_loop_exit_conditions.py \
	tests/integration/test_x86_16_terminal_wide_validation.py \
	tests/frontend/test_x86_16_render_compat.py \
	tests/structuring/test_x86_16_structuring_condition_processor.py \
	tests/structuring/test_x86_16_structuring_condition_ownership.py \
	tests/structuring/test_x86_16_shared_loop_exit.py \
	tests/ir/test_x86_16_condition_decrement_fingerprints.py \
	tests/ir/test_x86_16_storage_or_fingerprints.py \
	tests/structuring/test_x86_16_structured_tag_projection.py \
	tests/validation/test_x86_16_validation_additive_semantic_casts.py \
	tests/validation/test_x86_16_materialized_condition_storage.py \
	tests/validation/test_x86_16_validation_control_flow.py \
	tests/validation/test_x86_16_validation_dataflow.py \
	tests/validation/test_x86_16_validation_semantic_failures.py \
	tests/validation/test_x86_16_validation_virtual_carriers.py \
	tests/validation/test_x86_16_validation_predicates.py \
	tests/validation/test_x86_16_validation_storage.py \
	tests/validation/test_x86_16_validation_required_memory_effects.py \
	tests/lowering/test_x86_16_runtime_segment_access.py \
	tests/cli/test_x86_16_sortd_indexed_aggregate_regression.py \
	tests/cli/test_x86_16_sortd_menu_pointer_table.py \
	tests/validation/test_x86_16_validation_manifest.py \
	tests/validation/test_x86_16_validation_helper_report.py \
	tests/frontend/test_x86_16_low_memory_regions.py \
	tests/cli/test_x86_16_recompilable_source_evidence.py \
	tests/cli/test_x86_16_recompilable_subset.py \
	tests/cli/test_x86_16_recompilable_storage_map.py \
	tests/cli/test_x86_16_recompilable_storage_objects.py \
	tests/lowering/test_x86_16_array_matching.py \
	tests/lowering/test_x86_16_struct_merging.py \
	tests/structuring/test_x86_16_structuring_condition_materialization.py \
	tests/ir/test_x86_16_condition_chain_refusal.py \
	tests/frontend/test_x86_16_recorded_return_argument_replay.py \
	tests/lowering/test_x86_16_stack_reload_instruction_ownership.py \
	tests/lowering/test_x86_16_runtime_call_results.py \
	tests/cli/test_x86_16_inbox_long_live.py \
	tests/structuring/test_x86_16_wide_return_condition_coverage.py \
	tests/structuring/test_x86_16_condition_exit_normalization.py \
	tests/structuring/test_x86_16_structuring_multi_arm_condition_ownership.py \
	tests/structuring/test_x86_16_local_condition_regions.py \
	tests/structuring/test_x86_16_structuring_loop_body_repair.py \
	tests/structuring/test_x86_16_total_return_suffixes.py \
	tests/structuring/test_x86_16_switch_loop_tail_breaks.py \
	tests/structuring/test_x86_16_wide_stack_condition_chains.py \
	tests/structuring/test_x86_16_wide_condition_ordering.py \
	tests/lowering/test_x86_16_wide_call_condition_source.py \
	tests/lowering/test_x86_16_wide_call_condition_capture.py \
	tests/integration/test_x86_16_wide_return_type_preservation.py \
	tests/lowering/test_x86_16_positive_bp_wide_arguments.py \
	tests/cli/test_x86_16_cli.py::test_decompile_function_disables_structuring_for_tiny_single_call_helpers \
	tests/cli/test_x86_16_cod_regressions.py::test_cod_runner_hotspots_fall_back_through_scan_safe_classifier \
	tests/structuring/test_x86_16_wide_call_condition_plan.py \
	tests/structuring/test_x86_16_wide_condition_provenance.py \
	tests/postprocess/test_x86_16_dce_optimization.py \
	tests/postprocess/test_x86_16_dce_noop_conditionals.py \
	tests/frontend/test_x86_16_packed_flags_state.py \
	tests/frontend/test_x86_16_packed_flags_cycles.py \
	tests/lowering/test_x86_16_packed_flags_call_evidence.py \
	tests/postprocess/test_x86_16_flags_physical_register_contract.py \
	tests/postprocess/test_x86_16_dce_lvalue_reads.py \
	tests/integration/test_x86_16_dead_local_prune.py \
	tests/integration/test_x86_16_dead_local_structured_reads.py \
	tests/postprocess/test_x86_16_local_liveness.py \
	tests/cli/test_cli_semantic_rollback.py \
	tests/cli/test_cli_rollback_snapshot.py \
	tests/cli/test_cli_call_inventory.py \
	tests/cli/test_cli_retry_outcome.py \
	tests/postprocess/test_x86_16_trivial_copy_optimization.py \
	tests/widening/test_x86_16_widening_copyprop.py \
	tests/widening/test_x86_16_widening_copyprop_width.py \
	tests/lowering/test_x86_16_linear_global_decomposition_cache.py \
	tests/widening/test_x86_16_widening_memory_fold.py \
	tests/widening/test_x86_16_stack_subview_call_writes.py \
	tests/widening/test_x86_16_stack_subview_projection.py \
	tests/widening/test_x86_16_stack_subview_coordinates.py \
	tests/widening/test_x86_16_stack_subview_projection_wide.py \
	tests/lowering/test_x86_16_indexed_load_subviews.py \
	tools/dev/tests/test_makefile_quiet_output.py \
	tests/widening/test_x86_16_widening_rules.py \
	tests/integration/test_x86_16_far_load_access_width.py \
	tests/cli/test_x86_16_generated_c_acceptance.py \
	tests/structuring/test_x86_16_structuring_grouping_report.py \
	tests/structuring/test_x86_16_structuring_grouped_refusal_report.py \
	tests/structuring/test_x86_16_structuring_sequences.py \
	tests/lowering/test_x86_16_stack_aggregate_objects.py \
	tests/lowering/test_x86_16_stack_prototype_codegen_api.py \
	tests/frontend/test_x86_16_stack_aggregate_coordinate_replay.py \
	tests/lowering/test_x86_16_positive_bp_argument_plan.py \
	tests/lowering/test_x86_16_stack_argument_identity.py \
	tests/lowering/test_x86_16_projected_stack_argument_identity.py \
	tests/lowering/test_x86_16_stack_declaration_identity.py \
	tests/lowering/test_x86_16_stack_lowering_contracts.py \
	tests/widening/test_x86_16_stack_memory_object_widening.py \
	tests/lowering/test_x86_16_stack_memory_ssa_lowering.py \
	tests/alias/test_x86_16_stack_memory_ssa_safety.py \
	tests/lowering/test_x86_16_unused_void_return_types.py \
	tests/lowering/test_x86_16_segmented_runtime_lowering.py \
	tests/ir/test_x86_16_ir_segmented_load_carriers.py \
	tests/ir/test_x86_16_reload_provenance_boundaries.py \
	tests/lowering/test_x86_16_assignment_lvalue_casts.py \
	tests/lowering/test_x86_16_stack_byte_writes.py \
	tests/lowering/test_x86_16_instruction_stack_write_width.py \
	tests/lowering/test_x86_16_semantic_cast.py \
	tests/ir/test_x86_16_condition_operand_signedness.py \
	tests/lowering/test_x86_16_condition_signedness_storage_width.py \
	tests/validation/test_x86_16_validation_argument_coordinates.py \
	tests/validation/test_x86_16_condition_storage_views.py \
	tests/lowering/test_x86_16_wide_stack_pair_coordinates.py \
	tests/lowering/test_x86_16_direct_stack_access_widths.py \
	tests/lowering/test_x86_16_stack_address_coordinates.py \
	tests/frontend/test_x86_16_native_stack_anchor.py \
	tests/lowering/test_x86_16_runtime_push_carrier.py \
	tests/lowering/test_x86_16_storage_prototype_snapshot.py \
	tests/lowering/test_x86_16_frame_prologue_carriers.py \
	tests/lowering/test_x86_16_frame_byte_carriers.py \
	tests/frontend/test_x86_16_native_segment_live_out.py \
	tests/frontend/test_x86_16_native_terminal_return_values.py \
	tests/frontend/test_x86_16_native_unsigned_constant_casts.py \
	tests/integration/test_x86_16_loadprogram_behavior.py \
	tests/integration/test_x86_16_configcrts_behavior.py \
	tests/integration/test_x86_16_mset_pos_behavior.py \
	tests/integration/test_x86_16_changeweather_behavior.py \
	tests/integration/test_x86_16_mouse_position_behavior.py \
	tests/frontend/test_x86_16_native_integer_operations.py \
	tests/integration/test_x86_16_ail_remainder.py \
	tests/alias/test_x86_16_stack_reference_offsets.py \
	tests/lowering/test_x86_16_les_stack_argument_behavior.py \
	tests/lowering/test_x86_16_string_corpus_anchors.py \
	tests/lowering/test_x86_16_segment_stack_restore_carriers.py \
	tests/lowering/test_x86_16_far_return_boundary_carriers.py \
	tests/lowering/test_x86_16_ss_traversal_contract.py \
	tests/lowering/test_x86_16_stack_prototype_wrapped_locals.py \
	tests/integration/test_x86_16_ast_traversal_coverage.py \
	tests/cli/test_x86_16_msetpos_behavior.py \
	tests/lowering/test_x86_16_gp_livein_authority.py \
	tests/integration/test_x86_16_anonymous_store_width.py \
	tests/ir/test_x86_16_ssa_register_displacements.py \
	tests/alias/test_x86_16_stack_coordinate_conflicts.py \
	tests/validation/test_x86_16_escaped_stack_validation.py \
	tests/cli/test_x86_16_bios_strict_compilation.py \
	tests/cli/test_x86_16_rep_store_codegen.py \
	tests/lowering/test_x86_16_runtime_store_scope.py \
	tests/cli/test_x86_16_string_timeout_fallback.py \
	tests/ir/test_x86_16_ir_memory_byte_ssa.py \
	tests/lowering/test_x86_16_string_codegen_override.py \
	tests/cli/test_cli_codegen_policy.py \
	tests/cli/test_x86_16_segment_call_effects.py \
	tests/lowering/test_x86_16_frame_carrier_liveness.py \
	tests/semantics/test_x86_16_unobserved_return_maker.py \
	tests/integration/test_x86_16_dosfunc_behavior.py \
	tests/integration/test_x86_16_heapsort_behavior.py \
	tests/integration/test_x86_16_quicksort_behavior.py \
	tests/integration/test_x86_16_sleep_behavior.py \
	tests/integration/test_x86_16_insertionsort_behavior.py \
	tests/lowering/test_x86_16_swapbars_behavior.py \
	tests/lowering/test_x86_16_gp_word_runtime.py \
	tests/lowering/test_x86_16_gp_word_assignment.py \
	tests/ir/test_x86_16_address_base_snapshots.py \
	tests/integration/test_x86_16_reinitbars_execution.py \
	tests/integration/test_x86_16_setgear_behavior.py \
	tests/integration/test_x86_16_tidshowrange_behavior.py \
	tests/cli/test_x86_16_cli.py::test_decompile_cli_recovers_setgear_guard_logic \
	tests/ir/test_x86_16_memory_ssa_address_provenance.py \
	tests/ir/test_x86_16_ir_stack_frame.py \
	tests/integration/test_x86_16_consumed_push_lvalues.py \
	tests/cli/test_x86_16_sortdemo_decompiler_status.py \
	tests/cli/test_x86_16_heapsort_widening_regression.py \
	tests/lowering/test_x86_16_global_declarations.py \
	tests/widening/test_x86_16_alias_global_object_layout.py \
	tests/cli/test_indexed_alias_program_parallel.py \
	tests/widening/test_x86_16_global_object_layout.py \
	tests/lowering/test_x86_16_project_type_contracts.py \
	tests/lowering/test_x86_16_function_pointer_parameters.py \
	tests/lowering/test_x86_16_callee_global_object_interface.py \
	tests/lowering/test_x86_16_global_object_program_requirement.py \
	tests/lowering/test_x86_16_callee_global_object_sources.py \
	tests/lowering/test_x86_16_global_object_source_codec.py \
	tests/lowering/test_x86_16_callee_pointer_evidence.py \
	tests/lowering/test_x86_16_callee_pointer_codec.py \
	tests/alias/test_x86_16_callsite_summary_codec.py \
	tests/cli/test_x86_16_callsite_summary_program.py \
	tests/lowering/test_x86_16_project_callee_callsite_collection.py \
	tests/cli/test_project_callee_callsite_transport.py \
	tests/cli/test_serial_clean_worker_callsite_evidence.py \
	tests/cli/test_project_argument_evidence_ranges.py \
	tests/integration/test_x86_16_project_global_object_source_collection.py \
	tests/integration/test_indexed_alias_source_collection_scope.py \
	tests/cli/test_project_global_source_evidence_transport.py \
	tests/cli/test_serial_clean_worker_global_source_evidence.py \
	tests/structuring/test_x86_16_direct_stack_move_branches.py \
	tests/structuring/test_x86_16_direct_stack_move_ownership_priority.py \
	tests/lowering/test_x86_16_direct_stack_reload_idempotence.py \
	tests/lowering/test_x86_16_direct_global_store_prefilter.py \
	tests/integration/test_x86_16_pipeline_result_contracts.py \
	tests/postprocess/test_x86_16_postprocess_validation_policy.py \
	tests/postprocess/test_x86_16_postprocess_bootstrap_orchestration.py \
	tests/postprocess/test_x86_16_postprocess_pass_transaction.py \
	tests/postprocess/test_x86_16_postprocess_rollback_snapshot_cache.py \
	tests/postprocess/test_x86_16_postprocess_runtime_config.py \
	tests/validation/test_x86_16_control_flow_ast_index.py \
	tests/lowering/test_x86_16_runtime_memory_helpers.py \
	tests/integration/test_x86_16_indexed_stack_frame_terms.py \
	tests/structuring/test_x86_16_loop_condition_materialization.py \
	tests/structuring/test_x86_16_pretest_loop_condition_ownership.py \
	tests/structuring/test_x86_16_loop_condition_block_identity.py \
	tests/integration/test_x86_16_nested_loop_behavior.py \
	tests/integration/test_x86_16_goto_accumulate_behavior.py \
	tests/lowering/test_x86_16_stack_update_scope_guard.py \
	tests/structuring/test_x86_16_instruction_fragment_placement.py \
	tests/lowering/test_x86_16_call_return_stack_stores.py \
	tests/structuring/test_x86_16_direct_stack_move_loop_entries.py \
	tests/structuring/test_x86_16_direct_stack_move_pretest_body.py \
	tests/structuring/test_x86_16_direct_stack_move_pretest_initializers.py \
	tests/postprocess/test_x86_16_stack_probe_local_preservation.py \
	tests/structuring/test_x86_16_casted_loop_induction.py \
	tests/structuring/test_x86_16_direct_stack_move_loops.py \
	tests/lowering/test_x86_16_direct_stack_update_groups.py \
	tests/alias/test_x86_16_indexed_address_copies.py \
	tests/integration/test_x86_16_indexed_address_evidence.py \
	tests/alias/test_x86_16_indexed_address_aliases.py \
	tests/ir/test_x86_16_indexed_address_range_candidates.py \
	tests/widening/test_x86_16_indexed_global_object_program_ranges.py \
	tests/widening/test_x86_16_indexed_global_object_ranges.py \
	tests/lowering/test_x86_16_bounded_global_array_declarations.py \
	tests/lowering/test_x86_16_indexed_address_collector_parity.py \
	tests/lowering/test_x86_16_indexed_address_parity_inventory.py \
	tests/cli/test_x86_16_sortd_indexed_address_parity_inventory.py \
	tests/lowering/test_x86_16_cod_global_identity.py \
	tests/lowering/test_x86_16_segmented_global_loads.py \
	tests/lowering/test_x86_16_wide_store_call_preservation.py \
	tests/cli/test_x86_16_decompilation_cache_surface.py \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_heapsort_materializes_call_arguments_without_stack_leaks \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_percolateup_materializes_parent_once_and_preserves_calls \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_reinitbars_preserves_clock_store_loop_and_validation_contract \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_drawtime_materializes_clock_return_to_clfinish_once \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_initmenu_pause_zero_guard_has_no_raw_flag_carrier \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_insertionsort_word_stores_materialized_without_raw_high_byte_memory \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_drawbar_word_stride_byte_fields_validate_without_indexed_mem_helper_syntax \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_percolatedown_direct_global_increment_materialized \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_swapbars_materializes_arguments_without_dead_setup_artifacts \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_swaps_preserves_binary_proven_global_increment_and_pointer_swap \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_bubblesort_sidecar_free_preserves_direct_ds_row_count \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_exchangesort_sidecar_free_folds_alias_proven_high_byte \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_drawbar_sidecar_free_materializes_stack_buffer_and_conservative_return \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_drawframe_sidecar_free_materializes_segmented_buffer_calls \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_reinitbars_sidecar_free_materializes_indexed_global_copy \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_drawtime_sidecar_free_materializes_wide_delay_arguments \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_insertionsort_sidecar_free_splits_header_and_rebases_source \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_initmenu_sidecar_free_preserves_calls_and_compiles \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortdemo_runmenu_default_direct_path_validates_without_temp_carrier_fallback \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_runmenu_sidecar_free_preserves_binary_escape_exit \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_sidecar_free_initbars_preserves_binary_stack_array \
	tests/cli/test_x86_16_sortdemo_regressions.py::test_sortd_sidecar_free_swapbars_recovers_binary_stack_arguments \
	tests/postprocess/test_x86_16_decompiler_postprocess_callsites.py::test_normalize_call_target_names_drops_detached_angr_callee_func \
	tests/postprocess/test_x86_16_decompiler_postprocess_callsites.py::test_callsite_stats_count_stale_target_rejection \
	tests/integration/test_x86_16_access_trait_arrays.py \
	tests/integration/test_x86_16_access_trait_policy.py \
	tests/integration/test_x86_16_access_trait_strides.py \
	tests/postprocess/test_x86_16_decompiler_postprocess_utils.py \
	tests/alias/test_x86_16_segmented_memory.py \
	tests/lowering/test_x86_16_type_equivalence_classes.py \
	tools/compiler_toolchain/tests/test_msc6_toolchain_lock.py \
	tests/cli/test_x86_16_cod_module_caller_evidence.py \
	tests/ir/test_x86_16_cfg_direct_jump.py \
	tests/semantics/test_x86_16_cfg_direct_call.py \
	tests/frontend/test_x86_16_frontend_function_boundary_index.py \
	tests/frontend/test_x86_16_frontend_instruction_reachability.py \
	tests/integration/test_x86_16_function_callsite_inventory.py \
	tests/semantics/test_x86_16_return_compat_counters.py \
	tests/frontend/test_x86_16_return_expression_preservation.py \
	tests/lowering/test_x86_16_overlay_return_behavior.py \
	tests/structuring/test_x86_16_boolean_condition_ites.py \
	tests/lowering/test_x86_16_direct_stack_move_indexed_use.py \
	tests/frontend/test_x86_16_msvc_x87_interrupts.py \
	tests/semantics/test_x86_16_return_stack_address_compat.py \
	tests/lowering/test_x86_16_stack_prototype_layout.py \
	tests/cli/test_accepted_payload_integrity.py \
	tests/cli/test_acceptance_scorecard.py \
	tests/cli/test_tail_validation_display_outcome.py

# Focused owner tests are appended while the legacy QA lists remain curated.
LINTERS_DEV_MYPY_FILES += inertia/lowering/return_witness_source.py
QA_TYPED_FILES += inertia/lowering/return_witness_source.py
QA_RUFF_TARGETS += inertia/lowering/return_witness_source.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/argument_frame_base.py
QA_TYPED_FILES += inertia/lowering/argument_frame_base.py
QA_RUFF_TARGETS += inertia/lowering/argument_frame_base.py tests/lowering/test_x86_16_argument_frame_base.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_argument_frame_base.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/far_pointer_type.py
QA_TYPED_FILES += inertia/lowering/far_pointer_type.py
QA_RUFF_TARGETS += inertia/lowering/far_pointer_type.py
QA_TYPED_FILES += tools/ada_script/__init__.py tools/ada_script/cli.py tools/ada_script/signatures.py tools/ada_script/contracts.py
QA_RUFF_TARGETS += tools/ada_script/__init__.py tools/ada_script/cli.py tools/ada_script/signatures.py tools/ada_script/contracts.py tests/integration/test_ada_signature_integration.py

QA_TYPED_FILES +=
QA_RUFF_TARGETS +=
LINTERS_DEV_MYPY_FILES += tools/compiler_toolchain/compiler_coverage_cross_unit.py
QA_RUFF_TARGETS += tools/compiler_toolchain/tests/test_compiler_coverage_cross_unit.py
QA_PYTEST_TARGETS += tools/compiler_toolchain/tests/test_compiler_coverage_cross_unit.py
LINTERS_DEV_MYPY_FILES += tools/compiler_toolchain/compiler_coverage_provenance.py tools/compiler_toolchain/compiler_coverage_runner.py
QA_RUFF_TARGETS += tools/compiler_toolchain/tests/test_compiler_coverage_provenance.py
QA_PYTEST_TARGETS += tools/compiler_toolchain/tests/test_compiler_coverage_provenance.py tools/compiler_toolchain/tests/test_compiler_coverage_runner.py
LINTERS_DEV_MYPY_FILES += inertia/ir/logical_word_read_reaching_value.py
QA_TYPED_FILES += inertia/ir/logical_word_read_reaching_value.py
QA_RUFF_TARGETS += inertia/ir/logical_word_read_reaching_value.py tests/ir/test_x86_16_logical_word_read_reaching_value.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_logical_word_read_reaching_value.py
QA_RUFF_TARGETS += tests/integration/test_x86_16_high_byte_remnant_walk.py
QA_PYTEST_TARGETS += tests/integration/test_x86_16_high_byte_remnant_walk.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/binary_callback_targets.py
QA_TYPED_FILES += inertia/lowering/binary_callback_targets.py
QA_RUFF_TARGETS += inertia/lowering/binary_callback_targets.py tests/integration/test_x86_16_binary_callback_targets.py
QA_PYTEST_TARGETS += tests/integration/test_x86_16_binary_callback_targets.py
QA_RUFF_TARGETS += tests/lowering/test_x86_16_far_callback_call_shape.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_far_callback_call_shape.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/far_callback_call_shape.py
QA_TYPED_FILES += inertia/lowering/far_callback_call_shape.py
QA_RUFF_TARGETS += inertia/lowering/far_callback_call_shape.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/far_callback_call_value.py inertia/lowering/binary_far_callback_targets.py
QA_TYPED_FILES += inertia/lowering/far_callback_call_value.py inertia/lowering/binary_far_callback_targets.py
QA_RUFF_TARGETS += inertia/lowering/far_callback_call_value.py inertia/lowering/binary_far_callback_targets.py tests/lowering/test_x86_16_far_callback_call_value.py tests/lowering/test_x86_16_binary_far_callback_targets.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_far_callback_call_value.py tests/lowering/test_x86_16_binary_far_callback_targets.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/far_callback_call_materialization.py
QA_TYPED_FILES += inertia/lowering/far_callback_call_materialization.py
QA_RUFF_TARGETS += inertia/lowering/far_callback_call_materialization.py tests/lowering/test_x86_16_far_callback_call_materialization.py tests/integration/test_x86_16_typed_call_argument_path_conditions.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_far_callback_call_materialization.py tests/integration/test_x86_16_typed_call_argument_path_conditions.py
LINTERS_DEV_MYPY_FILES += inertia/semantics/terminal_boundary_paths.py
QA_TYPED_FILES +=
QA_RUFF_TARGETS +=
LINTERS_DEV_MYPY_FILES += inertia/frontend/x86_16/frontend_boundary_transport.py
QA_TYPED_FILES += inertia/frontend/x86_16/frontend_boundary_transport.py
QA_RUFF_TARGETS += inertia/frontend/x86_16/frontend_boundary_transport.py tests/frontend/test_x86_16_frontend_boundary_transport.py
QA_PYTEST_TARGETS += tests/frontend/test_x86_16_frontend_boundary_transport.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/interprocedural_storage_return_discard.py
QA_TYPED_FILES += inertia/lowering/interprocedural_storage_return_discard.py
QA_RUFF_TARGETS += inertia/lowering/interprocedural_storage_return_discard.py tests/lowering/test_x86_16_interprocedural_discarded_return.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_interprocedural_discarded_return.py
LINTERS_DEV_MYPY_FILES += inertia/frontend/x86_16/frontend_caller_entry_identity.py
QA_TYPED_FILES += inertia/frontend/x86_16/frontend_caller_entry_identity.py
QA_RUFF_TARGETS += inertia/frontend/x86_16/frontend_caller_entry_identity.py tests/frontend/test_x86_16_frontend_caller_entry_identity.py
QA_PYTEST_TARGETS += tests/frontend/test_x86_16_frontend_caller_entry_identity.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/gp_register_versions.py
QA_TYPED_FILES += inertia/lowering/gp_register_versions.py
QA_RUFF_TARGETS += inertia/lowering/gp_register_versions.py tests/lowering/test_x86_16_gp_register_versions.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_gp_register_versions.py
LINTERS_DEV_MYPY_FILES += inertia/validation/validation_indexed_bytes.py
QA_TYPED_FILES += inertia/validation/validation_indexed_bytes.py
QA_RUFF_TARGETS += inertia/validation/validation_indexed_bytes.py tests/validation/test_x86_16_validation_indexed_bytes.py
QA_PYTEST_TARGETS += tests/validation/test_x86_16_validation_indexed_bytes.py
QA_RUFF_TARGETS += tests/alias/test_x86_16_stack_restore_value_identity.py
QA_PYTEST_TARGETS += tests/alias/test_x86_16_stack_restore_value_identity.py
LINTERS_DEV_MYPY_FILES += inertia/postprocess/bitwise_terms.py
QA_TYPED_FILES +=
QA_RUFF_TARGETS +=
LINTERS_DEV_MYPY_FILES += inertia/alias/condition_register_storage.py
QA_TYPED_FILES +=
QA_TYPED_FILES +=
QA_TYPED_FILES +=
QA_RUFF_TARGETS +=
QA_RUFF_TARGETS +=
QA_RUFF_TARGETS +=
QA_RUFF_TARGETS += tests/alias/test_x86_16_condition_register_source_bindings.py tests/alias/test_x86_16_condition_register_byte_extension.py
QA_PYTEST_TARGETS += tests/alias/test_x86_16_condition_register_source_bindings.py tests/alias/test_x86_16_condition_register_byte_extension.py
QA_RUFF_TARGETS += tests/semantics/test_x86_16_scalar_byte_behavior.py
QA_PYTEST_TARGETS += tests/semantics/test_x86_16_scalar_byte_behavior.py
QA_RUFF_TARGETS += tests/cli/test_sortd_generated_sort_core_gate.py
QA_PYTEST_TARGETS += tests/cli/test_sortd_generated_sort_core_gate.py
QA_PYTEST_TARGETS += tests/postprocess/test_x86_16_dce_purity.py
QA_PYTEST_TARGETS += tests/validation/test_x86_16_tail_validation_alias_cycles.py
QA_RUFF_TARGETS += tests/validation/test_x86_16_tail_validation_alias_cycles.py
QA_RUFF_TARGETS += tests/validation/test_x86_16_validation_owned_condition_precision.py
QA_PYTEST_TARGETS += tests/validation/test_x86_16_validation_owned_condition_precision.py
QA_RUFF_TARGETS += tests/cli/test_generated_translation_unit_gate.py
QA_PYTEST_TARGETS += tools/compiler_toolchain/tests/test_msc6_runtime_gate_artifacts.py
QA_PYTEST_TARGETS += tests/cli/test_x86_16_cod_regressions.py::test_cod_loadprog_preserves_binary_arguments_and_recompiles
QA_RUFF_TARGETS += \
	tests/frontend/test_x86_16_symbolic_value_boundaries.py \
	tools/dev/tests/test_make_linter_inputs.py \
	tests/frontend/test_x86_16_direction_flag_execution.py \
	tests/frontend/test_x86_16_stack_helpers.py \
	tests/validation/test_x86_16_structuring_pass_validation.py \
	tests/cli/test_x86_16_helper_abi.py \
	tests/lowering/test_x86_16_fixed_stack_probe_frames.py \
	tests/lowering/test_x86_16_stack_projection_renaming.py \
	tests/validation/test_x86_16_tail_validation_projection_coordinates.py \
	tests/validation/test_x86_16_validation_identical_return_guards.py \
	tests/widening/test_x86_16_widening_copyprop_returns.py \
	tools/dev/tests/test_architecture_import_attestation.py \
	tests/structuring/test_x86_16_tagged_subtree_projection.py \
	tests/postprocess/test_x86_16_dce_purity.py \
	tests/lowering/test_x86_16_condition_artifact_reuse.py \
	tests/lowering/test_x86_16_indexed_global_stack_coordinates.py \
	tests/semantics/test_x86_16_status_flag_cfg_liveness.py \
	tests/ir/test_x86_16_status_flag_cfg_projection.py \
	tests/structuring/test_x86_16_typed_switch_seqnode.py \
	tests/structuring/test_x86_16_switch_definition_coverage.py \
	tests/frontend/test_x86_16_status_flag_lift_context.py \
	tests/semantics/test_x86_16_status_flag_liveness.py \
	tests/frontend/test_x86_16_flag_lookahead_boundaries.py \
	tests/frontend/test_x86_16_msc_caller_cleanup.py \
	tests/postprocess/test_x86_16_decompiler_postprocess_calls.py \
	tests/frontend/test_x86_16_alu_effect_order.py \
	tests/lowering/test_x86_16_carry_predicate_execution.py \
	tests/integration/test_x86_16_simple_incdec_value_provenance.py \
	tests/frontend/test_x86_16_concrete_loop_conditions.py \
	tests/frontend/test_x86_16_lifting_opcode_tables.py \
	tests/validation/test_x86_16_callsite_completeness_validation.py \
	tests/lowering/test_x86_16_direct_global_call_return_materialization.py \
	tests/frontend/test_x86_16_borrow_verification.py \
	tools/compiler_toolchain/tests/test_build_msc6_artifact_names.py \
	tests/lowering/test_x86_16_call_argument_carrier_liveness.py \
	tests/lowering/test_x86_16_callee_saved_frame.py \
	tests/lowering/test_x86_16_callee_saved_frame_validation.py \
	tests/lowering/test_x86_16_canonical_frame_carriers.py \
	tests/lowering/test_x86_16_canonical_frame_setup_carriers.py \
	tests/cli/test_x86_16_cod_module_caller_evidence.py \
	tools/compiler_toolchain/tests/test_msc6_toolchain_lock.py \
	tests/semantics/test_x86_16_return_compat_counters.py \
	tests/frontend/test_x86_16_return_expression_preservation.py \
	tests/lowering/test_x86_16_overlay_return_behavior.py \
	tests/ir/test_x86_16_cfg_direct_jump.py \
	tests/semantics/test_x86_16_cfg_direct_call.py \
	tests/frontend/test_x86_16_frontend_function_boundary_index.py \
	tests/frontend/test_x86_16_frontend_instruction_reachability.py \
	tests/semantics/test_x86_16_callsite_block_inventory_reuse.py \
	tests/integration/test_x86_16_function_callsite_inventory.py \
	tests/frontend/test_x86_16_analysis_helper_direct_blocks.py \
	tests/cli/test_x86_16_stitched_direct_blocks.py \
	tests/cli/test_cli_decompilation_render_refresh.py \
	tests/cli/test_project_evidence_transport.py \
	tests/lowering/test_x86_16_condition_fact_arbitration.py \
	tests/frontend/test_x86_16_direct_global_zero_index_replay.py \
	tests/structuring/test_x86_16_direct_stack_immediate_branches.py \
	tests/frontend/test_x86_16_lifter_condition_cache.py \
	tests/frontend/test_x86_16_lifter_cython_dependency.py \
	tests/integration/test_x86_16_msc6_sort_patterns_regression.py \
	tests/lowering/test_x86_16_stack_pointer_snapshot.py \
	tests/cli/test_x86_16_cod_extract_control_flow.py \
	tests/lowering/test_x86_16_software_interrupt_pipeline.py \
	tests/validation/test_x86_16_software_interrupt_validation.py \
	tests/lowering/test_x86_16_terminal_register_return_values.py \
	tests/semantics/test_x86_16_terminal_register_return_semantics.py \
	tests/semantics/test_x86_16_terminal_register_restore.py \
	tests/semantics/test_x86_16_terminal_side_effect_returns.py \
	tests/semantics/test_x86_16_terminal_return_passthrough.py \
	tests/lowering/test_x86_16_terminal_return_expression_scaling.py \
	tests/semantics/test_x86_16_call_return_frame_effects.py \
	tests/alias/test_x86_16_register_reaching_source.py \
	tests/alias/test_x86_16_register_source_memory_dependencies.py \
	tests/alias/test_x86_16_register_source_wide_clobbers.py \
	tests/semantics/test_x86_16_register_entry_overwrite.py \
	tests/lowering/test_x86_16_consumed_stack_address_setup.py \
	tests/ir/test_x86_16_register_source_block_inventory.py \
	tests/frontend/test_x86_16_patch_direct_calls.py \
	tests/structuring/test_x86_16_stored_call_return_early_exit.py \
	tests/validation/test_x86_16_validation_call_return_storage.py

QA_PYTEST_TARGETS += \
	tools/dev/tests/test_make_linter_inputs.py \
	tests/frontend/test_x86_16_symbolic_value_boundaries.py \
	tests/frontend/test_x86_16_direction_flag_execution.py \
	tests/frontend/test_x86_16_stack_helpers.py \
	tests/validation/test_x86_16_structuring_pass_validation.py \
	tests/cli/test_x86_16_helper_abi.py \
	tests/lowering/test_x86_16_fixed_stack_probe_frames.py \
	tests/alias/test_x86_16_register_source_memory_dependencies.py \
	tests/integration/test_x86_16_tail_callsite_inventory.py \
	tests/alias/test_x86_16_register_source_wide_clobbers.py \
	tests/semantics/test_x86_16_register_entry_overwrite.py \
	tests/lowering/test_x86_16_consumed_stack_address_setup.py \
	tests/lowering/test_x86_16_stack_projection_renaming.py \
	tests/validation/test_x86_16_tail_validation_projection_coordinates.py \
	tests/validation/test_x86_16_validation_identical_return_guards.py \
	tests/widening/test_x86_16_widening_copyprop_returns.py \
	tools/dev/tests/test_architecture_import_attestation.py \
	tests/structuring/test_x86_16_tagged_subtree_projection.py \
	tests/lowering/test_x86_16_indexed_global_stack_coordinates.py \
	tests/semantics/test_x86_16_status_flag_cfg_liveness.py \
	tests/ir/test_x86_16_status_flag_cfg_projection.py \
	tests/structuring/test_x86_16_typed_switch_seqnode.py \
	tests/structuring/test_x86_16_switch_definition_coverage.py \
	tests/frontend/test_x86_16_status_flag_lift_context.py \
	tests/semantics/test_x86_16_status_flag_liveness.py \
	tests/frontend/test_x86_16_flag_lookahead_boundaries.py \
	tests/frontend/test_x86_16_msc_caller_cleanup.py \
	tests/postprocess/test_x86_16_decompiler_postprocess_calls.py::test_materialize_callsite_stack_arguments_requires_exact_consumed_push_evidence \
	tests/postprocess/test_x86_16_decompiler_postprocess_calls.py::test_materialize_callsite_stack_arguments_keeps_unproven_far_pointer_stores \
	tests/postprocess/test_x86_16_decompiler_postprocess_calls.py::test_materialize_callsite_stack_arguments_keeps_unproven_scalar_byte_pair_stores \
	tests/frontend/test_x86_16_alu_effect_order.py \
	tests/lowering/test_x86_16_carry_predicate_execution.py \
	tests/integration/test_x86_16_simple_incdec_value_provenance.py \
	tests/frontend/test_x86_16_concrete_loop_conditions.py \
	tests/frontend/test_x86_16_lifting_opcode_tables.py \
	tests/validation/test_x86_16_callsite_completeness_validation.py \
	tests/frontend/test_x86_16_borrow_verification.py \
	tools/compiler_toolchain/tests/test_build_msc6_artifact_names.py \
	tests/lowering/test_x86_16_call_argument_carrier_liveness.py \
	tests/lowering/test_x86_16_callee_saved_frame.py \
	tests/semantics/test_x86_16_callsite_block_inventory_reuse.py \
	tests/lowering/test_x86_16_canonical_frame_carriers.py \
	tests/lowering/test_x86_16_canonical_frame_setup_carriers.py \
	tests/cli/test_x86_16_cod_extract_control_flow.py \
	tests/frontend/test_x86_16_lifter_condition_cache.py \
	tests/frontend/test_x86_16_lifter_cython_dependency.py \
	tests/lowering/test_x86_16_stack_pointer_snapshot.py \
	tests/lowering/test_x86_16_software_interrupt_pipeline.py \
	tests/validation/test_x86_16_software_interrupt_validation.py \
	tests/lowering/test_x86_16_terminal_register_return_values.py \
	tests/semantics/test_x86_16_terminal_register_return_semantics.py \
	tests/semantics/test_x86_16_terminal_register_restore.py \
	tests/semantics/test_x86_16_terminal_side_effect_returns.py \
	tests/semantics/test_x86_16_terminal_return_passthrough.py \
	tests/lowering/test_x86_16_terminal_return_expression_scaling.py \
	tests/semantics/test_x86_16_call_return_frame_effects.py \
	tests/alias/test_x86_16_register_reaching_source.py \
	tests/frontend/test_x86_16_patch_direct_calls.py \
	tests/structuring/test_x86_16_stored_call_return_early_exit.py \
	tests/validation/test_x86_16_validation_call_return_storage.py

QA_RUFF_TARGETS += inertia/frontend/x86_16/pklite.py inertia/cli/catalog_policy.py
QA_TYPED_FILES += inertia/cli/external_unpacker_cache.py
QA_RUFF_TARGETS += inertia/cli/external_unpacker_cache.py
QA_PYTEST_TARGETS += tests/cli/test_x86_16_pklite.py tests/cli/test_cli_catalog_budget.py tools/compiler_toolchain/tests/test_missing_dos_toolchain.py

LINTERS_DEV_MYPY_FILES += inertia/structuring/string_io_loop_carriers.py inertia/validation/validation_condition_chains.py
QA_TYPED_FILES +=  inertia/validation/validation_condition_chains.py
QA_RUFF_TARGETS +=  inertia/validation/validation_condition_chains.py
LINTERS_DEV_MYPY_FILES += inertia/ir/stack_argument_modular_use.py inertia/ir/stack_argument_modular_use_contracts.py inertia/ir/stack_argument_modular_use_flow.py
QA_TYPED_FILES += inertia/ir/stack_argument_modular_use.py inertia/ir/stack_argument_modular_use_contracts.py inertia/ir/stack_argument_modular_use_flow.py
QA_RUFF_TARGETS += inertia/ir/stack_argument_modular_use.py inertia/ir/stack_argument_modular_use_contracts.py inertia/ir/stack_argument_modular_use_flow.py tests/ir/test_x86_16_stack_argument_modular_use.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_stack_argument_modular_use.py
QA_RUFF_TARGETS += tests/ir/test_x86_16_modular_unary_controls.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_modular_unary_controls.py
QA_RUFF_TARGETS += tests/ir/test_x86_16_indexed_copy_projection_controls.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_indexed_copy_projection_controls.py
QA_RUFF_TARGETS += tests/lowering/test_x86_16_physical_push_controls.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_physical_push_controls.py
QA_RUFF_TARGETS += tests/alias/test_x86_16_entry_affine_projection_controls.py
QA_PYTEST_TARGETS += tests/alias/test_x86_16_entry_affine_projection_controls.py
QA_RUFF_TARGETS += tests/alias/test_x86_16_stack_escape_unary_controls.py
QA_PYTEST_TARGETS += tests/alias/test_x86_16_stack_escape_unary_controls.py
QA_RUFF_TARGETS += tests/semantics/test_x86_16_carry_unary_controls.py tests/semantics/test_x86_16_carry_conversion_soundness.py
QA_PYTEST_TARGETS += tests/semantics/test_x86_16_carry_unary_controls.py tests/semantics/test_x86_16_carry_conversion_soundness.py
QA_RUFF_TARGETS += tests/alias/test_x86_16_carry_destination_controls.py tests/frontend/test_x86_16_retained_boundary_controls.py
QA_PYTEST_TARGETS += tests/alias/test_x86_16_carry_destination_controls.py tests/frontend/test_x86_16_retained_boundary_controls.py
LINTERS_DEV_MYPY_FILES += inertia/ir/stack_argument_scaled_return.py
QA_TYPED_FILES += inertia/ir/stack_argument_scaled_return.py
QA_RUFF_TARGETS += inertia/ir/stack_argument_scaled_return.py tests/ir/test_x86_16_stack_argument_scaled_return.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_stack_argument_scaled_return.py
LINTERS_DEV_MYPY_FILES += inertia/semantics/direct_ret_call_effect.py
LINTERS_DEV_MYPY_FILES += inertia/semantics/bp_call_preservation.py
QA_TYPED_FILES +=
QA_TYPED_FILES +=
QA_RUFF_TARGETS +=
QA_RUFF_TARGETS +=  tests/semantics/test_x86_16_bp_call_preservation.py
QA_PYTEST_TARGETS += tests/semantics/test_x86_16_bp_call_preservation.py
QA_RUFF_TARGETS += tests/lowering/test_x86_16_far_stack_probe_aggregate.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_far_stack_probe_aggregate.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/far_return_pointer_census.py inertia/lowering/far_return_pointer_use.py inertia/lowering/far_return_pointer_use_contracts.py
QA_TYPED_FILES += inertia/lowering/far_return_pointer_census.py inertia/lowering/far_return_pointer_use.py inertia/lowering/far_return_pointer_use_contracts.py
QA_RUFF_TARGETS += inertia/lowering/far_return_pointer_census.py inertia/lowering/far_return_pointer_use.py inertia/lowering/far_return_pointer_use_contracts.py tests/lowering/test_x86_16_far_return_pointer_use.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_far_return_pointer_use.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/far_return_expression_binding.py
QA_TYPED_FILES += inertia/lowering/far_return_expression_binding.py
QA_RUFF_TARGETS += inertia/lowering/far_return_expression_binding.py tests/lowering/test_x86_16_far_return_expression_binding.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_far_return_expression_binding.py

LINTERS_DEV_MYPY_FILES += inertia/lowering/near_scaled_return_candidate.py
QA_TYPED_FILES += inertia/lowering/near_scaled_return_candidate.py
QA_RUFF_TARGETS += inertia/lowering/near_scaled_return_candidate.py tests/lowering/test_x86_16_near_scaled_return_candidate.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_near_scaled_return_candidate.py

LINTERS_DEV_MYPY_FILES += inertia/lowering/near_return_c_ast_congruence.py
QA_TYPED_FILES += inertia/lowering/near_return_c_ast_congruence.py
QA_RUFF_TARGETS += inertia/lowering/near_return_c_ast_congruence.py tests/lowering/test_x86_16_near_return_c_ast_congruence.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_near_return_c_ast_congruence.py

LINTERS_DEV_MYPY_FILES += inertia/lowering/near_return_segment_use.py
QA_TYPED_FILES += inertia/lowering/near_return_segment_use.py
QA_RUFF_TARGETS += inertia/lowering/near_return_segment_use.py tests/lowering/test_x86_16_near_return_segment_use.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_near_return_segment_use.py

LINTERS_DEV_MYPY_FILES += inertia/lowering/near_pointer_stack_input_segment.py
QA_TYPED_FILES += inertia/lowering/near_pointer_stack_input_segment.py
QA_RUFF_TARGETS += inertia/lowering/near_pointer_stack_input_segment.py tests/lowering/test_x86_16_near_pointer_stack_input_segment.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_near_pointer_stack_input_segment.py

LINTERS_DEV_MYPY_FILES += inertia/lowering/near_return_expression.py inertia/lowering/near_return_selector.py
QA_TYPED_FILES += inertia/lowering/near_return_expression.py inertia/lowering/near_return_selector.py
QA_RUFF_TARGETS += inertia/lowering/near_return_expression.py inertia/lowering/near_return_selector.py tests/lowering/test_x86_16_near_return_expression.py tests/frontend/test_x86_16_near_return_expression_replay.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_near_return_expression.py tests/frontend/test_x86_16_near_return_expression_replay.py

LINTERS_DEV_MYPY_FILES += inertia/lowering/near_return_entry_selector.py
QA_TYPED_FILES += inertia/lowering/near_return_entry_selector.py
QA_RUFF_TARGETS += inertia/lowering/near_return_entry_selector.py tests/lowering/test_x86_16_near_return_entry_selector.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_near_return_entry_selector.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/near_return_body_preflight.py
QA_TYPED_FILES += inertia/lowering/near_return_body_preflight.py
QA_RUFF_TARGETS += inertia/lowering/near_return_body_preflight.py tests/lowering/test_x86_16_near_return_body_preflight.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_near_return_body_preflight.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/storage_word_input_binding.py
QA_TYPED_FILES += inertia/lowering/storage_word_input_binding.py
QA_RUFF_TARGETS += inertia/lowering/storage_word_input_binding.py tests/lowering/test_x86_16_storage_word_input_binding.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_storage_word_input_binding.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/near_pointer_value_runtime.py inertia/lowering/near_pointer_argument_values.py
QA_TYPED_FILES += inertia/lowering/near_pointer_value_runtime.py
QA_RUFF_TARGETS += inertia/lowering/near_pointer_value_runtime.py

LINTERS_DEV_MYPY_FILES += inertia/ir/direct_call_segment_entry.py
LINTERS_DEV_MYPY_FILES += inertia/ir/ir_boundary_cfg.py
QA_TYPED_FILES += inertia/ir/ir_boundary_cfg.py
QA_RUFF_TARGETS += inertia/ir/ir_boundary_cfg.py tests/ir/test_x86_16_ir_boundary_cfg.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_ir_boundary_cfg.py
LINTERS_DEV_MYPY_FILES += inertia/ir/no_effect_instructions.py
QA_TYPED_FILES += inertia/ir/no_effect_instructions.py
QA_RUFF_TARGETS += inertia/ir/no_effect_instructions.py tests/ir/test_nop_census_8616.py tests/frontend/test_nop_native_binding.py tests/ir/test_nop_cache_cost.py
QA_PYTEST_TARGETS += tests/ir/test_nop_census_8616.py tests/frontend/test_nop_native_binding.py tests/ir/test_nop_cache_cost.py
LINTERS_DEV_MYPY_FILES += inertia/ir/segment_effect_closure.py
QA_TYPED_FILES += inertia/ir/segment_effect_closure.py
QA_RUFF_TARGETS += inertia/ir/segment_effect_closure.py tests/ir/test_x86_16_segment_effect_closure.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_segment_effect_closure.py
SCOPED_IR_OWNERS := \
	inertia/frontend/x86_16/frontend_local_call_evidence.py \
	inertia/frontend/x86_16/mz_static_boot.py \
	inertia/cli/mz_static_intake.py \
	inertia/frontend/x86_16/frontend_near_return_continuation.py \
	inertia/ir/near_return_continuation_view.py \
	inertia/ir/scoped_control_obligations.py \
	tools/dosunit/catalog/real16_scoped_invocation.py \
	inertia/frontend/x86_16/frontend_invocation_inventory.py \
	inertia/ir/entry_domain_call_preservation.py \
	inertia/ir/scoped_function_ir_view.py
SCOPED_IR_CONTRACT_TESTS := \
	tests/ir/test_x86_16_premise_collection_budget.py \
	tests/integration/test_x86_16_invocation_pending_inventory.py \
	tests/integration/test_x86_16_near_call_frame_width.py \
	tests/integration/test_x86_16_invocation_inventory_budgets.py \
	tests/ir/test_x86_16_scoped_ir_view.py \
	tests/ir/test_x86_16_scoped_ir_view_counters.py \
	tests/ir/test_x86_16_scoped_ir_coverage.py \
	tests/ir/test_x86_16_scoped_ir_function_refusals.py \
	tests/ir/test_x86_16_scoped_segment_state.py \
	tests/ir/test_x86_16_scoped_resolution_guard.py
SCOPED_IR_NATIVE_TESTS := \
	tests/ir/test_x86_16_invocation_edge_refinement.py \
	tests/ir/test_x86_16_repeated_store_invocation.py \
	tests/semantics/test_x86_16_declared_call_target_binding.py \
	tests/ir/test_x86_16_invocation_path_load.py \
	tests/frontend/test_x86_16_native_load_binding.py \
	tests/ir/test_x86_16_invocation_feasible_joins.py \
	tests/ir/test_x86_16_invocation_wide_multiply.py \
	tests/ir/test_x86_16_invocation_internal_exit.py \
	tests/ir/test_x86_16_declared_resize_boundary.py \
	tests/ir/test_x86_16_resize_path_memory.py \
	tests/frontend/test_x86_16_caller_native_intake.py \
	tests/frontend/test_x86_16_encoded_entry_transport.py \
	tests/frontend/test_x86_16_local_call_evidence.py \
	tests/frontend/test_x86_16_local_evidence_epoch.py \
	tests/integration/test_x86_16_scoped_invocation_source.py \
	tests/integration/test_x86_16_declared_service_chain.py \
	tests/frontend/test_x86_16_mz_static_invocation.py \
	tests/cli/test_x86_16_mz_static_intake_guards.py \
	tests/frontend/test_x86_16_mz_static_pending_callee.py \
	tests/integration/test_x86_16_per_edge_frame_premise.py \
	tests/integration/test_x86_16_near_return_continuation.py \
	tests/integration/test_x86_16_scoped_control_obligations.py \
	tests/integration/test_x86_16_scoped_control_refusal_ledger.py \
	tests/integration/test_x86_16_near_return_scope_guards.py \
	tests/frontend/test_x86_16_scoped_invocation_adapter.py \
	tests/frontend/test_x86_16_scoped_ir_native_view.py \
	tests/frontend/test_x86_16_scoped_ir_native_import.py \
	tests/frontend/test_x86_16_scoped_ir_native_closure.py \
	tests/frontend/test_x86_16_scoped_ir_native_resolution.py
LINTERS_DEV_MYPY_FILES += $(SCOPED_IR_OWNERS)
LINTERS_DEV_MYPY_FILES += inertia/ir/real16_invocation_domain.py
# Follow-imports=skip needs the owned records visible for exact-type narrowing.
LINTERS_DEV_MYPY_FILES += inertia/ir/core.py inertia/frontend/x86_16/frontend_function_boundary.py
LINTERS_DEV_MYPY_FILES += inertia/ir/function_artifact.py inertia/ir/segment_state_transfer.py inertia/frontend/x86_16/frontend_function_boundary_index.py
LINTERS_DEV_MYPY_FILES += inertia/ir/vex_import.py
# Keep the declared boot/image contracts visible under follow_imports=skip;
# otherwise the adapter's runtime-authenticated ProgramBoot becomes Any.
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_boot.py tools/dosunit/runtime/real16_replay_model.py
QA_TYPED_FILES += $(SCOPED_IR_OWNERS)
QA_RUFF_TARGETS += $(SCOPED_IR_OWNERS) $(SCOPED_IR_CONTRACT_TESTS) $(SCOPED_IR_NATIVE_TESTS) tools/dosunit/tests/test_x86_16_scoped_native_inputs.py
QA_PYTEST_TARGETS += $(SCOPED_IR_CONTRACT_TESTS)
# Native transport checks have their own serial lane to avoid proof-budget
# contention with the ordinary six-worker unit cohort.
.PHONY: test-scoped-ir-native
test-scoped-ir-native:
	$(PYTHON) -m pytest $(PYTEST_OUTPUT_FLAGS) --durations=10 $(SCOPED_IR_NATIVE_TESTS)
test-pipeline-expanded: test-scoped-ir-native

LINTERS_DEV_MYPY_FILES += inertia/ir/segment_call_preservation.py
LINTERS_DEV_MYPY_FILES += inertia/semantics/segment_call_preservation_stage.py
QA_TYPED_FILES += inertia/semantics/segment_call_preservation_stage.py
QA_RUFF_TARGETS += inertia/semantics/segment_call_preservation_stage.py
QA_TYPED_FILES += inertia/ir/segment_call_preservation.py
QA_RUFF_TARGETS += inertia/ir/segment_call_preservation.py tests/ir/test_x86_16_segment_call_preservation.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_segment_call_preservation.py
QA_RUFF_TARGETS += tests/fixtures/segment_nonleaf_test_helpers.py tests/ir/test_segment_nonleaf_contracts.py tests/integration/test_segment_nonleaf_budgets.py tests/ir/test_segment_nonleaf_native.py
QA_PYTEST_TARGETS += tests/ir/test_segment_nonleaf_contracts.py tests/integration/test_segment_nonleaf_budgets.py
LINTERS_DEV_MYPY_FILES += inertia/lowering/input_offset_value.py
QA_TYPED_FILES += inertia/lowering/input_offset_value.py
QA_RUFF_TARGETS += inertia/lowering/input_offset_value.py tests/lowering/test_x86_16_input_offset_value.py tests/lowering/x86_16_native_call_fixtures.py
QA_PYTEST_TARGETS += tests/lowering/test_x86_16_input_offset_value.py
QA_TYPED_FILES += inertia/ir/direct_call_segment_entry.py
QA_RUFF_TARGETS += inertia/ir/direct_call_segment_entry.py tests/ir/test_x86_16_direct_call_segment_entry.py tests/ir/test_x86_16_direct_call_segment_entry_integrity.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_direct_call_segment_entry.py tests/ir/test_x86_16_direct_call_segment_entry_integrity.py

LINTERS_DEV_MYPY_FILES += inertia/ir/direct_call_segment_entry_binding.py
QA_TYPED_FILES += inertia/ir/direct_call_segment_entry_binding.py
QA_RUFF_TARGETS += inertia/ir/direct_call_segment_entry_binding.py tests/ir/test_x86_16_direct_call_segment_entry_provenance.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_direct_call_segment_entry_provenance.py
LINTERS_DEV_MYPY_FILES += inertia/ir/direct_call_segment_context.py
QA_TYPED_FILES += inertia/ir/direct_call_segment_context.py
QA_RUFF_TARGETS += inertia/ir/direct_call_segment_context.py tests/ir/test_x86_16_direct_call_segment_context.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_direct_call_segment_context.py
LINTERS_DEV_MYPY_FILES += inertia/alias/saved_stack_store_window.py
QA_TYPED_FILES +=
QA_RUFF_TARGETS +=
LINTERS_DEV_MYPY_FILES += inertia/ir/memory_offset_word_value.py
QA_TYPED_FILES += inertia/ir/memory_offset_word_value.py
QA_RUFF_TARGETS += inertia/ir/memory_offset_word_value.py tests/ir/test_x86_16_memory_offset_word_value.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_memory_offset_word_value.py

LINTERS_DEV_MYPY_FILES += inertia/frontend/x86_16/frontend_block_partition.py
QA_TYPED_FILES += inertia/frontend/x86_16/frontend_block_partition.py
QA_RUFF_TARGETS += inertia/frontend/x86_16/frontend_block_partition.py tests/frontend/test_x86_16_frontend_block_partition.py
QA_PYTEST_TARGETS += tests/frontend/test_x86_16_frontend_block_partition.py

# Keep every exact fast-pipeline pytest target in the hard QA lane as well.
QA_PYTEST_TARGETS += \
	tests/frontend/test_x86_16_calling_convention_compat.py \
	tools/dev/tests/test_fork_timeout.py \
	tools/dev/tests/test_fork_owner_death.py \
	tests/cli/test_batch_decompile_procs_runtime.py \
	tests/lowering/test_x86_16_c_ast_utils.py \
	tests/cli/test_cli_c_text_postprocess.py::test_known_helper_signature_text_preserves_recovered_signature \
	tests/cli/test_x86_16_cod_samples.py::test_dosfunc_cod_sample_process_helpers_stay_empty \
	tests/cli/test_cod_stability_sweep.py \
	tests/cli/test_cli_fallback_slice_entry.py::test_sidecar_slice_refuses_truncated_cfg_ownership \
	tests/frontend/test_x86_16_bounded_linear_instruction_inventory.py::test_bounded_inventory_decodes_to_exact_region_end \
	tests/frontend/test_x86_16_function_pointer_argument_replay.py \
	tests/lowering/test_x86_16_stack_annotation_authority.py \
	tests/frontend/test_x86_16_frontend_capstone_decode.py \
	tools/compiler_toolchain/tests/test_compiler_coverage_manifest.py \
	tools/compiler_toolchain/tests/test_compiler_coverage_csmith.py \
	tools/compiler_toolchain/tests/test_compiler_coverage_pointer_oracle.py \
	tools/compiler_toolchain/tests/test_compiler_coverage_result.py \
	tools/compiler_toolchain/tests/test_compiler_coverage_suite.py \
	tests/integration/test_x86_16_nested_cdecl_arguments.py \
	tools/compiler_toolchain/tests/test_msc6_original_evidence.py \
	tests/cli/test_discovery_pre_entry_order.py \
	tests/integration/test_signature_catalog_without_flair.py \
	tests/integration/test_ada_signature_integration.py \
	tests/integration/test_signature_region_bounds.py \
	tools/signatures/tests/test_discovery_signature_isolation.py \
	tools/signatures/tests/test_discovery_library_boundaries.py \
	tests/cli/test_discovery_recovery_policy.py \
	tests/frontend/test_callsite_complement_sources.py \
	tests/lowering/test_x86_16_interprocedural_storage_caller_context.py \
	tests/cli/test_x86_16_cli.py::test_decompile_cli_can_extract_and_name_cod_procedure \
	tests/frontend/test_x86_16_far_probe_lifting.py

include tools/compiler_toolchain/coverage.mk

QA_RUFF_TARGETS += tests/frontend/test_x86_16_far_probe_lifting.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_scalar_value_projection.py
QA_RUFF_TARGETS += tests/ir/test_x86_16_ssa_call_target_inputs.py
QA_PYTEST_TARGETS += tests/ir/test_x86_16_ssa_call_target_inputs.py
QA_TYPED_FILES += \

QA_RUFF_TARGETS += \
	tests/integration/test_x86_16_entry_stack_word_bits.py \
	tests/widening/test_x86_16_entry_stack_word_values.py \
	tests/widening/test_x86_16_entry_stack_word_boundaries.py \
	tests/widening/test_x86_16_entry_stack_word_effects.py
QA_PYTEST_TARGETS += \
	tests/integration/test_x86_16_entry_stack_word_bits.py \
	tests/widening/test_x86_16_entry_stack_word_values.py \
	tests/widening/test_x86_16_entry_stack_word_boundaries.py \
	tests/widening/test_x86_16_entry_stack_word_effects.py

# One typed register-effect owner shared by entry-word value consumers.
ENTRY_WORD_TRANSPORT_TYPED_FILES := \
	inertia/ir/scalar_instruction_effects.py \
	inertia/widening/entry_word_transport.py \
	inertia/widening/entry_word_transport_contracts.py \
	inertia/widening/entry_word_transport_state.py \
	inertia/widening/entry_word_transport_flow.py \
	inertia/widening/entry_word_transport_snapshots.py
QA_TYPED_FILES += \
	inertia/ir/scalar_instruction_effects.py \

QA_RUFF_TARGETS += \
	inertia/ir/scalar_instruction_effects.py \
	tests/ir/test_x86_16_scalar_instruction_effects.py \
	tests/ir/test_x86_16_scalar_instruction_effects_emitter.py \
	tests/widening/test_x86_16_entry_word_transport.py \
	tests/widening/test_x86_16_entry_word_transport_sites.py \
	tests/widening/test_x86_16_entry_word_transport_control.py \
	tests/widening/test_x86_16_entry_word_transport_snapshots.py \
	tests/widening/test_x86_16_entry_word_transport_snapshot_coherence.py
QA_PYTEST_TARGETS += \
	tests/ir/test_x86_16_scalar_instruction_effects.py \
	tests/ir/test_x86_16_scalar_instruction_effects_emitter.py \
	tests/widening/test_x86_16_entry_word_transport.py \
	tests/widening/test_x86_16_entry_word_transport_sites.py \
	tests/widening/test_x86_16_entry_word_transport_control.py \
	tests/widening/test_x86_16_entry_word_transport_snapshots.py \
	tests/widening/test_x86_16_entry_word_transport_snapshot_coherence.py

# Binary comparison contracts and independent replay owners.
QA_TYPED_FILES += \
	tools/dosunit/runtime/replay_machine_inputs.py \
	tools/dosunit/runtime/replay_capture_model.py \
	tools/dosunit/runtime/flat32_memory_permissions.py \
	tools/dosunit/runtime/flat32_replay_model.py \
	tools/dosunit/runtime/flat32_replay_memory.py \
	tools/dosunit/tests/flat32_replay_test_support.py
QA_RUFF_TARGETS += \
	tools/dosunit/runtime/replay_machine_inputs.py \
	tools/dosunit/runtime/replay_capture_model.py \
	tools/dosunit/runtime/flat32_memory_permissions.py \
	tools/dosunit/runtime/flat32_replay_model.py \
	tools/dosunit/runtime/flat32_replay_memory.py \
	tools/dosunit/tests/flat32_replay_test_support.py \
	tools/dosunit/tests/test_flat32_file_permissions.py \
	tools/dosunit/tests/test_flat32_mapping_contract.py \
	tools/dosunit/tests/test_flat32_observation_contract.py
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_flat32_file_permissions.py \
	tools/dosunit/tests/test_flat32_mapping_contract.py \
	tools/dosunit/tests/test_flat32_observation_contract.py
QA_TYPED_FILES += tools/dev/workspace_sandbox.py
QA_TYPED_FILES += tools/dosunit/contracts/scc_proof_admission.py
QA_RUFF_TARGETS += tools/dosunit/contracts/scc_proof_admission.py tools/dosunit/tests/test_ssa_scc_status_admission.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_ssa_scc_status_admission.py
QA_RUFF_TARGETS += tools/dev/workspace_sandbox.py tools/dev/tests/test_workspace_sandbox.py
QA_PYTEST_TARGETS += tools/dev/tests/test_workspace_sandbox.py


# Declared DOS version-query effects and checked public receipts.
REPEATED_STORE_FILES := inertia/frontend/x86_16/frontend_repeated_store8616.py \
	inertia/ir/real16_repeated_store8616.py
QA_TYPED_FILES += $(REPEATED_STORE_FILES)
LINTERS_DEV_MYPY_FILES += $(REPEATED_STORE_FILES)
QA_RUFF_TARGETS += $(REPEATED_STORE_FILES)
DECLARED_INTERRUPT_FILES := inertia/frontend/real16_version_response8616.py \
	inertia/frontend/real16_resize_response8616.py \
	inertia/ir/real16_path_memory8616.py \
	inertia/ir/real16_initial_memory8616.py \
	inertia/ir/real16_wide_multiply8616.py \
	inertia/ir/real16_declared_interrupt8616.py \
	tools/dosunit/runtime/real16_declared_invocation8616.py
DECLARED_INTERRUPT_TESTS := tests/ir/test_x86_16_declared_interrupt_boundary.py \
	tests/ir/test_x86_16_declared_interrupt_collision.py
QA_TYPED_FILES += $(DECLARED_INTERRUPT_FILES)
LINTERS_DEV_MYPY_FILES += $(DECLARED_INTERRUPT_FILES)
QA_RUFF_TARGETS += $(DECLARED_INTERRUPT_FILES) $(DECLARED_INTERRUPT_TESTS)
QA_PYTEST_TARGETS += $(DECLARED_INTERRUPT_TESTS)
# Declared-call transport and projected-call block authentication owners.
QA_TYPED_FILES += inertia/cli/declared_call_transport.py inertia/frontend/x86_16/declared_external_call_evidence.py
LINTERS_DEV_MYPY_FILES += inertia/cli/declared_call_transport.py inertia/frontend/x86_16/declared_external_call_evidence.py inertia/semantics/call_projection_blocks.py
QA_RUFF_TARGETS += inertia/cli/declared_call_transport.py inertia/frontend/x86_16/declared_external_call_evidence.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_binary_callee_relative_call_coordinates.py
QA_PYTEST_TARGETS += tests/cli/test_x86_16_mapped_backward_boundary.py
QA_PYTEST_TARGETS += tests/frontend/test_x86_16_local_call_evidence.py
QA_PYTEST_TARGETS += tests/frontend/test_x86_16_local_evidence_epoch.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_version.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_version.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_version.py tools/dosunit/tests/test_real16_program_version.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_version.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_resize.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_resize.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_resize.py tools/dosunit/tests/test_real16_program_resize.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_resize.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_memory.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_memory.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_memory.py tools/dosunit/tests/test_real16_program_memory.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_memory.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_interrupts.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_interrupts.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_interrupts.py tools/dosunit/tests/test_real16_program_interrupts.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_interrupts.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_vectors.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_vectors.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_vectors.py tools/dosunit/tests/test_real16_program_vectors.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_vectors.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_device_info.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_device_info.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_device_info.py tools/dosunit/tests/test_real16_program_device_info.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_device_info.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_video.py tools/dosunit/runtime/real16_program_video_boundary.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_video.py tools/dosunit/runtime/real16_program_video_boundary.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_video.py tools/dosunit/runtime/real16_program_video_boundary.py tools/dosunit/tests/test_real16_program_video.py tools/dosunit/tests/test_real16_program_video_policy.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_video.py tools/dosunit/tests/test_real16_program_video_policy.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_video_state.py tools/dosunit/runtime/real16_video_state_boundary.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_video_state.py tools/dosunit/runtime/real16_video_state_boundary.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_video_state.py tools/dosunit/runtime/real16_video_state_boundary.py tools/dosunit/tests/test_real16_video_state_policy.py tools/dosunit/tests/test_real16_video_state_boundary.py tools/dosunit/tests/test_real16_program_video_state.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_video_state_policy.py tools/dosunit/tests/test_real16_video_state_boundary.py tools/dosunit/tests/test_real16_program_video_state.py
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_rom.py
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_program_rom.py
# SegOffset/LinearRange own the typed coordinates consumed by these contracts;
# MyPy's skipped imports otherwise turn their fields into Any in this lane.
LINTERS_DEV_MYPY_FILES += tools/dosunit/runtime/real16_replay_model.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_rom.py tools/dosunit/tests/test_real16_program_rom.py tools/dosunit/tests/test_real16_program_rom_integration.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_rom.py tools/dosunit/tests/test_real16_program_rom_integration.py

# Explicit bounded initialized-program output stream contracts.
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_output.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_output.py \
	tools/dosunit/tests/test_real16_program_output.py tools/dosunit/tests/test_real16_program_output_integration.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_output.py \
	tools/dosunit/tests/test_real16_program_output_integration.py

# Declared read-only input file effects and complete cursor receipts.
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_input.py tools/dosunit/reporting/real16_program_input_manifest.py \
	tools/dosunit/runtime/real16_program_file_receipts.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_input.py tools/dosunit/reporting/real16_program_input_manifest.py \
	tools/dosunit/runtime/real16_program_file_receipts.py \
	tools/dosunit/tests/test_real16_program_input.py tools/dosunit/tests/test_real16_program_input_integration.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_input.py \
	tools/dosunit/tests/test_real16_program_input_integration.py

# Genuine PE32-to-PE32 public branch proof and mutation controls.
QA_RUFF_TARGETS += tools/dosunit/tests/test_relational_branch_public32.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_relational_branch_public32.py
QA_RUFF_TARGETS += tools/dosunit/compare/macro_step_contracts.py tools/dosunit/compare/macro_step_pairing.py tools/dosunit/ssa/region_path_terms.py tools/dosunit/compare/real16_macro_rows.py tools/dosunit/compare/real16_macro_proof.py tools/dosunit/compare/flat32_macro_terms.py tools/dosunit/compare/flat32_macro_proof.py tools/dosunit/compare/flat32_environment_coverage.py tools/dosunit/compare/real16_macro_retry.py tools/dosunit/tests/test_real16_macro_public.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_macro_public.py
QA_TYPED_FILES += tools/dosunit/compare/real16_macro_retry.py
QA_RUFF_TARGETS += tools/dosunit/compare/real16_retry_diagnostics.py tools/dosunit/tests/test_real16_retry_budget_diagnostics.py
QA_TYPED_FILES += tools/dosunit/compare/real16_retry_diagnostics.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_retry_budget_diagnostics.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_macro_step_proof.py tools/dosunit/tests/test_macro_step_admission.py tools/dosunit/tests/test_macro_step_deadlines.py tools/dosunit/tests/test_macro_step_concat_exhaustion.py tools/dosunit/tests/test_macro_step_return_state.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_macro_step_proof.py tools/dosunit/tests/test_macro_step_admission.py tools/dosunit/tests/test_macro_step_deadlines.py tools/dosunit/tests/test_macro_step_concat_exhaustion.py tools/dosunit/tests/test_macro_step_return_state.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_flat32_macro_retry.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_flat32_term_budget.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_macro_retry.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_term_budget.py

# Combined initialized-MZ immutable input and bounded output replay.
QA_RUFF_TARGETS += tools/dosunit/tests/test_real16_program_file_copy.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_file_copy.py

# Initialized PE32 process contracts, independent of function return replay.
QA_TYPED_FILES += tools/dosunit/runtime/pe32_program_boot.py tools/dosunit/runtime/pe32_program_replay.py \
	tools/dosunit/reporting/pe32_program_manifest.py tools/dosunit/reporting/pe32_program_cli.py
QA_RUFF_TARGETS += tools/dosunit/runtime/pe32_program_boot.py tools/dosunit/runtime/pe32_program_replay.py \
	tools/dosunit/reporting/pe32_program_manifest.py tools/dosunit/reporting/pe32_program_cli.py \
	tools/dosunit/tests/test_pe32_program_boot.py tools/dosunit/tests/test_pe32_program_replay.py \
	tools/dosunit/tests/test_pe32_program_cli.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_pe32_program_boot.py \
	tools/dosunit/tests/test_pe32_program_replay.py tools/dosunit/tests/test_pe32_program_cli.py

# Literal gate lists are required by the architecture enrollment checker.
QA_TYPED_FILES += tools/dosunit/runtime/real16_program_boot.py tools/dosunit/runtime/real16_program_model.py \
	tools/dosunit/runtime/real16_program_replay.py tools/dosunit/reporting/real16_program_manifest.py tools/dosunit/reporting/real16_program_cli.py
QA_RUFF_TARGETS += tools/dosunit/runtime/real16_program_boot.py tools/dosunit/runtime/real16_program_model.py \
	tools/dosunit/runtime/real16_program_replay.py tools/dosunit/reporting/real16_program_manifest.py tools/dosunit/reporting/real16_program_cli.py \
	tools/dosunit/tests/test_real16_program_boot.py tools/dosunit/tests/test_real16_program_replay.py \
	tools/dosunit/tests/test_real16_program_cli.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_program_boot.py \
	tools/dosunit/tests/test_real16_program_replay.py tools/dosunit/tests/test_real16_program_cli.py
QA_TYPED_FILES += tools/dosunit/catalog/binary_callee_intake.py tools/dosunit/catalog/binary_callee_discovery.py
QA_RUFF_TARGETS += tools/dosunit/catalog/binary_callee_intake.py tools/dosunit/catalog/binary_callee_discovery.py \
	tools/dosunit/tests/test_binary_callee_intake.py \
	tools/dosunit/tests/test_binary_callee_intake_review.py \
	tools/dosunit/tests/test_real16_uncatalogued_calls.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_binary_callee_intake.py \
	tools/dosunit/tests/test_binary_callee_intake_review.py \
	tools/dosunit/tests/test_real16_uncatalogued_calls.py
QA_TYPED_FILES += \
	tools/dosunit/compare/flat32_call_composition.py \
	tools/dosunit/contracts/flat32_proof_domain.py \
	tools/dosunit/reporting/flat32_proof_domain_cli.py \
	tools/dosunit/architectures/flat32_pe_loader.py \
	tools/dosunit/compare/flat32_call_contracts.py \
	tools/dosunit/compare/flat32_call_lowering.py \
	tools/dosunit/compare/flat32_call_execution.py \
	tools/dosunit/compare/flat32_cfg_regions.py \
	tools/dosunit/contracts/binary_environment.py \
	tools/dosunit/contracts/ordered_io_environment.py \
	tools/dosunit/ssa/ssa_io_retention.py \
	tools/dosunit/contracts/callee_proof_scope.py \
	tools/dosunit/contracts/proof_contracts.py \
	tools/dosunit/reporting/proof_public_domain.py \
	tools/dosunit/contracts/proof_obligations.py \
	tools/dosunit/reporting/proof_serialization.py \
	tools/dosunit/reporting/proof_projection.py \
	tools/dosunit/reporting/flat32_proof_report.py \
	tools/dosunit/compare/flat32_proof_retry.py \
	tools/dosunit/runtime/flat32_replay.py \
	tools/dosunit/reporting/flat32_replay_cli.py \
	tools/dosunit/reporting/ssa_provenance.py \
	tools/dosunit/compare/real16_binary_compare.py \
	tools/dosunit/compare/real16_proof_evidence.py \
	tools/dosunit/ssa/ssa_constant_terms.py \
	tools/dosunit/contracts/real16_entry_domain.py \
	tools/dosunit/compare/real16_loop_invariants.py \
	tools/dosunit/contracts/repeat_string_contracts.py \
	tools/dosunit/ssa/x86_lazy_conditions.py \
	tools/dosunit/compare/real16_call_composition.py \
	tools/dosunit/compare/real16_call_contracts.py \
	tools/dosunit/compare/real16_call_evidence.py \
	tools/dosunit/compare/real16_call_execution.py \
	tools/dosunit/runtime/real16_replay_model.py \
	tools/dosunit/runtime/real16_mz_load.py \
	tools/dosunit/runtime/real16_guest.py \
	tools/dosunit/runtime/real16_replay_compare.py \
	tools/dosunit/runtime/real16_replay.py \
	tools/dosunit/reporting/real16_replay_report.py \
	tools/dosunit/reporting/real16_replay_cli.py \
	tools/dosunit/reporting/real16_replay_manifest.py \
	tools/dosunit/compare/real16_call_frames.py \
	tools/dosunit/compare/real16_call_boundary.py \
	tools/dosunit/compare/real16_loop_calls.py \
	tools/dosunit/compare/real16_call_control.py \
	tools/dosunit/compare/real16_control_resolution.py \
	tools/dosunit/compare/real16_call_retry.py \
	tools/dosunit/contracts/binary_initial_state.py

QA_RUFF_TARGETS += \
	tools/dosunit/compare/flat32_call_composition.py \
	tools/dosunit/contracts/flat32_proof_domain.py \
	tools/dosunit/reporting/flat32_proof_domain_cli.py \
	tools/dosunit/architectures/flat32_pe_loader.py \
	tools/dosunit/compare/flat32_call_contracts.py \
	tools/dosunit/compare/flat32_call_lowering.py \
	tools/dosunit/compare/flat32_call_execution.py \
	tools/dosunit/compare/flat32_cfg_regions.py \
	tools/dosunit/contracts/binary_environment.py \
	tools/dosunit/contracts/ordered_io_environment.py \
	tools/dosunit/ssa/ssa_io_retention.py \
	tools/dosunit/contracts/callee_proof_scope.py \
	tools/dosunit/contracts/proof_contracts.py \
	tools/dosunit/reporting/proof_public_domain.py \
	tools/dosunit/contracts/proof_obligations.py \
	tools/dosunit/reporting/proof_serialization.py \
	tools/dosunit/reporting/proof_projection.py \
	tools/dosunit/reporting/flat32_proof_report.py \
	tools/dosunit/compare/flat32_proof_retry.py \
	tools/dosunit/runtime/flat32_replay.py \
	tools/dosunit/reporting/flat32_replay_cli.py \
	tools/dosunit/reporting/ssa_provenance.py \
	tools/dosunit/compare/real16_binary_compare.py \
	tools/dosunit/compare/real16_proof_evidence.py \
	tools/dosunit/ssa/ssa_constant_terms.py \
	tools/dosunit/contracts/real16_entry_domain.py \
	tools/dosunit/compare/real16_loop_invariants.py \
	tools/dosunit/contracts/repeat_string_contracts.py \
	tools/dosunit/ssa/x86_lazy_conditions.py \
	tools/dosunit/compare/real16_call_composition.py \
	tools/dosunit/compare/real16_call_contracts.py \
	tools/dosunit/compare/real16_call_evidence.py \
	tools/dosunit/compare/real16_call_execution.py \
	tools/dosunit/runtime/real16_replay_model.py \
	tools/dosunit/runtime/real16_mz_load.py \
	tools/dosunit/runtime/real16_guest.py \
	tools/dosunit/runtime/real16_replay_compare.py \
	tools/dosunit/runtime/real16_replay.py \
	tools/dosunit/reporting/real16_replay_report.py \
	tools/dosunit/reporting/real16_replay_cli.py \
	tools/dosunit/reporting/real16_replay_manifest.py \
	tools/dosunit/compare/real16_call_frames.py \
	tools/dosunit/compare/real16_call_boundary.py \
	tools/dosunit/compare/real16_loop_calls.py \
	tools/dosunit/compare/real16_call_control.py \
	tools/dosunit/compare/real16_control_resolution.py \
	tools/dosunit/tests/test_real16_symbolic_call_control.py \
	tools/dosunit/tests/test_real16_symbolic_successors.py \
	tests/frontend/test_x86_16_relative_control_edge.py \
	tests/ir/test_x86_16_relative_condition_producers.py \
	tools/dosunit/compare/real16_call_retry.py \
	tools/dosunit/contracts/binary_initial_state.py \
	tools/dosunit/tests/test_dosunit_initial_image_relation.py \
	tools/dosunit/tests/test_dosunit_proof_contracts.py \
	tools/dosunit/tests/test_dosunit_public_domain.py \
	tools/dosunit/tests/test_dosunit_public_domain_integration.py \
	tools/dosunit/tests/test_dosunit_proof_projection.py \
	tools/dosunit/tests/test_ssa_array_input_substitution.py \
	tools/dosunit/tests/test_flat32_comparator_lane.py \
	tools/dosunit/tests/test_flat32_loop_controls.py \
	tools/dosunit/tests/test_flat32_stack_domain.py \
	tools/dosunit/tests/test_flat32_stack_domain_cli.py \
	tools/dosunit/tests/test_flat32_tail_transfer.py \
	tools/dosunit/tests/test_flat32_compose_total_budget.py \
	tools/dosunit/tests/test_flat32_tail_retry_projection.py \
	tools/dosunit/tests/test_flat32_conditional_boundaries.py \
	tools/dosunit/tests/test_flat32_loaded_byte_boundaries.py \
	tools/dosunit/tests/test_flat32_concrete_replay.py \
	tools/dosunit/tests/test_dosunit_guarded_capture.py \
	tools/dosunit/tests/test_flat32_replay_cli.py \
	tools/dosunit/tests/test_flat32_replay_full_state.py \
	tools/dosunit/tests/test_dosunit_binary_environment.py \
	tools/dosunit/tests/test_ordered_io_environment.py \
	tools/dosunit/tests/test_ordered_io_native.py \
	tools/dosunit/tests/test_ordered_io_native_extended.py \
	tests/semantics/test_x86_16_immediate_port.py \
	tests/frontend/test_x86_16_immediate_port_vex.py \
	tools/dosunit/tests/test_dosunit_ssa_provenance.py \
	tools/dosunit/tests/test_dosunit_callee_scope.py \
	tools/dosunit/tests/test_dosunit_induction_soundness.py \
	tools/dosunit/tests/test_real16_binary_compare.py \
	tools/dosunit/tests/test_real16_self_lowering_reuse.py \
	tools/dosunit/tests/test_real16_call_composition.py \
	tools/dosunit/tests/test_real16_argument_controls.py \
	tools/dosunit/tests/test_real16_repeat_summary_contract.py \
	tools/dosunit/tests/test_dosunit_x86_lazy_conditions.py \
	tools/dosunit/tests/test_dosunit_x86_carry_helper.py \
	tests/integration/test_x86_16_import_identity.py \
	tools/dosunit/tests/test_real16_ail_control_contract.py \
	tools/dosunit/tests/test_real16_call_admission.py \
	tools/dosunit/tests/test_real16_public_calls.py \
	tools/dosunit/tests/test_real16_concrete_replay.py \
	tools/dosunit/tests/test_real16_replay_observations.py \
	tools/dosunit/tests/test_real16_write_readback.py

QA_RUFF_TARGETS += \
	tools/dosunit/tests/test_real16_control_domain.py \
	tools/dosunit/tests/test_real16_return_coordinates.py \
	tools/dosunit/tests/test_real16_operand_call_composition.py \
	tools/dosunit/tests/test_real16_replay_snapshot.py \
	tools/dosunit/tests/test_real16_replay_cli.py \
	tools/dosunit/tests/test_real16_loop_calls.py \
	tools/dosunit/tests/test_real16_far_loop_controls.py \
	tools/dosunit/tests/test_real16_far_call_composition.py

QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_real16_control_domain.py \
	tools/dosunit/tests/test_real16_return_coordinates.py \
	tools/dosunit/tests/test_real16_operand_call_composition.py \
	tools/dosunit/tests/test_real16_replay_snapshot.py \
	tools/dosunit/tests/test_dosunit_initial_image_relation.py \
	tools/dosunit/tests/test_dosunit_proof_contracts.py \
	tools/dosunit/tests/test_dosunit_public_domain.py \
	tools/dosunit/tests/test_dosunit_public_domain_integration.py \
	tools/dosunit/tests/test_dosunit_proof_projection.py \
	tools/dosunit/tests/test_ssa_array_input_substitution.py \
	tools/dosunit/tests/test_flat32_comparator_lane.py \
	tools/dosunit/tests/test_flat32_loop_controls.py \
	tools/dosunit/tests/test_flat32_stack_domain.py \
	tools/dosunit/tests/test_flat32_stack_domain_cli.py \
	tools/dosunit/tests/test_flat32_tail_transfer.py \
	tools/dosunit/tests/test_flat32_compose_total_budget.py \
	tools/dosunit/tests/test_flat32_tail_retry_projection.py \
	tools/dosunit/tests/test_flat32_conditional_boundaries.py \
	tools/dosunit/tests/test_flat32_loaded_byte_boundaries.py \
	tools/dosunit/tests/test_flat32_concrete_replay.py \
	tools/dosunit/tests/test_dosunit_guarded_capture.py \
	tools/dosunit/tests/test_flat32_replay_cli.py \
	tools/dosunit/tests/test_flat32_replay_full_state.py \
	tools/dosunit/tests/test_dosunit_binary_environment.py \
	tools/dosunit/tests/test_ordered_io_environment.py \
	tools/dosunit/tests/test_ordered_io_native.py \
	tools/dosunit/tests/test_ordered_io_native_extended.py \
	tests/semantics/test_x86_16_immediate_port.py \
	tests/frontend/test_x86_16_immediate_port_vex.py \
	tools/dosunit/tests/test_dosunit_ssa_provenance.py \
	tools/dosunit/tests/test_dosunit_callee_scope.py \
	tools/dosunit/tests/test_dosunit_induction_soundness.py \
	tools/dosunit/tests/test_real16_binary_compare.py \
	tools/dosunit/tests/test_real16_self_lowering_reuse.py \
	tools/dosunit/tests/test_real16_call_composition.py \
	tools/dosunit/tests/test_real16_argument_controls.py \
	tools/dosunit/tests/test_real16_repeat_summary_contract.py \
	tools/dosunit/tests/test_dosunit_x86_lazy_conditions.py \
	tools/dosunit/tests/test_dosunit_x86_carry_helper.py \
	tools/dosunit/tests/test_real16_ail_control_contract.py \
	tools/dosunit/tests/test_real16_call_admission.py \
	tools/dosunit/tests/test_real16_public_calls.py \
	tools/dosunit/tests/test_real16_concrete_replay.py \
	tools/dosunit/tests/test_real16_replay_observations.py \
	tools/dosunit/tests/test_real16_write_readback.py

QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_real16_replay_cli.py \
	tools/dosunit/tests/test_real16_loop_calls.py \
	tools/dosunit/tests/test_real16_far_loop_controls.py \
	tools/dosunit/tests/test_real16_far_call_composition.py

QA_TYPED_FILES += \
	tools/dosunit/compare/paired_region_graph.py \
	tools/dosunit/ssa/ssa_control_flow.py \
	tools/dosunit/compare/real16_region_transitions.py \
	tools/dosunit/compare/real16_region_proof.py
QA_RUFF_TARGETS += \
	tools/dosunit/compare/paired_region_graph.py \
	tools/dosunit/ssa/ssa_control_flow.py \
	tools/dosunit/tests/test_dosunit_ssa_versions.py \
	tools/dosunit/compare/real16_region_transitions.py \
	tools/dosunit/compare/real16_region_proof.py \
	tools/dosunit/tests/test_paired_region_graph.py \
	tools/dosunit/tests/test_real16_region_proof.py \
	tools/dosunit/tests/test_real16_region_public.py
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_dosunit_ssa_versions.py \
	tools/dosunit/tests/test_paired_region_graph.py \
	tools/dosunit/tests/test_real16_region_proof.py \
	tools/dosunit/tests/test_real16_region_public.py

QA_TYPED_FILES += \
	tools/dosunit/contracts/register_state_relations.py \
	tools/dosunit/contracts/proof_scope.py
QA_RUFF_TARGETS += \
	tools/dosunit/contracts/register_state_relations.py \
	tools/dosunit/contracts/proof_scope.py \
	tools/dosunit/tests/test_register_state_relations.py \
	tools/dosunit/tests/test_proof_scope.py \
	tools/dosunit/tests/test_real16_register_regions.py \
	tools/dosunit/tests/test_real16_register_public.py \
	tools/dosunit/tests/test_flat32_register_regions.py \
	tools/dosunit/tests/test_flat32_register_replay.py
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_register_state_relations.py \
	tools/dosunit/tests/test_proof_scope.py \
	tools/dosunit/tests/test_real16_register_regions.py \
	tools/dosunit/tests/test_real16_register_public.py \
	tools/dosunit/tests/test_flat32_register_regions.py \
	tools/dosunit/tests/test_flat32_register_replay.py

QA_TYPED_FILES += \
	tools/dosunit/contracts/register_affine_relations.py \
	tools/dosunit/architectures/flat32_cfg_lifting.py
QA_RUFF_TARGETS += \
	tools/dosunit/contracts/register_affine_relations.py \
	tools/dosunit/architectures/flat32_cfg_lifting.py \
	tools/dosunit/tests/test_real16_affine_regions.py \
	tools/dosunit/tests/test_flat32_affine_regions.py \
	tools/dosunit/tests/test_register_affine_relations.py \
	tools/dosunit/tests/test_affine_concrete_replay.py
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_real16_affine_regions.py \
	tools/dosunit/tests/test_flat32_affine_regions.py \
	tools/dosunit/tests/test_register_affine_relations.py \
	tools/dosunit/tests/test_affine_concrete_replay.py

# Finite-cover and memory-invariant relations require complete state proofs.
QA_TYPED_FILES += tools/dosunit/compare/region_branch_pairing.py
QA_RUFF_TARGETS += \
	tools/dosunit/compare/region_branch_pairing.py \
	tools/dosunit/tests/test_region_branch_pairing.py \
	tools/dosunit/tests/test_branch_pairing_oracle.py \
	tools/dosunit/tests/test_region_pairing_reporting.py \
	tools/dosunit/tests/test_real16_branch_regions.py
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_region_branch_pairing.py \
	tools/dosunit/tests/test_branch_pairing_oracle.py \
	tools/dosunit/tests/test_region_pairing_reporting.py \
	tools/dosunit/tests/test_real16_branch_regions.py
QA_TYPED_FILES += \
	tools/dosunit/contracts/cutpoint_state_relations.py \
	tools/dosunit/compare/finite_region_cover.py \
	tools/dosunit/compare/flat32_invariant_proof.py \
	tools/dosunit/compare/flat32_invariant_retry.py \
	tools/dosunit/compare/flat32_region_attempts.py \
	tools/dosunit/compare/flat32_relation_evidence.py \
	tools/dosunit/compare/memory_invariant_obligations.py \
	tools/dosunit/compare/memory_invariant_priority.py \
	tools/dosunit/compare/memory_invariant_proposals.py \
	tools/dosunit/compare/memory_relation_proposals.py \
	tools/dosunit/contracts/memory_state_invariants.py \
	tools/dosunit/contracts/memory_state_relations.py \
	tools/dosunit/compare/real16_memory_relations.py \
	tools/dosunit/compare/region_pairing.py
QA_RUFF_TARGETS += \
	tools/dosunit/contracts/cutpoint_state_relations.py \
	tools/dosunit/compare/finite_region_cover.py \
	tools/dosunit/compare/flat32_invariant_proof.py \
	tools/dosunit/compare/flat32_invariant_retry.py \
	tools/dosunit/compare/flat32_region_attempts.py \
	tools/dosunit/compare/flat32_relation_evidence.py \
	tools/dosunit/compare/memory_invariant_obligations.py \
	tools/dosunit/compare/memory_invariant_priority.py \
	tools/dosunit/compare/memory_invariant_proposals.py \
	tools/dosunit/compare/memory_relation_proposals.py \
	tools/dosunit/contracts/memory_state_invariants.py \
	tools/dosunit/contracts/memory_state_relations.py \
	tools/dosunit/compare/real16_memory_relations.py \
	tools/dosunit/compare/region_pairing.py \
	tools/dosunit/tests/test_region_cover.py \
	tools/dosunit/tests/test_region_composition_admission.py \
	tools/dosunit/tests/test_memory_state_relations.py \
	tools/dosunit/tests/test_memory_relation_proposals.py \
	tools/dosunit/tests/test_memory_invariant_obligations.py \
	tools/dosunit/tests/test_memory_invariant_proposals.py \
	tools/dosunit/tests/test_memory_state_invariants.py \
	tools/dosunit/tests/test_invariant_retry_contracts.py \
	tools/dosunit/tests/test_flat32_source_closure.py \
	tools/dosunit/tests/test_real16_rotation_regions.py \
	tools/dosunit/tests/test_flat32_rotation_regions.py \
	tools/dosunit/tests/test_rotation_concrete_replay.py \
	tools/dosunit/tests/test_relational_rotation_public32.py \
	tools/dosunit/tests/test_relational_saved_public32.py \
	tools/dosunit/tests/test_relational_saved_public16.py
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_region_cover.py \
	tools/dosunit/tests/test_region_composition_admission.py \
	tools/dosunit/tests/test_memory_state_relations.py \
	tools/dosunit/tests/test_memory_relation_proposals.py \
	tools/dosunit/tests/test_memory_invariant_obligations.py \
	tools/dosunit/tests/test_memory_invariant_proposals.py \
	tools/dosunit/tests/test_memory_state_invariants.py \
	tools/dosunit/tests/test_invariant_retry_contracts.py \
	tools/dosunit/tests/test_flat32_source_closure.py \
	tools/dosunit/tests/test_real16_rotation_regions.py \
	tools/dosunit/tests/test_flat32_rotation_regions.py \
	tools/dosunit/tests/test_rotation_concrete_replay.py \
	tools/dosunit/tests/test_relational_rotation_public32.py \
	tools/dosunit/tests/test_relational_saved_public32.py \
	tools/dosunit/tests/test_relational_saved_public16.py

# Declared candidate scopes retain external obligations without binary expansion.
QA_TYPED_FILES += tools/dosunit/contracts/ssa_lowering_scope.py
QA_RUFF_TARGETS += tools/dosunit/contracts/ssa_lowering_scope.py tools/dosunit/tests/test_ssa_declared_scope.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_ssa_declared_scope.py

# Complete SSA array-output lemmas retain scalar/flag/memory mutations and
# unknown-lemma refusals in the normal comparator regression lane.
QA_TYPED_FILES += \
	tools/dosunit/ssa/ssa_output_lemmas.py
QA_RUFF_TARGETS += \
	tools/dosunit/ssa/ssa_output_lemmas.py \
	tools/dosunit/tests/test_ssa_output_lemmas.py
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_ssa_output_lemmas.py

# Exact generation comparison has a bounded pure-DAG regression and native
# subclass/depth/hash controls; keep these in both routine entry points.
QA_RUFF_TARGETS += \
	tests/validation/test_x86_16_tail_validation_generation_atoms.py \
	tests/validation/test_x86_16_tail_validation_generation_equality.py \
	tests/validation/test_x86_16_validation_goto_target_identity.py
QA_PYTEST_TARGETS += \
	tests/validation/test_x86_16_tail_validation_generation_atoms.py \
	tests/validation/test_x86_16_tail_validation_generation_equality.py \
	tests/validation/test_x86_16_validation_goto_target_identity.py

# Real nonzero-base MZs pin absolute bounds and relative Clemory counts.
QA_RUFF_TARGETS += \
	tests/frontend/test_x86_16_image_extent_projection.py \
	tests/cli/test_cli_loader_memory_boundary.py \
	tests/cli/test_cli_core_isolated_recovery.py \
	tests/cli/test_cli_function_discovery_regions.py
QA_PYTEST_TARGETS += \
	tests/frontend/test_x86_16_image_extent_projection.py \
	tests/cli/test_cli_loader_memory_boundary.py \
	tests/cli/test_cli_core_isolated_recovery.py \
	tests/cli/test_cli_function_discovery_regions.py

# The final direct clean-worker snapshot retains selected/neighbor/UNKNOWN
# evidence across same-project and rebased payload boundaries.
QA_RUFF_TARGETS += \
	tests/cli/test_cli_direct_caller_return_snapshot.py
QA_PYTEST_TARGETS += \
	tests/cli/test_cli_direct_caller_return_snapshot.py

# Callee-bound modular input typing must retain foreign-callee, unknown SSA,
# pointer/condition-conflict and five-stage evidence refusal controls.
LINTERS_DEV_MYPY_FILES += inertia/lowering/modular_argument_type_facts.py
QA_TYPED_FILES += inertia/lowering/modular_argument_type_facts.py
QA_RUFF_TARGETS += \
	inertia/lowering/modular_argument_type_facts.py \
	tests/lowering/test_x86_16_modular_input_type_join.py
QA_PYTEST_TARGETS += \
	tests/lowering/test_x86_16_modular_input_type_join.py

# Optional signatures must not truncate independently closed binary callers;
# unknown bodies and genuine neighboring library boundaries remain refused.
LINTERS_DEV_MYPY_FILES += inertia/cli/discovery_candidate_ranges.py
QA_RUFF_TARGETS += \
	tests/cli/test_cli_caller_range_binary_bounds.py
QA_PYTEST_TARGETS += \
	tests/cli/test_cli_caller_range_binary_bounds.py

# Native near-pointer ABI execution is default-only; lint it in the regular gate.
QA_RUFF_TARGETS += tests/frontend/test_x86_16_near_pointer_native_runtime.py

# Logical PUSH transport is a typed input contract, not pointer or segment proof.
LINTERS_DEV_MYPY_FILES += inertia/lowering/interprocedural_storage_logical_input_contracts.py
QA_TYPED_FILES += inertia/lowering/interprocedural_storage_logical_input_contracts.py
QA_RUFF_TARGETS += inertia/lowering/interprocedural_storage_logical_input_contracts.py

# Disposable focused-job concurrency keeps serial IPC and per-job budgets.
LINTERS_DEV_MYPY_FILES += tools/dev/batch_decompile_scheduler.py
QA_TYPED_FILES += tools/dev/batch_decompile_scheduler.py
QA_RUFF_TARGETS += \
	tools/dev/batch_decompile_scheduler.py \
	tests/cli/test_batch_decompile_scheduler.py \
	tests/cli/test_batch_decompile_frame_deadline.py \
	tests/cli/test_batch_decompile_result_contract.py \
	tests/integration/test_msc6_batch_worker_budget.py
QA_PYTEST_TARGETS += \
	tests/cli/test_batch_decompile_scheduler.py \
	tests/cli/test_batch_decompile_frame_deadline.py \
	tests/cli/test_batch_decompile_result_contract.py \
	tests/integration/test_msc6_batch_worker_budget.py

# Binary-bound recursive component contracts; unresolved model scope stays conditional.
LINTERS_DEV_MYPY_FILES += tools/dosunit/recursive_proofs/real16_normal_outcome_scope.py
QA_TYPED_FILES += tools/dosunit/recursive_proofs/real16_normal_outcome_scope.py
QA_RUFF_TARGETS += tools/dosunit/recursive_proofs/real16_normal_outcome_scope.py tools/dosunit/tests/test_real16_normal_outcome_scope.py
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
QA_RUFF_TARGETS += tools/dosunit/tests/test_dosunit_ssa_source_identity_paths.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_dosunit_ssa_source_identity_paths.py
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
	tools/dosunit/tests/test_recursive_joint_deadlines.py \
	tools/dosunit/tests/test_real16_domain_dispatch.py \
	tools/dosunit/tests/test_recursive_fetched_code_composition.py \
	tools/dosunit/tests/test_recursive_native_deadlines.py \
	tools/dosunit/tests/test_recursive_entry_deadlines.py \
	tools/dosunit/tests/test_recursive_entry_layout_deadlines.py \
	tools/dosunit/tests/test_recursive_domain_deadlines.py \
	tools/dosunit/tests/test_recursive_consumer_model_refresh.py \
	tools/dosunit/tests/test_real16_address_final_seal.py \
	tools/dosunit/tests/test_recursive_loaded_memory_seed.py \
	tools/dosunit/tests/test_recursive_joint_actual_binary.py \
	tools/dosunit/tests/test_recursive_call_continuation_binding.py \
	tools/dosunit/tests/test_recursive_call_continuation_contracts.py \
	tools/dosunit/tests/test_recursive_fetched_code_invariant.py \
	tools/dosunit/tests/recursive_proof_fixtures
QA_PYTEST_TARGETS += \
	tools/dosunit/tests/test_recursive_joint_deadlines.py \
	tools/dosunit/tests/test_real16_domain_dispatch.py \
	tools/dosunit/tests/test_recursive_call_continuation_contracts.py \
	tools/dosunit/tests/test_recursive_fetched_code_composition.py \
	tools/dosunit/tests/test_recursive_native_deadlines.py \
	tools/dosunit/tests/test_recursive_entry_deadlines.py \
	tools/dosunit/tests/test_recursive_entry_layout_deadlines.py \
	tools/dosunit/tests/test_recursive_domain_deadlines.py \
	tools/dosunit/tests/test_recursive_consumer_model_refresh.py \
	tools/dosunit/tests/test_real16_address_final_seal.py \
	tools/dosunit/tests/test_recursive_loaded_memory_seed.py


# PE32 binary-bound recursive component prerequisites (conditional scope).
QA_TYPED_FILES += tools/dosunit/recursive_proofs/flat32_image_bound_domain.py tools/dosunit/recursive_proofs/flat32_image_bound_joint_proof.py tools/dosunit/recursive_proofs/flat32_native_effect_binding.py tools/dosunit/recursive_proofs/flat32_pe_component.py
QA_RUFF_TARGETS += tools/dosunit/recursive_proofs/flat32_image_bound_domain.py tools/dosunit/recursive_proofs/flat32_image_bound_joint_proof.py tools/dosunit/recursive_proofs/flat32_native_effect_binding.py tools/dosunit/recursive_proofs/flat32_pe_component.py tools/dosunit/tests/test_flat32_pe32_recursive_joint.py tools/dosunit/tests/test_flat32_model_namespaces.py tools/dosunit/tests/test_flat32_code_write_domain.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_pe32_recursive_joint.py tools/dosunit/tests/test_flat32_model_namespaces.py tools/dosunit/tests/test_flat32_code_write_domain.py

# Public initialized-entry real16 recursive comparison and intake guards.
QA_TYPED_FILES += tools/dosunit/compare/real16_call_graph_admission.py tools/dosunit/recursive_proofs/real16_joint_construction.py tools/dosunit/compare/real16_recursive_compare.py
QA_RUFF_TARGETS += tools/dosunit/compare/real16_call_graph_admission.py tools/dosunit/recursive_proofs/real16_joint_construction.py tools/dosunit/compare/real16_recursive_compare.py tools/dosunit/tests/test_real16_recursive_public.py tools/dosunit/tests/test_real16_recursive_intake_controls.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_recursive_public.py tools/dosunit/tests/test_real16_recursive_intake_controls.py

# Public PE32 recursive component reports; ordinary member verdicts stay separate.
QA_TYPED_FILES += tools/dosunit/compare/pe32_recursive_compare.py
QA_RUFF_TARGETS += tools/dosunit/compare/pe32_recursive_compare.py tools/dosunit/tests/test_pe32_recursive_public.py tools/dosunit/tests/test_pe32_recursive_report_contracts.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_pe32_recursive_public.py tools/dosunit/tests/test_pe32_recursive_report_contracts.py

# Bounded real16 indirect-call composition and complete target coverage.
QA_TYPED_FILES += tools/dosunit/compare/real16_call_indirect.py
QA_RUFF_TARGETS += tools/dosunit/compare/real16_call_indirect.py tools/dosunit/tests/test_real16_indirect_call_composition.py tools/dosunit/tests/test_real16_indirect_call_budgets.py tools/dosunit/tests/test_real16_indirect_call_multiarm.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_indirect_call_composition.py tools/dosunit/tests/test_real16_indirect_call_budgets.py tools/dosunit/tests/test_real16_indirect_call_multiarm.py

# Shared symbolic terminal-service proof and public scope schema.
QA_TYPED_FILES += tools/dosunit/compare/terminal_fault.py
QA_RUFF_TARGETS += tools/dosunit/compare/terminal_fault.py tools/dosunit/tests/test_symbolic_terminal_faults.py tools/dosunit/tests/test_symbolic_terminal_signed_divmod.py tools/dosunit/tests/test_dosunit_signed_divmod.py tools/dosunit/tests/test_flat32_loop_call_failure_report.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_symbolic_terminal_faults.py tools/dosunit/tests/test_symbolic_terminal_signed_divmod.py tools/dosunit/tests/test_dosunit_signed_divmod.py tools/dosunit/tests/test_flat32_loop_call_failure_report.py
QA_TYPED_FILES += tools/dosunit/reporting/symbolic_terminal_cli.py tools/dosunit/compare/symbolic_terminal.py tools/dosunit/compare/terminal_memory_effects.py
QA_TYPED_FILES += tools/dosunit/compare/symbolic_terminal_real16_services.py tools/dosunit/architectures/terminal_native_decode.py
QA_TYPED_FILES += tools/dosunit/runtime/pe32_import_service.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_pe32_import_service_cli.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_pe32_import_service_cli.py
QA_RUFF_TARGETS += tools/dosunit/runtime/pe32_import_service.py tools/dosunit/tests/test_pe32_import_service.py tools/dosunit/tests/test_pe32_import_service_schema.py tools/dosunit/tests/test_symbolic_terminal_configured_limits.py tools/dosunit/tests/test_symbolic_terminal_pe32_thunk_census.py tools/dosunit/tests/test_symbolic_terminal_ivt_precision.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_pe32_import_service.py tools/dosunit/tests/test_pe32_import_service_schema.py tools/dosunit/tests/test_symbolic_terminal_configured_limits.py tools/dosunit/tests/test_symbolic_terminal_pe32_thunk_census.py tools/dosunit/tests/test_symbolic_terminal_ivt_precision.py
QA_RUFF_TARGETS += tools/dosunit/compare/symbolic_terminal_real16_services.py tools/dosunit/architectures/terminal_native_decode.py tools/dosunit/tests/test_symbolic_terminal_services.py tools/dosunit/tests/test_symbolic_terminal_service_census.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_symbolic_terminal_services.py tools/dosunit/tests/test_symbolic_terminal_service_census.py
QA_RUFF_TARGETS += tools/dosunit/reporting/symbolic_terminal_cli.py tools/dosunit/tests/test_symbolic_terminal_cli.py tools/dosunit/compare/symbolic_terminal.py tools/dosunit/compare/terminal_memory_effects.py tools/dosunit/tests/test_symbolic_terminal.py tools/dosunit/tests/test_symbolic_terminal_read_permissions.py tools/dosunit/tests/test_symbolic_terminal_partial_pe_data.py tools/dosunit/tests/test_symbolic_terminal_output_coverage.py tools/dosunit/tests/test_symbolic_terminal_read_audit_lifetime.py tools/dosunit/tests/test_real16_recursive_report_schema.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_symbolic_terminal_cli.py tools/dosunit/tests/test_symbolic_terminal.py tools/dosunit/tests/test_symbolic_terminal_read_permissions.py tools/dosunit/tests/test_symbolic_terminal_partial_pe_data.py tools/dosunit/tests/test_symbolic_terminal_output_coverage.py tools/dosunit/tests/test_symbolic_terminal_read_audit_lifetime.py tools/dosunit/tests/test_real16_recursive_report_schema.py

# Source-bound callee region candidate scanner and contracts.
QA_TYPED_FILES += tools/dosunit/catalog/binary_callee_region_contracts.py tools/dosunit/catalog/binary_callee_region_scan.py tools/dosunit/catalog/binary_callee_control_target.py tools/dosunit/catalog/binary_callee_region_split.py
QA_RUFF_TARGETS += tools/dosunit/catalog/binary_callee_region_contracts.py tools/dosunit/catalog/binary_callee_region_scan.py tools/dosunit/catalog/binary_callee_control_target.py tools/dosunit/catalog/binary_callee_region_split.py tools/dosunit/tests/test_binary_callee_region_scan.py tools/dosunit/tests/test_binary_callee_control_target.py tools/dosunit/tests/test_binary_callee_leader_split.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_binary_callee_region_scan.py tools/dosunit/tests/test_binary_callee_control_target.py tools/dosunit/tests/test_binary_callee_leader_split.py

QA_TYPED_FILES += tools/dosunit/catalog/binary_callee_region_intake.py
QA_RUFF_TARGETS += tools/dosunit/catalog/binary_callee_region_intake.py tools/dosunit/tests/test_binary_callee_region_intake.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_binary_callee_region_intake.py

QA_TYPED_FILES += tools/dosunit/catalog/binary_callee_region_lowering.py
QA_TYPED_FILES += tools/dosunit/catalog/binary_callee_region_pending.py
QA_RUFF_TARGETS += tools/dosunit/catalog/binary_callee_region_pending.py tools/dosunit/tests/test_binary_callee_repeat_intake.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_binary_callee_repeat_intake.py
QA_RUFF_TARGETS += tools/dosunit/catalog/binary_callee_region_lowering.py

# Native-bound real16 symbolic-control proofs and closed evidence budgets.
QA_TYPED_FILES += tools/dosunit/compare/real16_control_targets.py tools/dosunit/compare/real16_control_boundary.py
QA_RUFF_TARGETS += tools/dosunit/compare/real16_control_targets.py tools/dosunit/compare/real16_control_boundary.py \
	tools/dosunit/tests/test_real16_control_boundary.py tools/dosunit/tests/test_real16_control_target_proof.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_control_boundary.py tools/dosunit/tests/test_real16_control_target_proof.py

# Source-bound native lifter bundles and initialized MZ boot provenance.
QA_RUFF_TARGETS += tests/integration/test_mypyc_vex_bundle.py tools/dosunit/tests/test_real16_boot_provenance.py
QA_PYTEST_TARGETS += tests/integration/test_mypyc_vex_bundle.py tools/dosunit/tests/test_real16_boot_provenance.py

# Checked flat32 call-loop owner and bounded capture controls.
QA_TYPED_FILES += tools/dosunit/compare/flat32_loop_calls.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_native_effect_environment_guards.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_dosunit_io_read_state.py
QA_RUFF_TARGETS += tools/dosunit/compare/flat32_loop_calls.py tools/dosunit/tests/test_flat32_loop_calls.py tools/dosunit/tests/test_flat32_loop_calls_public.py tools/dosunit/tests/test_flat32_dependency_cache.py tools/dosunit/tests/test_replay_capture_vectors.py tests/frontend/test_replay_capture_cohorts.py tools/dosunit/tests/test_flat32_indirect_callbacks.py tools/dosunit/tests/test_flat32_indirect_callback_effects.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_loop_calls.py tools/dosunit/tests/test_replay_capture_vectors.py

QA_RUFF_TARGETS += tools/dosunit/tests/test_m4_exit_controls.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_m4_pe32_relations.py

# Actual PE32 public relational proofs and independent execution controls.
QA_RUFF_TARGETS += tools/dosunit/tests/test_relational_pe32_public.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_relational_pe32_public.py

QA_RUFF_TARGETS += tests/frontend/test_mz_invocation_source.py
QA_PYTEST_TARGETS += tests/frontend/test_mz_invocation_source.py

# Full-selector control proof shared by real16 region and macro transitions.
QA_RUFF_TARGETS += tools/dosunit/compare/real16_region_control.py tools/dosunit/tests/test_real16_region_control.py
QA_TYPED_FILES += tools/dosunit/compare/real16_region_control.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_region_control.py

# Isolated native DOS worker; actual KVM execution stays in the native lane.
KVIKDOS_WORKER_TESTS := tools/dosunit/tests/test_dosunit_kvikdos_worker.py \
	tools/dosunit/tests/test_dosunit_kvikdos_memory_range.py \
	tools/dosunit/tests/test_dosunit_kvikdos_protocol_errors.py \
	tools/dosunit/tests/test_dosunit_kvikdos_snapshot_registry.py
QA_TYPED_FILES += tools/dosunit/runtime/kvikdos_vm_worker.py tools/dosunit/runtime/kvikdos_backend.py
QA_RUFF_TARGETS += tools/dosunit/runtime/kvikdos_vm_worker.py tools/dosunit/runtime/kvikdos_backend.py \
	$(KVIKDOS_WORKER_TESTS) tools/dosunit/tests/dosunit_kvikdos_fake_worker.py \
	tools/dosunit/tests/dosunit_kvikdos_test_support.py \
	tools/dosunit/tests/test_dosunit_kvikdos_worker_native.py
QA_PYTEST_TARGETS += $(KVIKDOS_WORKER_TESTS)

QA_TYPED_FILES += tools/dev/compact_paths.py
QA_RUFF_TARGETS += tools/dev/compact_paths.py tools/dev/tests/test_compact_paths.py
QA_PYTEST_TARGETS += tools/dev/tests/test_compact_paths.py
QA_RUFF_TARGETS += tools/dev/tests/test_pytest_live_failures.py tests/ir/test_native_relift_scope.py
QA_PYTEST_TARGETS += tools/dev/tests/test_pytest_live_failures.py tests/ir/test_native_relift_scope.py

# Inventory additions must precede the eager scoped-selector assignments.
QA_RUFF_TARGETS += tools/dosunit/tests/test_flat32_contextual_calls.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_contextual_calls.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_flat32_proof_seal.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_proof_seal.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_real16_public_accounting.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_public_accounting.py
QA_TYPED_FILES += tools/dosunit/ssa/vex_cache_identity.py
QA_RUFF_TARGETS += tools/dosunit/ssa/vex_cache_identity.py tools/dosunit/tests/test_dosunit_vex_cache_identity.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_dosunit_vex_cache_identity.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_dosunit_transitive_callees.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_dosunit_transitive_callees.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_dosunit_alarm_boundary.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_dosunit_alarm_boundary.py

QA_TYPED_FILES += tools/dosunit/ssa/ssa_selection.py
QA_RUFF_TARGETS += tools/dosunit/ssa/ssa_selection.py tools/dosunit/tests/test_real16_selected_lowering.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_real16_selected_lowering.py

# Shared direct-evidence deadline ownership.
LINTERS_DEV_MYPY_FILES += inertia/ir/direct_evidence_deadline.py
QA_TYPED_FILES += inertia/ir/direct_evidence_deadline.py

# Saved-comparator diagnostics and complete accounting controls.
QA_RUFF_TARGETS += tools/dosunit/catalog/flat32_catalog_admission.py tools/dosunit/catalog/pe32_link_map.py tools/dosunit/tests/test_flat32_catalog_admission.py tools/dosunit/tests/test_pe32_link_map.py
QA_TYPED_FILES += tools/dosunit/catalog/flat32_catalog_admission.py tools/dosunit/catalog/pe32_link_map.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_catalog_admission.py tools/dosunit/tests/test_pe32_link_map.py
QA_RUFF_TARGETS += tools/dosunit/tests/test_flat32_block_retry.py
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_block_retry.py
QA_RUFF_TARGETS += tools/comparator/comparator_refusal_report.py tools/comparator/tests/test_comparator_refusal_report.py
QA_TYPED_FILES += tools/comparator/comparator_refusal_report.py
QA_PYTEST_TARGETS += tools/comparator/tests/test_comparator_refusal_report.py
QA_RUFF_TARGETS += inertia/ir/direct_evidence_deadline.py tests/cli/test_direct_indexed_alias_local_cache.py
QA_PYTEST_TARGETS += tests/cli/test_direct_indexed_alias_local_cache.py

include reference/components.mk

PYRIGHT_SELECTED_FILES := $(filter $(QA_TYPED_FILES),$(PY_FILES))
PYRIGHT_SKIPPED_FILES := $(filter-out $(QA_TYPED_FILES),$(PY_FILES))
MYPY_SELECTED_FILES := $(filter $(QA_TYPED_FILES),$(PY_FILES))
# Keep the worker facade's owned error and integer-parsing contracts visible.
ifneq ($(filter tools/dosunit/runtime/kvikdos_backend.py tools/dosunit/runtime/kvikdos_vm_worker.py,$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) tools/dosunit/contracts/model.py \
	tools/dosunit/runtime/kvikdos_vm_worker.py tools/dosunit/runtime/kvikdos_backend.py)
endif
# With follow_imports=skip, the entry-byte subclass needs its shared base and
# owned IR contracts selected explicitly; checking an Any base is not proof.
ENTRY_STACK_BYTE_MYPY_COHORT := \
	inertia/alias/entry_stack_byte_contracts.py \
	inertia/alias/entry_stack_bytes.py \
	inertia/alias/entry_stack_pointer_snapshots.py \
	inertia/ir/vex_operation_membership.py \
	inertia/alias/stack_pointer_snapshots.py \
	inertia/ir/core.py
ifneq ($(filter $(ENTRY_STACK_BYTE_MYPY_COHORT) tests/fixtures/entry_stack_byte_test_support.py,$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(ENTRY_STACK_BYTE_MYPY_COHORT))
endif
# Select owned contracts with their consumers, not skipped-import Any values.
IR_SCALAR_VALUE_MYPY_COHORT := \
	inertia/ir/constant_flow.py \
	inertia/ir/scalar_value_projection.py \
	inertia/ir/core.py
ifneq ($(filter $(IR_SCALAR_VALUE_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(IR_SCALAR_VALUE_MYPY_COHORT))
endif
MYPY_SKIPPED_FILES := $(filter-out $(QA_TYPED_FILES),$(PY_FILES))
# Range consumers need their owned SSA/condition providers, not skipped Any.
INDEXED_LOOP_RANGE_MYPY_COHORT := \
	inertia/ir/indexed_address_range_candidates.py \
	inertia/ir/indexed_address_range_contracts.py \
	inertia/ir/indexed_address_range_evidence.py \
	inertia/ir/indexed_induction_write_census.py \
	inertia/ir/function_condition_artifact.py \
	inertia/ir/condition_cache_relift.py \
	inertia/ir/condition_cache_relift_contracts.py \
	inertia/ir/condition_cache_relift_cache.py \
	inertia/ir/ssa_function.py \
	inertia/ir/ssa.py
# The development gate needs the same owned-provider closure as scoped checks.
LINTERS_DEV_MYPY_FILES += $(INDEXED_LOOP_RANGE_MYPY_COHORT)
ifneq ($(filter $(INDEXED_LOOP_RANGE_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(INDEXED_LOOP_RANGE_MYPY_COHORT))
endif
# Widening consumes owned contracts, never skipped-import Any values.
ENTRY_STACK_WORD_MYPY_COHORT := \
	$(ENTRY_STACK_BYTE_MYPY_COHORT) \
	inertia/widening/entry_stack_word_bits.py \
	inertia/widening/entry_stack_word_value_contracts.py \
	inertia/widening/entry_stack_word_values.py \
	inertia/ir/function_artifact.py \
	inertia/ir/scalar_value_projection.py \
	inertia/ir/ssa.py \
	inertia/semantics/register_value_preservation.py
ifneq ($(filter $(ENTRY_STACK_WORD_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(ENTRY_STACK_WORD_MYPY_COHORT))
endif
ENTRY_WORD_TRANSPORT_MYPY_COHORT := \
	$(ENTRY_STACK_WORD_MYPY_COHORT) \
	$(ENTRY_WORD_TRANSPORT_TYPED_FILES) \
	inertia/ir/ssa_function.py
ifneq ($(filter $(ENTRY_WORD_TRANSPORT_MYPY_COHORT),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) $(ENTRY_WORD_TRANSPORT_MYPY_COHORT))
endif
RUFF_SELECTED_FILES := $(filter $(QA_RUFF_TARGETS),$(PY_FILES))
RUFF_SKIPPED_FILES := $(filter-out $(QA_RUFF_TARGETS),$(PY_FILES))

QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))
# FunctionCtx and ComposeSession remain typed when selecting one call consumer.
REAL16_CALL_MYPY_CONSUMERS := \
	tools/dosunit/compare/real16_call_indirect.py \
	tools/dosunit/compare/real16_region_control.py \
	tools/dosunit/compare/real16_call_execution.py \
	tools/dosunit/compare/real16_call_control.py \
	tools/dosunit/compare/real16_control_resolution.py \
	tools/dosunit/compare/real16_call_boundary.py \
	tools/dosunit/compare/real16_call_composition.py \
	tools/dosunit/compare/real16_loop_calls.py \
	tools/dosunit/compare/real16_loop_invariants.py \
	tools/dosunit/compare/real16_region_transitions.py \
	tools/dosunit/compare/real16_region_proof.py
ifneq ($(filter $(REAL16_CALL_MYPY_CONSUMERS),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) tools/dosunit/compare/real16_call_contracts.py)
endif
# Proof adapters need the owned status/state and serialization contracts typed together.
REGISTER_PROOF_MYPY_CONSUMERS := \
	tools/dosunit/ssa/ssa_output_lemmas.py \
	tools/dosunit/contracts/register_state_relations.py \
	tools/dosunit/contracts/proof_scope.py \
	tools/dosunit/compare/real16_region_proof.py \
	tools/dosunit/compare/flat32_cfg_regions.py
ifneq ($(filter $(REGISTER_PROOF_MYPY_CONSUMERS),$(PY_FILES)),)
MYPY_SELECTED_FILES := $(sort $(MYPY_SELECTED_FILES) \
	tools/dosunit/contracts/proof_contracts.py tools/dosunit/contracts/proof_obligations.py \
	tools/dosunit/reporting/proof_serialization.py tools/dosunit/contracts/register_state_relations.py \
	tools/dosunit/contracts/register_affine_relations.py)
endif
TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)

# Early comparator admission gate: reuse existing positive/corruption controls
# before the full decompiler suite. This is not M0-M7 release acceptance.
COMPARATOR_ADMISSION_TESTS := \
	tools/dosunit/tests/test_ordered_io_environment.py \
	tests/semantics/test_x86_16_immediate_port.py \
	tools/dosunit/tests/test_flat32_indirect_callbacks.py \
	tools/dosunit/tests/test_flat32_indirect_callback_effects.py \
	tools/dosunit/tests/test_flat32_loop_calls_public.py \
	tools/dosunit/tests/test_flat32_loop_calls.py \
	tools/dosunit/tests/test_replay_capture_vectors.py \
	tools/dosunit/tests/test_binary_callee_control_target.py \
	tools/dosunit/tests/test_real16_uncatalogued_calls.py::test_public_uncatalogued_direct_leaf \
	tools/dosunit/tests/test_dosunit_guarded_capture.py \
	tools/dosunit/tests/test_real16_write_readback.py \
	tools/dosunit/tests/test_real16_argument_controls.py \
	tools/dosunit/tests/test_real16_far_loop_controls.py \
	tools/dosunit/tests/test_dosunit_alarm_boundary.py \
	tools/dosunit/tests/test_dosunit_transitive_callees.py \
	tools/dosunit/tests/test_dosunit_vex_cache_identity.py \
	tools/dosunit/tests/test_real16_public_accounting.py \
	tools/dosunit/tests/test_real16_selected_lowering.py \
	tools/dosunit/tests/test_real16_self_lowering_reuse.py \
	tools/dosunit/tests/test_dosunit_ssa_source_identity_paths.py \
	tools/dosunit/tests/test_flat32_proof_seal.py \
	tools/dosunit/tests/test_flat32_contextual_calls.py \
	tools/dosunit/tests/test_real16_program_interrupts.py \
	tools/dosunit/tests/test_real16_program_vectors.py \
	tools/dosunit/tests/test_real16_program_device_info.py \
	tools/dosunit/tests/test_real16_program_video.py \
	tools/dosunit/tests/test_real16_program_video_policy.py \
	tools/dosunit/tests/test_real16_video_state_policy.py \
	tools/dosunit/tests/test_real16_video_state_boundary.py \
	tools/dosunit/tests/test_real16_program_video_state.py \
	tools/dosunit/tests/test_real16_program_rom.py \
	tools/dosunit/tests/test_real16_program_rom_integration.py \
	tools/dev/tests/test_pytest_directory_cache.py \
	tests/cli/test_batch_decompile_scheduler.py::test_scheduler_incomplete_eof_waits_for_actual_exit \
	tests/cli/test_batch_decompile_scheduler.py::test_scheduler_incomplete_eof_keeps_deadline_without_polling_closed_fd \
	tests/alias/test_x86_16_bp_preservation.py \
	tests/ir/test_x86_16_ir_boundary_cfg.py \
	tests/ir/test_x86_16_segment_function_summary.py \
	tools/dosunit/tests/test_dosunit_proof_contracts.py \
	tools/dosunit/tests/test_dosunit_public_domain.py \
	tools/dosunit/tests/test_dosunit_public_domain_integration.py \
	tools/dosunit/tests/test_dosunit_ssa_provenance.py \
	tools/dosunit/tests/test_real16_control_target_proof.py \
	tools/dosunit/tests/test_real16_control_boundary.py \
	tests/frontend/test_x86_16_aam_fault.py \
	tools/dosunit/tests/test_native_effect_environment_guards.py \
	tools/dosunit/tests/test_dosunit_io_read_state.py \
	tests/frontend/test_nop_native_binding.py \
	tests/ir/test_nop_cache_cost.py \
	tests/ir/test_segment_call_binding_regression.py \
	tests/ir/test_native_relift_scope.py \
	tests/semantics/test_direct_near_call_target_binding.py \
	tests/ir/test_x86_16_declared_call_consumption.py \
	tests/cli/test_declared_call_transport.py \
	tests/semantics/test_projected_call_consumption.py \
	tests/integration/test_declared_call_admission.py \
	tests/integration/test_declared_call_schema.py \
	tests/integration/test_declared_call_binding.py \
	tests/frontend/test_x86_16_native_helper_call_retention.py \
	tools/dosunit/tests/test_flat32_comparator_lane.py \
	tools/dosunit/tests/test_flat32_loop_controls.py \
	tools/dosunit/tests/test_flat32_compose_total_budget.py \
	tools/dosunit/tests/test_relational_pe32_public.py

.PHONY: comparator-check-fast
# A dependency edge, rather than sibling prerequisites, also serializes these
# pytest pools under make -j. Keep the shared six-worker allowance bounded.
comparator-check-fast: override PYTEST_WORKERS := $(COMPARATOR_PYTEST_WORKERS)
comparator-check-fast: decompiler-contracts
	$(Q)$(PYTHON) -m pytest -q $(PYTEST_ARGS) --maxfail=1 $(COMPARATOR_ADMISSION_TESTS)

# Keep the complete QA inventory while deriving its host-only control selectors
# from the pipeline owner. Guarded controls execute after the outer pytest pool.
SPLIT_CONTROL_TEST_FILES := tools/dev/tests/test_fork_owner_death.py tools/dev/tests/test_pytest_live_failures.py tools/compiler_toolchain/tests/test_compiler_coverage_runner.py tests/lowering/test_x86_16_gp_word_runtime.py
CONTROL_HOST_TARGETS_COMMAND ?= $(PYTHON) tools/dev/test_pipeline.py --print-host-controls
define load_control_host_pytest_targets
$(eval CONTROL_HOST_TARGETS_CACHE := $(shell $(CONTROL_HOST_TARGETS_COMMAND)))
$(if $(filter 0,$(.SHELLSTATUS)),,$(error control-host-targets: provider command failed))
$(if $(strip $(CONTROL_HOST_TARGETS_CACHE)),,$(error control-host-targets: provider returned an empty inventory))
$(CONTROL_HOST_TARGETS_CACHE)
endef
CONTROL_HOST_PYTEST_TARGETS = $(if $(CONTROL_HOST_TARGETS_CACHE),$(CONTROL_HOST_TARGETS_CACHE),$(strip $(call load_control_host_pytest_targets)))
GNU_MAKE_ORACLE_TEST_FILE := tools/dev/tests/test_makefile_gnu_oracle.py
GNU_MAKE_ORACLE_TARGET_PATTERN := $(GNU_MAKE_ORACLE_TEST_FILE)::%
QA_HOST_PYTEST_TARGETS = $(filter-out $(SPLIT_CONTROL_TEST_FILES) $(GNU_MAKE_ORACLE_TEST_FILE),$(QA_PYTEST_TARGETS)) $(CONTROL_HOST_PYTEST_TARGETS)
SERIAL_CONTROL_TARGET_PATTERN := tools/dev/tests/test_pytest_live_failures.py::test_live_failures_preserve_reports_and_emit_before_session_end%
LINUX_CONTROL_TARGET_PATTERN := tools/dev/tests/test_fork_owner_death.py::% tools/compiler_toolchain/tests/test_compiler_coverage_runner.py::test_real_timeout_stops_descendants_and_retains_both_output_streams%
NATIVE_CONTROL_TARGET_PATTERN := tests/lowering/test_x86_16_gp_word_runtime.py::test_msc6_word_runtime_compiles_and_executes%
PROFILE_GUARDED_TARGETS = $(filter $(SERIAL_CONTROL_TARGET_PATTERN) $(LINUX_CONTROL_TARGET_PATTERN) $(NATIVE_CONTROL_TARGET_PATTERN) $(GNU_MAKE_ORACLE_TARGET_PATTERN),$(PYTEST_PROFILE_TARGETS))
PROFILE_EXPLICIT_GUARDED_TARGETS = $(foreach target,$(PROFILE_GUARDED_TARGETS),$(if $(filter $(firstword $(subst ::, ,$(target))),$(PYTEST_PROFILE_TARGETS)),,$(target)))
PROFILE_HOST_PYTEST_TARGETS = $(filter-out $(SPLIT_CONTROL_TEST_FILES) $(GNU_MAKE_ORACLE_TEST_FILE) $(PROFILE_GUARDED_TARGETS),$(PYTEST_PROFILE_TARGETS)) $(foreach control_file,$(filter $(SPLIT_CONTROL_TEST_FILES),$(PYTEST_PROFILE_TARGETS)),$(filter $(control_file)::%,$(CONTROL_HOST_PYTEST_TARGETS)))
PROFILE_CONTROL_LANES = $(if $(filter tools/dev/tests/test_pytest_live_failures.py $(SERIAL_CONTROL_TARGET_PATTERN),$(PYTEST_PROFILE_TARGETS)),--lane pytest-serial) $(if $(filter tools/compiler_toolchain/tests/test_compiler_coverage_runner.py tools/dev/tests/test_fork_owner_death.py $(LINUX_CONTROL_TARGET_PATTERN),$(PYTEST_PROFILE_TARGETS)),--lane linux-process-controls) $(if $(filter tests/lowering/test_x86_16_gp_word_runtime.py $(NATIVE_CONTROL_TARGET_PATTERN),$(PYTEST_PROFILE_TARGETS)),--lane gp-word-native) $(if $(filter $(GNU_MAKE_ORACLE_TEST_FILE) $(GNU_MAKE_ORACLE_TARGET_PATTERN),$(PYTEST_PROFILE_TARGETS)),--lane makefile-gnu-oracle)

pytest:
	$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FOCUSED_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) -m pytest -q $(PYTEST_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)" $(QA_HOST_PYTEST_TARGETS)
	$(Q)$(PYTHON) tools/dev/test_pipeline.py --lane pytest-serial --lane linux-process-controls --lane gp-word-native --lane makefile-gnu-oracle --out .cache/pytest/guarded-controls.json

pytest-profile:
	$(if $(strip $(PROFILE_HOST_PYTEST_TARGETS)),$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FULL_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) -m tools.dev.pytest_profile $(PYTEST_PROFILE_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)" --profile-json $(PYTEST_PROFILE_JSON) $(PROFILE_HOST_PYTEST_TARGETS))
	$(if $(strip $(PROFILE_CONTROL_LANES)),$(Q)$(PYTHON) tools/dev/test_pipeline.py $(PROFILE_CONTROL_LANES) $(foreach target,$(PROFILE_EXPLICIT_GUARDED_TARGETS),--control-target '$(target)') --out .cache/pytest/profile-guarded-controls.json)

pytest-inventory:
	$(PYTHON) -m tools.dev.pytest_profile --profile-json $(PYTEST_INVENTORY_JSON) --collect-only -q >/dev/null
	$(PYTHON) -m tools.dev.pytest_inventory_check $(PYTEST_INVENTORY_JSON)
	@echo "pytest inventory: $(PYTEST_INVENTORY_JSON)"

pytest-inventory-check:
	$(PYTHON) -m tools.dev.pytest_inventory_check $(PYTEST_INVENTORY_JSON)

pytest-files:
	@manifest_tests="$$( $(PYTHON) tools/dev/test_ownership_manifest.py $(PY_FILES) )"; \
	selected_tests="$$( \
		for test_target in $$manifest_tests $(PYTEST_FILES); do \
			printf '%s\n' "$$test_target"; \
		done | sort -u | tr '\n' ' ' \
	)"; \
	host_tests=""; control_lanes=""; guarded_targets=""; \
	for test_target in $$selected_tests; do \
		case "$$test_target" in \
			tools/dev/tests/test_pytest_live_failures.py) \
				host_tests="$$host_tests $(filter tools/dev/tests/test_pytest_live_failures.py::%,$(CONTROL_HOST_PYTEST_TARGETS))"; control_lanes="$$control_lanes pytest-serial" ;; \
			tools/dev/tests/test_pytest_live_failures.py::test_live_failures_preserve_reports_and_emit_before_session_end*) control_lanes="$$control_lanes pytest-serial"; guarded_targets="$$guarded_targets $$test_target" ;; \
			tools/dev/tests/test_fork_owner_death.py) control_lanes="$$control_lanes linux-process-controls" ;; \
			tools/dev/tests/test_fork_owner_death.py::*) control_lanes="$$control_lanes linux-process-controls"; guarded_targets="$$guarded_targets $$test_target" ;; \
			tools/compiler_toolchain/tests/test_compiler_coverage_runner.py) \
				host_tests="$$host_tests $(filter tools/compiler_toolchain/tests/test_compiler_coverage_runner.py::%,$(CONTROL_HOST_PYTEST_TARGETS))"; control_lanes="$$control_lanes linux-process-controls" ;; \
			tools/compiler_toolchain/tests/test_compiler_coverage_runner.py::test_real_timeout_stops_descendants_and_retains_both_output_streams*) control_lanes="$$control_lanes linux-process-controls"; guarded_targets="$$guarded_targets $$test_target" ;; \
			tests/lowering/test_x86_16_gp_word_runtime.py) \
				host_tests="$$host_tests $(filter tests/lowering/test_x86_16_gp_word_runtime.py::%,$(CONTROL_HOST_PYTEST_TARGETS))"; control_lanes="$$control_lanes gp-word-native" ;; \
			tests/lowering/test_x86_16_gp_word_runtime.py::test_msc6_word_runtime_compiles_and_executes*) control_lanes="$$control_lanes gp-word-native"; guarded_targets="$$guarded_targets $$test_target" ;; \
			$(GNU_MAKE_ORACLE_TEST_FILE)) control_lanes="$$control_lanes makefile-gnu-oracle" ;; \
			$(GNU_MAKE_ORACLE_TEST_FILE)::*) control_lanes="$$control_lanes makefile-gnu-oracle"; guarded_targets="$$guarded_targets $$test_target" ;; \
			*) host_tests="$$host_tests $$test_target" ;; \
		esac; \
	done; \
	host_tests="$$(for test_target in $$host_tests; do printf '%s\n' "$$test_target"; done | sort -u | tr '\n' ' ')"; \
	if [ -n "$$(echo "$$host_tests" | tr -d '[:space:]')" ]; then \
		INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FOCUSED_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) -m pytest -q $(PYTEST_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)" $$host_tests || exit $$?; \
	else \
		echo "pytest-files: no host test files selected"; \
	fi; \
	if [ -n "$$control_lanes" ]; then \
		control_target_args=""; \
		for test_target in $$guarded_targets; do \
			guarded_file="$${test_target%%::*}"; \
			case " $$selected_tests " in *" $$guarded_file "*) ;; *) control_target_args="$$control_target_args --control-target $$test_target" ;; esac; \
		done; \
		lane_args=""; \
		for lane in $$(for lane in $$control_lanes; do printf '%s\n' "$$lane"; done | sort -u); do lane_args="$$lane_args --lane $$lane"; done; \
		$(PYTHON) tools/dev/test_pipeline.py $$lane_args $$control_target_args --out .cache/pytest/selected-guarded-controls.json; \
	fi

pytest-all: pytest-inventory
	$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-$(FULL_TEST_DECOMPILE_TIMEOUT_SCALE)} $(PYTHON) -m tools.dev.pytest_partitioned \
		--inventory-json $(PYTEST_INVENTORY_JSON) \
		--history-json $(PYTEST_ALL_SUMMARY_JSON) \
		--summary-json $(PYTEST_ALL_SUMMARY_JSON) \
		--workers $(PYTEST_ALL_WORKERS) \
		--heavy-workers $(PYTEST_ALL_HEAVY_WORKERS) \
		--heavy-shards $(PYTEST_ALL_HEAVY_SHARDS) \
		--max-rss-mib $(PYTEST_ALL_MAX_RSS_MIB)

architecture-check:
	$(PYTHON) tools/dev/check_decompiler_architecture.py

architecture-check-fast:
	$(PYTHON) -m tools.dev.check_decompiler_architecture --startup-only

agent-context-check:
	$(Q)$(PYTHON) tools/dev/agent_context_check.py --compact

test-ownership-check: component-catalog-check
	$(PYTHON) tools/dev/test_ownership_manifest.py --check

.PHONY: component-catalog-check
component-catalog-check:
	$(Q)$(PYTHON) -m tools.dev.component_catalog_cli

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
	$(Q)$(PYRIGHT_CMD_BASE) $(wordlist 1,55,$(wildcard inertia/frontend/x86_16/*.py))
	$(Q)$(PYRIGHT_CMD_BASE) $(wordlist 56,110,$(wildcard inertia/frontend/x86_16/*.py))
	$(Q)$(PYRIGHT_CMD_BASE) $(wordlist 111,10000,$(wildcard inertia/frontend/x86_16/*.py))
	$(Q)$(PYRIGHT_CMD_BASE) inertia/alias inertia/ir/analysis inertia/ir inertia/pipeline
	$(Q)$(PYRIGHT_CMD_BASE) inertia/lowering
	$(Q)$(PYRIGHT_CMD_BASE) $(filter-out inertia/postprocess/optimization/dce.py,$(wildcard inertia/postprocess/*.py) $(wildcard inertia/postprocess/optimization/*.py))
	# Legacy hardening check expects this exact DCE command form in makefile text.
	$(Q)$(if $(strip $(PYRIGHT_WATCH_FLAG)),,$(TIMEOUT) --foreground $(PYRIGHT_DCE_TIMEOUT) $(PYTHON) -m pyright inertia/postprocess/optimization/dce.py $(PYRIGHT_OUTPUT_FLAGS) --pythonpath $(PYRIGHT_PYTHON_PATH)) || { \
		status=$$?; \
		if [ $$status -eq 124 ]; then echo "pyright: DCE batch exceeded $(PYRIGHT_DCE_TIMEOUT)s; split its oversized function instead of suppressing types"; fi; \
		exit $$status; \
	}
	$(Q)$(PYRIGHT_CMD_BASE) inertia/semantics
	$(Q)$(PYRIGHT_CMD_BASE) inertia/structuring
	$(Q)$(PYRIGHT_CMD_BASE) inertia/validation
	$(Q)$(PYRIGHT_CMD_BASE) inertia/widening
	$(Q)$(PYRIGHT_CMD_BASE) inertia/cli $(filter-out inertia/% inertia/cli/%,$(QA_TYPED_FILES))

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
		$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES); \
	fi

type-ratchet-changed:
	@if [ -n "$(strip $(QA_CHANGED_TYPED_FILES))" ]; then \
		$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES); \
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
	flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) tools/dev/build_mypyc.py --jobs $(MYPYC_JOBS)

mypyc-smoke:
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) tools/dev/build_mypyc.py --jobs $(MYPYC_JOBS)

vulture:
	$(Q)$(PYTHON) -m vulture $(QA_TYPED_FILES)

# Scan canonical source and test roots so Basta can classify test support;
# passing a test directory alone
# as a scan root loses that classification and reports every helper.
# --entry marks modules reachable only from repo-root entry scripts that
# stay outside the lint scan scope: decompile.py (the [project.scripts]
# console entry) imports inertia/cli/direct_request_fast_path.py. The canonical
# discovery owner lazily imports inertia/cli/borland_mangling.py. The pytest_runtime
# hook is registered by root conftest, outside the scan roots. Scanning those
# root scripts directly is not viable: it activates repo-root Makefile/path-name
# reachability, which collapses the report to almost nothing.
unused-python-files:
	$(Q)npm_config_cache="$(CURDIR)/.cache/npm-cache" $(BASTA) --categories unused-file --workers 3 --no-colors \
		--entry '**/direct_request_fast_path.py' \
		--entry '**/borland_mangling.py' \
		--entry '**/pytest_directory_cache.py' \
		--entry '**/pytest_live_failures.py' \
		--entry '**/pytest_runtime.py' \
		inertia tools tests

lizard:
	$(Q)$(PYTHON) -m lizard $(LIZARD_OUTPUT_FLAGS) -l python -C 10 -i -1 tools inertia/cli

lizard-dev:
	$(Q)$(PYTHON) -m lizard $(LIZARD_OUTPUT_FLAGS) -l python -C 10 -i -1 $(LINTERS_DEV_LIZARD_PATHS)

.PHONY: decompiler-contracts
# This small cohort is dominated by worker imports: two workers measured
# 15.05s versus 28.68s with six. Preserve serial requests and cap only this
# precheck; the following comparator/decompiler suites retain the requested pool.
decompiler-contracts: override PYTEST_WORKERS := $(if $(filter 1,$(PYTEST_WORKERS)),1,2)
decompiler-contracts:
	$(Q)PYTHON_JIT=1 $(PYTHON) -m pytest -q $(PYTEST_ARGS) --durations=10 \
		tests/lowering/test_x86_16_c_ast_utils.py \
		tests/integration/test_x86_16_ast_traversal_coverage.py \
		tests/lowering/test_x86_16_ss_traversal_contract.py \
		tests/lowering/test_x86_16_stack_prototype_wrapped_locals.py \
		tests/validation/test_x86_16_validation_entry_stack_ranges.py \
		tests/lowering/test_x86_16_far_return_boundary_carriers.py \
		tests/alias/test_x86_16_stack_reference_offsets.py


test-pipeline: decompiler-contracts
	mkdir -p "$(dir $(TEST_PIPELINE_LOCK))"
	flock "$(TEST_PIPELINE_LOCK)" $(PYTHON) tools/dev/test_pipeline.py --require-external --pytest-workers $(PYTEST_WORKERS) --msc6-workers $(PIPELINE_WORKERS)

test-pipeline-fast: comparator-check-fast
	mkdir -p "$(dir $(TEST_PIPELINE_LOCK))"
	flock "$(TEST_PIPELINE_LOCK)" $(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external --pytest-workers $(PYTEST_WORKERS) --msc6-workers $(PIPELINE_WORKERS)

test-pipeline-expanded: decompiler-contracts
	mkdir -p "$(dir $(TEST_PIPELINE_LOCK))"
	flock "$(TEST_PIPELINE_LOCK)" $(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external --pytest-workers $(PYTEST_WORKERS) --msc6-workers $(PIPELINE_WORKERS)

test-layer:
	$(PYTHON) tools/dev/agent_test_focus.py \
		$(if $(strip $(LAYER)),--layer $(LAYER),) \
		$(if $(strip $(FILES)),--files $(FILES),$(if $(strip $(LAYER)),--no-infer-changed,)) \
		$(if $(strip $(MAX_TESTS)),--max-tests $(MAX_TESTS),) \
		$(if $(strip $(AGENT_TEST_JSON)),--json,) \
		$(if $(strip $(AGENT_TEST_JSON_ONLY)),--json-only,) \
		$(if $(strip $(NO_SHARED)),--no-shared,) \
		$(if $(filter 1,$(RUN)),--run)

test-agent-confidence:
	$(PYTHON) tools/dev/agent_test_focus.py --run \
		$(if $(strip $(MAX_TESTS)),--max-tests $(MAX_TESTS),) \
		$(if $(strip $(AGENT_TEST_JSON)),--json,) \
		$(if $(strip $(AGENT_TEST_JSON_ONLY)),--json-only,) \
		$(if $(strip $(NO_SHARED)),--no-shared,)

msc6-examples:
	INERTIA_ENABLE_TAIL_VALIDATION=1 INERTIA_DISABLE_TIMING=1 $(PYTHON) tools/compiler_toolchain/build_msc6_examples.py --skip-constructs medium_structs,enum_union --decompile-mode functions --decompile-max-functions 0 --decompile-timeout 60 --decompile-run-timeout 600

sortdemo-selftest:
	$(PYTHON) tools/dev/build_sortdemo_selftest.py --clean

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
		$(PYTHON) tools/compiler_toolchain/build_msc6_examples.py \
			--out-dir examples/build_msc6_tiny \
			--only-constructs $(DECOMP_OPT_REGRESSION_CONSTRUCTS) \
			--skip-constructs $(DECOMP_OPT_REGRESSION_CONSTRUCTS) \
			--harvest-success-code 255; \
	fi

decomp-opt-regression:
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) tools/dev/benchmark_optimization_quality_guard.py examples/build_msc6/CMP16.EXE -- $(DECOMP_OPT_REGRESSION_ARGS)

decomp-opt-regression-suite: decomp-opt-regression-inputs
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	@for binary in $(DECOMP_OPT_REGRESSION_BINARIES); do \
		echo "/* decompilation quality guard: $$binary */"; \
		flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) tools/dev/benchmark_optimization_quality_guard.py "$$binary" \
			--mode-timeout $(DECOMP_OPT_REGRESSION_TIMEOUT) \
			-- $(DECOMP_OPT_REGRESSION_ARGS) \
			|| exit $$?; \
	done

decomp-opt-regression-thread:
	mkdir -p "$(dir $(MYPYC_ARTIFACT_LOCK))"
	@for binary in $(DECOMP_OPT_REGRESSION_BINARIES); do \
		echo "/* decompilation quality guard (thread timeout lanes): $$binary */"; \
		INERTIA_FORCE_TIMEOUT_LANES_THREAD=1 flock "$(MYPYC_ARTIFACT_LOCK)" $(PYTHON) tools/dev/benchmark_optimization_quality_guard.py "$$binary" \
			--mode-timeout $(DECOMP_OPT_REGRESSION_TIMEOUT) \
			-- $(DECOMP_OPT_REGRESSION_ARGS) \
			|| exit $$?; \
	done

monkeytype-trace:
	$(PYTHON) tools/dev/collect_monkeytype_pytest.py

monkeytype-stubs:
	$(PYTHON) tools/dev/export_monkeytype_stubs.py

monkeytype-apply:
	$(PYTHON) tools/dev/apply_monkeytype_annotations.py

types: monkeytype-trace monkeytype-apply

# Source-bound native terminal targets at the Clinic conversion boundary.
LINTERS_DEV_MYPY_FILES += inertia/frontend/x86_16/clinic_terminal_control.py
QA_TYPED_FILES += inertia/frontend/x86_16/clinic_terminal_control.py
QA_RUFF_TARGETS += inertia/frontend/x86_16/clinic_terminal_control.py tests/frontend/test_x86_16_clinic_terminal_control.py
QA_RUFF_TARGETS += tests/cli/test_x86_16_clinic_binary_terminal_control.py
QA_PYTEST_TARGETS += tests/frontend/test_x86_16_clinic_terminal_control.py

# Complete focused-test admission; duplicate detection remains enforced.
QA_PYTEST_TARGETS += tools/dosunit/tests/test_flat32_indirect_callbacks.py tools/dosunit/tests/test_flat32_indirect_callback_effects.py tools/dosunit/tests/test_dosunit_kvikdos_strict.py tests/frontend/test_x86_16_aam_fault.py tools/dosunit/tests/test_native_effect_environment_guards.py tools/dosunit/tests/test_dosunit_io_read_state.py tests/integration/test_x86_16_import_identity.py tests/cli/test_acceptance_reporting.py tests/cli/test_cli_shared_future_collection.py tests/cli/test_cli_ranked_task_queue.py tests/ir/test_x86_16_vex_binop_result_width.py tests/ir/test_x86_16_vex_wrtmp_result_width.py tests/cli/test_inertia_telemetry.py tools/dev/tests/test_makefile_variable_expansion.py
QA_RUFF_TARGETS += tools/dev/tests/test_makefile_variable_expansion.py

# External GNU parity controls retain explicit unavailable-tool accounting.
QA_PYTEST_TARGETS += tools/dev/tests/test_makefile_gnu_oracle.py
QA_RUFF_TARGETS += tools/dev/tests/test_makefile_gnu_oracle.py

QA_PYTEST_TARGETS += tools/dev/tests/test_kvm_marker_policy.py
QA_RUFF_TARGETS += tools/dev/tests/test_kvm_marker_policy.py

# Promote reviewed compiler-evidence owners into the existing quality gates.
QA_TYPED_FILES += inertia/cli/borland_mangling.py inertia/lowering/call_return_bridge_projection.py inertia/lowering/call_target_bind_common.py inertia/lowering/call_target_projection_integrity.py inertia/lowering/call_target_raw_route.py inertia/lowering/call_target_semantic_route.py inertia/lowering/call_target_ssa_binder.py inertia/lowering/call_target_ssa_contracts.py inertia/lowering/gp_constant_restore.py inertia/lowering/gp_word_assignment.py inertia/lowering/gp_word_runtime.py
QA_RUFF_TARGETS += inertia/cli/borland_mangling.py inertia/lowering/call_return_bridge_projection.py inertia/lowering/call_target_bind_common.py inertia/lowering/call_target_projection_integrity.py inertia/lowering/call_target_raw_route.py inertia/lowering/call_target_semantic_route.py inertia/lowering/call_target_ssa_binder.py inertia/lowering/call_target_ssa_contracts.py inertia/lowering/gp_constant_restore.py inertia/lowering/gp_word_assignment.py inertia/lowering/gp_word_runtime.py

# Typed confidence metadata reporting: static producer/refusal controls.
QA_RUFF_TARGETS += tests/structuring/test_x86_16_confidence_and_assumptions.py
QA_PYTEST_TARGETS += tests/structuring/test_x86_16_confidence_and_assumptions.py

# Canonical owners repointed from moved compatibility paths stay enrolled.
QA_TYPED_FILES += \
	inertia/frontend/x86_16/__init__.py \
	inertia/ir/analysis/__init__.py \
	inertia/pipeline/__init__.py
QA_RUFF_TARGETS += \
	inertia/frontend/x86_16/__init__.py \
	inertia/ir/analysis/__init__.py \
	inertia/pipeline/__init__.py

# Compatibility forwarders under the moved X86_16 package stay promoted;
# canonical implementations live under inertia/ and the alias modules keep
# the historical import surface lint- and type-clean.
QA_TYPED_FILES += \
	inertia/postprocess/optimization/__init__.py \

QA_RUFF_TARGETS += \
	inertia/postprocess/optimization/__init__.py \


# Canonical package boundaries and pure DOS service contracts.
QA_TYPED_FILES += inertia/__init__.py inertia/frontend/__init__.py   inertia/ir/public_api.py
QA_RUFF_TARGETS += inertia/__init__.py inertia/frontend/__init__.py   inertia/ir/public_api.py
