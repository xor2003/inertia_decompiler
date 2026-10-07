# Candidate round trips; semantic feature witnesses are reported separately.
COMPILER_COVERAGE_TYPED_OWNERS := \
	tools/compiler_toolchain/compiler_profile.py \
	tools/compiler_toolchain/msc6_memory_model.py \
	inertia/lowering/callsite_pointer_values.py \
	inertia/lowering/near_pointer_argument_values.py \
	inertia/cli/binary_signature_metadata.py \
	inertia/cli/discovery_candidate_ranges.py \
	inertia/cli/metadata_evidence.py
COMPILER_COVERAGE_REGRESSION_FILES := \
	tools/compiler_toolchain/tests/test_compiler_coverage_profile.py \
	tools/compiler_toolchain/tests/test_msc6_memory_model.py \
	tools/compiler_toolchain/tests/test_msc6_dos_tmp.py \
	tests/integration/test_msc6_binary_recovery_policy.py \
	tests/lowering/test_near_pointer_argument_values.py \
	tests/integration/test_default_signature_provenance.py \
	tests/cli/test_metadata_evidence.py \
	tools/signatures/tests/test_binary_signature_metadata.py
COMPILER_COVERAGE_QA_OWNERS := \
	inertia/lowering/callsite_pointer_values.py \
	inertia/lowering/near_pointer_argument_values.py \
	inertia/cli/binary_signature_metadata.py \
	inertia/cli/discovery_candidate_ranges.py \
	inertia/cli/metadata_evidence.py
QA_TYPED_FILES += $(COMPILER_COVERAGE_QA_OWNERS)
LINTERS_DEV_MYPY_FILES += $(COMPILER_COVERAGE_TYPED_OWNERS)
QA_RUFF_TARGETS += $(COMPILER_COVERAGE_QA_OWNERS) $(COMPILER_COVERAGE_REGRESSION_FILES)
QA_PYTEST_TARGETS += $(COMPILER_COVERAGE_REGRESSION_FILES)

MODEL ?= small
COMPILER_COVERAGE_MANIFEST ?= examples/compiler_coverage/$(if $(filter large,$(MODEL)),large,pilot).json
COMPILER_COVERAGE_OUT ?= .cache/compiler-coverage/run-$(shell date +%Y%m%d-%H%M%S)
COMPILER_COVERAGE_TIMEOUT ?= 600
COMPILER_COVERAGE_PROFILE_EVIDENCE ?=
CSMITH_SEED ?= 2
CSMITH_RUNTIME_SOURCE ?= /home/xor/csmith/runtime
CSMITH_RUNTIME_BUILD ?= $(abspath $(dir $(CSMITH))/../runtime)

.PHONY: compiler-coverage compiler-coverage-batch compiler-coverage-contracts compiler-coverage-generate compiler-coverage-csmith
compiler-coverage-csmith:
	$(Q)test -x "$(CSMITH)" || { printf 'Set CSMITH to the pinned MS-DOS generator executable\n' >&2; exit 2; }
	$(Q)PYTHON_JIT=1 PYTHONHASHSEED=0 $(PYTHON) -m scripts.compiler_coverage_csmith \
		--csmith "$(CSMITH)" --seed "$(CSMITH_SEED)" --out-dir "$(COMPILER_COVERAGE_OUT)" \
		--roundtrip --runtime-source "$(CSMITH_RUNTIME_SOURCE)" --runtime-build "$(CSMITH_RUNTIME_BUILD)" \
		--memory-model "$(MODEL)" --case-timeout "$(COMPILER_COVERAGE_TIMEOUT)" \
		$(if $(strip $(CSMITH_SIGNATURE_CATALOG)),--signature-catalog "$(CSMITH_SIGNATURE_CATALOG)",)

compiler-coverage-generate:
	$(Q)test -x "$(CSMITH)" || { printf 'Set CSMITH to the pinned MS-DOS generator executable\n' >&2; exit 2; }
	$(Q)PYTHON_JIT=1 PYTHONHASHSEED=0 $(PYTHON) -m scripts.compiler_coverage_csmith \
		--csmith "$(CSMITH)" --seed "$(CSMITH_SEED)" --out-dir "$(COMPILER_COVERAGE_OUT)"

compiler-coverage-batch:
	$(Q)status=0; for model in small large; do \
		$(MAKE) --no-print-directory compiler-coverage MODEL=$$model \
			COMPILER_COVERAGE_OUT="$(COMPILER_COVERAGE_OUT)/$$model" || status=1; \
	done; exit $$status

compiler-coverage:
	$(Q)case "$(MODEL)" in small|large) ;; *) printf 'Unsupported MODEL: %s\n' "$(MODEL)" >&2; exit 2;; esac
	$(Q)PYTHON_JIT=1 PYTHONHASHSEED=0 $(PYTHON) tools/compiler_toolchain/compiler_coverage_suite.py \
		--manifest "$(COMPILER_COVERAGE_MANIFEST)" --out-dir "$(COMPILER_COVERAGE_OUT)" \
		--timeout "$(COMPILER_COVERAGE_TIMEOUT)" \
		$(if $(strip $(CASE)),--case "$(CASE)",) \
		$(if $(strip $(OBLIGATION)),--obligation "$(OBLIGATION)",) \
		$(if $(strip $(RERUN_FAILED)),--rerun-failed "$(RERUN_FAILED)",) \
		$(if $(strip $(COMPILER_COVERAGE_PROFILE_EVIDENCE)),--profile-evidence "$(COMPILER_COVERAGE_PROFILE_EVIDENCE)",)

compiler-coverage-contracts:
	$(Q)PYTHON_JIT=1 PYTHONHASHSEED=0 $(PYTHON) -m pytest -n $(PYTEST_WORKERS) -q --tb=short --no-header --durations=10 \
		tools/compiler_toolchain/tests/test_msc6_memory_model.py \
		tools/compiler_toolchain/tests/test_msc6_dos_tmp.py \
		tools/compiler_toolchain/tests/test_msc6_original_evidence.py \
		tools/compiler_toolchain/tests/test_compiler_coverage_csmith.py \
		tools/compiler_toolchain/tests/test_compiler_coverage_manifest.py \
		angr_platforms/tests/test_compiler_coverage_pointer_oracle.py \
		tools/compiler_toolchain/tests/test_compiler_coverage_profile.py \
		tools/compiler_toolchain/tests/test_compiler_coverage_provenance.py \
		tools/compiler_toolchain/tests/test_compiler_coverage_result.py \
		$(filter tools/compiler_toolchain/tests/test_compiler_coverage_runner.py::%,$(CONTROL_HOST_PYTEST_TARGETS)) \
		tests/integration/test_msc6_binary_recovery_policy.py \
		tools/compiler_toolchain/tests/test_compiler_coverage_suite.py
	$(Q)$(PYTHON) tools/dev/test_pipeline.py --lane linux-process-controls --out .cache/pytest/compiler-process-controls.json
