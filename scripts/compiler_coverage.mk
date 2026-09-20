# Candidate round trips; semantic feature witnesses are reported separately.
COMPILER_COVERAGE_TYPED_OWNERS := \
	scripts/msc6_memory_model.py \
	angr_platforms/angr_platforms/X86_16/callsite_pointer_values.py \
	angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument_values.py \
	inertia_decompiler/binary_signature_metadata.py \
	inertia_decompiler/discovery_candidate_ranges.py \
	inertia_decompiler/metadata_evidence.py
COMPILER_COVERAGE_REGRESSION_FILES := \
	angr_platforms/tests/test_msc6_memory_model.py \
	angr_platforms/tests/test_msc6_binary_recovery_policy.py \
	angr_platforms/tests/test_near_pointer_argument_values.py \
	angr_platforms/tests/test_default_signature_provenance.py \
	angr_platforms/tests/test_metadata_evidence.py \
	angr_platforms/tests/test_binary_signature_metadata.py
QA_TYPED_FILES += $(COMPILER_COVERAGE_TYPED_OWNERS)
LINTERS_DEV_MYPY_FILES += $(COMPILER_COVERAGE_TYPED_OWNERS)
QA_RUFF_TARGETS += $(COMPILER_COVERAGE_TYPED_OWNERS) $(COMPILER_COVERAGE_REGRESSION_FILES)
QA_PYTEST_TARGETS += $(COMPILER_COVERAGE_REGRESSION_FILES)

MODEL ?= small
COMPILER_COVERAGE_MANIFEST ?= examples/compiler_coverage/$(if $(filter large,$(MODEL)),large,pilot).json
COMPILER_COVERAGE_OUT ?= .cache/compiler-coverage/run-$(shell date +%Y%m%d-%H%M%S)
COMPILER_COVERAGE_TIMEOUT ?= 600
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
	$(Q)PYTHON_JIT=1 PYTHONHASHSEED=0 $(PYTHON) scripts/compiler_coverage_suite.py \
		--manifest "$(COMPILER_COVERAGE_MANIFEST)" --out-dir "$(COMPILER_COVERAGE_OUT)" \
		--timeout "$(COMPILER_COVERAGE_TIMEOUT)" \
		$(if $(strip $(CASE)),--case "$(CASE)",) \
		$(if $(strip $(OBLIGATION)),--obligation "$(OBLIGATION)",) \
		$(if $(strip $(RERUN_FAILED)),--rerun-failed "$(RERUN_FAILED)",)

compiler-coverage-contracts:
	$(Q)PYTHON_JIT=1 PYTHONHASHSEED=0 $(PYTHON) -m pytest -n 7 -q --tb=short --no-header --durations=10 \
		angr_platforms/tests/test_msc6_memory_model.py \
		angr_platforms/tests/test_msc6_original_evidence.py \
		angr_platforms/tests/test_compiler_coverage_csmith.py \
		angr_platforms/tests/test_compiler_coverage_manifest.py \
		angr_platforms/tests/test_compiler_coverage_pointer_oracle.py \
		angr_platforms/tests/test_compiler_coverage_provenance.py \
		angr_platforms/tests/test_compiler_coverage_result.py \
		angr_platforms/tests/test_compiler_coverage_runner.py \
		angr_platforms/tests/test_msc6_binary_recovery_policy.py \
		angr_platforms/tests/test_compiler_coverage_suite.py
