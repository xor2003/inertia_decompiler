"""Legacy paths share the canonical compiler-tool identities."""

from importlib import import_module

import pytest


@pytest.mark.parametrize("name", [
    "compiler_coverage_manifest", "compiler_coverage_result",
    "compiler_coverage_provenance", "compiler_coverage_cross_unit",
    "compiler_coverage_rerun", "compiler_coverage_runner",
    "compiler_coverage_suite", "compiler_coverage_csmith", "compiler_profile",
    "msc6_memory_model", "build_msc6_examples", "msc6_function_targets",
    "msc6_original_evidence", "msc6_runtime_gate_artifacts", "msc6_runtime_support",
    "msc6_pointer_memory_harness", "msc6_compat_headers", "msc6_entrypoint",
    "msc6_toolchain_lock", "generated_c_contracts",
    "generated_c_indexed_argument_contract",
])
def test_legacy_module_is_canonical_owner(name):
    assert import_module("scripts." + name) is import_module("tools.compiler_toolchain." + name)


def test_profile_registry_stays_repository_relative():
    from pathlib import Path

    from tools.compiler_toolchain.compiler_profile import DEFAULT_PROFILE_REGISTRY

    assert Path(__file__).resolve().parents[3] / "examples/compiler_coverage/toolchains.json" == DEFAULT_PROFILE_REGISTRY


def test_process_measurements_share_legacy_identity():
    import tools.dev.process_metrics as pytest_process_metrics
    from tools.dev import process_metrics

    assert pytest_process_metrics is process_metrics
