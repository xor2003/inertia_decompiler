from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from inertia_decompiler.cache_io import load_cache_json_path, store_cache_json_path
from scripts.pytest_cache_events import begin_cache_event_capture, finish_cache_event_capture
from scripts.pytest_inventory_review import RETIRED_TEST_CONTRACTS, REVIEWED_TEST_MODULE_LAYERS
from scripts.pytest_process_metrics import ChildUsageSnapshot
from scripts.pytest_profile_rankings import profile_cost_rankings
from scripts.pytest_source_index import load_pytest_source_index
from scripts.pytest_test_inventory import record_for_item

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PROFILE_SCHEMA_VERSION = 11
PROFILED_TEST_COUNT = 2


def test_child_usage_delta_is_non_negative():
    earlier = ChildUsageSnapshot(user_seconds=3.0, system_seconds=2.0)

    delta = ChildUsageSnapshot(user_seconds=2.0, system_seconds=4.5).delta_since(earlier)

    assert delta == ChildUsageSnapshot(user_seconds=0.0, system_seconds=2.5)


def test_profile_cost_rankings_identify_wall_and_child_cpu_leaders():
    records = [
        {"nodeid": "test_fast", "outcome": "passed", "total_seconds": 1.0, "child_cpu_seconds": 0.8},
        {"nodeid": "test_slow", "outcome": "passed", "total_seconds": 3.0, "child_cpu_seconds": 0.2},
        {"nodeid": "test_not_run", "outcome": "not-run", "total_seconds": 9.0, "child_cpu_seconds": 9.0},
    ]

    rankings = profile_cost_rankings(records, limit=2)

    assert [item["nodeid"] for item in rankings["wall_seconds"]] == ["test_slow", "test_fast"]
    assert [item["nodeid"] for item in rankings["child_cpu_seconds"]] == ["test_fast", "test_slow"]


def test_cache_event_capture_preserves_keys_outcomes_and_validation(tmp_path):
    profile_path = tmp_path / "profile.json"
    event_path = begin_cache_event_capture(profile_path, "run", "gw0", "test_node")
    cache_path = tmp_path / "cache" / "function_decompile" / "accepted.json"
    missing_path = cache_path.with_name("missing.json")
    payload = {"tail_validation": {"structuring": {"status": "stable"}}}
    key_context = {"environment": {"INERTIA_MODE": "1"}, "function_addr": 0x10060}

    store_cache_json_path("function_decompile", cache_path, payload, key_context=key_context)
    assert load_cache_json_path("function_decompile", cache_path, key_context=key_context) == payload
    assert load_cache_json_path("function_decompile", missing_path, key_context=key_context) is None
    summary = finish_cache_event_capture(event_path)

    assert summary.keys == ("function_decompile:accepted", "function_decompile:missing")
    assert summary.hit_count == 1
    assert summary.miss_count == 1
    assert summary.store_count == 1
    assert summary.invalid_count == 0
    assert summary.store_failed_count == 0
    assert summary.validation_statuses == ("stable",)
    assert [operation.as_dict() for operation in summary.operations] == [
        {
            "key": "function_decompile:accepted",
            "hit_count": 1,
            "miss_count": 0,
            "invalid_count": 0,
            "store_count": 1,
            "store_failed_count": 0,
            "validation_statuses": ["stable"],
            "context": key_context,
        },
        {
            "key": "function_decompile:missing",
            "hit_count": 0,
            "miss_count": 1,
            "invalid_count": 0,
            "store_count": 0,
            "store_failed_count": 0,
            "validation_statuses": [],
            "context": key_context,
        },
    ]
    assert not event_path.exists()


def test_reviewed_inventory_module_paths_exist():
    assert REVIEWED_TEST_MODULE_LAYERS
    assert all((REPO_ROOT / path).is_file() for path in REVIEWED_TEST_MODULE_LAYERS)


@pytest.mark.parametrize(("module", "test_name", "layer", "status"), [
    ("inbox_long_live", "test_inbox_long_passes_validation_and_compiled_behavior",
     "inertia_decompiler/cli", "reviewed-module"),
    ("reinitbars_execution", "test_reinitbars_oracle_accepts_preserved_register_state",
     "tooling/gates", "reviewed-module"),
    ("setgear_behavior", "test_setgear_oracle_accepts_reference_decisions", "tooling/gates", "reviewed-module"),
    ("tidshowrange_behavior", "test_tidshowrange_oracle_accepts_source_behavior", "tooling/gates", "reviewed-module"),
    ("insertionsort_behavior", "test_insertion_oracle_accepts_complete_behavior", "tooling/gates", "reviewed-manifest"),
])
def test_indirect_behavior_tests_have_reviewed_inventory(module, test_name, layer, status):
    path = f"angr_platforms/tests/test_x86_16_{module}.py"
    assert load_pytest_source_index(REPO_ROOT / path, frozenset()).has_node(test_name)
    item = SimpleNamespace(
        location=(path, 0, test_name), nodeid=f"{path}::{test_name}",
        iter_markers=lambda: (), keywords={},
    )
    record = record_for_item(item)
    assert record.owner_layers == [layer]
    assert record.inventory_status == status
    if status == "reviewed-manifest":
        assert record.owner_contracts
    assert record.required_pipeline_evidence


def test_retired_inert_tests_have_existing_replacements():
    assert RETIRED_TEST_CONTRACTS
    for retired_nodeid, contract in RETIRED_TEST_CONTRACTS.items():
        assert contract.reason
        assert retired_nodeid not in contract.replacements
        for replacement in contract.replacements:
            path, selector = replacement.split("::", 1)
            assert load_pytest_source_index(REPO_ROOT / path, frozenset()).has_node(selector)


def test_xdist_profile_merges_executed_records_and_removes_fragments(tmp_path):
    profile_path = tmp_path / "profile.json"
    env = os.environ.copy()
    env.pop("PYTEST_XDIST_WORKER", None)
    env.pop("PYTEST_XDIST_WORKER_COUNT", None)
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pytest_profile.py",
            "--profile-json",
            str(profile_path),
            "-q",
            "-n",
            "2",
            "--dist",
            "loadgroup",
            "angr_platforms/tests/test_x86_16_decompilation_cache_surface.py::"
            "test_function_cache_key_separates_semantic_runtime_modes",
            "angr_platforms/tests/test_x86_16_decompilation_cache_surface.py::"
            "test_function_cache_key_ignores_non_semantic_runtime_environment",
        ],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == EXPECTED_PROFILE_SCHEMA_VERSION
    assert payload["collected_count"] == PROFILED_TEST_COUNT
    assert len(payload["records"]) == PROFILED_TEST_COUNT
    assert {record["outcome"] for record in payload["records"]} == {"passed"}
    assert all(record["assertion_count"] > 0 for record in payload["records"])
    assert all(record["effective_assertion_count"] >= record["assertion_count"] for record in payload["records"])
    assert all(record["effective_expectation_count"] >= record["expectation_count"] for record in payload["records"])
    assert all(isinstance(record["assertion_sources"], list) for record in payload["records"])
    assert all(isinstance(record["module_hints"], list) for record in payload["records"])
    assert all(record["static_subprocess_count"] == 0 for record in payload["records"])
    assert all(record["direct_static_subprocess_count"] == 0 for record in payload["records"])
    assert all(isinstance(record["cost_sources"], list) for record in payload["records"])
    assert all(isinstance(record["function_address_hints"], list) for record in payload["records"])
    assert all(record["child_cpu_measured"] is True for record in payload["records"])
    assert all(record["child_cpu_seconds"] >= 0.0 for record in payload["records"])
    assert all(isinstance(record["cache_keys"], list) for record in payload["records"])
    assert all(isinstance(record["cache_operations"], list) for record in payload["records"])
    assert all(record["cache_store_failed_count"] == 0 for record in payload["records"])
    assert all(record["cache_hints"] for record in payload["records"])
    assert all("function-decompilation-cache-context" in record["owner_contracts"] for record in payload["records"])
    assert all("inertia_decompiler/cache" in record["owner_layers"] for record in payload["records"])
    assert all(record["required_pipeline_evidence"] == record["evidence"] for record in payload["records"])
    assert all(record["inventory_status"] == "reviewed-manifest" for record in payload["records"])
    assert all(record["rss_start_kib"] > 0 for record in payload["records"])
    assert all(record["rss_peak_kib"] >= record["rss_start_kib"] for record in payload["records"])
    assert all(record["rss_finish_kib"] > 0 for record in payload["records"])
    assert {worker["worker_id"] for worker in payload["worker_results"]} == {"gw0", "gw1"}
    assert all(worker["exit_status"] == 0 for worker in payload["worker_results"])
    assert all(event["error"] is None for event in payload["worker_events"])
    assert payload["source_state"]["stable"] is True
    assert payload["source_state"]["start"] == payload["source_state"]["finish"]
    assert set(payload["rankings"]) == {"wall_seconds", "child_cpu_seconds"}
    assert all(len(ranking) == PROFILED_TEST_COUNT for ranking in payload["rankings"].values())
    assert list(tmp_path.glob(".profile.json.*.json")) == []
