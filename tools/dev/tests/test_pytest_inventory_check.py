from __future__ import annotations

from tools.dev.pytest_inventory_check import validate_inventory_payload


def _record(nodeid: str = "tests/test_sample.py::test_contract") -> dict[str, object]:
    return {
        "assertion_count": 1,
        "cache_hints": [],
        "cache_hit_count": 0,
        "cache_invalid_count": 0,
        "cache_keys": [],
        "cache_miss_count": 0,
        "cache_operations": [],
        "cache_store_count": 0,
        "cache_store_failed_count": 0,
        "child_cpu_measured": False,
        "child_cpu_seconds": 0.0,
        "child_system_seconds": 0.0,
        "child_user_seconds": 0.0,
        "cost_sources": [],
        "direct_function_address_hints": [],
        "direct_input_hints": [],
        "direct_option_hints": [],
        "direct_static_subprocess_count": 0,
        "effective_assertion_count": 1,
        "effective_expectation_count": 0,
        "function_address_hints": [],
        "input_hints": [],
        "inventory_status": "classified-static",
        "module_hints": ["package.module"],
        "nodeid": nodeid,
        "option_hints": [],
        "owner_layers": ["inertia/semantics"],
        "purpose": "unit-or-layer-contract",
        "required_pipeline_evidence": ["assertion"],
        "static_subprocess_count": 0,
        "validation_statuses": [],
    }


def test_inventory_audit_accepts_complete_unique_records():
    payload = {"schema_version": 11, "collected_count": 1, "records": [_record()]}

    audit = validate_inventory_payload(payload)

    assert audit.passed
    assert audit.record_count == 1
    assert audit.status_counts == (("classified-static", 1),)


def test_inventory_audit_rejects_unresolved_missing_and_duplicate_records():
    first = _record()
    first["inventory_status"] = "review-needed"
    first["owner_layers"] = []
    first["required_pipeline_evidence"] = []
    payload = {"schema_version": 11, "collected_count": 1, "records": [first, _record()]}

    audit = validate_inventory_payload(payload)

    assert not audit.passed
    assert any("missing owner layers" in error for error in audit.errors)
    assert any("missing required evidence" in error for error in audit.errors)
    assert any("review is unresolved" in error for error in audit.errors)
    assert any("duplicate nodeid" in error for error in audit.errors)
    assert any("collected_count" in error for error in audit.errors)
