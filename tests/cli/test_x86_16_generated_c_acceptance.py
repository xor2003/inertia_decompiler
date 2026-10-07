from __future__ import annotations

import inertia.cli.cli_core as cli_core


def _stable_snapshot() -> dict[str, dict[str, object]]:
    return {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }


def test_generated_c_acceptance_rejects_address_taken_unresolved_temporary(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda accepted_payload: ([("portable-flat", accepted_payload)], None),
    )

    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload=("int *escaped = &vvar_18;\n\nvoid SwapBars(void)\n{\n}\n"),
        tail_validation_snapshot=_stable_snapshot(),
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == "validation_failed"
    assert result.blocker == "Final quality guard rejected emitted C (unresolved-vvar)."


def test_generated_c_acceptance_rejects_unresolved_temporaries_with_stable_validation(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda accepted_payload: ([("portable-flat", accepted_payload)], None),
    )

    payload = "unsigned short escaped = vvar_18;\n\nvoid unknown_binary_function(void)\n{\n}\n"
    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload=payload,
        tail_validation_snapshot=_stable_snapshot(),
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == "validation_failed"
    assert result.blocker == "Final quality guard rejected emitted C (unresolved-vvar)."


def test_generated_c_acceptance_allows_declared_virtual_temporary(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda accepted_payload: ([("portable-flat", accepted_payload)], None),
    )

    payload = "unsigned short f(void)\n{\n    unsigned short vvar_18;\n    vvar_18 = 7;\n    return vvar_18;\n}\n"
    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload=payload,
        tail_validation_snapshot=_stable_snapshot(),
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == "ok"
    assert result.blocker is None
