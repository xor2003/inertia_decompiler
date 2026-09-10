"""Malformed telemetry must fail assertions rather than be coerced into proof."""

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest
from x86_16_telemetry_support import diagnostic_payloads, telemetry_integer


@pytest.mark.parametrize("value", [True, False, "1", 1.0, None, [], {}])
def test_integer_telemetry_refuses_non_integer_values(value: object) -> None:
    with pytest.raises(AssertionError, match="Expected integer telemetry field count"):
        telemetry_integer({"count": value}, "count")


@pytest.mark.parametrize("value", [-1, 0, 4])
def test_integer_telemetry_preserves_exact_integers(value: int) -> None:
    assert telemetry_integer({"count": value}, "count") == value


def test_integer_telemetry_requires_present_fields() -> None:
    with pytest.raises(KeyError):
        telemetry_integer({}, "count")


def test_json_records_preserve_order_and_ignore_unrelated_lines() -> None:
    output = 'noise\n[other] {}\n[record] {"count": 1}\nnoise [record] {}\n[record] {"count": 2}\n'
    assert diagnostic_payloads(output, "[record] ") == ({"count": 1}, {"count": 2})


@pytest.mark.parametrize("payload", ["[]", "null", "3", '"text"'])
def test_json_records_require_objects(payload: str) -> None:
    with pytest.raises(AssertionError, match="Expected a JSON object"):
        diagnostic_payloads(f"[record] {payload}", "[record] ")


def test_json_records_refuse_malformed_selected_lines() -> None:
    with pytest.raises(json.JSONDecodeError):
        diagnostic_payloads("[record] not-json", "[record] ")


@pytest.mark.parametrize("reason", ["already_structured", "ambiguous_default"])
def test_switch_reporting_keeps_history_without_hiding_latest_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], reason: str
) -> None:
    from inertia_decompiler import cli_decompilation

    success = {
        "function_addr": 4096, "attempted_count": 1, "changed": True,
        "replaced_count": 1, "case_count": 9, "default_target_addr": 4523,
        "refusal_reasons": [],
    }
    latest = {
        "function_addr": 4096, "stage": "pre_codegen", "attempted_count": 0,
        "changed": False, "replaced_count": 0, "refusal_reasons": [reason],
    }
    records = [success, {**success, "function_addr": 8192}, latest]
    original = deepcopy(records)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=4096),
        project=SimpleNamespace(_inertia_typed_switch_seqnode_replacement_8616=records),
    )
    monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", "1")
    monkeypatch.setattr(
        cli_decompilation, "record_typed_edge_switch_replacement_diagnostics_8616", lambda _: None
    )
    monkeypatch.setattr(
        cli_decompilation, "_typed_switch_seqnode_case_segment_quality_8616", lambda _: {}
    )
    cli_decompilation._emit_typed_edge_switch_replacement_safety_stats_8616(codegen)
    captured = capsys.readouterr()
    assert not captured.out
    [payload] = diagnostic_payloads(captured.err, "[typed-switch-seqnode-replacement] ")
    assert payload["attempt_history"] == [success, latest]
    assert payload["attempted_count"] == 0
    assert payload["replaced_count"] == 0
    assert payload["changed"] is False
    assert payload["refusal_reasons"] == {reason: 1}
    assert records == original
