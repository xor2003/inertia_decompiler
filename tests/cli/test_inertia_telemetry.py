from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

import inertia.cli.cli_core as cli_core
import inertia.cli.telemetry as telemetry
from inertia.cli.telemetry import (
    build_agent_slow_trace_text,
    build_agent_trace_text,
    build_compact_summary,
    configure_telemetry_from_env,
    emit_compact_summary,
    reset_telemetry_for_tests,
    span,
    span_here,
    trace_function,
)


def test_failed_span_retains_bounded_reason_without_replacing_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """A timed failure must retain its cause in compact traces and propagate unchanged."""
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    assert configure_telemetry_from_env()
    failure = RuntimeError("missing frame evidence\n" + "x" * 1000)
    try:
        with pytest.raises(RuntimeError) as raised, span("test.failure", function="0x1000"):
            raise failure
        assert raised.value is failure
        attributes = build_compact_summary()["errors"][0][2]
        assert attributes["exception"] == "RuntimeError"
        message = attributes["exception_message"]
        assert message.startswith("missing frame evidence")
        assert len(message) <= telemetry._MAX_ATTR_TEXT
        assert message.endswith("~")
        assert "exception_message=missing_frame_evidence" in build_agent_trace_text()
        assert "exception_message=missing_frame_evidence" in build_agent_slow_trace_text()
    finally:
        reset_telemetry_for_tests()


def test_pipeline_failure_retains_bounded_typed_details(monkeypatch: pytest.MonkeyPatch) -> None:
    """Distinct typed registry refusals must survive the generic exception message."""
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    assert configure_telemetry_from_env()
    failure = cli_core.PipelineHardError(
        "Semantics raw IR conflicts with retained evidence",
        layer="semantics",
        details={"failure": "artifact_refused", "extra": "x" * 1000},
    )
    try:
        with pytest.raises(cli_core.PipelineHardError) as raised, span("test.pipeline.failure"):
            raise failure
        assert raised.value is failure
        attributes = build_compact_summary()["errors"][0][2]
        assert attributes["exception_layer"] == "semantics"
        assert "artifact_refused" in attributes["exception_details"]
        assert len(attributes["exception_details"]) <= telemetry._MAX_ATTR_TEXT
        assert "exception_details=" in build_agent_trace_text()
    finally:
        reset_telemetry_for_tests()


def test_compact_telemetry_summary_records_decorator_and_nested_spans(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    monkeypatch.setenv("INERTIA_OTEL_TOP_N", "4")

    assert configure_telemetry_from_env()

    @trace_function(name="test.decorated")
    def _work():
        with span("test.child", addr="0x1000"):
            time.sleep(0.001)

    _work()

    summary = build_compact_summary()
    names = {row[0] for row in summary["top"]}
    aggregate_names = {row[0] for row in summary["agg"]}

    assert summary["span_count"] == 2
    assert "test.decorated" in names
    assert "test.child" in names
    assert "test.decorated" in aggregate_names
    assert "test.child" in aggregate_names

    reset_telemetry_for_tests()


def test_span_here_uses_calling_function_name(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    assert configure_telemetry_from_env()

    def _caller():
        with span_here():
            pass

    _caller()

    summary = build_compact_summary()
    names = {row[0] for row in summary["top"]}

    assert any(name.endswith("._caller") for name in names)

    reset_telemetry_for_tests()


def test_trace_function_disabled_records_nothing(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.delenv("INERTIA_OTEL_SPANS", raising=False)

    @trace_function(name="test.disabled")
    def _work():
        return 7

    assert _work() == 7
    assert build_compact_summary()["span_count"] == 0

    reset_telemetry_for_tests()


def test_agent_trace_text_is_compact_and_pipe_delimited(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    assert configure_telemetry_from_env()
    with span("test.parent", addr="0x1000"), span("test.child", function_label="cmp_i16", low_memory_path=False):
        pass

    text = build_agent_trace_text()

    assert "summary total_ms=" in text
    assert "schema: id|parent|ms|name|attrs" in text
    assert "|test.parent|addr=0x1000" in text
    assert "label=cmp_i16" in text
    assert "lowmem=0" in text
    assert "{" not in text

    reset_telemetry_for_tests()


def test_agent_trace_text_uses_name_dictionary_when_smaller(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    assert configure_telemetry_from_env()
    for index in range(20):
        with span("decompiler.very_repetitive_slow_stage", addr=hex(0x1000 + index)):
            pass

    text = build_agent_trace_text()

    assert "names:\n0=decompiler.very_repetitive_slow_stage" in text
    assert "schema: id|parent|ms|n|attrs" in text
    assert "|0|addr=0x1000" in text

    reset_telemetry_for_tests()


def test_agent_slow_trace_text_reports_top_spans_without_row_schema(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    monkeypatch.setenv("INERTIA_OTEL_TOP_N", "2")

    assert configure_telemetry_from_env()
    with span("slow.first", status="ok"):
        time.sleep(0.002)
    with span("slow.second", addr="0x1000"):
        time.sleep(0.001)
    with span("slow.hidden"):
        pass

    text = build_agent_slow_trace_text()
    lines = text.splitlines()

    assert lines[0].startswith("trace total=")
    assert "schema:" not in text
    assert len(lines) == 3
    assert "slow.first" in lines[1]
    assert "slow.second" in lines[2]
    assert "addr=0x1000" in lines[2]
    assert "{" not in text

    reset_telemetry_for_tests()


def test_trace_file_slow_format_is_compact_text(monkeypatch, tmp_path):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_STDERR", "0")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    monkeypatch.setenv("INERTIA_OTEL_SPAN_FORMAT", "slow")
    text_path = tmp_path / "trace.json"

    assert configure_telemetry_from_env(file_path=text_path)
    with span("test.slow_file", binary="CMP16.EXE"):
        pass

    emit_compact_summary()
    text = text_path.read_text(encoding="utf-8")
    assert text.startswith("trace total=")
    assert "test.slow_file binary=CMP16.EXE" in text
    assert "{" not in text

    reset_telemetry_for_tests()


def test_trace_file_defaults_to_text_even_with_json_suffix(monkeypatch, tmp_path):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_STDERR", "0")
    text_path = tmp_path / "trace.agent.txt"

    assert configure_telemetry_from_env(file_path=text_path)
    with span("test.file"):
        pass

    emit_compact_summary()
    assert text_path.read_text(encoding="utf-8").startswith("summary total_ms=")

    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_STDERR", "0")
    json_path = tmp_path / "trace.json"

    assert configure_telemetry_from_env(file_path=json_path)
    with span("test.file_json_default_text"):
        pass

    emit_compact_summary()
    assert json_path.read_text(encoding="utf-8").startswith("summary total_ms=")

    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_STDERR", "0")
    monkeypatch.setenv("INERTIA_OTEL_SPAN_FORMAT", "json")

    assert configure_telemetry_from_env(file_path=json_path)
    with span("test.file_json_explicit"):
        pass

    emit_compact_summary()
    assert json_path.read_text(encoding="utf-8").startswith("{")

    reset_telemetry_for_tests()


def test_json_file_mode_keeps_stderr_agent_text(monkeypatch, tmp_path, capsys):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    monkeypatch.setenv("INERTIA_OTEL_SPAN_FORMAT", "jsonl")
    jsonl_path = tmp_path / "trace.jsonl"

    assert configure_telemetry_from_env(file_path=jsonl_path)
    with span("test.jsonl_file", binary="CMP16.EXE"):
        pass

    emit_compact_summary()

    stderr = capsys.readouterr().err
    file_text = jsonl_path.read_text(encoding="utf-8")
    assert stderr.startswith("[otel-trace] summary total_ms=")
    assert "schema: id|parent|ms|name|attrs" in stderr
    assert "{" not in stderr
    assert file_text.startswith("{")

    reset_telemetry_for_tests()


def test_cli_otel_args_drive_telemetry_output(monkeypatch, tmp_path):
    reset_telemetry_for_tests()
    trace_path = tmp_path / "trace.txt"
    args = SimpleNamespace(
        otel_spans=True,
        otel_span_file=trace_path,
        otel_top_n=None,
        otel_min_ms=None,
        otel_full_jsonl=None,
        otel_stderr=None,
        otel_format=None,
        otel_text_max_spans=None,
        otel_export_otlp=None,
        otel_service_name=None,
        otel_force_flush_ms=None,
        otel_endpoint=None,
    )

    cli_core._configure_cli_telemetry_8616(args)

    with span("cli.unit", binary="CMP16.EXE", addr="0x1000"):
        pass
    emit_compact_summary()

    assert trace_path.exists()
    trace_text = trace_path.read_text(encoding="utf-8")
    assert trace_text.startswith("summary total_ms=")
    assert "schema: id|parent|ms|name|attrs" in trace_text
    assert "cli.unit" in trace_text
    # output stays human-readable while still using the configured CLI mode.
    assert "{" not in trace_text

    reset_telemetry_for_tests()


def test_span_records_error_without_swallowing_exception(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    assert configure_telemetry_from_env()

    try:
        with span("test.error"):
            raise ValueError("boom")
    except ValueError:
        pass

    summary = build_compact_summary()

    assert summary["span_count"] == 1
    assert summary["errors"]
    assert summary["errors"][0][0] == "test.error"
    assert summary["errors"][0][2]["exception"] == "ValueError"

    reset_telemetry_for_tests()


@pytest.mark.parametrize("timeout_millis", [0, -10, 1, 1234])
def test_otlp_export_uses_provider_without_collector(monkeypatch, tmp_path, timeout_millis):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "1")
    monkeypatch.setenv("INERTIA_OTEL_STDERR", "0")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    monkeypatch.setenv("INERTIA_OTEL_FORCE_FLUSH_MS", str(timeout_millis))

    class _Provider:
        def __init__(self):
            self.flushed = False
            self.shutdown_called = False

        def force_flush(self, *, timeout_millis):
            self.flushed = timeout_millis

        def shutdown(self):
            self.shutdown_called = True

    provider = _Provider()
    monkeypatch.setattr(telemetry, "_configure_otlp_exporter", lambda: (provider, "configured"))

    assert configure_telemetry_from_env(file_path=tmp_path / "otel.json")
    with span("test.otlp"):
        pass

    summary = build_compact_summary()
    assert summary["otel_export"] == "configured"

    emit_compact_summary()
    assert provider.flushed == max(1, timeout_millis)
    assert provider.shutdown_called

    reset_telemetry_for_tests()


def test_otlp_export_can_be_enabled_from_cli_arg(monkeypatch, tmp_path):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "0")
    monkeypatch.setenv("INERTIA_OTEL_STDERR", "0")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    args = SimpleNamespace(
        otel_spans=True,
        otel_span_file=tmp_path / "otel_cli.json",
        otel_top_n=None,
        otel_min_ms=None,
        otel_full_jsonl=None,
        otel_stderr=None,
        otel_format=None,
        otel_text_max_spans=None,
        otel_export_otlp=True,
        otel_service_name=None,
        otel_force_flush_ms=None,
        otel_endpoint=None,
    )

    class _Provider:
        def __init__(self):
            self.flushed = False
            self.shutdown_called = False

        def force_flush(self, *, timeout_millis):
            self.flushed = timeout_millis > 0

        def shutdown(self):
            self.shutdown_called = True

    provider = _Provider()
    monkeypatch.setattr(telemetry, "_configure_otlp_exporter", lambda: (provider, "configured"))

    cli_core._configure_cli_telemetry_8616(args)

    with telemetry.span("test.otlp.cli"):
        pass

    summary = telemetry.build_compact_summary()
    assert summary["otel_export"] == "configured"

    emit_compact_summary()
    assert provider.flushed
    assert provider.shutdown_called

    reset_telemetry_for_tests()


def test_otlp_endpoint_does_not_enable_export_implicitly(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.delenv("INERTIA_OTEL_EXPORT_OTLP", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")

    assert configure_telemetry_from_env()
    with span("test.no_otlp"):
        pass

    assert build_compact_summary()["otel_export"] == "disabled"

    reset_telemetry_for_tests()
