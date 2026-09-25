"""Collect optional telemetry spans and compact runtime summaries.

Layer: CLI/fallback/reporting.
Responsibility: report optional runtime timing diagnostics without owning decompiler semantics.

Dynamic attribute access is limited to third-party telemetry payloads and optional
OpenTelemetry compatibility objects.
"""

from __future__ import annotations

import atexit
import contextlib
import contextvars
import functools
import importlib
import inspect
import json
import os
import signal
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol, cast, overload

TRACE_ENABLE_ENV: str = "INERTIA_OTEL_SPANS"
TRACE_FILE_ENV: str = "INERTIA_OTEL_SPAN_FILE"
TRACE_TOP_N_ENV: str = "INERTIA_OTEL_TOP_N"
TRACE_MIN_MS_ENV: str = "INERTIA_OTEL_MIN_MS"
TRACE_FULL_JSONL_ENV: str = "INERTIA_OTEL_FULL_JSONL"
TRACE_STDERR_ENV: str = "INERTIA_OTEL_STDERR"
TRACE_FORMAT_ENV: str = "INERTIA_OTEL_SPAN_FORMAT"
TRACE_TEXT_MAX_SPANS_ENV: str = "INERTIA_OTEL_TEXT_MAX_SPANS"
TRACE_OTLP_ENABLE_ENV: str = "INERTIA_OTEL_EXPORT_OTLP"
TRACE_SERVICE_NAME_ENV: str = "INERTIA_OTEL_SERVICE_NAME"
TRACE_FORCE_FLUSH_MS_ENV: str = "INERTIA_OTEL_FORCE_FLUSH_MS"

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}
_MAX_ATTR_TEXT = 96


class TraceOutputFormat(Enum):
    """Supported compact telemetry output formats."""

    TEXT = "text"
    SLOW = "slow"
    JSON = "json"
    JSONL = "jsonl"


class _OtelSpan(Protocol):
    """Minimal optional OpenTelemetry span surface used by this module."""

    def set_attribute(self, key: str, value: object) -> None:
        """Attach one attribute to the active OpenTelemetry span."""
        ...


class _OtelTracer(Protocol):
    """Minimal optional OpenTelemetry tracer surface used by this module."""

    def start_as_current_span(self, name: str) -> contextlib.AbstractContextManager[_OtelSpan]:
        """Return an OpenTelemetry span context manager."""
        ...


class _OtelTraceModule(Protocol):
    """Minimal optional OpenTelemetry trace module surface used here."""

    def get_tracer(self, name: str) -> _OtelTracer:
        """Return a tracer by instrumentation name."""
        ...

    def set_tracer_provider(self, provider: object) -> None:
        """Install a tracer provider."""
        ...


class _OtelProvider(Protocol):
    """Minimal optional OpenTelemetry provider surface used by shutdown."""

    def add_span_processor(self, _processor: object) -> None:
        """Register a span processor."""
        ...

    def force_flush(self, *, timeout_millis: int) -> None:
        """Flush queued spans."""
        ...

    def shutdown(self) -> None:
        """Shutdown the provider."""
        ...


class _ResourceFactory(Protocol):
    """Factory protocol for optional OpenTelemetry resources."""

    def create(self, _attributes: dict[str, str]) -> object:
        """Create an OpenTelemetry resource object."""
        ...


class _ProviderFactory(Protocol):
    """Factory protocol for optional OpenTelemetry tracer providers."""

    def __call__(self, *, resource: object) -> _OtelProvider:
        """Create a provider from a resource."""
        ...


class _ProcessorFactory(Protocol):
    """Factory protocol for optional OpenTelemetry span processors."""

    def __call__(self, _exporter: object) -> object:
        """Create a span processor from an exporter."""
        ...


class _ExporterFactory(Protocol):
    """Factory protocol for optional OpenTelemetry exporters."""

    def __call__(self) -> object:
        """Create an exporter."""
        ...


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _compact_attr(value: object) -> object:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Path) or not isinstance(value, str):
        value = str(value)
    if len(value) > _MAX_ATTR_TEXT:
        return value[: _MAX_ATTR_TEXT - 1] + "~"
    return value


def _compact_attrs(attrs: dict[str, object]) -> dict[str, object]:
    return {str(key): _compact_attr(value) for key, value in attrs.items() if value is not None}


@dataclass
class _SpanRecord:
    span_id: int
    parent_id: int | None
    name: str
    start_ns: int
    attrs: dict[str, object] = field(default_factory=dict)
    end_ns: int | None = None
    status: str = "ok"

    @property
    def duration_ms(self) -> float:
        """Return elapsed span duration in milliseconds."""
        end_ns = self.end_ns if self.end_ns is not None else time.perf_counter_ns()
        return max(0.0, (end_ns - self.start_ns) / 1_000_000.0)


@dataclass
class _TelemetryState:
    enabled: bool = False
    configured: bool = False
    emitted: bool = False
    top_n: int = 16
    min_ms: float = 1.0
    file_path: Path | None = None
    stderr_summary: bool = True
    full_jsonl: bool = False
    output_format: TraceOutputFormat = TraceOutputFormat.TEXT
    text_max_spans: int = 200
    records: list[_SpanRecord] = field(default_factory=list)
    next_id: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)
    otel_tracer: _OtelTracer | None = None
    otel_provider: _OtelProvider | None = None
    otel_export_status: str | None = None
    otel_shutdown: bool = False
    signal_handlers_installed: bool = False


_STATE = _TelemetryState()
_CURRENT_SPAN_ID: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "inertia_current_span_id",
    default=None,
)
_AUTO_ATTR_NAMES = {
    "addr",
    "address",
    "base_addr",
    "binary",
    "binary_path",
    "candidate_addr",
    "c_target",
    "entry_point",
    "force_blob",
    "function_label",
    "image_end",
    "low_memory",
    "low_memory_path",
    "pat_backend",
    "region_span",
    "signature_catalog",
    "status",
    "timeout",
    "window",
}


def configure_telemetry_from_env(
    *,
    enabled: bool | None = None,
    file_path: Path | str | None = None,
    top_n: int | None = None,
    min_ms: float | None = None,
    full_jsonl: bool | None = None,
    stderr_summary: bool | None = None,
    output_format: str | TraceOutputFormat | None = None,
    text_max_spans: int | None = None,
    otlp_export: bool | None = None,
    service_name: str | None = None,
    force_flush_ms: int | None = None,
    otlp_endpoint: str | None = None,
) -> bool:
    """Configure optional trace collection from explicit arguments and environment variables."""
    requested = _env_bool(TRACE_ENABLE_ENV) if enabled is None else bool(enabled)
    if not requested:
        return False

    with _STATE.lock:
        _STATE.enabled = True
        _STATE.top_n = max(1, int(top_n if top_n is not None else _env_int(TRACE_TOP_N_ENV, _STATE.top_n)))
        _STATE.min_ms = max(0.0, float(min_ms if min_ms is not None else _env_float(TRACE_MIN_MS_ENV, _STATE.min_ms)))
        resolved_full_jsonl = full_jsonl if full_jsonl is not None else _env_bool(TRACE_FULL_JSONL_ENV, False)
        _publish_env_overrides(
            otlp_export=otlp_export,
            otlp_endpoint=otlp_endpoint,
            service_name=service_name,
            force_flush_ms=force_flush_ms,
        )

        raw_file_path = file_path if file_path is not None else os.environ.get(TRACE_FILE_ENV)
        _STATE.file_path = Path(raw_file_path) if raw_file_path else None
        _STATE.stderr_summary = _env_bool(TRACE_STDERR_ENV, True) if stderr_summary is None else bool(stderr_summary)
        _STATE.full_jsonl = resolved_full_jsonl
        _STATE.output_format = _resolve_output_format(
            _STATE.file_path,
            _STATE.full_jsonl,
            explicit_format=output_format,
        )
        if stderr_summary is not None:
            _STATE.stderr_summary = bool(stderr_summary)
        if text_max_spans is not None:
            _STATE.text_max_spans = max(1, int(text_max_spans))
        else:
            _STATE.text_max_spans = max(1, _env_int(TRACE_TEXT_MAX_SPANS_ENV, _STATE.text_max_spans))
        if not _STATE.configured:
            _STATE.otel_tracer = _optional_otel_tracer()
            atexit.register(emit_compact_summary)
            _install_signal_handlers()
            _STATE.configured = True
    return True


def _publish_env_overrides(
    *,
    otlp_export: bool | None,
    otlp_endpoint: str | None,
    service_name: str | None,
    force_flush_ms: int | None,
) -> None:
    """Publish explicit configuration arguments into OTLP env variables."""
    if otlp_export is not None:
        os.environ[TRACE_OTLP_ENABLE_ENV] = "1" if bool(otlp_export) else "0"
    if otlp_endpoint is not None:
        if otlp_endpoint:
            os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = otlp_endpoint
        else:
            os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    if service_name is not None:
        if service_name:
            os.environ[TRACE_SERVICE_NAME_ENV] = service_name
        else:
            os.environ.pop(TRACE_SERVICE_NAME_ENV, None)
    if force_flush_ms is not None:
        os.environ[TRACE_FORCE_FLUSH_MS_ENV] = str(max(1, int(force_flush_ms)))


def _install_signal_handlers() -> None:
    """Flush compact diagnostics before an external timeout kills the process."""
    if _STATE.signal_handlers_installed:
        return

    def _handle_signal(signum: int, _frame: object | None) -> None:
        try:
            emit_compact_summary()
        finally:
            raise SystemExit(128 + int(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, _handle_signal)
        except (OSError, ValueError):
            continue
    _STATE.signal_handlers_installed = True


def telemetry_enabled() -> bool:
    """Return whether optional telemetry collection is active."""
    return _STATE.enabled


def caller_span_name(stacklevel: int = 1) -> str:
    """Return a stable module-qualified span name for the caller frame."""
    try:
        frame = inspect.currentframe()
        for _ in range(max(1, int(stacklevel))):
            if frame is None:
                break
            frame = frame.f_back
        if frame is None:
            return "unknown"
        module_name = frame.f_globals.get("__name__", "")
        function_name = frame.f_code.co_name
        if module_name:
            return f"{module_name}.{function_name}"
        return function_name
    except Exception:
        return "unknown"


def _optional_otel_tracer() -> _OtelTracer | None:
    """Load optional OpenTelemetry tracing through a dynamic third-party boundary."""
    try:
        # Dynamic third-party optional dependency boundary: OpenTelemetry is not
        # required for normal CLI runs.
        trace = cast(_OtelTraceModule, importlib.import_module("opentelemetry.trace"))
    except Exception:
        return None
    if _otlp_export_requested():
        provider, status = _configure_otlp_exporter()
        _STATE.otel_provider = provider
        _STATE.otel_export_status = status
    else:
        _STATE.otel_export_status = "disabled"
    try:
        return trace.get_tracer("inertia_decompiler")
    except Exception:
        return None


def _otlp_export_requested() -> bool:
    explicit = os.environ.get(TRACE_OTLP_ENABLE_ENV)
    if explicit is not None:
        return _env_bool(TRACE_OTLP_ENABLE_ENV, False)
    return False


def _resolve_output_format(
    file_path: Path | None,
    full_jsonl: bool,
    *,
    explicit_format: str | TraceOutputFormat | None = None,
) -> TraceOutputFormat:
    if isinstance(explicit_format, TraceOutputFormat):
        return explicit_format
    explicit = explicit_format if explicit_format is not None else os.environ.get(TRACE_FORMAT_ENV)
    if explicit is not None:
        normalized = explicit.strip().lower()
        if normalized in {"text", "agent", "agent_text", "txt"}:
            return TraceOutputFormat.TEXT
        if normalized in {"slow", "top", "top_text", "agent_slow"}:
            return TraceOutputFormat.SLOW
        if normalized in {"jsonl", "full_jsonl"}:
            return TraceOutputFormat.JSONL
        if normalized in {"json", "compact_json"}:
            return TraceOutputFormat.JSON
    if full_jsonl:
        return TraceOutputFormat.JSONL
    return TraceOutputFormat.TEXT


def _configure_otlp_exporter() -> tuple[_OtelProvider | None, str]:
    """Configure optional OTLP export through a dynamic third-party boundary."""
    try:
        # Dynamic third-party optional dependency boundary: OTLP export is an
        # opt-in integration and must stay absent-tolerant.
        trace = cast(_OtelTraceModule, importlib.import_module("opentelemetry.trace"))
        exporter_module = importlib.import_module("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        resources_module = importlib.import_module("opentelemetry.sdk.resources")
        trace_sdk_module = importlib.import_module("opentelemetry.sdk.trace")
        trace_export_module = importlib.import_module("opentelemetry.sdk.trace.export")
        # Dynamic third-party boundary: optional OpenTelemetry modules are imported by name.
        otlp_span_exporter = cast(_ExporterFactory, exporter_module.OTLPSpanExporter)
        # Dynamic third-party boundary: optional OpenTelemetry modules are imported by name.
        resource_factory = cast(_ResourceFactory, resources_module.Resource)
        # Dynamic third-party boundary: optional OpenTelemetry SDK classes are absent-tolerant.
        provider_factory = cast(_ProviderFactory, trace_sdk_module.TracerProvider)
        # Dynamic third-party boundary: optional OpenTelemetry SDK classes are absent-tolerant.
        processor_factory = cast(_ProcessorFactory, trace_export_module.BatchSpanProcessor)
    except Exception as ex:
        return None, f"unavailable:{type(ex).__name__}"

    try:
        resource = resource_factory.create(
            {
                "service.name": os.environ.get(TRACE_SERVICE_NAME_ENV, "inertia-decompiler"),
                "service.namespace": "inertia",
            }
        )
        provider = provider_factory(resource=resource)
        provider.add_span_processor(processor_factory(otlp_span_exporter()))
        trace.set_tracer_provider(provider)
        return provider, "configured"
    except Exception as ex:
        return None, f"configure_failed:{type(ex).__name__}"


def _auto_span_attrs(target: Callable[..., object], args: tuple[object, ...], kwargs: dict[str, object]) -> dict[str, object]:
    attrs: dict[str, object] = {}
    try:
        signature = inspect.signature(target)
        bound = signature.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        values = dict(bound.arguments)
    except Exception:
        values = {f"arg{index}": value for index, value in enumerate(args[:4])}
        values.update(kwargs)

    for name, value in values.items():
        _collect_auto_attr(attrs, name, value)

    return attrs


def _collect_auto_attr(attrs: dict[str, object], name: str, value: object) -> None:
    if value is None:
        return
    if name in _AUTO_ATTR_NAMES:
        attrs[name] = _format_auto_value(name, value)
        return
    if name in {"path", "file_path"}:
        _collect_path_attr(attrs, value)
        return
    if name in {"function", "function_obj", "decompile_function"}:
        _collect_function_attrs(attrs, value)
        return
    if name in {"project", "candidate_project", "decompile_project", "project_obj"}:
        _collect_project_attrs(attrs, value)
        return
    if name in {"item", "task"}:
        _collect_item_attrs(attrs, value)
        return


def _collect_path_attr(attrs: dict[str, object], value: object) -> None:
    """Record a path/file_path payload as binary name plus path."""
    if isinstance(value, Path):
        attrs.setdefault("binary", value.name)
        attrs["path"] = value.name
    elif isinstance(value, str) and value:
        attrs.setdefault("binary", Path(value).name)
        attrs["path"] = Path(value).name


def _collect_item_attrs(attrs: dict[str, object], value: object) -> None:
    """Record function/index attributes from a queued work item."""
    # Dynamic third-party payload boundary: queued work items are not owned contracts.
    item_function = getattr(value, "function", None)
    if item_function is not None:
        _collect_function_attrs(attrs, item_function)
    # Dynamic third-party payload boundary: queued work items are not owned contracts.
    item_index = getattr(value, "index", None)
    if isinstance(item_index, int):
        attrs.setdefault("index", item_index)


def _collect_function_attrs(attrs: dict[str, object], function: object) -> None:
    # Dynamic third-party payload boundary: angr function objects provide optional fields.
    addr = getattr(function, "addr", None)
    if isinstance(addr, int):
        attrs.setdefault("addr", hex(addr))
    # Dynamic third-party payload boundary: angr function objects provide optional fields.
    name = getattr(function, "name", None)
    if isinstance(name, str) and name:
        attrs.setdefault("name", name)
    # Dynamic third-party payload boundary: angr function objects provide optional fields.
    block_addrs = getattr(function, "block_addrs_set", None)
    if block_addrs:
        with contextlib.suppress(Exception):
            attrs.setdefault("blocks", len(block_addrs))


def _collect_project_attrs(attrs: dict[str, object], project: object) -> None:
    # Dynamic third-party payload boundary: angr projects expose optional metadata fields.
    filename = getattr(project, "filename", None)
    if isinstance(filename, str) and filename:
        attrs.setdefault("binary", Path(filename).name)
    # Dynamic third-party payload boundary: angr projects expose optional metadata fields.
    entry = getattr(project, "entry", None)
    if isinstance(entry, int):
        attrs.setdefault("entry", hex(entry))
    # Dynamic third-party payload boundary: angr projects expose optional metadata fields.
    arch = getattr(project, "arch", None)
    # Dynamic third-party payload boundary: angr projects expose optional metadata fields.
    arch_name = getattr(arch, "name", None)
    if isinstance(arch_name, str) and arch_name:
        attrs.setdefault("arch", arch_name)


def _format_auto_value(name: str, value: object) -> object:
    if isinstance(value, Path):
        return value.name
    if isinstance(value, int) and ("addr" in name or name in {"entry_point", "image_end"}):
        return hex(value)
    if isinstance(value, int) and abs(value) > 4096:
        return hex(value)
    return value


@contextlib.contextmanager
def span(span_name: str, **attrs: object) -> Iterator[None]:
    """Collect a timing span around a decompiler operation when telemetry is enabled."""
    if not _STATE.enabled:
        yield
        return

    parent_id = _CURRENT_SPAN_ID.get()
    with _STATE.lock:
        span_id = _STATE.next_id
        _STATE.next_id += 1
        record = _SpanRecord(
            span_id=span_id,
            parent_id=parent_id,
            name=str(span_name),
            start_ns=time.perf_counter_ns(),
            attrs=_compact_attrs(attrs),
        )
        _STATE.records.append(record)

    token = _CURRENT_SPAN_ID.set(span_id)
    otel_cm = _otel_span_context(span_name, record.attrs)
    try:
        with otel_cm:
            yield
    except BaseException as ex:
        record.status = "error"
        record.attrs.setdefault("exception", type(ex).__name__)
        raise
    finally:
        record.end_ns = time.perf_counter_ns()
        _CURRENT_SPAN_ID.reset(token)


def annotate_current_span(**attrs: object) -> None:
    """Attach compact attributes to the currently active telemetry span."""
    if not _STATE.enabled:
        return
    span_id = _CURRENT_SPAN_ID.get()
    if span_id is None:
        return
    compact = _compact_attrs(attrs)
    with _STATE.lock:
        for record in reversed(_STATE.records):
            if record.span_id == span_id:
                record.attrs.update(compact)
                return


def span_here(**attrs: object) -> contextlib.AbstractContextManager[None]:
    """Collect a span named after the immediate caller when telemetry is enabled."""
    if not _STATE.enabled:
        return contextlib.nullcontext()
    return span(caller_span_name(stacklevel=2), **attrs)


@overload
def trace_function[**P, R](
    func: None = None,
    *,
    name: str | None = None,
    attrs: dict[str, object] | None = None,
    attr_factory: None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Return a decorator configured for a function discovered later."""


@overload
def trace_function[**P, R](
    func: None = None,
    *,
    name: str | None = None,
    attrs: dict[str, object] | None = None,
    attr_factory: Callable[P, dict[str, object] | None],
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Bind arguments from an attribute factory while preserving result type."""


@overload
def trace_function[**P, R](
    func: Callable[P, R],
    *,
    name: str | None = None,
    attrs: dict[str, object] | None = None,
    attr_factory: Callable[P, dict[str, object] | None] | None = None,
) -> Callable[P, R]:
    """Decorate an already supplied function with an optional telemetry span."""


def trace_function[**P, R](
    func: Callable[P, R] | None = None,
    *,
    name: str | None = None,
    attrs: dict[str, object] | None = None,
    attr_factory: Callable[P, dict[str, object] | None] | None = None,
) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorate a function so calls are wrapped in optional telemetry spans."""

    def _decorate(target: Callable[P, R]) -> Callable[P, R]:
        span_name = name or f"{target.__module__}.{target.__name__}"

        @functools.wraps(target)
        def _wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            if not _STATE.enabled:
                return target(*args, **kwargs)
            span_attrs = _auto_span_attrs(target, tuple(args), dict(kwargs))
            span_attrs.update(attrs or {})
            if attr_factory is not None:
                try:
                    dynamic_attrs = attr_factory(*args, **kwargs)
                except Exception as ex:
                    dynamic_attrs = {"attr_factory_error": type(ex).__name__}
                if isinstance(dynamic_attrs, dict):
                    span_attrs.update(dynamic_attrs)
            with span(span_name, **span_attrs):
                return target(*args, **kwargs)

        return _wrapped

    if func is None:
        return _decorate
    return _decorate(func)


@contextlib.contextmanager
def _otel_span_context(span_name: str, attrs: dict[str, object]) -> Iterator[None]:
    tracer = _STATE.otel_tracer
    if tracer is None:
        yield
        return
    try:
        span_context = tracer.start_as_current_span(span_name)
    except Exception:
        yield
        return
    with span_context as otel_span:
        for key, value in attrs.items():
            try:
                otel_span.set_attribute(key, value)
            except Exception:
                continue
        yield


def build_compact_summary() -> dict[str, object]:
    """Build a parser-friendly aggregate summary for collected telemetry spans."""
    with _STATE.lock:
        records = list(_STATE.records)
    if not records:
        summary: dict[str, object] = {
            "span_count": 0,
            "total_ms": 0.0,
            "top": [],
            "agg": [],
            "errors": [],
        }
        if _STATE.otel_export_status is not None:
            summary["otel_export"] = _STATE.otel_export_status
        return summary

    current_ns = time.perf_counter_ns()
    first_start = min(record.start_ns for record in records)
    last_end = max(record.end_ns or current_ns for record in records)
    total_ms = max(0.0, (last_end - first_start) / 1_000_000.0)
    visible = [record for record in records if record.duration_ms >= _STATE.min_ms]
    top = sorted(visible, key=lambda record: record.duration_ms, reverse=True)[: _STATE.top_n]

    aggregate: dict[str, dict[str, float | int]] = {}
    for record in records:
        entry = aggregate.setdefault(record.name, {"count": 0, "cum_ms": 0.0, "max_ms": 0.0})
        entry["count"] = int(entry["count"]) + 1
        entry["cum_ms"] = float(entry["cum_ms"]) + record.duration_ms
        entry["max_ms"] = max(float(entry["max_ms"]), record.duration_ms)
    agg_rows = sorted(
        (
            [name, int(data["count"]), round(float(data["cum_ms"]), 1), round(float(data["max_ms"]), 1)]
            for name, data in aggregate.items()
        ),
        key=lambda row: (row[2], row[3]),
        reverse=True,
    )[: _STATE.top_n]

    summary = {
        "span_count": len(records),
        "total_ms": round(total_ms, 1),
        "top": [
            [
                record.name,
                round(record.duration_ms, 1),
                _summary_attrs(record.attrs),
            ]
            for record in top
        ],
        "agg": agg_rows,
        "errors": [
            [record.name, round(record.duration_ms, 1), _summary_attrs(record.attrs)]
            for record in records
            if record.status == "error"
        ][: _STATE.top_n],
    }
    if _STATE.otel_export_status is not None:
        summary["otel_export"] = _STATE.otel_export_status
    return summary


def build_agent_trace_text() -> str:
    """Render collected spans as compact text suitable for agent handoff and stderr."""
    with _STATE.lock:
        records = list(_STATE.records)
    summary = build_compact_summary()
    otel_status = summary.get("otel_export", "-")
    if otel_status == "disabled":
        otel_status = "off"
    errors_value = summary.get("errors", [])
    errors = errors_value if isinstance(errors_value, list) else []
    lines = [
        (
            f"summary total_ms={summary.get('total_ms', 0.0)} "
            f"spans={len(records)} otel={otel_status} errors={len(errors)}"
        ),
        "schema: id|parent|ms|name|attrs",
    ]
    ordered = sorted(records, key=lambda record: record.span_id)
    limit = max(1, int(_STATE.text_max_spans))
    shown = ordered[:limit]
    if len(ordered) > len(shown):
        lines[0] += f" shown={len(shown)}"
    name_ids = _agent_trace_name_dictionary(shown)
    if name_ids:
        lines.append("names:")
        for name, name_id in sorted(name_ids.items(), key=lambda item: item[1]):
            lines.append(f"{name_id}={name}")
        lines[1] = "schema: id|parent|ms|n|attrs"
    lines.extend(_format_agent_trace_record(record, name_ids=name_ids) for record in shown)
    return "\n".join(lines) + "\n"


def build_agent_slow_trace_text() -> str:
    """Render the slowest visible spans as compact text for profiling decompiler runs."""
    with _STATE.lock:
        records = list(_STATE.records)
    summary = build_compact_summary()
    otel_status = summary.get("otel_export", "-")
    if otel_status == "disabled":
        otel_status = "off"
    errors_value = summary.get("errors", [])
    errors = errors_value if isinstance(errors_value, list) else []
    lines = [
        (f"trace total={summary.get('total_ms', 0.0)}ms spans={len(records)} otel={otel_status} errors={len(errors)}")
    ]
    visible = [record for record in records if record.duration_ms >= _STATE.min_ms]
    top = sorted(visible, key=lambda record: record.duration_ms, reverse=True)[: max(1, int(_STATE.top_n))]
    for record in top:
        attrs_dict = dict(record.attrs)
        if record.end_ns is None:
            attrs_dict.setdefault("status", "active")
        attrs = _format_agent_attrs(attrs_dict)
        status = "" if record.status == "ok" else f" status={record.status}"
        suffix = f" {attrs}" if attrs else ""
        lines.append(f"{round(record.duration_ms, 3)} {record.name}{suffix}{status}")
    return "\n".join(lines) + "\n"


def _agent_trace_name_dictionary(records: list[_SpanRecord]) -> dict[str, int] | None:
    if len(records) < 16:
        return None
    names: dict[str, int] = {}
    for record in records:
        if record.name not in names:
            names[record.name] = len(names)
    if len(names) >= len(records):
        return None
    raw_name_chars = sum(len(record.name) for record in records)
    dict_name_chars = sum(len(str(name_id)) + 1 + len(name) for name, name_id in names.items())
    row_name_chars = sum(len(str(names[record.name])) for record in records)
    if dict_name_chars + row_name_chars + len("names:\n") + 32 >= raw_name_chars:
        return None
    return names


def _format_agent_trace_record(record: _SpanRecord, *, name_ids: dict[str, int] | None = None) -> str:
    parent = "-" if record.parent_id is None else str(record.parent_id)
    attrs_dict = dict(record.attrs)
    if record.end_ns is None:
        attrs_dict.setdefault("status", "active")
    elif record.status != "ok":
        attrs_dict.setdefault("status", record.status)
    attrs = _format_agent_attrs(attrs_dict)
    name = str(name_ids[record.name]) if name_ids is not None else record.name
    return f"{record.span_id}|{parent}|{round(record.duration_ms, 3)}|{name}|{attrs}"


def _format_agent_attrs(attrs: dict[str, object]) -> str:
    if not attrs:
        return ""
    preferred = (
        "binary",
        "addr",
        "name",
        "function",
        "function_label",
        "status",
        "stage",
        "blocks",
        "bytes",
        "c_target",
        "backend",
        "functions",
        "cache",
        "timeout",
        "window",
        "entry",
        "entry_point",
        "base_addr",
        "arch",
        "low_memory_path",
        "exception",
    )
    aliases = {
        "function_label": "label",
        "c_target": "target",
        "entry_point": "entry",
        "base_addr": "base",
        "low_memory_path": "lowmem",
    }
    seen: set[str] = set()
    parts: list[str] = []
    for key in preferred:
        if key in attrs:
            parts.append(f"{aliases.get(key, key)}={_format_agent_attr_value(attrs[key])}")
            seen.add(key)
    for key in sorted(str(key) for key in attrs):
        if key in seen:
            continue
        parts.append(f"{aliases.get(key, key)}={_format_agent_attr_value(attrs[key])}")
    return " ".join(parts)


def _format_agent_attr_value(value: object) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return "-"
    text = str(value)
    if not text:
        return "-"
    if any(ch.isspace() for ch in text):
        text = "_".join(text.split())
    return text.replace("|", "/")


def _summary_attrs(attrs: dict[str, object]) -> dict[str, object]:
    preferred = (
        "binary",
        "addr",
        "name",
        "function",
        "status",
        "stage",
        "blocks",
        "bytes",
        "backend",
        "functions",
        "cache",
        "exception",
    )
    out: dict[str, object] = {}
    for key in preferred:
        value = attrs.get(key)
        if value is not None:
            out[key] = value
    return out


def emit_compact_summary() -> None:
    """Emit the compact telemetry summary once to stderr and the configured file."""
    if not _STATE.enabled or _STATE.emitted:
        return
    _STATE.emitted = True
    summary = build_compact_summary()
    if summary["span_count"] == 0:
        return

    if _STATE.output_format == TraceOutputFormat.TEXT:
        encoded = build_agent_trace_text().rstrip("\n")
    elif _STATE.output_format == TraceOutputFormat.SLOW:
        encoded = build_agent_slow_trace_text().rstrip("\n")
    else:
        encoded = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    _emit_stderr_summary()
    _write_compact_summary_file(encoded)
    _flush_and_shutdown_otel()


def _emit_stderr_summary() -> None:
    """Emit the compact text summary to the stderr agent surface."""
    if not _STATE.stderr_summary:
        return
    if _STATE.output_format == TraceOutputFormat.SLOW:
        stderr_encoded = build_agent_slow_trace_text().rstrip("\n")
    else:
        # Stderr is an agent-facing surface. Keep it compact text even
        # when the file output is JSON/JSONL for external parsers.
        stderr_encoded = build_agent_trace_text().rstrip("\n")
    print(f"[otel-trace] {stderr_encoded}", file=sys.stderr)
    sys.stderr.flush()


def _write_compact_summary_file(encoded: str) -> None:
    """Write the summary to the configured file in its output format."""
    if _STATE.file_path is None:
        return
    _STATE.file_path.parent.mkdir(parents=True, exist_ok=True)
    if _STATE.output_format == TraceOutputFormat.JSONL:
        _write_full_jsonl(_STATE.file_path)
    elif _STATE.output_format == TraceOutputFormat.TEXT:
        _STATE.file_path.write_text(build_agent_trace_text(), encoding="utf-8")
    elif _STATE.output_format == TraceOutputFormat.SLOW:
        _STATE.file_path.write_text(build_agent_slow_trace_text(), encoding="utf-8")
    else:
        _STATE.file_path.write_text(encoded + "\n", encoding="utf-8")


def _flush_and_shutdown_otel() -> None:
    """Flush and shut down once, passing the provider a positive millisecond limit."""
    provider = _STATE.otel_provider
    if provider is None or _STATE.otel_shutdown:
        return
    _STATE.otel_shutdown = True
    timeout_millis = max(1, _env_int(TRACE_FORCE_FLUSH_MS_ENV, 3000))
    try:
        provider.force_flush(timeout_millis=timeout_millis)
    except Exception as ex:
        _STATE.otel_export_status = f"flush_failed:{type(ex).__name__}"
    try:
        provider.shutdown()
    except Exception as ex:
        _STATE.otel_export_status = f"shutdown_failed:{type(ex).__name__}"


def _write_full_jsonl(path: Path) -> None:
    with _STATE.lock:
        records = list(_STATE.records)
    with path.open("w", encoding="utf-8") as fp:
        fp.write(json.dumps(build_compact_summary(), sort_keys=True, separators=(",", ":")) + "\n")
        for record in records:
            if record.end_ns is None:
                continue
            fp.write(
                json.dumps(
                    {
                        "id": record.span_id,
                        "parent": record.parent_id,
                        "name": record.name,
                        "duration_ms": round(record.duration_ms, 3),
                        "status": record.status,
                        "attrs": record.attrs,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )


def reset_telemetry_for_tests() -> None:
    """Reset module-level telemetry state between focused tests."""
    with _STATE.lock:
        _STATE.enabled = False
        _STATE.configured = False
        _STATE.emitted = False
        _STATE.records.clear()
        _STATE.next_id = 1
        _STATE.top_n = 16
        _STATE.min_ms = 1.0
        _STATE.file_path = None
        _STATE.stderr_summary = True
        _STATE.full_jsonl = False
        _STATE.output_format = TraceOutputFormat.TEXT
        _STATE.text_max_spans = 200
        _STATE.otel_tracer = None
        _STATE.otel_provider = None
        _STATE.otel_export_status = None
        _STATE.otel_shutdown = False
        _STATE.signal_handlers_installed = False
    _CURRENT_SPAN_ID.set(None)
