"""Layer: CLI/fallback/reporting.

Responsibility: define command-line options and parse user-selected execution policy.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .catalog_policy import DEFAULT_CATALOG_TIMEOUT, positive_catalog_timeout

__all__ = ["CliArguments", "_build_cli_argument_parser", "parse_cli_arguments"]


class CliArguments(argparse.Namespace):
    """Typed command-line policy consumed by the CLI orchestration layer."""

    binary: Path
    addr: int | None
    blob: bool
    base_addr: int
    entry_point: int
    show_asm: bool
    alternate_source_c: bool
    c_target: str
    output_c_dir: Path | None
    trace_c_stages: bool
    dump_layers: bool
    dump_layer_dir: Path
    dump_layer_filter: str
    proc: str | None
    proc_kind: str
    timeout: int
    catalog_timeout: int
    window: int
    exact_region_end: int | None
    max_memory_mb: int
    max_functions: int
    include_library_functions: bool
    ignore_local_sidecar_hints: bool
    api_style: str
    pat_backend: str
    function_discovery_backend: str
    rizin_timeout: int
    signature_catalog: Path | None
    seed_engine: str
    brief: bool
    otel_spans: bool | None
    otel_top_n: int | None
    otel_min_ms: float | None
    otel_full_jsonl: bool | None
    otel_stderr: bool | None
    otel_format: str | None
    otel_text_max_spans: int | None
    otel_export_otlp: bool | None
    otel_service_name: str | None
    otel_force_flush_ms: int | None
    otel_endpoint: str | None
    otel_span_file: Path | None


def _parse_int(value: str) -> int:
    return int(value, 0)


def _build_cli_argument_parser() -> argparse.ArgumentParser:
    """Build the parser defining the public decompiler CLI surface."""
    parser = argparse.ArgumentParser(
        description="Decompile a DOS/x86-16 sample with angr-platforms.",
    )
    parser.add_argument("binary", type=Path, help="Path to the binary to decompile.")
    parser.add_argument(
        "--addr",
        type=_parse_int,
        default=None,
        help="Function start address to decompile. Defaults to the entry point.",
    )
    parser.add_argument(
        "--blob",
        action="store_true",
        help="Force blob loading instead of auto-detecting a loader backend.",
    )
    parser.add_argument(
        "--base-addr",
        type=_parse_int,
        default=0x1000,
        help="Base address for blob/.COM loading. Defaults to 0x1000.",
    )
    parser.add_argument(
        "--entry-point",
        type=_parse_int,
        default=0x1000,
        help="Entry point for blob/.COM loading. Defaults to 0x1000.",
    )
    parser.add_argument(
        "--show-asm",
        action="store_true",
        help="Print the first lifted block before the decompiled C.",
    )
    parser.add_argument(
        "--alternate-source-c",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "When a same-stem .c/.C source sidecar exists, print it before each "
            "decompiled C block. Enabled by default; use --no-alternate-source-c "
            "to suppress it."
        ),
    )
    parser.add_argument(
        "--c-target",
        choices=("msc-dos", "portable-flat"),
        default="portable-flat",
        help="Emit segmented-memory helper macros for a specific recompilable C target.",
    )
    output_c_dir = os.environ.get("INERTIA_OUTPUT_C_DIR", "").strip()
    parser.add_argument(
        "--output-c-dir",
        type=Path,
        default=Path(output_c_dir) if output_c_dir else None,
        help=(
            "Atomically persist each validated function as soon as it completes, then write the "
            "deterministic assembled translation unit to this directory."
        ),
    )
    parser.add_argument(
        "--trace-c-stages",
        action="store_true",
        help="Print labeled C snapshots after major decompilation text stages so line origin is visible.",
    )
    parser.add_argument(
        "--dump-layers",
        action="store_true",
        help=("Dump every decompilation-stage C snapshot under a layer directory instead of printing to stdout only."),
    )
    parser.add_argument(
        "--dump-layer-dir",
        type=Path,
        default=Path("angr_platforms/.cache/decompilation_layers"),
        help="Directory for per-layer decompilation artifacts (default: %(default)s).",
    )
    parser.add_argument(
        "--dump-layer-filter",
        default=os.environ.get("INERTIA_DUMP_LAYER_FILTER", ""),
        help="Comma-separated list of layer labels to dump (default: all).",
    )
    parser.add_argument(
        "--proc",
        default=None,
        help="Extract and decompile one procedure from a .COD listing by PROC name.",
    )
    parser.add_argument(
        "--proc-kind",
        default="NEAR",
        help="Procedure kind for --proc lookup in .COD files. Defaults to NEAR.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Analysis timeout in seconds. Defaults to 60.",
    )
    parser.add_argument(
        "--catalog-timeout",
        type=positive_catalog_timeout,
        default=os.environ.get("INERTIA_CATALOG_TIMEOUT", str(DEFAULT_CATALOG_TIMEOUT)),
        help="Candidate catalog recovery budget in seconds (default: 60; INERTIA_CATALOG_TIMEOUT). Independent of --timeout.",
    )
    parser.add_argument(
        "--window",
        type=_parse_int,
        default=0x200,
        help="Bound CFG recovery to [addr, addr+window). Defaults to 0x200.",
    )
    parser.add_argument(
        "--exact-region-end",
        type=_parse_int,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--max-memory-mb",
        type=int,
        default=2048,
        help="Best-effort address-space limit in MB. Defaults to 2048.",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="Maximum number of recovered functions to print when decompiling a whole binary. Defaults to 0 (all functions).",
    )
    parser.add_argument(
        "--include-library-functions",
        action="store_true",
        help="Include sidecar signature/library-labeled functions in whole-binary decompilation and tail-validation sweeps.",
    )
    parser.add_argument(
        "--ignore-local-sidecar-hints",
        action="store_true",
        help="Ignore on-disk sidecar hints for function discovery only.",
    )
    parser.add_argument(
        "--api-style",
        choices=("modern", "dos", "raw", "pseudo", "service", "msc", "compiler"),
        default="modern",
        help="Name recovered DOS helpers as modern-style calls, DOS/compiler-style calls, pseudo-callee service calls, or raw interrupt helpers.",
    )
    parser.add_argument(
        "--pat-backend",
        choices=("python_regex", "hyperscan"),
        default="hyperscan",
        help="PAT matcher backend. Use python_regex for the portable fallback or hyperscan for the faster scanner.",
    )
    parser.add_argument(
        "--function-discovery-backend",
        choices=("auto", "angr", "rizin", "hybrid"),
        default=os.environ.get("INERTIA_FUNCTION_DISCOVERY_BACKEND", "auto"),
        help="Function discovery backend for whole-binary EXE sweeps: angr, rizin, hybrid, or auto.",
    )
    parser.add_argument(
        "--rizin-timeout",
        type=int,
        default=int(os.environ.get("INERTIA_RIZIN_TIMEOUT", "8")),
        help="Timeout in seconds for optional rizin pre-discovery in hybrid/rizin modes.",
    )
    parser.add_argument(
        "--signature-catalog",
        type=Path,
        default=None,
        help="Optional deduplicated PAT catalog built from .pat/.obj/.lib inputs.",
    )
    parser.add_argument(
        "--seed-engine",
        choices=("auto", "angr", "rizin"),
        default="auto",
        help=(
            "Function seed discovery engine for whole-binary runs. "
            "'auto' tries rizin first only when no local sidecar discovery hints are present and then "
            "falls back to angr-ranked seeds."
        ),
    )
    parser.add_argument(
        "-q",
        "--brief",
        action="store_true",
        default=os.environ.get("INERTIA_BRIEF", "").lower() in ("1", "true", "yes"),
        help="Token-efficient output: suppress timestamps, progress, diagnostic commentary. "
        "Also set via INERTIA_BRIEF=1.",
    )
    parser.add_argument(
        "--otel-spans",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable compact OTLP-like span output for decompilation (default: INERTIA_OTEL_SPANS).",
    )
    parser.add_argument(
        "--otel-top-n",
        type=int,
        default=None,
        help=("Keep only N slowest spans in compact summaries (default: INERTIA_OTEL_TOP_N, env fallback)."),
    )
    parser.add_argument(
        "--otel-min-ms",
        type=float,
        default=None,
        help=(
            "Only include spans whose duration is at least this many milliseconds "
            "(default: INERTIA_OTEL_MIN_MS, env fallback)."
        ),
    )
    parser.add_argument(
        "--otel-full-jsonl",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Write full JSONL spans plus compact summary to --otel-span-file when enabled "
            "(default: INERTIA_OTEL_FULL_JSONL)."
        ),
    )
    parser.add_argument(
        "--otel-stderr",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Write compact telemetry output to stderr (default: INERTIA_OTEL_STDERR, false disables stderr summary)."
        ),
    )
    parser.add_argument(
        "--otel-format",
        default=None,
        choices=("text", "slow", "json", "jsonl", "agent", "agent_text", "slow_text"),
        help=(
            "Span output format override for compact traces: text, slow, json, jsonl "
            "(default: INERTIA_OTEL_SPAN_FORMAT)."
        ),
    )
    parser.add_argument(
        "--otel-text-max-spans",
        type=int,
        default=None,
        help="Maximum number of spans to include in compact text output (default: INERTIA_OTEL_TEXT_MAX_SPANS).",
    )
    parser.add_argument(
        "--otel-export-otlp",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Enable OTLP export in addition to local tracing. This is controlled by CLI "
            "and no longer requires INERTIA_OTEL_EXPORT_OTLP in the environment."
        ),
    )
    parser.add_argument(
        "--otel-service-name",
        default=None,
        help="OTEL service.name attribute (default: INERTIA_OTEL_SERVICE_NAME).",
    )
    parser.add_argument(
        "--otel-force-flush-ms",
        type=int,
        default=None,
        help="OTLP provider shutdown flush timeout in milliseconds (default: INERTIA_OTEL_FORCE_FLUSH_MS).",
    )
    parser.add_argument(
        "--otel-endpoint",
        default=None,
        help="OTLP endpoint URL (sets OTEL_EXPORTER_OTLP_ENDPOINT).",
    )
    parser.add_argument(
        "--otel-span-file",
        type=Path,
        default=None,
        help="Write telemetry summary/spans to this file.",
    )
    return parser


def parse_cli_arguments(argv: list[str] | None = None) -> CliArguments:
    """Parse ``argv`` into the owned typed CLI argument contract."""
    parser = _build_cli_argument_parser()
    parsed = parser.parse_args(argv, namespace=CliArguments())
    if not isinstance(parsed, CliArguments):
        raise TypeError("CLI parser returned an unexpected namespace type")
    return parsed
