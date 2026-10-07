"""Deterministic identity and eligibility policy for direct CLI result reuse.

Layer: CLI/fallback/reporting.
Responsibility: derive a direct-request cache key from complete static inputs
and refuse fast reuse when live diagnostic artifacts are requested.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from inertia.cli.cache import _cache_file_fingerprint, _recovery_cache_key
from inertia.cli.cache_runtime_contract import live_decompilation_diagnostics_requested_8616
from inertia.cli.cli_arg_parser import CliArguments

DIRECT_REQUEST_CACHE_NAMESPACE_8616: str = "direct_accepted_result"
DIRECT_REQUEST_CACHE_SCHEMA_8616: int = 1


@dataclass(frozen=True, slots=True)
class DirectRequestCacheInputs8616:
    """Complete deterministic identity for one direct-address CLI request."""

    binary_path: Path
    requested_addr: int
    blob: bool
    base_addr: int
    entry_point: int
    window: int
    c_target: str
    api_style: str
    pat_backend: str
    function_discovery_backend: str
    seed_engine: str
    alternate_source_c: bool
    ignore_local_sidecar_hints: bool
    include_library_functions: bool
    proc_name: str | None
    proc_kind: str
    signature_catalog: Path | None
    declared_call_effects: tuple[Path, ...] = ()

    @classmethod
    def from_cli(
        cls,
        args: CliArguments,
        *,
        signature_catalog: Path | None,
    ) -> DirectRequestCacheInputs8616 | None:
        """Build cache inputs when the CLI already has an explicit address."""
        if args.addr is None:
            return None
        return cls(
            binary_path=args.binary,
            requested_addr=args.addr,
            blob=args.blob,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
            window=args.window,
            c_target=args.c_target,
            api_style=args.api_style,
            pat_backend=args.pat_backend,
            function_discovery_backend=args.function_discovery_backend,
            seed_engine=args.seed_engine,
            alternate_source_c=bool(args.alternate_source_c),
            ignore_local_sidecar_hints=bool(args.ignore_local_sidecar_hints),
            include_library_functions=bool(args.include_library_functions),
            proc_name=args.proc,
            proc_kind=args.proc_kind,
            signature_catalog=signature_catalog,
            declared_call_effects=tuple(args.declared_call_effects),
        )


def direct_request_cache_enabled_8616(args: CliArguments) -> bool:
    """Return whether this request needs no live diagnostic artifacts."""
    telemetry_requested = any(
        value is not None
        for value in (
            args.otel_spans,
            args.otel_top_n,
            args.otel_min_ms,
            args.otel_full_jsonl,
            args.otel_stderr,
            args.otel_format,
            args.otel_text_max_spans,
            args.otel_export_otlp,
            args.otel_service_name,
            args.otel_force_flush_ms,
            args.otel_endpoint,
            args.otel_span_file,
        )
    ) or any(name.startswith("INERTIA_OTEL_") for name in os.environ)
    clean_worker_transport = bool(os.environ.get("INERTIA_SERIAL_CLEAN_WORKER_RESULT"))
    return (
        not args.show_asm
        and not args.trace_c_stages
        and not args.dump_layers
        and not telemetry_requested
        and not clean_worker_transport
        and not live_decompilation_diagnostics_requested_8616()
    )


def build_direct_request_cache_key_8616(
    inputs: DirectRequestCacheInputs8616,
) -> dict[str, object] | None:
    """Build request identity; declaration fingerprints never prove consumption.

    A matching key still requires current live admission authentication before
    a receipt-bearing artifact may be emitted by the ordinary CLI path.
    """
    key = _recovery_cache_key(
        binary_path=inputs.binary_path,
        kind=DIRECT_REQUEST_CACHE_NAMESPACE_8616,
        extra={
            "direct_request_cache_schema": DIRECT_REQUEST_CACHE_SCHEMA_8616,
            "requested_addr": inputs.requested_addr,
            "blob": inputs.blob,
            "base_addr": inputs.base_addr,
            "entry_point": inputs.entry_point,
            "window": inputs.window,
            "c_target": inputs.c_target,
            "api_style": inputs.api_style,
            "pat_backend": inputs.pat_backend,
            "function_discovery_backend": inputs.function_discovery_backend,
            "seed_engine": inputs.seed_engine,
            "alternate_source_c": inputs.alternate_source_c,
            "ignore_local_sidecar_hints": inputs.ignore_local_sidecar_hints,
            "include_library_functions": inputs.include_library_functions,
            "proc_name": inputs.proc_name,
            "proc_kind": inputs.proc_kind,
            "signature_catalog": _cache_file_fingerprint(inputs.signature_catalog),
            "declared_call_effects": [
                _cache_file_fingerprint(path) for path in inputs.declared_call_effects
            ],
        },
    )
    if not isinstance(key, dict):
        return None
    return {str(name): value for name, value in key.items()}
