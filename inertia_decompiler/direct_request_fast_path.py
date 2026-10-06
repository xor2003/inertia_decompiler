"""Lightweight entrypoint reuse for validated direct-address results.

Layer: CLI/fallback/reporting.
Responsibility: emit an accepted direct-request cache hit before importing angr
or the full X86 decompiler stack. Misses and diagnostic requests fall through
without changing normal CLI execution.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from inertia_decompiler.cli_arg_parser import CliArguments, parse_cli_arguments
from inertia_decompiler.cli_output import _timestamped_print
from inertia_decompiler.default_signature_catalog import default_signature_catalog_path
from inertia_decompiler.direct_request_cache import (
    DirectRequestCacheArtifact8616,
    DirectRequestCacheVerdict8616,
    load_direct_request_cache_8616,
    render_direct_request_tail_snapshot_diagnostic_8616,
)
from inertia_decompiler.direct_request_identity import (
    DirectRequestCacheInputs8616,
    direct_request_cache_enabled_8616,
)
from inertia_decompiler.generated_c_artifacts import write_generated_function_c


def _prepare_fast_path_args_8616(
    argv: list[str] | None,
) -> tuple[CliArguments, Path | None]:
    """Parse the lightweight subset with the same startup policy as the full CLI."""
    args = parse_cli_arguments(argv)
    raw_argv = list(argv) if argv is not None else list(sys.argv[1:])
    seed_engine_was_explicit = any(
        token == "--seed-engine" or token.startswith("--seed-engine=") for token in raw_argv
    )
    if seed_engine_was_explicit and args.seed_engine:
        mapped_backend = {"auto": "auto", "angr": "angr", "rizin": "rizin"}.get(
            args.seed_engine.strip().lower()
        )
        if mapped_backend is not None:
            args.function_discovery_backend = mapped_backend
    if args.ignore_local_sidecar_hints:
        os.environ["INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616"] = "1"
    signature_catalog = args.signature_catalog
    if signature_catalog is None:
        signature_catalog = default_signature_catalog_path()
    return args, signature_catalog


def _emit_fast_cache_artifact_8616(
    args: CliArguments,
    artifact: DirectRequestCacheArtifact8616,
) -> int:
    """Emit one already-validated artifact through the direct CLI streams."""
    _timestamped_print(f"/* loading: {args.binary} */", flush=True)
    if artifact.runtime_header:
        sys.stdout.write(artifact.runtime_header)
        if not artifact.runtime_header.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    for diagnostic_line in artifact.startup_diagnostic_lines:
        _timestamped_print(diagnostic_line)
    _timestamped_print(f"/* binary: {args.binary} */")
    _timestamped_print(f"/* arch: {artifact.arch_name} */")
    _timestamped_print(f"/* entry: {artifact.entry_point:#x} */")
    _timestamped_print(f"/* function: {artifact.function_addr:#x} {artifact.function_name} */")
    print(
        f"[dbg] direct request cache hit: {artifact.function_addr:#x} "
        f"{artifact.function_name} validation=passed",
        file=sys.stderr,
    )
    if artifact.diagnostic_output:
        print(artifact.diagnostic_output, file=sys.stderr, end="")
    print(
        render_direct_request_tail_snapshot_diagnostic_8616(artifact.tail_validation),
        file=sys.stderr,
    )
    print("[dbg] direct function cache hit validation=passed", file=sys.stderr)
    print(f"[dbg] direct failure family: {artifact.failure_family_snapshot.label()}", file=sys.stderr)
    print("[tail-validation] whole-tail validation clean across 1 functions", file=sys.stderr)
    if args.output_c_dir is not None:
        write_generated_function_c(
            args.output_c_dir,
            address=artifact.function_addr,
            name=artifact.function_name,
            payload=artifact.payload,
        )
    _timestamped_print("\n/* == c == */")
    print(artifact.payload, end="" if artifact.payload.endswith("\n") else "\n", flush=True)
    return 0


def try_direct_request_fast_path_8616(argv: list[str] | None = None) -> int | None:
    """Return a cache-hit exit status, or None to run the full decompiler."""
    args, signature_catalog = _prepare_fast_path_args_8616(argv)
    # No live project exists here to reauthenticate declared-call authority.
    if args.declared_call_effects:
        return None
    inputs = DirectRequestCacheInputs8616.from_cli(
        args,
        signature_catalog=signature_catalog,
    )
    if inputs is None:
        return None
    lookup = load_direct_request_cache_8616(
        inputs,
        enabled=direct_request_cache_enabled_8616(args),
    )
    if lookup.verdict is not DirectRequestCacheVerdict8616.HIT or lookup.artifact is None:
        return None
    record = lookup.artifact.segment_program_function_evidence_record
    if isinstance(record, dict) and "declared_call_consumptions" in record:
        receipts = record["declared_call_consumptions"]
        if type(receipts) is not list or receipts:
            return None
    return _emit_fast_cache_artifact_8616(args, lookup.artifact)


