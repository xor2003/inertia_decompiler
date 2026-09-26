from __future__ import annotations  # noqa: D100

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from tools.dosunit.complexity import analyze_function_complexity
from tools.dosunit.data_compare import compare_loaded_data_images
from tools.dosunit.discovery import discover_functions
from tools.dosunit.failure_report import render_failure_report
from tools.dosunit.generate import generate_vectors
from tools.dosunit.libdosbox_import import import_libdosbox_trace
from tools.dosunit.mapping import make_mapping_document
from tools.dosunit.model import DosUnitError, load_json, write_json
from tools.dosunit.region_effects import compare_region_effect_documents, summarize_region_effects
from tools.dosunit.runner import compare_vectors, record_oracle, summarize_results
from tools.dosunit.straightline_ssa import (
    ABI_OUTPUT_REGS,
    DEFAULT_ABI,
    compare_ssa_abi_documents,
    compare_ssa_documents,
    lower_straightline_ssa_document,
)
from tools.dosunit.vectors import select_vectors

DEFAULT_SSA_MAX_BLOCKS_PER_FUNCTION = 1000
DEFAULT_SSA_MAX_INSNS_PER_FUNCTION = 256
DEFAULT_SSA_MAX_ASSIGNMENTS = 0
DEFAULT_SSA_SCAN_LIMIT = 0x1000
DEFAULT_COMPARE_SOLVER_TIMEOUT_MS = 60000
DEFAULT_COMPARE_BATCH_TIMEOUT_MS = 300000
DEFAULT_COMPARE_MAX_ASSIGNMENTS = 0
DEFAULT_COMPARE_MAX_INPUTS = 0
DEFAULT_COMPARE_MAX_MEMORY_STORES = 32
DEFAULT_COMPARE_SEMANTIC_PROOF_PASSES = 2
DEFAULT_COMPARE_REGION_LOOP_UNROLL = 2
DEFAULT_COMPARE_BATCH_SIZE = 64


def _path_or_none(value: str | None) -> Path | None:
    return None if value is None else Path(value)


def _default_max_rss_mb() -> int:
    raw = os.environ.get("DOSUNIT_MAX_RSS_MB", "4096")
    try:
        return int(raw)
    except ValueError:
        return 4096


def _current_rss_kib() -> int | None:
    try:
        with open("/proc/self/status", encoding="ascii") as status_file:
            for line in status_file:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
    except (FileNotFoundError, OSError, ValueError):
        return None
    return None


def _rss_limit_exceeded(rss_kib: int | None, max_rss_mb: int) -> bool:
    return bool(max_rss_mb and max_rss_mb > 0 and rss_kib is not None and rss_kib > max_rss_mb * 1024)


def _watchdog_interval_seconds() -> float:
    raw = os.environ.get("DOSUNIT_RSS_WATCHDOG_INTERVAL_SEC", "0.25")
    try:
        return max(0.05, float(raw))
    except ValueError:
        return 0.25


def _start_rss_watchdog(max_rss_mb: int, label: str) -> None:
    if max_rss_mb <= 0:
        return
    interval = _watchdog_interval_seconds()

    def worker() -> None:
        while True:
            rss_kib = _current_rss_kib()
            if _rss_limit_exceeded(rss_kib, max_rss_mb):
                rss_mb = "unknown" if rss_kib is None else f"{rss_kib / 1024:.1f}"
                print(
                    f"dosunit: {label} RSS {rss_mb} MiB exceeded --max-rss-mb {max_rss_mb}; killing process",
                    file=sys.stderr,
                    flush=True,
                )
                os._exit(137)
            time.sleep(interval)

    thread = threading.Thread(target=worker, name="dosunit-rss-watchdog", daemon=True)
    thread.start()


def _add_max_rss_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-rss-mb",
        type=int,
        default=_default_max_rss_mb(),
        help="Kill this process if RSS exceeds this many MiB; default: env DOSUNIT_MAX_RSS_MB or 4096; 0 disables",
    )


def cmd_discover(args: argparse.Namespace) -> int:  # noqa: D103
    catalog = discover_functions(
        exe_path=_path_or_none(args.exe),
        map_path=_path_or_none(args.map),
        cod_listing_path=_path_or_none(args.cod_listing),
        ida_listing_path=_path_or_none(args.ida_listing),
        module=args.module,
    )
    write_json(Path(args.out), catalog)
    return 0


def cmd_gen_vectors(args: argparse.Namespace) -> int:  # noqa: D103
    catalog = load_json(Path(args.functions))
    document = generate_vectors(
        functions_catalog=catalog,
        exe_path=_path_or_none(args.exe),
        strategy=args.strategy,
        max_vectors_per_function=args.max_vectors_per_function,
        max_branches=args.max_branches,
        max_blocks=args.max_blocks,
        max_loop_unroll=args.max_loop_unroll,
        solver_timeout_ms=args.solver_timeout_ms,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_import_libdosbox(args: argparse.Namespace) -> int:  # noqa: D103
    document = import_libdosbox_trace(
        trace_path=Path(args.trace),
        functions_path=_path_or_none(args.functions),
        dump_path=_path_or_none(args.dump),
        meta_path=_path_or_none(args.meta),
    )
    write_json(Path(args.out), document)
    return 0


def cmd_regions(args: argparse.Namespace) -> int:  # noqa: D103
    catalog = load_json(Path(args.functions))
    document = summarize_region_effects(
        exe_path=Path(args.exe),
        functions_catalog=catalog,
        max_regions_per_function=args.max_regions_per_function,
        max_insns_per_region=args.max_insns_per_region,
        scan_limit=args.scan_limit,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_complexity(args: argparse.Namespace) -> int:  # noqa: D103
    catalog = load_json(Path(args.functions))
    document = analyze_function_complexity(
        exe_path=Path(args.exe),
        functions_catalog=catalog,
        max_blocks_per_function=args.max_blocks_per_function,
        max_insns_per_function=args.max_insns_per_function,
        max_simple_insns=args.max_simple_insns,
        simple_score_threshold=args.simple_score_threshold,
        max_simple_symbolic_memory=args.max_simple_symbolic_memory,
        max_risk_points=args.max_risk_points,
        scan_limit=args.scan_limit,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_ssa(args: argparse.Namespace) -> int:  # noqa: D103
    _start_rss_watchdog(args.max_rss_mb, "ssa")
    catalog = load_json(Path(args.functions))
    output_regs = tuple(args.output_reg or ABI_OUTPUT_REGS[args.abi])
    document = lower_straightline_ssa_document(
        exe_path=Path(args.exe),
        functions_catalog=catalog,
        output_regs=output_regs,
        source_ir=args.ir,
        max_blocks_per_function=args.max_blocks_per_function,
        max_insns_per_function=args.max_insns_per_function,
        max_assignments_per_function=args.max_ssa_assignments,
        scan_limit=args.scan_limit,
        cache_dir=None if args.no_cache else Path(args.cache_dir),
        follow_call_fallthrough=bool(args.follow_call_fallthrough),
        max_lift_block_ms=args.max_lift_block_ms,
        max_function_ms=args.max_function_ms,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_compare_ssa(args: argparse.Namespace) -> int:  # noqa: D103
    _start_rss_watchdog(args.max_rss_mb, "compare-ssa")
    oracle = load_json(Path(args.oracle_ssa))
    candidate = load_json(Path(args.candidate_ssa))
    oracle_index = load_json(Path(args.oracle_index_ssa)) if args.oracle_index_ssa else None
    candidate_index = load_json(Path(args.candidate_index_ssa)) if args.candidate_index_ssa else None
    mapping = load_json(Path(args.mapping)) if args.mapping else None
    document = compare_ssa_documents(
        oracle=oracle,
        candidate=candidate,
        oracle_index_document=oracle_index,
        candidate_index_document=candidate_index,
        mapping_document=mapping,
        include_unmapped=not bool(args.skip_unmapped),
        timeout_ms=args.solver_timeout_ms,
        max_solver_assignments=args.max_solver_assignments,
        max_solver_inputs=args.max_solver_inputs,
        max_solver_memory_stores=args.max_solver_memory_stores,
        skip_binary_equal=not bool(args.no_skip_binary_equal),
        enable_callee_lemmas=not bool(args.disable_callee_lemmas),
        semantic_proof_passes=args.semantic_proof_passes,
        enable_region_equality=not bool(args.disable_region_equality),
        enable_connectivity=not bool(args.disable_connectivity),
        max_region_loop_unroll=args.max_region_loop_unroll,
        max_rss_mb=args.max_rss_mb,
    )
    write_json(Path(args.out), document)
    summary = document.get("summary", {})
    return 0 if summary.get("failed") == 0 and summary.get("refused") == 0 else 1


def _ssa_batch_command(
    args: argparse.Namespace,
    batch_oracle_path: Path,
    batch_compare_path: Path,
) -> list[str]:
    """Build the per-batch compare-ssa subprocess command."""
    command = [
        sys.executable,
        "-m",
        "tools.dosunit.dosunit",
        "compare-ssa",
        "--oracle-ssa",
        str(batch_oracle_path),
        "--candidate-ssa",
        str(Path(args.candidate_ssa)),
        "--oracle-index-ssa",
        str(Path(args.oracle_index_ssa or args.oracle_ssa)),
        "--candidate-index-ssa",
        str(Path(args.candidate_index_ssa or args.candidate_ssa)),
        "--max-rss-mb",
        str(args.max_rss_mb),
        "--solver-timeout-ms",
        str(args.solver_timeout_ms),
        "--max-solver-assignments",
        str(args.max_solver_assignments),
        "--max-solver-inputs",
        str(args.max_solver_inputs),
        "--max-solver-memory-stores",
        str(args.max_solver_memory_stores),
        "--semantic-proof-passes",
        str(args.semantic_proof_passes),
        "--max-region-loop-unroll",
        str(args.max_region_loop_unroll),
        "--out",
        str(batch_compare_path),
    ]
    if args.mapping:
        command.extend(["--mapping", str(Path(args.mapping))])
    if args.skip_unmapped:
        command.append("--skip-unmapped")
    if args.no_skip_binary_equal:
        command.append("--no-skip-binary-equal")
    if args.disable_callee_lemmas:
        command.append("--disable-callee-lemmas")
    if args.disable_region_equality:
        command.append("--disable-region-equality")
    if args.disable_connectivity:
        command.append("--disable-connectivity")
    return command


def _run_ssa_batch(command: list[str], batch_timeout_ms: int) -> tuple[int, bool]:
    """Run one compare-ssa batch; return (returncode, timed_out)."""
    try:
        completed = subprocess.run(
            command,
            cwd=Path.cwd(),
            timeout=None if batch_timeout_ms <= 0 else batch_timeout_ms / 1000.0,
        )
        return completed.returncode, False
    except subprocess.TimeoutExpired:
        return -9, True


def _ssa_batch_failure_row(
    batch_index: int,
    batch: list[dict[str, Any]],
    returncode: int,
    timed_out: bool,
    elapsed_ms: int,
    batch_oracle_path: Path,
    batch_compare_path: Path,
) -> dict[str, Any]:
    """Build the failure row for a batch that produced no compare output."""
    return {
        "batch": batch_index,
        "status": "timeout" if timed_out else "process_failed",
        "reason": "batch_timeout" if timed_out else "process_failed",
        "returncode": returncode,
        "elapsed_ms": elapsed_ms,
        "function_count": len(sorted({_ssa_function_key(function) for function in batch if _ssa_function_key(function)})),
        "ssa_part_count": len(batch),
        "functions": sorted({_ssa_function_key(function) for function in batch if _ssa_function_key(function)}),
        "oracle_ssa": str(batch_oracle_path),
        "compare": str(batch_compare_path),
    }




def cmd_compare_ssa_batched(args: argparse.Namespace) -> int:  # noqa: D103
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    oracle = load_json(Path(args.oracle_ssa))
    functions = [item for item in oracle.get("functions", []) or [] if isinstance(item, dict)]
    batches = _ssa_function_batches(functions, batch_size=args.batch_size)
    if not batches:
        raise DosUnitError("--oracle-ssa has no SSA functions to compare")

    rows: list[dict[str, Any]] = []
    for batch_index, batch in enumerate(batches, start=1):
        batch_doc = _ssa_batch_document(oracle, batch)
        batch_oracle_path = out_dir / f"oracle.batch{batch_index:03d}.ssa.json"
        batch_compare_path = out_dir / f"compare.batch{batch_index:03d}.json"
        write_json(batch_oracle_path, batch_doc)
        command = _ssa_batch_command(args, batch_oracle_path, batch_compare_path)
        started = time.time()
        returncode, timed_out = _run_ssa_batch(command, int(args.batch_timeout_ms))
        if not batch_compare_path.exists():
            elapsed_ms = int((time.time() - started) * 1000)
            rows.append(
                _ssa_batch_failure_row(
                    batch_index,
                    batch,
                    returncode,
                    timed_out,
                    elapsed_ms,
                    batch_oracle_path,
                    batch_compare_path,
                )
            )
            if not args.keep_going:
                break
            continue
        compare_doc = load_json(batch_compare_path)
        elapsed_ms = int((time.time() - started) * 1000)
        rows.append(_ssa_batch_row(batch_index, batch, compare_doc, returncode, elapsed_ms, batch_oracle_path, batch_compare_path))
        if returncode != 0 and not args.keep_going:
            break

    document = _ssa_batched_document(args, rows, len(batches))
    write_json(Path(args.out), document)
    return 0 if document["summary"]["failed"] == 0 and document["summary"]["refused"] == 0 and not document["summary"]["rc_nonzero"] else 1


def cmd_compare_ssa_abi(args: argparse.Namespace) -> int:  # noqa: D103
    _start_rss_watchdog(args.max_rss_mb, "compare-ssa-abi")
    oracle = load_json(Path(args.oracle_ssa))
    candidate = load_json(Path(args.candidate_ssa))
    abi_manifest = load_json(Path(args.abi_manifest))
    mapping = load_json(Path(args.mapping)) if args.mapping else None
    document = compare_ssa_abi_documents(
        oracle=oracle,
        candidate=candidate,
        abi_manifest=abi_manifest,
        mapping_document=mapping,
        timeout_ms=args.solver_timeout_ms,
        max_solver_assignments=args.max_solver_assignments,
        max_solver_inputs=args.max_solver_inputs,
        max_solver_memory_stores=args.max_solver_memory_stores,
        max_loop_unroll=args.max_loop_unroll,
    )
    write_json(Path(args.out), document)
    summary = document.get("summary", {})
    return 0 if summary.get("failed") == 0 and summary.get("refused") == 0 else 1


def cmd_compare_regions(args: argparse.Namespace) -> int:  # noqa: D103
    oracle = load_json(Path(args.oracle_regions))
    candidate = load_json(Path(args.candidate_regions))
    document = compare_region_effect_documents(oracle=oracle, candidate=candidate)
    write_json(Path(args.out), document)
    return (
        0 if document.get("summary", {}).get("failed") == 0 and document.get("summary", {}).get("refused") == 0 else 1
    )


def cmd_make_mapping(args: argparse.Namespace) -> int:  # noqa: D103
    oracle = load_json(Path(args.oracle_functions))
    candidate = load_json(Path(args.candidate_functions))
    document = make_mapping_document(oracle_catalog=oracle, candidate_catalog=candidate, mode=args.mode)
    write_json(Path(args.out), document)
    return 0


def cmd_select_vectors(args: argparse.Namespace) -> int:  # noqa: D103
    vectors = load_json(Path(args.vectors))
    document = select_vectors(vectors, names=args.function, limit=args.limit)
    write_json(Path(args.out), document)
    return 0


def cmd_record_oracle(args: argparse.Namespace) -> int:  # noqa: D103
    vectors = load_json(Path(args.vectors))
    functions = load_json(Path(args.functions)) if args.functions else None
    document = record_oracle(
        vectors,
        backend=args.backend,
        exe_path=_path_or_none(args.exe),
        functions_catalog=functions,
        kvikdos_path=_path_or_none(args.kvikdos),
    )
    write_json(Path(args.out), document)
    return 0 if _all_results_passed(document) else 1


def cmd_compare(args: argparse.Namespace) -> int:  # noqa: D103
    vectors = load_json(Path(args.vectors))
    functions = load_json(Path(args.functions)) if args.functions else None
    mapping = load_json(Path(args.mapping)) if args.mapping else None
    document = compare_vectors(
        vectors,
        backend=args.backend,
        candidate_path=_path_or_none(args.candidate),
        functions_catalog=functions,
        mapping_document=mapping,
        kvikdos_path=_path_or_none(args.kvikdos),
        ignore_fields=set(args.ignore_field or []),
    )
    write_json(Path(args.out), document)
    return 0 if _all_results_passed(document) else 1


def cmd_compare_data(args: argparse.Namespace) -> int:  # noqa: D103
    oracle_catalog = load_json(Path(args.oracle_functions))
    candidate_catalog = load_json(Path(args.candidate_functions))
    document = compare_loaded_data_images(
        oracle_exe=Path(args.oracle_exe),
        candidate_exe=Path(args.candidate_exe),
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        ranges=args.range,
        code_pointer_normalizations=args.normalize_code_pointer or [],
        oracle_load_base_para=_parse_cli_int(args.oracle_load_base, field="--oracle-load-base"),
        candidate_load_base_para=_parse_cli_int(args.candidate_load_base, field="--candidate-load-base"),
    )
    write_json(Path(args.out), document)
    return 0 if document.get("status") == "passed" else 1


def cmd_summarize(args: argparse.Namespace) -> int:  # noqa: D103
    document = load_json(Path(args.results))
    results = document.get("results", []) if isinstance(document, dict) else []
    summary = summarize_results(results if isinstance(results, list) else [])
    if args.out:
        write_json(Path(args.out), summary)
    else:
        for key, value in summary.items():
            print(f"{key}: {value}")
    return 0


def cmd_report_failures(args: argparse.Namespace) -> int:  # noqa: D103
    document = load_json(Path(args.results))
    if not isinstance(document, dict):
        raise DosUnitError("--results must be a JSON object")
    report = render_failure_report(
        document,
        limit=args.limit,
        mismatch_limit=args.mismatch_limit,
        show_unresolved_call_targets=bool(args.show_unresolved_call_targets),
        failed_only=bool(args.failed_only),
        group_by_function=bool(args.group_by_function),
    )
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report)
    else:
        print(report, end="")
    return 0


def _ssa_function_key(function: dict[str, Any]) -> str:
    info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
    function_id = str(info.get("id") or "")
    function_name = str(info.get("name") or "")
    return function_id or function_name or str(function.get("id") or "")


def _ssa_function_batches(functions: list[dict[str, Any]], *, batch_size: int) -> list[list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for function in functions:
        key = _ssa_function_key(function)
        if not key:
            continue
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(function)
    if batch_size <= 0:
        batch_size = len(order) or 1
    batches: list[list[dict[str, Any]]] = []
    for start in range(0, len(order), batch_size):
        batch_functions: list[dict[str, Any]] = []
        for key in order[start : start + batch_size]:
            batch_functions.extend(grouped[key])
        batches.append(batch_functions)
    return batches


def _ssa_batch_document(oracle: dict[str, Any], functions: list[dict[str, Any]]) -> dict[str, Any]:
    document = {
        key: value
        for key, value in oracle.items()
        if key not in {"functions", "refusals", "counters", "id"}
    }
    selected_keys = {_ssa_function_key(function) for function in functions}
    refusals = [
        refusal
        for refusal in oracle.get("refusals", []) or []
        if isinstance(refusal, dict) and _refusal_function_key(refusal) in selected_keys
    ]
    document["functions"] = functions
    document["refusals"] = refusals
    document["counters"] = {
        "functions_in_batch": len(selected_keys),
        "ssa_parts_in_batch": len(functions),
        "refusals_in_batch": len(refusals),
    }
    return document


def _refusal_function_key(refusal: dict[str, Any]) -> str:
    function = refusal.get("function") if isinstance(refusal.get("function"), dict) else {}
    return str(function.get("id") or function.get("name") or refusal.get("function_id") or "")


def _ssa_batch_row(
    batch_index: int,
    batch: list[dict[str, Any]],
    compare_doc: dict[str, Any],
    returncode: int,
    elapsed_ms: int,
    batch_oracle_path: Path,
    batch_compare_path: Path,
) -> dict[str, Any]:
    summary = compare_doc.get("summary", {}) if isinstance(compare_doc.get("summary"), dict) else {}
    external = compare_doc.get("external_parts", {}) if isinstance(compare_doc.get("external_parts"), dict) else {}
    region_equality = compare_doc.get("region_equality", {}) if isinstance(compare_doc.get("region_equality"), dict) else {}
    connectivity = compare_doc.get("connectivity", {}) if isinstance(compare_doc.get("connectivity"), dict) else {}
    loop_scc = compare_doc.get("loop_scc", {}) if isinstance(compare_doc.get("loop_scc"), dict) else {}
    call_scc = compare_doc.get("call_scc", {}) if isinstance(compare_doc.get("call_scc"), dict) else {}
    function_keys = sorted({_ssa_function_key(function) for function in batch if _ssa_function_key(function)})
    candidate_refs = _compare_doc_candidate_references(compare_doc)
    return {
        "batch": batch_index,
        "status": "passed" if returncode == 0 else "failed",
        "returncode": returncode,
        "elapsed_ms": elapsed_ms,
        "function_count": len(function_keys),
        "ssa_part_count": len(batch),
        "functions": function_keys,
        "oracle_ssa": str(batch_oracle_path),
        "compare": str(batch_compare_path),
        "main_total": int(summary.get("total", 0) or 0),
        "main_passed": int(summary.get("passed", 0) or 0),
        "main_failed": int(summary.get("failed", 0) or 0),
        "main_refused": int(summary.get("refused", 0) or 0),
        "external_total": int(external.get("total", 0) or 0),
        "external_passed": int(external.get("passed", 0) or 0),
        "external_failed": int(external.get("failed", 0) or 0),
        "external_refused": int(external.get("refused", 0) or 0),
        "external_unproved": int(external.get("unproved", 0) or 0),
        "region_equality": _ssa_batch_region_rollup(region_equality),
        "connectivity": _ssa_batch_connectivity_rollup(connectivity),
        "loop_scc": _ssa_batch_scc_rollup(loop_scc),
        "call_scc": _ssa_batch_scc_rollup(call_scc),
        "solver_time_ms": int(summary.get("solver_time_ms", 0) or 0),
        "candidate_parts_referenced": candidate_refs,
    }


def _ssa_batch_region_rollup(region_equality: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": str(region_equality.get("status", "not_applicable")),
        "total": int(region_equality.get("total", 0) or 0),
        "passed": int(region_equality.get("passed", 0) or 0),
        "failed": int(region_equality.get("failed", 0) or 0),
        "refused": int(region_equality.get("refused", 0) or 0),
        "covered_results": int(region_equality.get("covered_results", 0) or 0),
        "connectivity_covered_regions": int(region_equality.get("connectivity_covered_regions", 0) or 0),
        "skipped_passed_functions": int(region_equality.get("skipped_passed_functions", 0) or 0),
        "solver_time_ms": int(region_equality.get("solver_time_ms", 0) or 0),
    }


def _ssa_batch_connectivity_rollup(connectivity: dict[str, Any]) -> dict[str, Any]:
    failures = [item for item in connectivity.get("failures", []) or [] if isinstance(item, dict)]
    refusals = [item for item in connectivity.get("refusals", []) or [] if isinstance(item, dict)]
    return {
        "status": str(connectivity.get("status", "not_applicable")),
        "edges_checked": int(connectivity.get("edges_checked", 0) or 0),
        "state_edges_checked": int(connectivity.get("state_edges_checked", 0) or 0),
        "state_inputs_checked": int(connectivity.get("state_inputs_checked", 0) or 0),
        "external_successor_edges": _count_or_int(connectivity.get("external_successor_edges", 0)),
        "external_successor_edges_covered": int(connectivity.get("external_successor_edges_covered", 0) or 0),
        "external_successor_edges_unproved": int(connectivity.get("external_successor_edges_unproved", 0) or 0),
        "failures": len(failures),
        "refusals": len(refusals),
        "state_solver_time_ms": int(connectivity.get("state_solver_time_ms", 0) or 0),
    }


def _count_or_int(value: Any) -> int:  # noqa: ANN401
    if isinstance(value, list | tuple | set | dict):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _ssa_batch_scc_rollup(scc: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": str(scc.get("status", "not_applicable")),
        "total": int(scc.get("total", 0) or 0),
        "passed": int(scc.get("passed", 0) or 0),
        "failed": int(scc.get("failed", 0) or 0),
        "refused": int(scc.get("refused", 0) or 0),
    }


def _ssa_batched_document(args: argparse.Namespace, rows: list[dict[str, Any]], batch_count: int) -> dict[str, Any]:
    candidate_only_parts = _candidate_only_parts_for_batched(Path(args.candidate_ssa), rows)
    region_equality = _sum_batched_region_rollups(rows)
    connectivity = _sum_batched_connectivity_rollups(rows)
    loop_scc = _sum_batched_scc_rollups(rows, "loop_scc")
    call_scc = _sum_batched_scc_rollups(rows, "call_scc")
    summary = {
        "batches": batch_count,
        "batches_completed": len(rows),
        "rc_nonzero": [row.get("batch") for row in rows if int(row.get("returncode", 0) or 0) != 0],
        "failed": sum(int(row.get("main_failed", 0) or 0) for row in rows)
        + sum(int(row.get("external_failed", 0) or 0) for row in rows),
        "refused": sum(int(row.get("main_refused", 0) or 0) for row in rows)
        + sum(int(row.get("external_refused", 0) or 0) for row in rows),
        "main_total": sum(int(row.get("main_total", 0) or 0) for row in rows),
        "main_passed": sum(int(row.get("main_passed", 0) or 0) for row in rows),
        "main_failed": sum(int(row.get("main_failed", 0) or 0) for row in rows),
        "main_refused": sum(int(row.get("main_refused", 0) or 0) for row in rows),
        "external_total": sum(int(row.get("external_total", 0) or 0) for row in rows),
        "external_passed": sum(int(row.get("external_passed", 0) or 0) for row in rows),
        "external_failed": sum(int(row.get("external_failed", 0) or 0) for row in rows),
        "external_refused": sum(int(row.get("external_refused", 0) or 0) for row in rows),
        "external_unproved": sum(int(row.get("external_unproved", 0) or 0) for row in rows),
        "candidate_parts_total": candidate_only_parts.get("candidate_parts_total", 0),
        "candidate_parts_referenced": candidate_only_parts.get("candidate_parts_referenced", 0),
        "candidate_only_parts": candidate_only_parts.get("total", 0),
        "candidate_alias_only_parts": candidate_only_parts.get("alias_total", 0),
        "region_total": region_equality["total"],
        "region_passed": region_equality["passed"],
        "region_failed": region_equality["failed"],
        "region_refused": region_equality["refused"],
        "region_covered_results": region_equality["covered_results"],
        "connectivity_edges_checked": connectivity["edges_checked"],
        "connectivity_state_edges_checked": connectivity["state_edges_checked"],
        "connectivity_failures": connectivity["failures"],
        "connectivity_refusals": connectivity["refusals"],
        "loop_scc_total": loop_scc["total"],
        "loop_scc_passed": loop_scc["passed"],
        "loop_scc_failed": loop_scc["failed"],
        "loop_scc_refused": loop_scc["refused"],
        "call_scc_total": call_scc["total"],
        "call_scc_passed": call_scc["passed"],
        "call_scc_failed": call_scc["failed"],
        "call_scc_refused": call_scc["refused"],
        "solver_time_ms": sum(int(row.get("solver_time_ms", 0) or 0) for row in rows),
    }
    return {
        "schema": "dosunit.ssa_batched_compare.v1",
        "oracle_ssa": str(Path(args.oracle_ssa)),
        "candidate_ssa": str(Path(args.candidate_ssa)),
        "oracle_index_ssa": str(Path(args.oracle_index_ssa or args.oracle_ssa)),
        "candidate_index_ssa": str(Path(args.candidate_index_ssa or args.candidate_ssa)),
        "mapping": None if not args.mapping else str(Path(args.mapping)),
        "out_dir": str(Path(args.out_dir)),
        "parameters": {
            "batch_size": args.batch_size,
            "max_rss_mb": args.max_rss_mb,
            "solver_timeout_ms": args.solver_timeout_ms,
            "max_solver_assignments": args.max_solver_assignments,
            "max_solver_inputs": args.max_solver_inputs,
            "max_solver_memory_stores": args.max_solver_memory_stores,
            "semantic_proof_passes": args.semantic_proof_passes,
            "max_region_loop_unroll": args.max_region_loop_unroll,
            "batch_timeout_ms": args.batch_timeout_ms,
        },
        "summary": summary,
        "region_equality": region_equality,
        "connectivity": connectivity,
        "loop_scc": loop_scc,
        "call_scc": call_scc,
        "candidate_only_parts": candidate_only_parts,
        "batches": rows,
    }


def _rollup_status(*, failed: int, refused: int, total: int, enabled: bool = True) -> str:
    if not enabled:
        return "disabled"
    if failed:
        return "failed"
    if refused:
        return "refused"
    if total:
        return "passed"
    return "not_applicable"


def _sum_batched_region_rollups(rows: list[dict[str, Any]]) -> dict[str, Any]:
    enabled = any(str((row.get("region_equality") or {}).get("status", "")) != "disabled" for row in rows)
    result = {
        "enabled": enabled,
        "total": 0,
        "passed": 0,
        "failed": 0,
        "refused": 0,
        "covered_results": 0,
        "connectivity_covered_regions": 0,
        "skipped_passed_functions": 0,
        "solver_time_ms": 0,
    }
    for row in rows:
        item = row.get("region_equality") if isinstance(row.get("region_equality"), dict) else {}
        for key in result:
            if key == "enabled":
                continue
            result[key] += int(item.get(key, 0) or 0)
    result["status"] = _rollup_status(
        failed=result["failed"],
        refused=result["refused"],
        total=result["total"],
        enabled=enabled,
    )
    return result


def _sum_batched_connectivity_rollups(rows: list[dict[str, Any]]) -> dict[str, Any]:
    enabled = any(str((row.get("connectivity") or {}).get("status", "")) != "disabled" for row in rows)
    result = {
        "enabled": enabled,
        "edges_checked": 0,
        "state_edges_checked": 0,
        "state_inputs_checked": 0,
        "external_successor_edges": 0,
        "external_successor_edges_covered": 0,
        "external_successor_edges_unproved": 0,
        "failures": 0,
        "refusals": 0,
        "state_solver_time_ms": 0,
    }
    for row in rows:
        item = row.get("connectivity") if isinstance(row.get("connectivity"), dict) else {}
        for key in result:
            if key == "enabled":
                continue
            result[key] += int(item.get(key, 0) or 0)
    result["status"] = _rollup_status(
        failed=result["failures"],
        refused=result["refusals"] + result["external_successor_edges_unproved"],
        total=result["edges_checked"] + result["state_edges_checked"],
        enabled=enabled,
    )
    return result


def _sum_batched_scc_rollups(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    enabled = any(str((row.get(key) or {}).get("status", "")) != "disabled" for row in rows)
    result = {"enabled": enabled, "total": 0, "passed": 0, "failed": 0, "refused": 0}
    for row in rows:
        item = row.get(key) if isinstance(row.get(key), dict) else {}
        for field in ("total", "passed", "failed", "refused"):
            result[field] += int(item.get(field, 0) or 0)
    result["status"] = _rollup_status(
        failed=result["failed"],
        refused=result["refused"],
        total=result["total"],
        enabled=enabled,
    )
    return result


def _compare_doc_candidate_references(compare_doc: dict[str, Any]) -> list[str]:
    refs: set[str] = set()
    for result in compare_doc.get("results", []) or []:
        if isinstance(result, dict):
            _add_candidate_ref(refs, result.get("candidate_function"))
    external = compare_doc.get("external_parts") if isinstance(compare_doc.get("external_parts"), dict) else {}
    for result in external.get("results", []) or []:
        if isinstance(result, dict):
            _add_candidate_ref(refs, result.get("candidate_function"))
    return sorted(refs)


def _candidate_only_parts_for_batched(candidate_ssa_path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        candidate = load_json(candidate_ssa_path)
    except Exception as ex:
        return {
            "enabled": False,
            "reason": f"candidate_ssa_unavailable: {ex}",
            "candidate_parts_total": 0,
            "candidate_parts_referenced": 0,
            "total": 0,
            "alias_total": 0,
            "parts": [],
            "alias_parts": [],
        }
    candidate_functions = [item for item in candidate.get("functions", []) or [] if isinstance(item, dict)]
    referenced: set[str] = set()
    for row in rows:
        for ref in row.get("candidate_parts_referenced", []) or []:
            _add_candidate_ref(referenced, ref)
    referenced_alias_keys = {
        key
        for function in candidate_functions
        if str(function.get("id") or "") in referenced
        for key in [_candidate_part_alias_key(function)]
        if key is not None
    }
    parts: list[dict[str, Any]] = []
    alias_parts: list[dict[str, Any]] = []
    for function in candidate_functions:
        function_id = str(function.get("id") or "")
        if not function_id or function_id in referenced:
            continue
        alias_key = _candidate_part_alias_key(function)
        if alias_key is not None and alias_key in referenced_alias_keys:
            alias_parts.append(function)
        else:
            parts.append(function)
    return {
        "enabled": True,
        "candidate_parts_total": len(candidate_functions),
        "candidate_parts_referenced": len(referenced),
        "total": len(parts),
        "alias_total": len(alias_parts),
        "parts": [_candidate_only_part_detail(function) for function in parts],
        "alias_parts": [_candidate_only_part_detail(function) for function in alias_parts],
    }


def _add_candidate_ref(refs: set[str], value: Any) -> None:  # noqa: ANN401
    if isinstance(value, str) and value:
        refs.add(value)


def _candidate_only_part_detail(function: dict[str, Any]) -> dict[str, Any]:
    info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    part = function.get("part") if isinstance(function.get("part"), dict) else {}
    source = function.get("source") if isinstance(function.get("source"), dict) else {}
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    return {
        "id": function.get("id"),
        "function": {"id": info.get("id"), "name": info.get("name")},
        "entry": entry,
        "part": part,
        "jumpkind": source.get("jumpkind"),
        "instruction_count": source.get("instruction_count", len(instructions)),
        "instructions": instructions[:4],
    }


def _candidate_part_alias_key(function: dict[str, Any]) -> tuple[Any, ...] | None:
    entry = function.get("entry") if isinstance(function.get("entry"), dict) else {}
    part = function.get("part") if isinstance(function.get("part"), dict) else {}
    source = function.get("source") if isinstance(function.get("source"), dict) else {}
    linear = entry.get("linear")
    ip = entry.get("ip")
    if not linear and not ip:
        return None
    return (
        linear,
        ip,
        part.get("index"),
        part.get("delta"),
        source.get("machine_code_sha256"),
        source.get("machine_code_size"),
        source.get("instruction_count"),
    )


def _all_results_passed(document: dict[str, Any]) -> bool:
    results = document.get("results", [])
    return isinstance(results, list) and all(
        isinstance(result, dict) and result.get("status") == "passed" for result in results
    )


def _parse_cli_int(value: str, *, field: str) -> int:
    try:
        return int(value, 0)
    except ValueError as ex:
        raise DosUnitError(f"{field} must be an integer or hex string") from ex


def build_parser(*, prog: str = "dosunit") -> argparse.ArgumentParser:  # noqa: D103
    def subparser_factory(*args: Any, **kwargs: Any) -> argparse.ArgumentParser:  # noqa: ANN401
        kwargs.setdefault("formatter_class", argparse.ArgumentDefaultsHelpFormatter)
        return argparse.ArgumentParser(*args, **kwargs)

    parser = argparse.ArgumentParser(
        prog=prog,
        description="DOS SSA/Z3 function comparison and unit-test tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=subparser_factory)

    discover = subparsers.add_parser("discover", help="Discover function catalog from DOS metadata")
    discover.add_argument("--exe")
    discover.add_argument("--map")
    discover.add_argument("--cod-listing")
    discover.add_argument("--ida-listing")
    discover.add_argument("--module")
    discover.add_argument("--out", required=True)
    discover.set_defaults(func=cmd_discover)

    gen = subparsers.add_parser("gen-vectors", help="Generate input vectors")
    gen.add_argument("--exe")
    gen.add_argument("--functions", required=True)
    gen.add_argument("--strategy", default="entry", choices=["entry", "edge", "hot", "manual_seed"])
    gen.add_argument("--max-vectors-per-function", type=int, default=1)
    gen.add_argument("--max-branches", type=int)
    gen.add_argument("--max-blocks", type=int)
    gen.add_argument("--max-loop-unroll", type=int, default=0)
    gen.add_argument("--solver-timeout-ms", type=int, default=1000)
    gen.add_argument("--out", required=True)
    gen.set_defaults(func=cmd_gen_vectors)

    importer = subparsers.add_parser("import-libdosbox", help="Import libdosbox runtime trace")
    importer.add_argument("--trace", required=True)
    importer.add_argument("--dump")
    importer.add_argument("--meta")
    importer.add_argument("--functions")
    importer.add_argument("--out", required=True)
    importer.set_defaults(func=cmd_import_libdosbox)

    regions = subparsers.add_parser("regions", help="Summarize lifter-backed region operand/effects")
    regions.add_argument("--exe", required=True)
    regions.add_argument("--functions", required=True)
    regions.add_argument("--max-regions-per-function", type=int, default=8)
    regions.add_argument("--max-insns-per-region", type=int, default=32)
    regions.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x200)
    regions.add_argument("--out", required=True)
    regions.set_defaults(func=cmd_regions)

    complexity = subparsers.add_parser("complexity", help="Analyze per-function Z3/solver complexity")
    complexity.add_argument("--exe", required=True)
    complexity.add_argument("--functions", required=True)
    complexity.add_argument("--max-blocks-per-function", type=int, default=32)
    complexity.add_argument("--max-insns-per-function", type=int, default=128)
    complexity.add_argument("--max-simple-insns", type=int, default=16)
    complexity.add_argument("--simple-score-threshold", type=int, default=8)
    complexity.add_argument("--max-simple-symbolic-memory", type=int, default=0)
    complexity.add_argument("--max-risk-points", type=int, default=16)
    complexity.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x200)
    complexity.add_argument("--out", required=True)
    complexity.set_defaults(func=cmd_complexity)

    ssa = subparsers.add_parser("ssa", help="Lower bounded straight-line VEX/AIL slices into compact SSA")
    ssa.add_argument("--exe", required=True)
    ssa.add_argument("--functions", required=True)
    ssa.add_argument("--ir", default="vex", choices=["vex", "ail"], help="Source IR to lower into compact SSA")
    ssa.add_argument(
        "--abi",
        default=DEFAULT_ABI,
        choices=sorted(ABI_OUTPUT_REGS),
        help="Default output-register preset used when --output-reg is omitted",
    )
    ssa.add_argument("--output-reg", action="append")
    ssa.add_argument(
        "--max-blocks-per-function",
        type=int,
        default=DEFAULT_SSA_MAX_BLOCKS_PER_FUNCTION,
        help="Maximum direct in-function basic blocks to lower for a function",
    )
    ssa.add_argument(
        "--max-insns-per-function",
        type=int,
        default=DEFAULT_SSA_MAX_INSNS_PER_FUNCTION,
        help="Maximum decoded instructions allowed in one lifted SSA block",
    )
    ssa.add_argument(
        "--max-ssa-assignments",
        type=int,
        default=DEFAULT_SSA_MAX_ASSIGNMENTS,
        help="Refuse a function when compact SSA assignments exceed this limit; 0 disables the gate",
    )
    ssa.add_argument(
        "--scan-limit",
        type=lambda value: int(value, 0),
        default=DEFAULT_SSA_SCAN_LIMIT,
        help="Maximum bytes to scan when extending direct successor ranges",
    )
    ssa.add_argument("--max-lift-block-ms", type=int, default=10000, help="Refuse a single hard VEX block after this many milliseconds; 0 disables the alarm")
    ssa.add_argument("--max-function-ms", type=int, default=60000, help="Refuse one SSA function after this many milliseconds; 0 disables the alarm")
    ssa.add_argument("--cache-dir", default=os.environ.get("DOSUNIT_CACHE_DIR", ".cache/dosunit"))
    ssa.add_argument("--no-cache", action="store_true")
    _add_max_rss_argument(ssa)
    ssa.add_argument(
        "--follow-call-fallthrough",
        dest="follow_call_fallthrough",
        action="store_true",
        default=True,
        help="Also lower the direct fallthrough block after call blocks for ABI composition",
    )
    ssa.add_argument(
        "--no-follow-call-fallthrough",
        dest="follow_call_fallthrough",
        action="store_false",
        help="Stop each lowered SSA part at direct calls",
    )
    ssa.add_argument("--out", required=True)
    ssa.set_defaults(func=cmd_ssa)

    compare_ssa = subparsers.add_parser("compare-ssa", help="Compare compact SSA artifacts with Z3")
    compare_ssa.add_argument("--oracle-ssa", required=True)
    compare_ssa.add_argument("--candidate-ssa", required=True)
    compare_ssa.add_argument(
        "--oracle-index-ssa",
        help="Optional full oracle SSA document used only for call-target/function lookup during batched comparison",
    )
    compare_ssa.add_argument(
        "--candidate-index-ssa",
        help="Optional full candidate SSA document used only for call-target/function lookup during batched comparison",
    )
    compare_ssa.add_argument("--mapping")
    _add_max_rss_argument(compare_ssa)
    compare_ssa.add_argument(
        "--skip-unmapped",
        action="store_true",
        help="Do not emit refusals for mapped-oracle functions that have no candidate SSA",
    )
    compare_ssa.add_argument(
        "--solver-timeout-ms",
        type=int,
        default=DEFAULT_COMPARE_SOLVER_TIMEOUT_MS,
        help="Per-Z3-check timeout in milliseconds",
    )
    compare_ssa.add_argument(
        "--max-solver-assignments",
        type=int,
        default=DEFAULT_COMPARE_MAX_ASSIGNMENTS,
        help="Refuse a function before Z3 when either side has more SSA assignments; 0 disables the gate",
    )
    compare_ssa.add_argument(
        "--max-solver-inputs",
        type=int,
        default=DEFAULT_COMPARE_MAX_INPUTS,
        help="Refuse a function before Z3 when either side has more SSA inputs; 0 disables the gate",
    )
    compare_ssa.add_argument(
        "--max-solver-memory-stores",
        type=int,
        default=DEFAULT_COMPARE_MAX_MEMORY_STORES,
        help="Refuse a memory-output function before Z3 when either side has more store operations; 0 disables the gate",
    )
    compare_ssa.add_argument(
        "--semantic-proof-passes",
        type=int,
        default=DEFAULT_COMPARE_SEMANTIC_PROOF_PASSES,
        help="Retry call blocks this many passes while callee equality facts are discovered",
    )
    compare_ssa.add_argument(
        "--disable-callee-lemmas",
        action="store_true",
        help="Do not require/use proven callee equality facts for mapped/name-equivalent direct calls",
    )
    compare_ssa.add_argument(
        "--disable-region-equality", action="store_true", help="Disable composed acyclic function/region equality proof"
    )
    compare_ssa.add_argument("--disable-connectivity", action="store_true", help="Disable SSA block connectivity proof")
    compare_ssa.add_argument(
        "--max-region-loop-unroll",
        type=int,
        default=DEFAULT_COMPARE_REGION_LOOP_UNROLL,
        help="Bounded unroll count for raw region equality; 0 refuses loops",
    )
    compare_ssa.add_argument(
        "--no-skip-binary-equal",
        action="store_true",
        help="Run normal SSA/Z3 comparison even when function or block machine bytes are identical",
    )
    compare_ssa.add_argument("--out", required=True)
    compare_ssa.set_defaults(func=cmd_compare_ssa)

    compare_ssa_batched = subparsers.add_parser(
        "compare-ssa-batched",
        help="Compare compact SSA artifacts in sequential child processes to cap memory use",
    )
    compare_ssa_batched.add_argument("--oracle-ssa", required=True)
    compare_ssa_batched.add_argument("--candidate-ssa", required=True)
    compare_ssa_batched.add_argument("--oracle-index-ssa")
    compare_ssa_batched.add_argument("--candidate-index-ssa")
    compare_ssa_batched.add_argument("--mapping")
    compare_ssa_batched.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_COMPARE_BATCH_SIZE,
        help="Number of oracle SSA units per child compare process",
    )
    compare_ssa_batched.add_argument("--out-dir", required=True)
    compare_ssa_batched.add_argument("--out", required=True)
    compare_ssa_batched.set_defaults(keep_going=True)
    compare_ssa_batched.add_argument(
        "--keep-going",
        dest="keep_going",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Continue running later batches after a failed/refused/nonzero batch; this is the default",
    )
    compare_ssa_batched.add_argument(
        "--stop-on-failure",
        dest="keep_going",
        action="store_false",
        default=argparse.SUPPRESS,
        help="Stop after the first failed/refused/nonzero batch",
    )
    _add_max_rss_argument(compare_ssa_batched)
    compare_ssa_batched.add_argument("--skip-unmapped", action="store_true")
    compare_ssa_batched.add_argument(
        "--solver-timeout-ms",
        type=int,
        default=DEFAULT_COMPARE_SOLVER_TIMEOUT_MS,
        help="Per-Z3-check timeout forwarded to each child compare",
    )
    compare_ssa_batched.add_argument(
        "--batch-timeout-ms",
        type=int,
        default=DEFAULT_COMPARE_BATCH_TIMEOUT_MS,
        help="Kill one compare-ssa child batch after this many milliseconds; 0 disables the wall-clock gate",
    )
    compare_ssa_batched.add_argument(
        "--max-solver-assignments",
        type=int,
        default=DEFAULT_COMPARE_MAX_ASSIGNMENTS,
        help="Forwarded compare-ssa assignment-count solver gate; 0 disables",
    )
    compare_ssa_batched.add_argument(
        "--max-solver-inputs",
        type=int,
        default=DEFAULT_COMPARE_MAX_INPUTS,
        help="Forwarded compare-ssa symbolic-input solver gate; 0 disables",
    )
    compare_ssa_batched.add_argument(
        "--max-solver-memory-stores",
        type=int,
        default=DEFAULT_COMPARE_MAX_MEMORY_STORES,
        help="Forwarded compare-ssa modeled-memory-store solver gate; 0 disables",
    )
    compare_ssa_batched.add_argument(
        "--semantic-proof-passes",
        type=int,
        default=DEFAULT_COMPARE_SEMANTIC_PROOF_PASSES,
        help="Forwarded compare-ssa callee-proof retry pass count",
    )
    compare_ssa_batched.add_argument("--disable-callee-lemmas", action="store_true")
    compare_ssa_batched.add_argument("--disable-region-equality", action="store_true")
    compare_ssa_batched.add_argument("--disable-connectivity", action="store_true")
    compare_ssa_batched.add_argument(
        "--max-region-loop-unroll",
        type=int,
        default=DEFAULT_COMPARE_REGION_LOOP_UNROLL,
        help="Forwarded bounded region loop-unroll count",
    )
    compare_ssa_batched.add_argument("--no-skip-binary-equal", action="store_true")
    compare_ssa_batched.set_defaults(func=cmd_compare_ssa_batched)

    compare_ssa_abi = subparsers.add_parser(
        "compare-ssa-abi", help="Compare function-level ABI observables with composed SSA and Z3"
    )
    compare_ssa_abi.add_argument("--oracle-ssa", required=True)
    compare_ssa_abi.add_argument("--candidate-ssa", required=True)
    compare_ssa_abi.add_argument("--abi-manifest", required=True)
    compare_ssa_abi.add_argument("--mapping")
    _add_max_rss_argument(compare_ssa_abi)
    compare_ssa_abi.add_argument(
        "--solver-timeout-ms",
        type=int,
        default=DEFAULT_COMPARE_SOLVER_TIMEOUT_MS,
        help="Per-Z3-check timeout in milliseconds",
    )
    compare_ssa_abi.add_argument(
        "--max-solver-assignments",
        type=int,
        default=DEFAULT_COMPARE_MAX_ASSIGNMENTS,
        help="Assignment-count solver gate; 0 disables",
    )
    compare_ssa_abi.add_argument(
        "--max-solver-inputs",
        type=int,
        default=DEFAULT_COMPARE_MAX_INPUTS,
        help="Symbolic-input solver gate; 0 disables",
    )
    compare_ssa_abi.add_argument(
        "--max-solver-memory-stores",
        type=int,
        default=DEFAULT_COMPARE_MAX_MEMORY_STORES,
        help="Modeled-memory-store solver gate; 0 disables",
    )
    compare_ssa_abi.add_argument(
        "--max-loop-unroll",
        type=int,
        default=DEFAULT_COMPARE_REGION_LOOP_UNROLL,
        help="Bounded unroll count for repeated blocks before cutting loop paths; 0 refuses loops",
    )
    compare_ssa_abi.add_argument("--out", required=True)
    compare_ssa_abi.set_defaults(func=cmd_compare_ssa_abi)

    compare_regions = subparsers.add_parser("compare-regions", help="Compare region operand/effect artifacts")
    compare_regions.add_argument("--oracle-regions", required=True)
    compare_regions.add_argument("--candidate-regions", required=True)
    compare_regions.add_argument("--out", required=True)
    compare_regions.set_defaults(func=cmd_compare_regions)

    mapping = subparsers.add_parser("make-mapping", help="Build candidate mapping from function catalogs")
    mapping.add_argument("--oracle-functions", required=True)
    mapping.add_argument("--candidate-functions", required=True)
    mapping.add_argument("--mode", default="name", choices=["name"])
    mapping.add_argument("--out", required=True)
    mapping.set_defaults(func=cmd_make_mapping)

    selector = subparsers.add_parser("select-vectors", help="Select a bounded vector subset")
    selector.add_argument("--vectors", required=True)
    selector.add_argument("--function", action="append", default=[])
    selector.add_argument("--limit", type=int)
    selector.add_argument("--out", required=True)
    selector.set_defaults(func=cmd_select_vectors)

    record = subparsers.add_parser("record-oracle", help="Record oracle outputs")
    record.add_argument("--exe")
    record.add_argument("--vectors", required=True)
    record.add_argument("--functions")
    record.add_argument("--kvikdos")
    record.add_argument("--backend", default="fixture", choices=["fixture", "libkvikdos", "kvikdos"])
    record.add_argument("--out", required=True)
    record.set_defaults(func=cmd_record_oracle)

    compare = subparsers.add_parser("compare", help="Compare candidate outputs")
    compare.add_argument("--candidate")
    compare.add_argument("--vectors", required=True)
    compare.add_argument("--mapping")
    compare.add_argument("--functions")
    compare.add_argument("--kvikdos")
    compare.add_argument(
        "--ignore-field", action="append", choices=["status", "regs", "sregs", "flags", "memory", "return", "calls"]
    )
    compare.add_argument("--backend", default="fixture", choices=["fixture", "libkvikdos", "kvikdos"])
    compare.add_argument("--out", required=True)
    compare.set_defaults(func=cmd_compare)

    compare_data = subparsers.add_parser("compare-data", help="Compare loaded MZ data ranges")
    compare_data.add_argument("--oracle-exe", required=True)
    compare_data.add_argument("--candidate-exe", required=True)
    compare_data.add_argument("--oracle-functions", required=True)
    compare_data.add_argument("--candidate-functions", required=True)
    compare_data.add_argument("--range", action="append", required=True)
    compare_data.add_argument("--normalize-code-pointer", action="append")
    compare_data.add_argument("--oracle-load-base", default="0x0000")
    compare_data.add_argument("--candidate-load-base", default="0x0000")
    compare_data.add_argument("--out", required=True)
    compare_data.set_defaults(func=cmd_compare_data)

    summarize = subparsers.add_parser("summarize", help="Summarize result JSON")
    summarize.add_argument("--results", required=True)
    summarize.add_argument("--out")
    summarize.set_defaults(func=cmd_summarize)

    report = subparsers.add_parser("report-failures", help="Render a visible failure report from result JSON")
    report.add_argument("--results", required=True)
    report.add_argument("--limit", type=int, default=0, help="Maximum rows per section; 0 means all rows")
    report.add_argument("--mismatch-limit", type=int, default=8)
    report.add_argument(
        "--show-unresolved-call-targets",
        action="store_true",
        default=True,
        help="Include SSA failures caused by unresolved direct call targets",
    )
    report.add_argument(
        "--hide-unresolved-call-targets",
        dest="show_unresolved_call_targets",
        action="store_false",
        help="Hide SSA failures caused by unresolved direct call targets",
    )
    report.add_argument(
        "--failed-only", action="store_true", help="Show only results with status failed (hide refused rows)"
    )
    report.add_argument(
        "--group-by-function",
        action="store_true",
        help="Group SSA compare rows by function (deduplicates repeated block/region entries)",
    )
    report.add_argument("--out")
    report.set_defaults(func=cmd_report_failures)

    return parser


def main(argv: list[str] | None = None, *, prog: str = "dosunit") -> int:  # noqa: D103
    parser = build_parser(prog=prog)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except DosUnitError as ex:
        print(f"dosunit: {ex}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
