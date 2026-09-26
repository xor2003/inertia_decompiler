#!/usr/bin/env python3
"""Compare function-discovery backends without changing semantic ownership.

Layer: Tooling/gates.
Responsibility: compare optional discovery backends without turning sidecars or tool names into semantic proof.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.cli_function_discovery import (  # noqa: E402
    _recover_fast_exe_catalog,
    _recover_seeded_exe_functions,
)
from inertia_decompiler.project_loading import _build_project  # noqa: E402
from inertia_decompiler.rizin_discovery import discover_rizin_function_entries  # noqa: E402
from inertia_decompiler.sidecar_metadata import _load_lst_metadata  # noqa: E402


@dataclass(frozen=True)
class FunctionRecord:
    addr: int
    size: int | None
    name: str | None
    source: str


def _load_project(binary: Path, use_sidecar: bool, *, include_library_functions: bool) -> object:
    project = _build_project(binary, force_blob=False, base_addr=0x10000, entry_point=0x1000)
    # Dynamic angr boundary: discovery options are attached to Project for existing CLI helpers.
    project._inertia_include_library_functions = include_library_functions
    if use_sidecar:
        lst_metadata = _load_lst_metadata(
            binary,
            project,
            pat_backend=None,
            signature_catalog=None,
        )
        if lst_metadata is not None:
            # Dynamic angr boundary: sidecar metadata is consumed through project-scoped compatibility attrs.
            project._inertia_lst_metadata = lst_metadata
    return project


def _discovery_image_end(project: object) -> int:
    loader = getattr(project, "loader", None)
    main_object = getattr(loader, "main_object", None)
    if main_object is None:
        return 0
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if isinstance(linked_base, int) and isinstance(max_addr, int):
        return linked_base + max_addr + 1
    return 0


def _estimate_sizes(addrs: list[int], image_end: int) -> dict[int, int]:
    sorted_addrs = sorted({int(a) for a in addrs})
    out: dict[int, int] = {}
    for index, addr in enumerate(sorted_addrs):
        if index + 1 < len(sorted_addrs):
            out[addr] = max(0, sorted_addrs[index + 1] - addr)
        elif image_end:
            out[addr] = max(0, image_end - addr)
        else:
            out[addr] = 0
    return out


def _discover_angr(
    binary: Path,
    *,
    timeout_seconds: int,
    window: int,
    limit: int,
    angr_mode: str,
    include_library_functions: bool,
    use_sidecar: bool,
) -> tuple[list[FunctionRecord], float, str]:
    start = time.perf_counter()
    project = _load_project(
        binary,
        use_sidecar=use_sidecar,
        include_library_functions=include_library_functions,
    )
    limit_value = None if limit <= 0 else limit
    try:
        if angr_mode == "fast":
            recovered = _recover_fast_exe_catalog(
                project,
                timeout=timeout_seconds,
                window=window,
                low_memory=False,
                limit=limit_value,
            )
        else:
            recovered = cast(
                list[tuple[Any, Any]],
                _recover_seeded_exe_functions(
                    project,
                    timeout=timeout_seconds,
                    limit=limit_value,
                    region_span=0x120,
                    per_function_timeout=1,
                    return_addrs=False,
                    include_library_functions=include_library_functions,
                ),
            )
    except Exception as ex:
        return [], 0.0, f"failed: {ex}"
    elapsed = time.perf_counter() - start

    records: list[FunctionRecord] = []
    if angr_mode == "fast":
        for _cfg, func in recovered:
            addr = int(getattr(func, "addr", 0))
            size = getattr(func, "size", None)
            name = getattr(func, "name", None)
            if not isinstance(addr, int) or addr <= 0:
                continue
            if isinstance(size, int) and size < 0:
                size = None
            records.append(
                FunctionRecord(
                    addr=addr,
                    size=size if isinstance(size, int) else None,
                    name=str(name) if isinstance(name, str) else None,
                    source="angr_fast",
                )
            )
    else:
        for _cfg, func in recovered:
            addr = int(getattr(func, "addr", 0))
            size = getattr(func, "size", None)
            name = getattr(func, "name", None)
            if not isinstance(addr, int) or addr <= 0:
                continue
            if isinstance(size, int) and size < 0:
                size = None
            records.append(
                FunctionRecord(
                    addr=addr,
                    size=size if isinstance(size, int) else None,
                    name=str(name) if isinstance(name, str) else None,
                    source="angr",
                )
            )
    records.sort(key=lambda item: item.addr)
    return records, elapsed, "ok"


def _discover_rizin(binary: Path, *, timeout_seconds: int) -> tuple[list[FunctionRecord], float, str]:
    start = time.perf_counter()
    result = discover_rizin_function_entries(binary, timeout_sec=timeout_seconds)
    elapsed = time.perf_counter() - start
    if result.status.name != "OK":
        return [], elapsed, f"{result.status.value}: {result.detail}"

    records: list[FunctionRecord] = []
    for addr in result.offsets:
        records.append(
            FunctionRecord(
                addr=int(addr),
                size=None,
                name=None,
                source="rizin",
            )
        )

    return records, elapsed, result.detail or "ok"


def _has_local_sidecar_evidence(binary_path: Path, *, ignore_local_sidecar_evidence: bool = False) -> bool:
    if ignore_local_sidecar_evidence:
        return False
    stem = binary_path.stem
    parent = binary_path.parent
    if not parent.exists():
        return False
    sidecar_exts = {
        ".cod",
        ".lst",
        ".map",
        ".idc",
        ".inc",
        ".sym",
        ".dbg",
        ".tds",
        ".pdb",
    }
    for candidate in parent.glob(f"{stem}.*"):
        if candidate.resolve() == binary_path.resolve():
            continue
        if candidate.suffix.lower() in sidecar_exts:
            return True
    return False


def _rizin_available() -> bool:
    return shutil.which("rizin") is not None


def _annotate_sizes(records: list[FunctionRecord], project: object, default_size_source: str) -> list[FunctionRecord]:
    if not records:
        return records
    image_end = _discovery_image_end(project)
    estimated = _estimate_sizes([record.addr for record in records], image_end)
    out: list[FunctionRecord] = []
    for record in records:
        if record.size is None or record.size <= 0:
            out.append(
                FunctionRecord(
                    addr=record.addr,
                    size=estimated.get(record.addr, 0),
                    name=record.name,
                    source=f"{default_size_source}~estimated",
                )
            )
            continue
        out.append(record)
    return out


def _merge_hybrid(
    angr_records: list[FunctionRecord],
    rizin_records: list[FunctionRecord],
    *,
    project: object,
) -> list[FunctionRecord]:
    by_addr: dict[int, FunctionRecord] = {}
    for record in angr_records:
        by_addr[record.addr] = record
    for record in rizin_records:
        if record.addr not in by_addr:
            by_addr[record.addr] = record
        else:
            existing = by_addr[record.addr]
            if existing.size is None and record.size is not None:
                by_addr[record.addr] = FunctionRecord(
                    addr=record.addr,
                    size=record.size,
                    name=existing.name or record.name,
                    source="hybrid",
                )
    records = list(by_addr.values())
    records.sort(key=lambda item: item.addr)
    records = _annotate_sizes(records, project, default_size_source="hybrid")
    return records


def _unique_records(records: list[FunctionRecord]) -> list[FunctionRecord]:
    by_addr: dict[int, FunctionRecord] = {}
    for record in records:
        by_addr[record.addr] = record
    return [by_addr[key] for key in sorted(by_addr.keys())]


def _collect_addresses(records: list[FunctionRecord]) -> list[int]:
    return [record.addr for record in records]


def _collect_overlaps(records: list[FunctionRecord]) -> list[tuple[int, int]]:
    overlaps: list[tuple[int, int]] = []
    intervals: list[tuple[int, int, int]] = []
    for record in records:
        size = record.size if isinstance(record.size, int) and record.size >= 0 else 0
        if size == 0:
            size = 1
        end = record.addr + size
        intervals.append((record.addr, end, record.addr))
    intervals.sort()
    for i in range(1, len(intervals)):
        _prev_start, prev_end, prev_addr = intervals[i - 1]
        cur_start, _cur_end, cur_addr = intervals[i]
        if cur_start < prev_end:
            overlaps.append((prev_addr, cur_addr))
    return overlaps


def _compare_backends(
    records_by_backend: dict[str, list[FunctionRecord]],
) -> list[dict[str, object]]:
    names = sorted(records_by_backend.keys())
    out: list[dict[str, object]] = []
    for idx, left in enumerate(names):
        for right in names[idx + 1 :]:
            left_addrs = set(_collect_addresses(records_by_backend[left]))
            right_addrs = set(_collect_addresses(records_by_backend[right]))
            common = sorted(left_addrs & right_addrs)
            left_only = sorted(left_addrs - right_addrs)
            right_only = sorted(right_addrs - left_addrs)
            out.append(
                {
                    "left": left,
                    "right": right,
                    "intersection": [f"0x{addr:x}" for addr in common],
                    "left_only": [f"0x{addr:x}" for addr in left_only],
                    "right_only": [f"0x{addr:x}" for addr in right_only],
                }
            )
    return out


def _format_records(records: list[FunctionRecord]) -> list[dict[str, object]]:
    return [
        {"addr": f"0x{record.addr:x}", "size": record.size, "name": record.name, "source": record.source}
        for record in records
    ]


def _print_backend_result(
    name: str,
    records: list[FunctionRecord],
    duration: float,
    detail: str,
) -> None:
    print(f"[{name}] count={len(records)} time={duration:.3f}s detail={detail}")
    for record in records:
        size_text = str(record.size) if isinstance(record.size, int) else "?"
        addr_text = f"0x{record.addr:x}"
        print(f"  {addr_text:>10} size={size_text:>4} source={record.source} name={record.name or '-'}")


def _run_compare(
    binary: Path,
    args: argparse.Namespace,
    *,
    backend_override: str | None = None,
) -> dict[str, Any]:
    project = _load_project(
        binary,
        use_sidecar=args.use_sidecar,
        include_library_functions=args.include_library_functions,
    )
    outputs: dict[str, Any] = {"binary": str(binary)}
    results: dict[str, list[FunctionRecord]] = {}
    metrics: dict[str, dict[str, Any]] = {}

    backend = (backend_override or str(args.backends)).strip().lower()
    run_angr = backend in {"angr", "hybrid", "all"}
    run_rizin = backend in {"rizin", "hybrid", "all"}

    if run_angr:
        records, elapsed, detail = _discover_angr(
            binary,
            timeout_seconds=args.angr_timeout,
            window=args.angr_window,
            limit=args.limit,
            angr_mode=args.angr_mode,
            include_library_functions=args.include_library_functions,
            use_sidecar=args.use_sidecar,
        )
        records = _unique_records(records)
        records = _annotate_sizes(records, project, default_size_source="angr")
        results["angr"] = records
        metrics["angr"] = {"time_sec": elapsed, "detail": detail}

    if run_rizin:
        records, elapsed, detail = _discover_rizin(binary, timeout_seconds=args.rizin_timeout)
        records = _annotate_sizes(records, project, default_size_source="rizin")
        results["rizin"] = _unique_records(records)
        metrics["rizin"] = {"time_sec": elapsed, "detail": detail}

    if backend == "hybrid":
        results["hybrid"] = _merge_hybrid(
            results.get("angr", []),
            results.get("rizin", []),
            project=project,
        )
        metrics["hybrid"] = {
            "time_sec": metrics.get("angr", {}).get("time_sec", 0.0) + metrics.get("rizin", {}).get("time_sec", 0.0),
            "detail": "hybrid merged angr+rizin",
        }

    outputs["backends"] = {}
    for backend_name, entries in results.items():
        outputs["backends"][backend_name] = {
            "records": _format_records(entries),
            "metric": metrics.get(backend_name, {}),
            "count": len(entries),
            "overlaps": [[f"0x{a:x}", f"0x{b:x}"] for a, b in _collect_overlaps(entries)],
        }

    if len(results) > 1:
        outputs["comparisons"] = _compare_backends(results)
    else:
        outputs["comparisons"] = []

    return outputs


def _parse_binary_list(value: str) -> list[Path]:
    paths: list[Path] = []
    for token in value.split(","):
        candidate = Path(token.strip())
        if not candidate.is_absolute():
            candidate = REPO_ROOT / candidate
        if candidate.exists():
            paths.append(candidate)
    if not paths:
        raise ValueError(f"no valid binaries: {value!r}")
    return paths


def _select_backend_8616(args: argparse.Namespace, binary: Path) -> str:
    """Return the backend selected for one binary under the CLI policy."""
    selected_backend = args.backends
    if selected_backend == "auto":
        selected_backend = (
            "rizin"
            if (
                _rizin_available()
                and not _has_local_sidecar_evidence(
                    binary,
                    ignore_local_sidecar_evidence=args.ignore_local_sidecar_evidence,
                )
            )
            else "angr"
        )
        if args.use_sidecar:
            selected_backend = "angr"
    return str(selected_backend)


def _print_interval_summary_8616(run: dict[str, Any]) -> None:
    """Print the address/size overlap summary for one binary run."""
    print(f"\n{run['binary']}")
    for backend_name, payload in run["backends"].items():
        metric = payload["metric"]
        print(f"  {backend_name}: count={payload['count']} time={metric.get('time_sec', 0.0):.3f}s")
        overlaps = payload["overlaps"]
        if overlaps:
            print(f"    overlaps: {len(overlaps)}")
            for pair in overlaps:
                print(f"      {pair[0]} -> {pair[1]}")
        else:
            print("    overlaps: none")

    for comparison in run["comparisons"]:
        left = comparison["left"]
        right = comparison["right"]
        print(
            f"  compare {left} vs {right}: "
            f"+{len(comparison['left_only'])} {left} only, "
            f"+{len(comparison['right_only'])} {right} only"
        )


def _print_full_result_8616(run: dict[str, Any]) -> None:
    """Print the full per-backend function inventory for one binary run."""
    print(f"\n{run['binary']}")
    for backend_name, payload in run["backends"].items():
        _print_backend_result(
            backend_name,
            [
                FunctionRecord(int(entry["addr"], 16), entry["size"], entry["name"], entry["source"])
                for entry in payload["records"]
            ],
            payload["metric"].get("time_sec", 0.0),
            payload["metric"].get("detail", ""),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binaries",
        help="Comma-separated list of binaries to compare.",
    )
    parser.add_argument(
        "--backends",
        choices=("angr", "rizin", "hybrid", "all", "auto"),
        default="auto",
        help="Backends to run.",
    )
    parser.add_argument(
        "--angr-timeout",
        type=int,
        default=20,
        help="Timeout in seconds for angr seeded recovery.",
    )
    parser.add_argument(
        "--angr-mode",
        choices=("fast", "seeded"),
        default="fast",
        help="angr discovery mode: fast (catalog preview) or seeded (seeded candidate recovery).",
    )
    parser.add_argument(
        "--angr-window",
        type=int,
        default=0x200,
        help="CFG recovery window for angr fast discovery mode (default: 0x200).",
    )
    parser.add_argument(
        "--rizin-timeout",
        type=int,
        default=8,
        help="Timeout in seconds for rizin discovery.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional max function count for seeded recovery (0 = no limit).",
    )
    parser.add_argument(
        "--include-library-functions",
        action="store_true",
        help="Include library-like functions in comparison.",
    )
    parser.add_argument(
        "--use-sidecar",
        action="store_true",
        help="Use local sidecar metadata for angr discovery.",
    )
    parser.add_argument(
        "--ignore-local-sidecar-evidence",
        action="store_true",
        help="Ignore local sidecar files when auto-selecting backends.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=None,
        help="Optional JSON output path.",
    )
    parser.add_argument(
        "--print-interval-summary",
        action="store_true",
        help="Print address/size overlap summary lines only.",
    )
    args = parser.parse_args()

    binaries = _parse_binary_list(args.binaries)
    results: list[dict[str, Any]] = [
        _run_compare(binary, args, backend_override=_select_backend_8616(args, binary))
        for binary in binaries
    ]

    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(results, indent=2), encoding="utf-8")

    if args.print_interval_summary:
        for run in results:
            _print_interval_summary_8616(run)
    else:
        for run in results:
            _print_full_result_8616(run)


if __name__ == "__main__":
    main()
