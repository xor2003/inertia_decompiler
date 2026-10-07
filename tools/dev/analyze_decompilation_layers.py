#!/usr/bin/env python3
"""Summarize layer-dump manifests produced by `decompile.py --dump-layers`.

Layer: Tooling/gates.
Responsibility: summarize diagnostic layer dumps without owning decompiler semantics.

Examples:

    ./scripts/analyze_decompilation_layers.py
    ./scripts/analyze_decompilation_layers.py --root .cache/frontend/decompilation_layers --only-failures
    ./scripts/analyze_decompilation_layers.py --json
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class LayerDumpSummary:
    """Summary of one function layer-dump manifest."""

    function_addr: str
    function_name: str
    attempt: int
    root: Path
    total_entries: int
    written: int
    skipped: int
    failed: int
    errors: list[str]
    stages: list[tuple[int, str, str, int, str]]


def _safe_int(value: str | int | None) -> int:
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def _collect_run(manifest: Path) -> LayerDumpSummary | None:
    entries = []
    with manifest.open("r", encoding="utf-8") as stream:
        for raw in stream:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entries.append(json.loads(raw))
            except Exception:
                continue

    if not entries:
        return None

    first = entries[0]
    function_addr = f"{int(first.get('function_addr', 0)):#x}"
    function_name = str(first.get("function_name", ""))
    attempt = _safe_int(first.get("attempt", 0))
    if not attempt:
        match = re.search(r"_(\d{2})$", manifest.parent.name)
        if match is not None:
            attempt = _safe_int(match.group(1))
    root = manifest.parent

    written = sum(1 for entry in entries if entry.get("status") == "written")
    skipped = sum(1 for entry in entries if entry.get("status") == "skipped")
    failed = sum(1 for entry in entries if entry.get("status") == "failed")
    errors = [
        f"{entry.get('layer', '?')}: {entry.get('error', '')}"
        for entry in entries
        if entry.get("status") == "failed" and entry.get("error")
    ]

    stages = []
    for entry in entries:
        index = _safe_int(entry.get("index", 0))
        layer = str(entry.get("layer", ""))
        status = str(entry.get("status", ""))
        path = str(entry.get("path", ""))
        bytes_count = _safe_int(entry.get("bytes", 0))
        stages.append((index, layer, status, bytes_count, path))

    stages.sort(key=lambda item: item[0])

    return LayerDumpSummary(
        function_addr=function_addr,
        function_name=function_name,
        attempt=attempt,
        root=root,
        total_entries=len(entries),
        written=written,
        skipped=skipped,
        failed=failed,
        errors=errors,
        stages=stages,
    )


def _iter_manifests(root: Path) -> tuple[Path, ...]:
    if not root.exists():
        return ()
    return tuple(root.rglob("manifest.jsonl"))


def _matches_name_filter(fn_name: str, filter_text: str | None) -> bool:
    if not filter_text:
        return True
    try:
        matcher = re.compile(filter_text)
    except re.error:
        return filter_text in fn_name
    return matcher.search(fn_name) is not None


def _print_text_summary(summaries: list[LayerDumpSummary], only_failures: bool, show_layers: bool) -> int:
    failure_count = 0
    for summary in summaries:
        has_failure = summary.failed > 0
        if only_failures and not has_failure:
            continue

        status = "FAIL" if has_failure else "OK"
        print(
            f"{status:4} {summary.function_addr:>10} {summary.function_name:<24}"
            f"attempt={summary.attempt:02d} wrote={summary.written:02d} skip={summary.skipped:02d}"
            f" fail={summary.failed:02d} root={summary.root}"
        )
        if has_failure:
            failure_count += 1
        if summary.errors:
            for error in summary.errors:
                print(f"  error: {error}")

        if show_layers:
            for index, layer, layer_status, bytes_count, path in summary.stages:
                print(f"  {index:04d} {layer_status:7} {layer:<35} {bytes_count:4} {path}")

    return failure_count


def _print_json(summaries: list[LayerDumpSummary], only_failures: bool) -> int:
    payload = []
    for summary in summaries:
        if only_failures and summary.failed == 0:
            continue
        payload.append(
            {
                "function_addr": summary.function_addr,
                "function_name": summary.function_name,
                "attempt": summary.attempt,
                "root": str(summary.root),
                "total_entries": summary.total_entries,
                "written": summary.written,
                "skipped": summary.skipped,
                "failed": summary.failed,
                "errors": summary.errors,
                "stages": [
                    {
                        "index": stage[0],
                        "layer": stage[1],
                        "status": stage[2],
                        "bytes": stage[3],
                        "path": stage[4],
                    }
                    for stage in summary.stages
                ],
            }
        )
    print(json.dumps(payload, sort_keys=True, indent=2))
    return sum(
        isinstance(failed := summary.get("failed"), int) and failed > 0
        for summary in payload
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze decompilation layer dump manifests")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(".cache/frontend/decompilation_layers"),
        help="Root directory with dump attempts and manifest.jsonl files.",
    )
    parser.add_argument(
        "--only-failures",
        action="store_true",
        help="Show only dumps that contain failed layer snapshots.",
    )
    parser.add_argument(
        "--show-layers",
        action="store_true",
        help="Show per-layer entries in text output.",
    )
    parser.add_argument(
        "--function-filter",
        default=None,
        help="Regex fragment to match function names from manifest.function_name.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary instead of human-readable text.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Analyze layer-dump manifests and return nonzero when failures are present."""
    args = _build_parser().parse_args(argv)
    manifests = _iter_manifests(args.root)

    summaries: list[LayerDumpSummary] = []
    for manifest in manifests:
        summary = _collect_run(manifest)
        if summary is None:
            continue
        if not _matches_name_filter(summary.function_name, args.function_filter):
            continue
        summaries.append(summary)

    summaries.sort(key=lambda s: (s.function_addr, s.attempt, s.function_name))

    if not summaries:
        print(f"[layer-analyzer] no manifests found under {args.root}")
        return 0

    if args.json:
        failures = _print_json(summaries, args.only_failures)
    else:
        failures = _print_text_summary(summaries, args.only_failures, args.show_layers)

    if failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
