#!/usr/bin/env python3
"""Run dosunit SSA/Z3 comparison for rebuilt MS C tiny examples.

Layer: Tooling/gates.
Responsibility: compare rebuilt MS C examples through bounded SSA ABI equivalence gates.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
DEFAULT_REPORT: Path = REPO_ROOT / "examples" / "build_msc6" / "report.json"
DEFAULT_OUT_DIR: Path = REPO_ROOT / "examples" / "build_msc6" / "ssa_compare"
DEFAULT_KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC6_ROOT: Path = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")


def _run(
    cmd: list[str],
    *,
    cwd: Path = REPO_ROOT,
    check: bool = False,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def _ensure_msvc6_compat_headers(out_dir: Path) -> None:
    """Use the shared target-compatible headers for standalone SSA runs."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from scripts.msc6_compat_headers import write_msc6_compat_headers

    write_msc6_compat_headers(out_dir)


def _load_report(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain the build_msc6 report list")
    return [item for item in data if isinstance(item, dict)]


def _selected_examples(report: list[dict[str, Any]], only: set[str]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for item in report:
        name = str(item.get("name", ""))
        if only and name not in only:
            continue
        exe = Path(str(item.get("exe", "")))
        rebuilt = Path(str(item.get("decompile_recompiled_exe", "")))
        if not item.get("build_ok") or not item.get("run_ok"):
            continue
        if not item.get("decompile_ok") or not item.get("decompile_recompile_ok") or not item.get("decompile_run_ok"):
            continue
        if not exe.exists() or not rebuilt.exists():
            continue
        if exe.resolve() == rebuilt.resolve():
            continue
        selected.append(item)
    return selected


def _dos_name(path: Path) -> str:
    name = path.name.upper()
    if len(path.stem) > 8:
        raise ValueError(f"{path} is not DOS 8.3 compatible")
    return name


def _ensure_rebuilt_cod(
    item: dict[str, Any],
    *,
    kvikdos: Path,
    msc6_root: Path,
) -> tuple[Path | None, dict[str, Any] | None]:
    source_value = item.get("decompile_stdout_path")
    source = Path(str(source_value)) if source_value else None
    rebuilt = Path(str(item.get("decompile_recompiled_exe", "")))
    if source is None or not source.exists() or not rebuilt.exists():
        return None, {"status": "skipped", "reason": "missing_rebuilt_source_or_exe"}
    cod_path = rebuilt.with_suffix(".COD")
    if cod_path.exists():
        return cod_path, None
    out_dir = source.parent
    _ensure_msvc6_compat_headers(out_dir)
    tmp_obj = "SSACOD.OBJ"
    with contextlib.suppress(OSError):
        (out_dir / tmp_obj).unlink()
    cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc6_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--path-dos=e:\\BIN",
        "--env=INCLUDE=E:\\INCLUDE",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\CL.EXE",
        "e:\\BIN\\CL.EXE",
        "/Ic:\\",
        "/nologo",
        "/Od",
        "/c",
        f"/Foc:\\{tmp_obj}",
        f"/Fcc:\\{_dos_name(cod_path)}",
        f"c:\\{_dos_name(source)}",
    ]
    proc = _run(cmd)
    with contextlib.suppress(OSError):
        (out_dir / tmp_obj).unlink()
    if proc.returncode != 0 or not cod_path.exists():
        return None, {
            "status": "failed",
            "reason": "cod_compile_failed",
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    return cod_path, None


def _dosunit_cmd(*args: str) -> list[str]:
    return [sys.executable, str(REPO_ROOT / "dosunit.py"), *args]


def _is_msc_prologue_call_part(part: dict[str, Any]) -> bool:
    part_meta = part.get("part", {}) if isinstance(part.get("part"), dict) else {}
    if str(part_meta.get("entry_delta") or "").lower() not in {"0x0000", "0x0", "0"}:
        return False
    source = part.get("source", {}) if isinstance(part.get("source"), dict) else {}
    if source.get("jumpkind") != "Ijk_Call":
        return False
    instructions = source.get("instructions", []) if isinstance(source.get("instructions"), list) else []
    first_four = [item for item in instructions[:4] if isinstance(item, dict)]
    if [str(item.get("mnemonic") or "").lower() for item in first_four] != ["push", "mov", "mov", "call"]:
        return False
    return str(first_four[2].get("op_str") or "").lower().replace(" ", "").startswith("ax,")


def _ssa_parts_by_name_8616(document: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Group SSA document parts by their declared function name."""
    parts_by_name: dict[str, list[dict[str, Any]]] = {}
    for part in document.get("functions", []) or []:
        if not isinstance(part, dict):
            continue
        function = part.get("function", {}) if isinstance(part.get("function"), dict) else {}
        name = str(function.get("name") or "")
        if name:
            parts_by_name.setdefault(name, []).append(part)
    return parts_by_name


def _part_entry_linears_8616(parts: list[dict[str, Any]]) -> set[int]:
    """Return the hex entry-linears of one function's SSA parts."""
    return {
        int(str((part.get("entry", {}) if isinstance(part.get("entry"), dict) else {}).get("linear")), 0)
        for part in parts
        if str(
            (part.get("entry", {}) if isinstance(part.get("entry"), dict) else {}).get("linear") or ""
        ).startswith("0x")
    }


def _part_backedge_8616(
    source: dict[str, Any],
    entry_linears: set[int],
    current_linear: int,
) -> bool:
    """Return whether one part's last instruction is a backward jump edge."""
    instructions = source.get("instructions", []) if isinstance(source.get("instructions"), list) else []
    if not instructions:
        return False
    last = instructions[-1] if isinstance(instructions[-1], dict) else {}
    mnemonic = str(last.get("mnemonic") or "").lower()
    if not mnemonic.startswith("j"):
        return False
    op_str = str(last.get("op_str") or "")
    target_text = op_str.split(",", 1)[0].strip()
    if not target_text.startswith("0x"):
        return False
    try:
        target = int(target_text, 0)
    except ValueError:
        return False
    return target in entry_linears and target <= current_linear


def _accumulate_part_stats_8616(
    item: dict[str, Any],
    part: dict[str, Any],
    entry_linears: set[int],
) -> None:
    """Accumulate parts/calls/backedges counters for one SSA part."""
    item["parts"] += 1
    source = part.get("source", {}) if isinstance(part.get("source"), dict) else {}
    if source.get("jumpkind") == "Ijk_Call" and not _is_msc_prologue_call_part(part):
        item["non_prologue_calls"] += 1
    entry = part.get("entry", {}) if isinstance(part.get("entry"), dict) else {}
    try:
        current_linear = int(str(entry.get("linear")), 0)
    except ValueError:
        return
    if _part_backedge_8616(source, entry_linears, current_linear):
        item["backedges"] += 1


def _ssa_function_stats(ssa_path: Path) -> dict[str, dict[str, Any]]:
    document = json.loads(ssa_path.read_text(encoding="utf-8"))
    parts_by_name = _ssa_parts_by_name_8616(document)

    stats: dict[str, dict[str, Any]] = {}
    for name, parts in parts_by_name.items():
        entry_linears = _part_entry_linears_8616(parts)
        item = stats.setdefault(name, {"parts": 0, "non_prologue_calls": 0, "backedges": 0})
        for part in parts:
            _accumulate_part_stats_8616(item, part, entry_linears)
    return stats


def _matching_stats_name(stats: dict[str, dict[str, Any]], name: str) -> str | None:
    if name in stats:
        return name
    normalized = name.lstrip("_")
    for candidate in (f"_{normalized}", f"__{normalized}", normalized):
        if candidate in stats:
            return candidate
    for candidate in sorted(stats):
        if candidate.lstrip("_") == normalized:
            return candidate
    return None


def _write_abi_manifest(
    functions_path: Path,
    oracle_ssa_path: Path,
    candidate_ssa_path: Path,
    out_path: Path,
    *,
    max_parts: int,
    max_loop_unroll: int,
    abi_reg_profile: str,
) -> None:
    catalog = json.loads(functions_path.read_text(encoding="utf-8"))
    oracle_stats = _ssa_function_stats(oracle_ssa_path)
    candidate_stats = _ssa_function_stats(candidate_ssa_path)
    functions: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    for function in catalog.get("functions", []) or []:
        if not isinstance(function, dict):
            continue
        abi_entry, skip_entry = _manifest_function_8616(
            function,
            oracle_stats,
            candidate_stats,
            max_parts=max_parts,
            max_loop_unroll=max_loop_unroll,
            abi_reg_profile=abi_reg_profile,
        )
        if skip_entry is not None:
            skipped.append(skip_entry)
        if abi_entry is not None:
            functions.append(abi_entry)
    manifest = {
        "schema": "msc6.ssa_abi_manifest.v1",
        "calling_convention": "msc16-near",
        "functions": functions,
        "skipped_functions": skipped,
    }
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _manifest_function_8616(
    function: dict[str, Any],
    oracle_stats: dict[str, dict[str, Any]],
    candidate_stats: dict[str, dict[str, Any]],
    *,
    max_parts: int,
    max_loop_unroll: int,
    abi_reg_profile: str,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Apply the ABI manifest gates to one function; return (entry, skip)."""
    names = function.get("names", [])
    name = str(names[0]) if isinstance(names, list) and names else ""
    if not name:
        return None, None
    if name == "main":
        return None, {"name": name, "reason": "harness_main"}
    oracle_name = _matching_stats_name(oracle_stats, name)
    candidate_name = _matching_stats_name(candidate_stats, name)
    oracle_count = int(oracle_stats.get(oracle_name or "", {}).get("parts", 0))
    candidate_count = int(candidate_stats.get(candidate_name or "", {}).get("parts", 0))
    if oracle_count == 0 or candidate_count == 0:
        return None, {
            "name": name,
            "reason": "ssa_missing",
            "oracle_parts": oracle_count,
            "candidate_parts": candidate_count,
        }
    oracle_calls = int(oracle_stats.get(oracle_name or "", {}).get("non_prologue_calls", 0))
    candidate_calls = int(candidate_stats.get(candidate_name or "", {}).get("non_prologue_calls", 0))
    if oracle_calls or candidate_calls:
        return None, {
            "name": name,
            "reason": "call_boundary_gate",
            "oracle_non_prologue_calls": oracle_calls,
            "candidate_non_prologue_calls": candidate_calls,
        }
    oracle_backedges = int(oracle_stats.get(oracle_name or "", {}).get("backedges", 0))
    candidate_backedges = int(candidate_stats.get(candidate_name or "", {}).get("backedges", 0))
    if max_loop_unroll <= 0 and (oracle_backedges or candidate_backedges):
        return None, {
            "name": name,
            "reason": "loop_backedge_gate",
            "oracle_backedges": oracle_backedges,
            "candidate_backedges": candidate_backedges,
        }
    if max_parts and max(oracle_count, candidate_count) > max_parts:
        return None, {
            "name": name,
            "reason": "part_count_gate",
            "oracle_parts": oracle_count,
            "candidate_parts": candidate_count,
            "max_parts": max_parts,
        }
    return _abi_manifest_entry_8616(function, name, oracle_name, candidate_name, abi_reg_profile), None


def _abi_manifest_entry_8616(
    function: dict[str, Any],
    name: str,
    oracle_name: str | None,
    candidate_name: str | None,
    abi_reg_profile: str,
) -> dict[str, object]:
    """Return one ABI manifest entry for a gate-passing function."""
    strict_abi = abi_reg_profile == "strict"
    abi_entry: dict[str, object] = {
        "id": function.get("id"),
        "name": name,
        "kind": function.get("return_kind", "near"),
        "calling_convention": "msc16-near",
        "returns": [{"location": "ax"}, {"location": "dx"}] if strict_abi else [{"location": "ax"}],
        "preserved": ["bp", "si", "di"] if strict_abi else [],
        "clobbers": ["ax", "cx", "dx", "flags"],
        "ssa_call_policy": "msc_prologue_stack_check",
    }
    if oracle_name and oracle_name != name:
        abi_entry["oracle_name"] = oracle_name
    if candidate_name and candidate_name != name:
        abi_entry["candidate_name"] = candidate_name
    return abi_entry




def _ssa_lowering_args(args: argparse.Namespace) -> list[str]:
    default_output_regs = (
        ["ax", "dx", "sp", "ip", "bp", "si", "di", "ss"]
        if args.abi_reg_profile == "strict"
        else ["ax", "sp", "ip", "bp", "ss"]
    )
    output_regs = args.output_reg or default_output_regs
    result: list[str] = []
    for reg in output_regs:
        result.extend(["--output-reg", reg])
    return result


def _compare_process_timeout_seconds(args: argparse.Namespace) -> float:
    solver_guard = max(5.0, (float(args.solver_timeout_ms) / 1000.0) + 15.0)
    if args.compare_process_timeout_seconds > 0:
        return max(float(args.compare_process_timeout_seconds), solver_guard)
    return solver_guard


def _timeout_result(function: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    return {
        "function": {
            "name": function.get("name"),
            "kind": function.get("kind"),
            "calling_convention": function.get("calling_convention"),
            "inputs": function.get("inputs", []),
            "stack_args": function.get("stack_args", []),
            "returns": function.get("returns", []),
            "preserved": function.get("preserved", []),
            "clobbers": function.get("clobbers", []),
            "effects": function.get("effects", []),
        },
        "mapped_candidate": None,
        "observables": {"regs": [], "memory": []},
        "status": "refused",
        "reason": "compare_process_timeout",
        "mismatches": [
            {
                "kind": "compare_process_timeout",
                "detail": f"compare-ssa-abi process exceeded {timeout_seconds:.1f}s",
            }
        ],
    }


def _failed_compare_result(function: dict[str, Any], proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "function": {"name": function.get("name"), "kind": function.get("kind")},
        "mapped_candidate": None,
        "observables": {"regs": [], "memory": []},
        "status": "refused",
        "reason": "compare_process_failed",
        "mismatches": [
            {
                "kind": "compare_process_failed",
                "returncode": proc.returncode,
                "stdout": proc.stdout[-4000:],
                "stderr": proc.stderr[-4000:],
            }
        ],
    }


def _write_combined_compare(
    *,
    oracle_ssa_path: Path,
    candidate_ssa_path: Path,
    mapping_path: Path,
    abi_manifest_path: Path,
    compare_path: Path,
    results: list[dict[str, Any]],
    solver_time_ms: int,
    args: argparse.Namespace,
) -> None:
    oracle = json.loads(oracle_ssa_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_ssa_path.read_text(encoding="utf-8"))
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    manifest = json.loads(abi_manifest_path.read_text(encoding="utf-8"))
    summary = {
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "solver_time_ms": solver_time_ms,
    }
    document = {
        "schema": "dosunit.ssa_abi_compare.v1",
        "oracle": oracle.get("exe"),
        "candidate": candidate.get("exe"),
        "mapping": mapping.get("id"),
        "abi_manifest": manifest.get("schema"),
        "data_segment_para": "0x0100",
        "solver_gates": {
            "max_solver_assignments": args.max_solver_assignments,
            "max_solver_inputs": args.max_solver_inputs,
            "max_solver_memory_stores": args.max_solver_memory_stores,
            "max_loop_unroll": args.max_loop_unroll,
            "compare_process_timeout_seconds": _compare_process_timeout_seconds(args),
        },
        "skipped_functions": manifest.get("skipped_functions", []),
        "summary": summary,
        "results": results,
    }
    compare_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_abi_compare_per_function(paths: dict[str, Path], args: argparse.Namespace) -> tuple[int, str, str]:
    manifest = json.loads(paths["abi_manifest"].read_text(encoding="utf-8"))
    functions = [item for item in manifest.get("functions", []) or [] if isinstance(item, dict)]
    timeout_seconds = _compare_process_timeout_seconds(args)
    results: list[dict[str, Any]] = []
    solver_time_ms = 0
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    for index, function in enumerate(functions):
        single_manifest = dict(manifest)
        single_manifest["functions"] = [function]
        single_manifest["skipped_functions"] = []
        safe_name = "".join(
            ch if ch.isalnum() or ch in "._-" else "_" for ch in str(function.get("name") or f"function_{index}")
        )
        single_manifest_path = paths["abi_manifest"].with_name(f"abi.{index:03d}.{safe_name}.json")
        single_compare_path = paths["compare"].with_name(f"compare.{index:03d}.{safe_name}.json")
        single_manifest_path.write_text(json.dumps(single_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        cmd = _dosunit_cmd(
            "compare-ssa-abi",
            "--oracle-ssa",
            str(paths["oracle_ssa"]),
            "--candidate-ssa",
            str(paths["candidate_ssa"]),
            "--abi-manifest",
            str(single_manifest_path),
            "--mapping",
            str(paths["mapping"]),
            "--solver-timeout-ms",
            str(args.solver_timeout_ms),
            "--max-solver-assignments",
            str(args.max_solver_assignments),
            "--max-solver-inputs",
            str(args.max_solver_inputs),
            "--max-solver-memory-stores",
            str(args.max_solver_memory_stores),
            "--max-loop-unroll",
            str(args.max_loop_unroll),
            "--out",
            str(single_compare_path),
        )
        try:
            proc = _run(cmd, timeout=timeout_seconds)
        except subprocess.TimeoutExpired as ex:
            stdout_parts.append((ex.stdout or "") if isinstance(ex.stdout, str) else "")
            stderr_parts.append((ex.stderr or "") if isinstance(ex.stderr, str) else "")
            results.append(_timeout_result(function, timeout_seconds))
            continue
        stdout_parts.append(proc.stdout)
        stderr_parts.append(proc.stderr)
        if not single_compare_path.exists():
            results.append(_failed_compare_result(function, proc))
            continue
        document = json.loads(single_compare_path.read_text(encoding="utf-8"))
        solver_time_ms += int(
            (document.get("summary", {}) if isinstance(document, dict) else {}).get("solver_time_ms", 0) or 0
        )
        doc_results = document.get("results", []) if isinstance(document, dict) else []
        if isinstance(doc_results, list) and doc_results:
            results.extend(item for item in doc_results if isinstance(item, dict))
        elif proc.returncode != 0:
            results.append(_failed_compare_result(function, proc))
    _write_combined_compare(
        oracle_ssa_path=paths["oracle_ssa"],
        candidate_ssa_path=paths["candidate_ssa"],
        mapping_path=paths["mapping"],
        abi_manifest_path=paths["abi_manifest"],
        compare_path=paths["compare"],
        results=results,
        solver_time_ms=solver_time_ms,
        args=args,
    )
    failed_or_refused = any(result.get("status") in {"failed", "refused"} for result in results)
    return (1 if failed_or_refused else 0), "".join(stdout_parts), "".join(stderr_parts)


def _run_example(item: dict[str, Any], *, args: argparse.Namespace, out_root: Path) -> dict[str, Any]:
    name = str(item["name"])
    example_dir = out_root / name
    example_dir.mkdir(parents=True, exist_ok=True)

    oracle_exe = Path(str(item["exe"]))
    oracle_map = Path(str(item["map"]))
    oracle_cod = Path(str(item["cod"]))
    candidate_exe = Path(str(item["decompile_recompiled_exe"]))
    candidate_map = Path(str(item["decompile_recompiled_map"]))
    candidate_cod, cod_error = _ensure_rebuilt_cod(item, kvikdos=args.kvikdos, msc6_root=args.msc6_root)
    if cod_error is not None or candidate_cod is None:
        return {"name": name, "status": "failed", "stage": "ensure_rebuilt_cod", "error": cod_error}

    paths = {
        "oracle_functions": example_dir / "oracle.functions.json",
        "candidate_functions": example_dir / "candidate.functions.json",
        "mapping": example_dir / "mapping.json",
        "oracle_ssa": example_dir / "oracle.ssa.json",
        "candidate_ssa": example_dir / "candidate.ssa.json",
        "abi_manifest": example_dir / "abi.manifest.json",
        "compare": example_dir / "compare.ssa.json",
        "report": example_dir / "failures.md",
    }
    commands = [
        _dosunit_cmd(
            "discover",
            "--exe",
            str(oracle_exe),
            "--map",
            str(oracle_map),
            "--cod-listing",
            str(oracle_cod),
            "--module",
            oracle_exe.name,
            "--out",
            str(paths["oracle_functions"]),
        ),
        _dosunit_cmd(
            "discover",
            "--exe",
            str(candidate_exe),
            "--map",
            str(candidate_map),
            "--cod-listing",
            str(candidate_cod),
            "--module",
            candidate_exe.name,
            "--out",
            str(paths["candidate_functions"]),
        ),
        _dosunit_cmd(
            "make-mapping",
            "--oracle-functions",
            str(paths["oracle_functions"]),
            "--candidate-functions",
            str(paths["candidate_functions"]),
            "--mode",
            "name",
            "--out",
            str(paths["mapping"]),
        ),
        [
            *_dosunit_cmd(
                "ssa",
                "--exe",
                str(oracle_exe),
                "--functions",
                str(paths["oracle_functions"]),
                "--ir",
                args.ir,
                "--max-blocks-per-function",
                str(args.max_blocks_per_function),
                "--max-insns-per-function",
                str(args.max_insns_per_function),
                "--max-ssa-assignments",
                str(args.max_ssa_assignments),
                "--scan-limit",
                hex(args.scan_limit),
                "--follow-call-fallthrough",
                "--out",
                str(paths["oracle_ssa"]),
            ),
            *_ssa_lowering_args(args),
        ],
        [
            *_dosunit_cmd(
                "ssa",
                "--exe",
                str(candidate_exe),
                "--functions",
                str(paths["candidate_functions"]),
                "--ir",
                args.ir,
                "--max-blocks-per-function",
                str(args.max_blocks_per_function),
                "--max-insns-per-function",
                str(args.max_insns_per_function),
                "--max-ssa-assignments",
                str(args.max_ssa_assignments),
                "--scan-limit",
                hex(args.scan_limit),
                "--follow-call-fallthrough",
                "--out",
                str(paths["candidate_ssa"]),
            ),
            *_ssa_lowering_args(args),
        ],
    ]
    for cmd in commands:
        proc = _run(cmd)
        if proc.returncode != 0:
            return {
                "name": name,
                "status": "failed",
                "stage": cmd[2] if len(cmd) > 2 else cmd[0],
                "command": cmd,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
    _write_abi_manifest(
        paths["oracle_functions"],
        paths["oracle_ssa"],
        paths["candidate_ssa"],
        paths["abi_manifest"],
        max_parts=args.max_abi_parts,
        max_loop_unroll=args.max_loop_unroll,
        abi_reg_profile=args.abi_reg_profile,
    )

    compare_returncode, compare_stdout, compare_stderr = _run_abi_compare_per_function(paths, args)
    report_proc = _run(
        _dosunit_cmd(
            "report-failures",
            "--results",
            str(paths["compare"]),
            "--out",
            str(paths["report"]),
        )
    )
    compare_doc = json.loads(paths["compare"].read_text(encoding="utf-8")) if paths["compare"].exists() else {}
    summary = compare_doc.get("summary", {}) if isinstance(compare_doc, dict) else {}
    status = "passed" if compare_returncode == 0 else "failed"
    return {
        "name": name,
        "status": status,
        "summary": summary,
        "paths": {key: str(value) for key, value in paths.items()},
        "compare_returncode": compare_returncode,
        "compare_stdout": compare_stdout,
        "compare_stderr": compare_stderr,
        "report_returncode": report_proc.returncode,
        "report_stderr": report_proc.stderr,
    }


def main() -> int:
    """Run the selected rebuilt-example SSA comparisons and write a summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--only", action="append", default=[], help="Example name to include; may be passed more than once"
    )
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    parser.add_argument("--ir", choices=["vex", "ail"], default="vex")
    parser.add_argument("--output-reg", action="append", default=[])
    parser.add_argument(
        "--abi-reg-profile",
        choices=["return", "strict"],
        default="return",
        help="return compares AX+SP; strict also observes DX and preserved BP/SI/DI",
    )
    parser.add_argument("--max-blocks-per-function", type=int, default=64)
    parser.add_argument("--max-insns-per-function", type=int, default=256)
    parser.add_argument("--max-ssa-assignments", type=int, default=4096)
    parser.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x800)
    parser.add_argument(
        "--max-abi-parts",
        type=int,
        default=0,
        help="Skip ABI comparison for functions with more lowered SSA parts; 0 disables this gate",
    )
    parser.add_argument(
        "--max-loop-unroll",
        type=int,
        default=2,
        help="Bounded loop unroll count for ABI SSA composition; 0 skips loop/backedge functions",
    )
    parser.add_argument("--solver-timeout-ms", type=int, default=60000)
    parser.add_argument("--max-solver-assignments", type=int, default=0)
    parser.add_argument("--max-solver-inputs", type=int, default=0)
    parser.add_argument("--max-solver-memory-stores", type=int, default=15)
    parser.add_argument(
        "--compare-process-timeout-seconds",
        type=float,
        default=0.0,
        help="Outer timeout per ABI function compare; 0 uses solver timeout plus 15 seconds",
    )
    args = parser.parse_args()

    report = _load_report(args.report)
    selected = _selected_examples(report, set(args.only))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    results = [_run_example(item, args=args, out_root=args.out_dir) for item in selected]
    summary = {
        "schema": "msc6.ssa_compare.v1",
        "report": str(args.report),
        "selected": len(selected),
        "passed": sum(1 for item in results if item.get("status") == "passed"),
        "failed": sum(1 for item in results if item.get("status") != "passed"),
        "results": results,
    }
    out_path = args.out_dir / "summary.json"
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: summary[key] for key in ("selected", "passed", "failed")}, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
