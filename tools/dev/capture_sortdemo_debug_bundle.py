#!/usr/bin/env python3
"""Capture SORTDEMO debug artifacts for focused decompiler diagnostics.

Layer: Tooling/gates.
Responsibility: gather reproducible SORTDEMO diagnostics without changing decompiler semantics.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT))

import inertia.cli.cli_function_discovery as function_discovery  # noqa: E402
from inertia.cli.cli_c_ast_rewrites import _rewrite_ss_stack_byte_offsets  # noqa: E402
from inertia.cli.cli_decompilation import (  # noqa: E402
    _function_complexity,
    _function_decompilation_profile,
    _preferred_decompiler_options,
    _prepare_function_for_decompilation,
    _regenerate_codegen_text_safely,
    _snapshot_codegen_text,
)
from inertia.cli.disassembly_helpers import _format_asm_range, _format_first_block_asm  # noqa: E402
from inertia.cli.project_loading import _build_project, _is_blob_only_input  # noqa: E402
from inertia.cli.x86_16_exact_slice import function_original_addr  # noqa: E402
from inertia.frontend.x86_16.cod_extract import extract_cod_listing_metadata  # noqa: E402
from inertia.lowering.analysis_helpers import (  # noqa: E402
    extend_cfg_for_far_calls,
    extend_cfg_for_neighbor_calls,
    patch_interrupt_service_call_sites,
    seed_calling_conventions,
)
from inertia.lowering.segmented_memory_reasoning import apply_x86_16_segmented_memory_reasoning  # noqa: E402
from inertia.lowering.stack_lowering import run_stack_lowering_pass_8616  # noqa: E402
from inertia.lowering.stack_probe_return_facts import (  # noqa: E402
    build_typed_stack_probe_return_facts_8616,
)
from inertia.postprocess.decompiler_postprocess_calls import (  # noqa: E402
    _attach_callsite_summaries_8616,
    _materialize_callsite_prototypes_8616,
    _materialize_callsite_stack_arguments_8616,
)


def _collect_cod_window_lines(cod_text: str, addr: int, radius: int = 4) -> list[str]:
    def _impl() -> list[str]:
        """Return a small COD listing window centered on one offset."""

        lines = cod_text.splitlines()
        asm_rows: list[int] = []
        hit_index: int | None = None
        for idx, line in enumerate(lines):
            if "***" not in line or line.lstrip().startswith(";|***"):
                continue
            asm_rows.append(idx)
            parts = line.split("***", 1)[1].strip().split(None, 2)
            if not parts:
                continue
            try:
                row_addr = int(parts[0], 16)
            except ValueError:
                continue
            if row_addr == addr:
                hit_index = idx
        if hit_index is None:
            return [f"<no COD row for {addr:#x}>"]

        asm_pos = asm_rows.index(hit_index)
        start_idx = asm_rows[max(0, asm_pos - radius)]
        end_idx = asm_rows[min(len(asm_rows) - 1, asm_pos + radius)]

        while start_idx > 0 and lines[start_idx - 1].lstrip().startswith(";|***"):
            start_idx -= 1
        while end_idx + 1 < len(lines) and lines[end_idx + 1].lstrip().startswith(";|***"):
            end_idx += 1
        return lines[start_idx : end_idx + 1]

    return _impl()


for _name, _value in (
    ("extend_cfg_for_far_calls", extend_cfg_for_far_calls),
    ("extend_cfg_for_neighbor_calls", extend_cfg_for_neighbor_calls),
    ("patch_interrupt_service_call_sites", patch_interrupt_service_call_sites),
    ("seed_calling_conventions", seed_calling_conventions),
):
    if not hasattr(function_discovery, _name):
        # Dynamic compatibility boundary: legacy discovery modules may not export injected helpers.
        setattr(function_discovery, _name, _value)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_cli_capture(binary: Path, addr: int, timeout: int) -> tuple[int, str, str, list[str]]:
    cmd = [
        sys.executable,
        "-u",
        "decompile.py",
        str(binary),
        "--addr",
        hex(addr),
        "--timeout",
        str(timeout),
        "--alternate-source-c",
    ]
    result = subprocess.run(
        cmd,
        cwd=str(Path(__file__).resolve().parents[2]),
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr, cmd


def _focused_codegen_stage_dump(project: object, function: object) -> tuple[dict[str, object], dict[str, str]]:
    block_count, byte_count = _function_complexity(function)
    profile = _function_decompilation_profile(function, block_count, byte_count)
    options = _preferred_decompiler_options(
        block_count,
        byte_count,
        wrapper_like=bool(profile.get("wrapper_like")),
        tiny_single_call_helper=bool(profile.get("tiny_single_call_helper")),
    )
    # Dynamic angr boundary: project.analyses is supplied by the loaded angr project.
    dec = cast(Any, project).analyses.Decompiler(function, cfg=None, options=options, generate_code=True)
    if dec.codegen is None:
        return (
            {
                "block_count": block_count,
                "byte_count": byte_count,
                "raw_codegen_present": False,
            },
            {"00_raw_codegen.c": "<no raw codegen>"},
        )

    outputs: dict[str, str] = {
        "00_raw_codegen.c": _snapshot_codegen_text(dec.codegen),
    }
    summary: dict[str, object] = {
        "block_count": block_count,
        "byte_count": byte_count,
        "raw_codegen_present": True,
        "profile": profile,
    }

    callsite_changed = False
    for rewrite in (
        lambda: _attach_callsite_summaries_8616(project, dec.codegen),
        lambda: bool(build_typed_stack_probe_return_facts_8616(dec.codegen)),
        lambda: _materialize_callsite_stack_arguments_8616(project, dec.codegen),
        lambda: _materialize_callsite_prototypes_8616(project, dec.codegen),
    ):
        if rewrite():
            callsite_changed = True
    summary["callsite_pass_changed"] = callsite_changed
    function_addr = cast(Any, function).addr
    outputs["10_after_callsite_facts.c"], _ = _regenerate_codegen_text_safely(
        dec.codegen,
        context=f"{function_addr:#x} after callsite facts",
    )

    stack_lowering_changed = run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lambda: apply_x86_16_segmented_memory_reasoning(dec.codegen),
        rewrite_ss_stack_byte_offsets=lambda: _rewrite_ss_stack_byte_offsets(project, dec.codegen),
        canonicalize_stack_cvars=lambda: False,
        codegen=dec.codegen,
    )
    summary["stack_lowering_changed"] = stack_lowering_changed
    outputs["20_after_stack_lowering.c"], _ = _regenerate_codegen_text_safely(
        dec.codegen,
        context=f"{function_addr:#x} after stack lowering",
    )
    return summary, outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a deterministic SORTDEMO one-function debug bundle.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("--addr", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--window", type=lambda value: int(value, 0), default=0x40)
    parser.add_argument("--base-addr", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--entry-point", type=lambda value: int(value, 0), default=0x100)
    parser.add_argument("--cod", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path(".codex_automation") / "stage_debug")
    args = parser.parse_args()

    binary = args.binary.resolve()
    output_dir = (args.output_dir / f"{args.addr:#x}").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    cod_path = args.cod.resolve() if args.cod is not None else binary.with_suffix(".COD")
    project = _build_project(
        binary,
        force_blob=_is_blob_only_input(binary),
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    region = function_discovery._infer_x86_16_linear_region(project, args.addr, window=args.window)
    _, function = function_discovery._pick_function(project, args.addr, regions=[region], data_references=True)
    _prepare_function_for_decompilation(project, function)

    display_addr = function_original_addr(function)
    function_label = {
        "requested_addr": args.addr,
        "display_addr": display_addr,
        "slice_addr": function.addr,
        "name": function.name,
        "region": [region[0], region[1]],
        "binary": str(binary),
        "cod_path": str(cod_path) if cod_path.exists() else "",
    }
    _write_text(output_dir / "00_function.json", json.dumps(function_label, indent=2, sort_keys=True) + "\n")
    _write_text(output_dir / "01_linear.asm", _format_asm_range(project, region[0], region[1]) + "\n")
    _write_text(output_dir / "02_first_block.asm", _format_first_block_asm(project, function) + "\n")

    if cod_path.exists():
        cod_text = cod_path.read_text(encoding="utf-8", errors="replace")
        listing = extract_cod_listing_metadata(cod_path)
        cod_label = listing.code_labels.get(display_addr, "")
        cod_range = listing.code_ranges.get(display_addr)
        cod_window = "\n".join(_collect_cod_window_lines(cod_text, display_addr, radius=5))
        if cod_label:
            cod_window = f"; proc={cod_label}\n" + cod_window
        if cod_range is not None:
            cod_window = f"; range={cod_range[0]:#x}-{cod_range[1]:#x}\n" + cod_window
        _write_text(output_dir / "03_cod_window.asm", cod_window + "\n")
    else:
        _write_text(output_dir / "03_cod_window.asm", "<COD sidecar not found>\n")

    stage_summary, stage_outputs = _focused_codegen_stage_dump(project, function)
    _write_text(output_dir / "04_stage_summary.json", json.dumps(stage_summary, indent=2, sort_keys=True) + "\n")
    for name, text in stage_outputs.items():
        _write_text(output_dir / name, text + ("\n" if not text.endswith("\n") else ""))

    returncode, stdout_text, stderr_text, cmd = _run_cli_capture(binary, args.addr, args.timeout)
    _write_text(output_dir / "30_cli.stdout", stdout_text)
    _write_text(output_dir / "31_cli.stderr", stderr_text)
    _write_text(output_dir / "32_cli_command.txt", " ".join(cmd) + "\n")

    print(f"debug_bundle={output_dir}")
    print(f"function={function.name} display_addr={display_addr:#x} slice_addr={function.addr:#x}")
    print(f"cli_returncode={returncode}")
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
