#!/usr/bin/env python3
"""Agent-focused test selection helper for decompiler trust decisions.

Layer: Tooling/gates.
Responsibility: infer high-signal decompiler tests from changed files or an
explicit layer and optionally execute the selected pytest slice.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.dev import test_ownership_manifest as ownership_manifest  # noqa: E402
from tools.dev.task_context import build_task_context, component_focused_tests  # noqa: E402

LAYER_ORDER: Final[tuple[str, ...]] = (
    "alias",
    "ir",
    "semantics",
    "widening",
    "lowering",
    "structuring",
    "pipeline",
    "rewrite",
    "validation",
    "runtime",
    "frontend",
    "quality",
    "comparator",
    "tools",
)

DOC_LAYER_HINTS: Final[tuple[tuple[str, str], ...]] = (
    ("frontend/angr compatibility", "frontend"),
    ("frontend/runtime", "runtime"),
    ("frontend", "frontend"),
    ("tail validation", "validation"),
    ("validation", "validation"),
    ("structuring", "structuring"),
    ("semantics", "semantics"),
    ("rewrites", "rewrite"),
    ("rewrite", "rewrite"),
    ("widening", "widening"),
    ("compatibility shim", "alias"),
    ("recovery metadata", "pipeline"),
    ("recovery/reporting", "quality"),
    ("optional evidence/reporting", "quality"),
    ("helper boundary", "frontend"),
    ("recompilable output", "quality"),
    ("ir compatibility", "ir"),
    ("ir", "ir"),
)

LAYER_PATH_HINTS: Final[dict[str, tuple[str, ...]]] = {
    "comparator": ("tools/dosunit", "artifacts/bc5-z3cmp32", "artifacts/msc8-z3cmp32"),
    "tools": ("tools/compiler_toolchain", "tools/compiler_id", "tools/dev", "tools/ada_script", "tools/compiler_id/report.py"),
    "alias": ("inertia/alias/",),
    "ir": ("inertia/ir/",),
    "semantics": ("inertia/semantics/",),
    "widening": ("inertia/widening/",),
    "lowering": ("inertia/lowering/",),
    "structuring": ("inertia/structuring/",),
    "pipeline": ("inertia/pipeline/",),
    "rewrite": (
        "inertia/postprocess/",
        "inertia/postprocess/decompiler_postprocess.py",
        "inertia/postprocess/decompiler_postprocess_calls.py",
        "inertia/postprocess/flags_cleanup.py",
        "inertia/postprocess/decompiler_postprocess_jcc.py",
        "inertia/postprocess/decompiler_postprocess_loads.py",
        "inertia/postprocess/decompiler_postprocess_simplify.py",
        "inertia/postprocess/decompiler_postprocess_stage.py",
        "inertia/postprocess/decompiler_postprocess_typed_conditions.py",
        "inertia/postprocess/decompiler_postprocess_utils.py",
    ),
    "validation": ("inertia/validation/",),
    "runtime": (
        "inertia/frontend/x86_16/compat.py",
        "inertia/frontend/x86_16/debug.py",
        "inertia/frontend/x86_16/dev_io.py",
        "inertia/frontend/x86_16/emu.py",
        "inertia/frontend/x86_16/emulator.py",
        "inertia/frontend/x86_16/exception.py",
        "inertia/frontend/x86_16/hardware.py",
        "inertia/frontend/x86_16/interrupt.py",
        "inertia/frontend/x86_16/io.py",
        "inertia/frontend/x86_16/memory.py",
        "inertia/frontend/x86_16/simprocs_io.py",
    ),
}

LAYER_ANCHOR_TESTS: Final[dict[str, tuple[str, ...]]] = {
    "alias": (
        "tests/alias/test_x86_16_alias_api_and_widening_proof.py",
        "tests/alias/test_x86_16_alias_domains.py",
        "tests/alias/test_x86_16_alias_state_transfer.py",
        "tests/alias/test_x86_16_alias_stack_lowering.py",
    ),
    "ir": (
        "tests/ir/test_x86_16_address_ir.py",
        "tests/integration/test_x86_16_segment_state.py",
        "tests/ir/test_x86_16_ir_core.py",
        "tests/ir/test_x86_16_vex_import.py",
    ),
    "semantics": (
        "tests/frontend/test_x86_16_compare_semantics.py",
        "tests/semantics/test_x86_16_semantics_alias_query.py",
        "tests/semantics/test_x86_16_semantics_exports.py",
        "tests/semantics/test_x86_16_semantics_expression_analysis.py",
    ),
    "widening": (
        "tests/widening/test_x86_16_widening_copyprop.py",
        "tests/widening/test_x86_16_widening_memory_fold.py",
        "tests/widening/test_x86_16_widening_rules.py",
    ),
    "lowering": (
        "tests/lowering/test_x86_16_call_return_selectors.py",
        "tests/integration/test_x86_16_consumed_push_lvalues.py",
        "tests/lowering/test_x86_16_object_lowering.py",
        "tests/lowering/test_x86_16_stack_lowering_contracts.py",
    ),
    "structuring": (
        "tests/structuring/test_x86_16_condition_rendering.py",
        "tests/structuring/test_x86_16_structuring_condition_materialization.py",
        "tests/structuring/test_x86_16_structuring_loop_body_repair.py",
        "tests/validation/test_x86_16_structuring_pass_validation.py",
        "tests/structuring/test_x86_16_structuring_sequences.py",
    ),
    "pipeline": (
        "tools/dev/tests/test_decompiler_architecture_check.py",
        "tests/integration/test_x86_16_pipeline_contracts.py",
        "tests/alias/test_x86_16_rewrite_boundary.py",
    ),
    "rewrite": (
        "tests/postprocess/test_x86_16_decompiler_postprocess_callsites.py",
        "tests/postprocess/test_x86_16_decompiler_postprocess_utils.py",
        "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",
        "tests/postprocess/test_x86_16_dce_optimization.py",
        "tests/postprocess/test_x86_16_trivial_copy_optimization.py",
    ),
    "validation": (
        "tests/validation/test_x86_16_validation_canonicalize.py",
        "tests/validation/test_x86_16_validation_control_flow.py",
        "tests/validation/test_x86_16_validation_dataflow.py",
        "tests/validation/test_x86_16_validation_semantic_failures.py",
        "tests/validation/test_x86_16_validation_storage.py",
        "tests/validation/test_x86_16_validation_virtual_carriers.py",
    ),
    "runtime": (
        "tests/frontend/test_x86_16_debug.py",
        "tests/frontend/test_x86_16_emulator.py",
        "tests/frontend/test_x86_16_io.py",
    ),
    "frontend": (
        "tests/cli/test_check_sortd_sidecar_free.py",
        "tests/cli/test_cli_regeneration.py",
        "tools/dev/tests/test_decompiler_architecture_check.py",
    ),
    "quality": (
        "tests/cli/test_decompilation_quality.py",
        "tests/cli/test_x86_16_generated_c_acceptance.py",
        "tests/cli/test_x86_16_sortdemo_decompiler_status.py",
    ),
}

LAYER_SHARED_TESTS: Final[tuple[str, ...]] = (
    "tools/dev/tests/test_decompiler_architecture_check.py",
    "tools/dev/tests/test_test_ownership_manifest.py",
    "tests/integration/test_x86_16_package_exports.py",
)


@dataclass(frozen=True, slots=True)
class LayerPlan:
    """Structured focus plan for one pipeline layer."""

    layer: str
    files: tuple[str, ...]
    tests: tuple[str, ...]
    focused_tests: tuple[str, ...]
    anchor_tests: tuple[str, ...]

    def to_dict(self) -> dict[str, tuple[str, ...] | str]:
        """Return a JSON-serializable plan snapshot."""

        return {
            "layer": self.layer,
            "files": self.files,
            "tests": self.tests,
            "focused_tests": self.focused_tests,
            "anchor_tests": self.anchor_tests,
        }


@dataclass(frozen=True, slots=True)
class SelectedTest:
    """Single selected pytest target with a reason and originating layer."""

    test: str
    layer: str
    reason: str


def _materialize_selected_tests(plans: tuple[LayerPlan, ...]) -> tuple[SelectedTest, ...]:
    """Materialize a deduplicated selected test list with layer and reason annotations."""

    selected: list[SelectedTest] = []
    seen: set[str] = set()
    for plan in plans:
        for test in plan.tests:
            if test in seen:
                continue
            seen.add(test)
            if test in plan.focused_tests:
                reason = "focused-by-change"
            elif test in plan.anchor_tests:
                reason = "layer-anchor"
            else:
                reason = "layer-coverage"
            selected.append(SelectedTest(test=test, layer=plan.layer, reason=reason))
    return tuple(selected)


def _extract_layer_from_docstring(path: str) -> str | None:
    absolute = REPO_ROOT / _normalize_path(path)
    if not absolute.is_file():
        return None

    try:
        module_ast = ast.parse(absolute.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return None

    doc = ast.get_docstring(module_ast)
    if not doc:
        return None

    layer_line = next(
        (line.strip() for line in doc.splitlines() if line.strip().lower().startswith("layer:")),
        "",
    )
    if not layer_line:
        return None

    layer_hint = layer_line.split(":", 1)[1].strip().lower()
    layer_hint = layer_hint.rstrip(".")
    for hint, layer in DOC_LAYER_HINTS:
        if hint in layer_hint:
            return layer
    return None


def _normalize_path(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix().replace("\\", "/")


def _candidate_exists(path: str) -> bool:
    normalized = _normalize_path(path)
    absolute = REPO_ROOT / normalized
    return absolute.is_file() or absolute.is_dir()


def _run_git_changed_files() -> tuple[str, ...]:
    commands: tuple[tuple[str, ...], ...] = (
        ("git", "-C", str(REPO_ROOT), "diff", "--name-only", "--", "*.py"),
        ("git", "-C", str(REPO_ROOT), "ls-files", "--others", "--exclude-standard", "--", "*.py"),
    )
    lines: list[str] = []
    for command in commands:
        completed = subprocess.run(command, check=False, text=True, capture_output=True)
        if completed.returncode != 0:
            continue
        lines.extend(line.strip() for line in completed.stdout.splitlines())
    return tuple(sorted({line for line in lines if line}))


def _ordered_unique(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _path_matches(path: str, prefix: str) -> bool:
    normalized = _normalize_path(path)
    normalized_prefix = prefix.rstrip("/")
    return normalized == normalized_prefix or normalized.startswith(f"{normalized_prefix}/")


def _infer_layers_for_path(path: str) -> tuple[str, ...]:
    normalized = _normalize_path(path)
    detected: list[str] = []
    module_layer = _extract_layer_from_docstring(normalized)
    if module_layer is not None:
        detected.append(module_layer)

    for layer, hints in LAYER_PATH_HINTS.items():
        for hint in hints:
            if _path_matches(normalized, hint):
                detected.append(layer)
                break
    if not detected:
        if normalized.startswith("scripts/"):
            detected.append("quality")
        elif normalized.startswith(("inertia/",)):
            detected.append("frontend")
    return _ordered_unique(detected)


def _resolve_layers_for_files(files: tuple[str, ...], layer_filter: str | None) -> dict[str, tuple[str, ...]]:
    if layer_filter is not None:
        return {layer_filter: files}
    if not files:
        return {}

    layer_to_files: dict[str, list[str]] = {}
    for path in files:
        for layer in _infer_layers_for_path(path):
            layer_to_files.setdefault(layer, []).append(path)
    return {layer: _ordered_unique(paths) for layer, paths in layer_to_files.items()}


def _collect_layer_focus(layer_to_files: dict[str, tuple[str, ...]]) -> dict[str, LayerPlan]:
    """Build immutable focused and anchor test plans for each selected layer."""
    if not layer_to_files:
        quality_anchor_tests = _ordered_unique(LAYER_ANCHOR_TESTS["quality"])
        return {
            "quality": LayerPlan(
                layer="quality",
                files=(),
                tests=quality_anchor_tests,
                focused_tests=(),
                anchor_tests=quality_anchor_tests,
            ),
        }

    layer_plans: dict[str, LayerPlan] = {}
    for layer, files in layer_to_files.items():
        focused_tests: list[str] = []
        anchor_tests: list[str] = list(LAYER_ANCHOR_TESTS.get(layer, ()))
        if files:
            file_tests = ownership_manifest.select_tests_for_files(files)
            if file_tests:
                focused_tests.extend(file_tests)
            focused_tests.extend(component_focused_tests(files))
        # Explicit layer calls with no file list still keep anchor coverage.
        ordered_tests = _ordered_unique((*focused_tests, *anchor_tests))
        layer_plans[layer] = LayerPlan(
            layer=layer,
            files=files,
            tests=ordered_tests,
            focused_tests=_ordered_unique(tuple(focused_tests)),
            anchor_tests=_ordered_unique(tuple(anchor_tests)),
        )

    return layer_plans


def _collect_layer_focus_fallback() -> dict[str, LayerPlan]:
    anchor_tests = _ordered_unique(LAYER_ANCHOR_TESTS["quality"])
    return {
        "quality": LayerPlan(
            layer="quality",
            files=(),
            tests=anchor_tests,
            focused_tests=(),
            anchor_tests=anchor_tests,
        ),
    }


def _print_focus(plan: LayerPlan) -> None:
    print(f"- {plan.layer} ({len(plan.files)} file(s))")
    files = plan.files
    if files:
        for item in files:
            print(f"  · {item}")
    if plan.focused_tests:
        print("  focused-by-change:")
        for test in plan.focused_tests:
            print(f"    - {test}")
    if plan.anchor_tests:
        print("  layer-anchor")
        for test in plan.anchor_tests:
            if test in plan.focused_tests:
                continue
            print(f"    - {test}")
    if plan.tests:
        print("  tests:")
        for test in plan.tests:
            print(f"    - {test}")
    else:
        print("  tests: no focused tests resolved")


def _plan(
    layer_filter: str | None,
    files: tuple[str, ...],
    include_shared: bool,
) -> tuple[LayerPlan, ...]:
    selected_files = tuple(path for path in files if _candidate_exists(path))
    if not files and layer_filter is None:
        selected_files = _run_git_changed_files()

    layer_to_files = _resolve_layers_for_files(selected_files, layer_filter)
    if not layer_to_files and layer_filter is None:
        layer_to_files = {"quality": ()}

    layer_to_plans = _collect_layer_focus(layer_to_files) if layer_to_files else _collect_layer_focus_fallback()

    plans: list[LayerPlan] = []
    for layer in LAYER_ORDER:
        if layer in layer_to_plans:
            plans.append(layer_to_plans[layer])

    if include_shared:
        plans.append(
            LayerPlan(
                layer="shared-baseline",
                files=(),
                tests=LAYER_SHARED_TESTS,
                focused_tests=(),
                anchor_tests=LAYER_SHARED_TESTS,
            )
        )

    return tuple(plans)


def _run_pytest(selected_tests: tuple[str, ...], args: argparse.Namespace) -> int:
    command: list[str] = [sys.executable, "-m", "pytest", "-q", *selected_tests]
    if args.durations:
        command.extend(["--durations=25", "--durations-min=1.0"])
    try:
        completed = subprocess.run(command, check=False)
    except KeyboardInterrupt:
        return 130
    return completed.returncode


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select and run high-signal tests for decompiler changes.")
    parser.add_argument(
        "--files",
        nargs="*",
        default=(),
        help="Files to infer layer focus from (default: git changed files)",
    )
    parser.add_argument("--layer", choices=LAYER_ORDER, help="Force a single layer focus")
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the selected pytest targets instead of just printing",
    )
    parser.add_argument("--no-infer-changed", action="store_true", help="Do not auto-detect changed files")
    parser.add_argument("--durations", action="store_true", help="Pass pytest duration reporting when running")
    parser.add_argument(
        "--max-tests",
        type=int,
        default=0,
        help="Limit selected pytest targets during --run (0 = unlimited)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output in addition to standard output",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Emit only machine-readable JSON output (requires --json)",
    )
    parser.add_argument("--no-shared", action="store_true", help="Skip shared baseline tests")
    parser.add_argument("--context", action="store_true", help="Include bounded owner/API/source context in JSON")
    args = parser.parse_args(argv)
    if args.json_only and not args.json:
        parser.error("--json-only requires --json")
    return args


def main(argv: list[str] | None = None) -> int:
    """Resolve and optionally execute the smallest owned test plan."""
    args = _parse_args(argv)
    files = tuple(_normalize_path(item) for item in args.files)
    if not files and not args.no_infer_changed:
        files = _run_git_changed_files()
    files = tuple(files)

    plans = _plan(args.layer, files, include_shared=not args.no_shared)
    if not plans:
        print("No test plan could be resolved.")
        return 0

    selected_tests_with_reasons = _materialize_selected_tests(plans)
    selected_tests = [entry.test for entry in selected_tests_with_reasons]
    if args.max_tests > 0 and len(selected_tests) > args.max_tests:
        selected_tests = selected_tests[: args.max_tests]
        selected_tests_with_reasons = tuple(selected_tests_with_reasons[: args.max_tests])
        truncated = True
    else:
        truncated = False

    if args.json:
        print(json.dumps(_selection_payload(args, plans, selected_tests_with_reasons, files, truncated), indent=2))

    if not args.json_only:
        _print_plan(plans, selected_tests_with_reasons)

    return _run_selection(args, selected_tests, truncated)


def _selection_payload(
    args: argparse.Namespace,
    plans: tuple[LayerPlan, ...],
    selected_tests_with_reasons: tuple[SelectedTest, ...],
    files: tuple[str, ...],
    truncated: bool,
) -> dict[str, object]:
    """Build the machine-readable plan payload."""
    payload: dict[str, object] = {
        "plans": [plan.to_dict() for plan in plans],
        "selected_tests": [entry.test for entry in selected_tests_with_reasons],
        "selected_tests_with_reasons": [
            {
                "test": entry.test,
                "layer": entry.layer,
                "reason": entry.reason,
            }
            for entry in selected_tests_with_reasons
        ],
        "truncated": truncated,
        "max_tests": args.max_tests,
        "layer_filter": args.layer,
        "include_shared": not args.no_shared,
        "requested_files": files,
    }
    if args.context:
        payload["context"] = build_task_context(files, tuple(entry.test for entry in selected_tests_with_reasons))
    return payload


def _print_plan(plans: tuple[LayerPlan, ...], selected_tests_with_reasons: tuple[SelectedTest, ...]) -> None:
    """Print the human-readable plan and selected tests."""
    print("Agent trust-focused test plan:")
    for plan in plans:
        _print_focus(plan)
    if selected_tests_with_reasons:
        print(f"Selected {len(selected_tests_with_reasons)} tests:")
        for entry in selected_tests_with_reasons:
            print(f"  - {entry.test}")
            print(f"    reason={entry.reason}")
            print(f"    layer={entry.layer}")


def _run_selection(args: argparse.Namespace, selected_tests: list[str], truncated: bool) -> int:
    """Execute the selected pytest targets, or report why nothing ran."""
    if not args.run:
        if not args.json_only:
            print("\nNo run requested. Add --run to execute selected tests.")
        return 0

    if not selected_tests:
        if not args.json_only:
            print("\nNo pytest targets selected. Nothing to run.")
        return 0

    if not args.json_only:
        print("\nRunning:")
    if truncated and not args.json_only:
        print("  (max-tests reached; trimmed after ordered, high-signal-first selection)")
    for target in selected_tests:
        if not args.json_only:
            print(f"  - {target}")
    return _run_pytest(tuple(selected_tests), args)


if __name__ == "__main__":
    raise SystemExit(main())
