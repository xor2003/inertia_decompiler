from __future__ import annotations

import ast
from functools import cache
from pathlib import Path

import pytest
from angr_platforms.X86_16 import quality
from angr_platforms.X86_16.layer_module_status import (
    LAYER_MODULE_RECORDS,
    LayerModuleAdmission,
    layer_module_records_by_module,
)
from angr_platforms.X86_16.widening.widening_rules import run_typed_widening_pass_8616

from inertia_decompiler import acceptance_scorecard

pytestmark = pytest.mark.xdist_group("layer-boundaries")
_ROOT = Path(__file__).resolve().parents[1] / "angr_platforms" / "X86_16"
_OWNING_LAYERS = ("semantics", "alias", "widening", "structuring", "lowering")
_ALL_GUARDED_LAYERS = (*_OWNING_LAYERS, "postprocess")


def _iter_layer_py_files(layer: str):
    layer_dir = _ROOT / layer
    if not layer_dir.exists():
        return
    for path in sorted(layer_dir.rglob("*.py")):
        if path.name == "__pycache__":
            continue
        yield path


def _import_targets(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                targets.append(module)
    return targets


def _tracked_python_files() -> tuple[Path, ...]:
    repo = Path(__file__).resolve().parents[2]
    return tuple(
        path
        for base in (
            repo / "angr_platforms",
            repo / "inertia_decompiler",
            repo / "scripts",
        )
        if base.exists()
        for path in sorted(base.rglob("*.py"))
        if "__pycache__" not in path.parts
    )


def _module_name_for_path(path: Path) -> str:
    repo = Path(__file__).resolve().parents[2]
    rel = path.relative_to(repo)
    if rel.parts[:2] == ("angr_platforms", "angr_platforms"):
        rel = Path(*rel.parts[1:])
    return ".".join(rel.with_suffix("").parts)


def _resolve_import_from_module(current_module: str, level: int, module: str | None) -> str:
    if level <= 0:
        return module or ""
    parts = current_module.split(".")[:-1]
    base = parts[: max(0, len(parts) - level + 1)]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


@cache
def _production_import_index() -> dict[str, list[str]]:
    test_root = Path(__file__).resolve().parent
    index: dict[str, list[str]] = {}
    for path in _tracked_python_files():
        if test_root in path.parents:
            continue
        current_module = _module_name_for_path(path)
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    index.setdefault(alias.name, []).append(f"{path}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                source = _resolve_import_from_module(current_module, node.level, node.module)
                if source:
                    index.setdefault(source, []).append(f"{path}:{node.lineno}")
                for alias in node.names:
                    if source:
                        index.setdefault(f"{source}.{alias.name}", []).append(f"{path}:{node.lineno}")
    return index


def _production_importers_for_module(module_name: str) -> list[str]:
    importers: list[str] = []
    for source, source_importers in _production_import_index().items():
        if source == module_name or source.startswith(module_name + "."):
            importers.extend(source_importers)
    return importers


def test_layer_modules_do_not_import_cli_modules() -> None:
    offenders: list[str] = []
    for layer in _ALL_GUARDED_LAYERS:
        for path in _iter_layer_py_files(layer):
            for target in _import_targets(path):
                if target == "inertia_decompiler.cli" or target.startswith("inertia_decompiler.cli_"):
                    offenders.append(f"{path}: {target}")
    assert offenders == []


def test_owning_layers_do_not_import_postprocess_layer() -> None:
    offenders: list[str] = []
    for layer in _OWNING_LAYERS:
        for path in _iter_layer_py_files(layer):
            for target in _import_targets(path):
                if target == "angr_platforms.X86_16.postprocess" or target.startswith(
                    "angr_platforms.X86_16.postprocess."
                ):
                    offenders.append(f"{path}: {target}")
    assert offenders == []


def test_cli_segmented_modules_are_compatibility_shims_only() -> None:
    shim_paths = (
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_segmented.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_segmented_lowering.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_access_object_hints.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_stack_coalesce.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_segmented_store_coalesce.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_word_loads.py",
    )
    offenders: list[str] = []
    for path in shim_paths:
        tree = ast.parse(path.read_text(), filename=str(path))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body):
            offenders.append(str(path))
    assert offenders == []


def test_alias_stack_lowering_module_is_compatibility_shim_only() -> None:
    path = _ROOT / "alias" / "stack_lowering.py"
    tree = ast.parse(path.read_text(), filename=str(path))
    assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body)


def test_flat_widening_modules_are_compatibility_shims_only() -> None:
    widening_alias_path = _ROOT / "widening_alias.py"
    alias_tree = ast.parse(widening_alias_path.read_text(), filename=str(widening_alias_path))
    assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in alias_tree.body)

    widening_model_path = _ROOT / "widening_model.py"
    model_tree = ast.parse(widening_model_path.read_text(), filename=str(widening_model_path))
    assert not any(isinstance(node, ast.ClassDef) for node in model_tree.body)
    allowed_wrappers = {
        "prove_adjacent_storage_slices",
        "analyze_adjacent_storage_slices",
        "can_join_adjacent_storage_slices",
        "merge_storage_slice_domains",
    }
    wrapper_names = {node.name for node in model_tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert wrapper_names <= allowed_wrappers


def test_flat_alias_modules_are_compatibility_shims_only() -> None:
    shim_paths = (
        _ROOT / "alias_domains.py",
        _ROOT / "alias_state.py",
        _ROOT / "alias_transfer.py",
    )
    offenders: list[str] = []
    for path in shim_paths:
        tree = ast.parse(path.read_text(), filename=str(path))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body):
            offenders.append(str(path))
    assert offenders == []


def test_quality_and_diagnostics_modules_are_wired_into_production_paths() -> None:
    modules = (
        "angr_platforms.X86_16.alias.state",
        "angr_platforms.X86_16.alias.domains",
        "angr_platforms.X86_16.semantics.evidence_cache",
        "angr_platforms.X86_16.structuring.simple_loop_recovery",
        "angr_platforms.X86_16.lowering.segmented_lowering",
        "inertia_decompiler.acceptance_scorecard",
        "angr_platforms.X86_16.exact_region_diagnostics",
    )
    missing = [module for module in modules if not _production_importers_for_module(module)]

    assert missing == []


def test_quality_compatibility_exports_retain_canonical_identity() -> None:
    assert quality.X86_16QualityMetrics is acceptance_scorecard.X86_16QualityMetrics
    assert quality.measure_x86_16_codegen_quality_8616 is acceptance_scorecard.measure_x86_16_codegen_quality_8616
    assert quality.measure_x86_16_function_quality_8616 is acceptance_scorecard.measure_x86_16_function_quality_8616
    assert quality.format_x86_16_quality_report_8616 is acceptance_scorecard.format_x86_16_quality_report_8616


def test_prototype_quality_modules_are_test_only_until_pipeline_admission() -> None:
    modules = (
        "angr_platforms.X86_16.ir.ir_canonicalize_8616",
        "angr_platforms.X86_16.structuring.loop_recovery",
    )
    unexpected = {module: _production_importers_for_module(module) for module in modules}

    assert unexpected == {module: [] for module in modules}


def test_layer_compatibility_wrappers_do_not_hide_production_logic() -> None:
    shim_paths = (
        _ROOT / "postprocess" / "cleanup.py",
        _ROOT / "postprocess" / "simplify.py",
        _ROOT / "structuring" / "control_flow.py",
    )
    offenders: list[str] = []
    for path in shim_paths:
        tree = ast.parse(path.read_text(), filename=str(path))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body):
            offenders.append(str(path))

    assert offenders == []


def test_flagged_layer_modules_have_explicit_admission_status() -> None:
    modules = layer_module_records_by_module()
    expected = {
        "angr_platforms.X86_16.validation.canonicalize",
        "angr_platforms.X86_16.alias.state",
        "angr_platforms.X86_16.alias.domains",
        "angr_platforms.X86_16.structuring.loop_recovery",
        "angr_platforms.X86_16.structuring.simple_loop_recovery",
        "angr_platforms.X86_16.structuring.control_flow",
        "angr_platforms.X86_16.semantics.evidence_cache",
        "angr_platforms.X86_16.postprocess.simplify",
        "angr_platforms.X86_16.quality",
        "angr_platforms.X86_16.postprocess.cleanup",
        "angr_platforms.X86_16.lowering.segmented_lowering",
        "angr_platforms.X86_16.ir.ir_canonicalize_8616",
        "angr_platforms.X86_16.exact_region_diagnostics",
    }

    assert set(modules) == expected
    assert all(record.note for record in LAYER_MODULE_RECORDS)


def test_layer_module_admission_status_matches_production_imports() -> None:
    mismatches: list[str] = []
    for record in LAYER_MODULE_RECORDS:
        importers = _production_importers_for_module(record.module)
        if record.admission is LayerModuleAdmission.PRODUCTION_WIRED and not importers:
            mismatches.append(f"{record.module}: marked production_wired but has no production importer")
        if record.admission is LayerModuleAdmission.TEST_ONLY_PROTOTYPE and importers:
            mismatches.append(f"{record.module}: marked test_only_prototype but imported by {importers}")

    assert mismatches == []


def test_compatibility_wrapper_admission_modules_do_not_hide_logic() -> None:
    offenders: list[str] = []
    for record in LAYER_MODULE_RECORDS:
        if record.admission is not LayerModuleAdmission.COMPATIBILITY_WRAPPER:
            continue
        rel_parts = record.module.removeprefix("angr_platforms.X86_16.").split(".")
        path = _ROOT.joinpath(*rel_parts).with_suffix(".py")
        tree = ast.parse(path.read_text(), filename=str(path))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body):
            offenders.append(str(path))

    assert offenders == []


def test_layer_headers_present_on_migrated_modules() -> None:
    targets = (
        _ROOT / "alias" / "alias_model.py",
        _ROOT / "alias" / "domains.py",
        _ROOT / "alias" / "state.py",
        _ROOT / "alias" / "transfer.py",
        _ROOT / "lowering" / "stack_lowering.py",
        _ROOT / "ir" / "condition_ir.py",
        _ROOT / "ir" / "address_ir.py",
        _ROOT / "ir" / "value_ir.py",
        _ROOT / "widening" / "store_width.py",
        _ROOT / "widening" / "register_widening.py",
        _ROOT / "widening" / "stack_widening.py",
        _ROOT / "postprocess" / "flags_cleanup.py",
        _ROOT / "postprocess" / "cleanup.py",
    )
    missing: list[str] = []
    for path in targets:
        docstring = ast.get_docstring(ast.parse(path.read_text(), filename=str(path))) or ""
        if "Layer:" not in docstring or not ("Owns" in docstring or "Consumes" in docstring):
            missing.append(str(path))
    assert missing == []


def test_widening_entrypoint_runs_subpasses_in_fixed_order() -> None:
    calls: list[str] = []

    def _widths(_project, _codegen) -> bool:
        calls.append("widths")
        return True

    def _direct(_project, _codegen) -> bool:
        calls.append("direct")
        return False

    def _subviews(_codegen) -> bool:
        calls.append("subviews")
        return True

    def _word_projections(_codegen) -> bool:
        calls.append("word-projections")
        return True

    def _segmented(_project, _codegen) -> bool:
        calls.append("segmented")
        return True

    def _copyprop(_codegen, *, enable_nested: bool) -> bool:
        assert enable_nested is True
        calls.append("copyprop")
        return True

    changed = run_typed_widening_pass_8616(
        object(),
        object(),
        coalesce_direct_ss_local_word_statements=_direct,
        coalesce_segmented_word_store_statements=_segmented,
        copy_propagation_fn=_copyprop,
        promote_stack_slots_from_instruction_widths=_widths,
        materialize_stack_subviews_fn=_subviews,
        materialize_word_projections_fn=_word_projections,
    )
    assert changed is True
    assert calls == ["widths", "subviews", "direct", "segmented", "copyprop", "word-projections"]
