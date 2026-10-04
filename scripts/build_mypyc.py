#!/usr/bin/env python3
"""Build optional mypyc acceleration artifacts for local developer runs.

Layer: Tooling/gates.
Responsibility: run optional local mypyc builds without owning decompiler semantics.
"""

from __future__ import annotations

import argparse
import importlib.machinery
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.mypyc_build_cache import (  # noqa: E402
    MypycBuildCacheLayout,
    build_mypyc_import_smoke_identity,
    import_smoke_attestation_matches,
    reconcile_mypyc_build_cache,
    run_compiled_import_smoke,
    stage_isolated_vex_extension,
    sync_isolated_package_sources,
    write_import_smoke_attestation,
)

TARGET_MODULES: list[str] = [
    "angr_platforms.X86_16.lowering.callsite_prototype_declarations",
    "angr_platforms.X86_16.lowering.callsite_prototype_seeding",
    "angr_platforms.X86_16.lowering.stack_prototype_materialization",
    "angr_platforms.X86_16.lowering.terminal_return_expressions",
    "angr_platforms.X86_16.lowering.terminal_call_return_types",
    "angr_platforms.X86_16.lowering.terminal_register_return_types",
    "angr_platforms.X86_16.lowering.terminal_register_return_values",
    "angr_platforms.X86_16.lowering.unused_void_return_types",
    "angr_platforms.X86_16.structuring.call_return_conditions",
    "angr_platforms.X86_16.lowering.call_argument_shape",
    "angr_platforms.X86_16.lowering.call_argument_state",
    "angr_platforms.X86_16.lowering.call_return_selectors",
    "angr_platforms.X86_16.lowering.call_return_stack_stores",
    "angr_platforms.X86_16.validation_calls",
    "angr_platforms.X86_16.validation_dataflow",
    "angr_platforms.X86_16.lowering.return_type_evidence",
    "angr_platforms.X86_16.validation_predicates",
    "angr_platforms.X86_16.validation_control_flow",
    "angr_platforms.X86_16.validation_required_memory_effects",
    "angr_platforms.X86_16.lowering.callee_pointer_contracts",
    "angr_platforms.X86_16.lowering.callee_pointer_evidence",
    "angr_platforms.X86_16.lowering.callee_argument_count_evidence",
    "angr_platforms.X86_16.lowering.callee_argument_width_evidence",
    "angr_platforms.X86_16.lowering.callee_global_object_type_surface",
    "angr_platforms.X86_16.lowering.callee_argument_interface",
    "angr_platforms.X86_16.function_evidence_inventory",
    "angr_platforms.X86_16.lowering.near_pointer_argument",
    "angr_platforms.X86_16.lowering.near_pointer_type",
    "inertia_decompiler.decompile_file_summary",
    "inertia_decompiler.work_items",
    "inertia_decompiler.function_worker_policy",
    "inertia_decompiler.acceptance_scorecard",
    "inertia_decompiler.decompilation_quality",
    "inertia_decompiler.discovery_cache_contract",
    "inertia_decompiler.generated_c_artifacts",
    "inertia_decompiler.generated_c_function_extraction",
    "inertia_decompiler.generated_translation_unit_assembly",
    "inertia_decompiler.recompile_check",
    "inertia_decompiler.sidecar_policy",
]
MYPYC_CACHE_DIR: Path = Path(".cache") / "mypyc"
MYPYC_LIB_DIR: Path = MYPYC_CACHE_DIR / "lib"
MYPYC_TEMP_DIR: Path = MYPYC_CACHE_DIR / "temp"
MYPYC_CGEN_DIR: Path = MYPYC_CACHE_DIR / "cgen"
MYPYC_BUILD_SCHEMA: str = "4-incremental-module-cohort"
MYPYC_IMPORT_SMOKE_SCHEMA: str = "1-exact-source-artifact-cohort"
MYPYC_IMPORT_SMOKE_ATTESTATION: Path = MYPYC_CACHE_DIR / "import-smoke.sha256"


@dataclass(frozen=True)
class ModuleState:
    """Track one mypyc module source and cache marker."""

    module: str
    source_path: Path
    marker_path: Path


def _module_source_path(value: str) -> Path:
    """Resolve a module spec (dotted or file path) to a Python source file."""
    return Path(_module_to_path(value))


def _module_artifact_candidates(module_state: ModuleState, *, inplace: bool = False) -> list[Path]:
    """Return existing main and native-helper extensions for one module."""
    target_dir = (
        module_state.source_path.parent
        if inplace
        else REPO_ROOT / MYPYC_LIB_DIR / Path(*module_state.module.split(".")).parent
    )
    stem = module_state.source_path.stem
    candidates = [
        target_dir / f"{artifact_stem}{suffix}"
        for artifact_stem in (stem, f"{stem}__mypyc")
        for suffix in importlib.machinery.EXTENSION_SUFFIXES
    ]
    return sorted(path for path in candidates if path.is_file())


def _module_marker(module_state: ModuleState) -> Path:
    return module_state.marker_path


def _setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build optional mypyc-compiled modules.")
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, (os.cpu_count() or 1) - 1),
        help="Maximum parallel native build jobs; defaults to the host CPU count minus one.",
    )
    parser.add_argument(
        "setup_args",
        nargs="*",
        help="Arguments forwarded to setuptools (e.g. 'build_ext --inplace').",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=[],
        help="Extra modules to compile (append dotted module names).",
    )
    parser.add_argument(
        "--inplace",
        action="store_true",
        help="Write extensions into the source tree (legacy opt-in; unsafe for normal pytest runs).",
    )
    return parser


def _module_to_path(value: str) -> str:
    """Convert dotted module names to source file paths for mypyc CLI compatibility."""
    if value.endswith(".py"):
        return value
    if value.startswith("angr_platforms.angr_platforms."):
        raise ValueError(
            "compile the public angr_platforms.X86_16 module name; nested aliases split runtime type identity"
        )
    parts = value.split(".")
    if parts[0] == "angr_platforms":
        parts.insert(1, "angr_platforms")
    return str(Path(*parts)).replace("\\", "/") + ".py"


def _ensure_build_layout(modules: list[str]) -> None:
    """Reconcile schema and cohort state without rebuilding unchanged modules."""
    layout = MypycBuildCacheLayout(
        REPO_ROOT, MYPYC_CACHE_DIR, MYPYC_LIB_DIR, MYPYC_CGEN_DIR, MYPYC_BUILD_SCHEMA
    )
    reconcile_mypyc_build_cache(layout, modules, _module_to_path)


def _collect_module_states(modules: Iterable[str]) -> list[ModuleState]:
    cache_root = REPO_ROOT / MYPYC_CACHE_DIR
    cache_root.mkdir(parents=True, exist_ok=True)
    states: list[ModuleState] = []
    for module in modules:
        source_path = (REPO_ROOT / _module_to_path(module)).resolve()
        marker_path = cache_root / (str(source_path.relative_to(REPO_ROOT)).replace("/", "__") + ".stamp")
        states.append(
            ModuleState(
                module=module,
                source_path=source_path,
                marker_path=marker_path,
            )
        )
    return states


def _build_stale(module_states: list[ModuleState], *, inplace: bool = False) -> list[ModuleState]:
    stale: list[ModuleState] = []
    control_inputs = [REPO_ROOT / path for path in ("pyproject.toml", "scripts/build_mypyc.py", "scripts/mypyc_build_cache.py")]
    for module_state in module_states:
        source_mtime = module_state.source_path.stat().st_mtime if module_state.source_path.exists() else 0
        control_mtime = max((item.stat().st_mtime for item in control_inputs if item.exists()), default=0)
        marker = _module_marker(module_state)
        artifacts = _module_artifact_candidates(module_state, inplace=inplace)
        if len(artifacts) < 2:
            stale.append(module_state)
            continue
        latest_artifact_mtime = max(artifact.stat().st_mtime for artifact in artifacts)
        if marker.exists() and marker.stat().st_mtime >= max(source_mtime, control_mtime, latest_artifact_mtime):
            continue
        stale.append(module_state)
    return stale


def _refresh_markers(module_states: list[ModuleState]) -> None:
    marker_time = max((int(state.source_path.stat().st_mtime) for state in module_states), default=0)
    marker_epoch = marker_time if marker_time else 0
    for module_state in module_states:
        module_state.marker_path.write_text(f"{module_state.source_path} {marker_epoch}\n")


def _compiled_import_smoke(module_states: list[ModuleState]) -> int:
    """Import every compiled host from the isolated output directory."""
    result: int = run_compiled_import_smoke(
        modules=(module_state.module for module_state in module_states),
        lib_path=(REPO_ROOT / MYPYC_LIB_DIR).resolve(),
        source_path=REPO_ROOT.resolve(),
        python_executable=Path(sys.executable),
    )
    return result


def _isolated_package_sources() -> dict[str, Path]:
    """Return source package roots copied beside isolated native artifacts."""
    return {
        "inertia_decompiler": REPO_ROOT / "inertia_decompiler",
        "angr_platforms": REPO_ROOT / "angr_platforms" / "angr_platforms",
    }


def _prepare_isolated_package() -> None:
    """Make the isolated output a regular importable package tree.

    Source synchronization runs before bundle staging so the staged manifest
    is always a fresh byte copy bound to the current copied lifter source. A
    missing or stale verified Cython build leaves no usable bundle and the
    import smoke then fails closed through the normal backend error.
    """
    output_root = REPO_ROOT / MYPYC_LIB_DIR
    sync_isolated_package_sources(
        output_root=output_root,
        package_sources=_isolated_package_sources(),
    )
    stage_isolated_vex_extension(repo_root=REPO_ROOT, artifact_root=output_root)


def _import_smoke_identity(modules: Iterable[str]) -> str:
    """Return the exact current identity guarded by the native import smoke."""
    identity: str = build_mypyc_import_smoke_identity(
        modules=modules,
        package_sources=_isolated_package_sources(),
        artifact_root=REPO_ROOT / MYPYC_LIB_DIR,
        control_inputs=(
            REPO_ROOT / "pyproject.toml",
            Path(__file__).resolve(),
            REPO_ROOT / "scripts" / "mypyc_build_cache.py",
        ),
        schema=MYPYC_IMPORT_SMOKE_SCHEMA,
    )
    return identity


def _publish_import_smoke(module_states: list[ModuleState]) -> int:
    """Run the native import smoke and attest its exact successful inputs."""
    result = _compiled_import_smoke(module_states)
    if result == 0:
        identity = _import_smoke_identity(state.module for state in module_states)
        write_import_smoke_attestation(REPO_ROOT / MYPYC_IMPORT_SMOKE_ATTESTATION, identity)
    return result


def main(argv: list[str] | None = None) -> int:
    """Build stale configured modules with bounded native parallelism."""
    parser = _setup_parser()
    parsed, setup_args = parser.parse_known_args(argv)

    try:
        modules = list(dict.fromkeys(module for module in (TARGET_MODULES + list(parsed.module)) if module))
        if not modules:
            return 0

        if not parsed.inplace:
            _ensure_build_layout(modules)
        module_states = _collect_module_states(modules)
        stale_module_states = _build_stale(module_states, inplace=parsed.inplace)
        if not stale_module_states:
            print("mypyc: up-to-date; skipping build")
            if not parsed.inplace:
                identity = _import_smoke_identity(modules)
                attestation = REPO_ROOT / MYPYC_IMPORT_SMOKE_ATTESTATION
                if import_smoke_attestation_matches(attestation, identity):
                    print("mypyc: import smoke attestation matched; skipping import")
                    return 0
                _prepare_isolated_package()
                return _publish_import_smoke(module_states)
            return 0

        from mypyc.build import mypycify
        from setuptools import setup
    except Exception as exc:  # pragma: no cover
        print("mypy/mypyc is required for this build path. Install with: pip install .[mypyc]")
        print(f"Original error: {exc}")
        return 1

    stale_modules = [stale_state.module for stale_state in stale_module_states]
    module_paths = [_module_to_path(module) for module in stale_modules]
    if not module_paths:
        print("mypyc: no stale modules to compile")
        return 0

    output_lib = REPO_ROOT / MYPYC_LIB_DIR
    output_temp = REPO_ROOT / MYPYC_TEMP_DIR
    output_lib.mkdir(parents=True, exist_ok=True)
    output_temp.mkdir(parents=True, exist_ok=True)
    default_setup_args = [
        "build_ext",
        "--inplace" if parsed.inplace else f"--build-lib={output_lib}",
        f"--build-temp={output_temp}",
        "--parallel",
        str(max(1, parsed.jobs)),
    ]
    previous_mypypath = os.environ.get("MYPYPATH")
    os.environ["MYPYPATH"] = str(REPO_ROOT / "angr_platforms")
    try:
        extension_modules = mypycify(
            ["--explicit-package-bases", *module_paths],
            separate=True,
            target_dir=str(REPO_ROOT / MYPYC_CGEN_DIR),
        )
    finally:
        if previous_mypypath is None:
            os.environ.pop("MYPYPATH", None)
        else:
            os.environ["MYPYPATH"] = previous_mypypath

    setup(
        name="vextest-x86-16-mypyc",
        version="0.1",
        package_dir={"": "."},
        packages=["inertia_decompiler"],
        ext_modules=extension_modules,
        script_name=sys.argv[0],
        script_args=setup_args if setup_args else default_setup_args,
    )
    _refresh_markers(stale_module_states)
    if not parsed.inplace:
        _prepare_isolated_package()
        return _publish_import_smoke(module_states)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
