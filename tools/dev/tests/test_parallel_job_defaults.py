"""Regression tests for bounded N-1 development-tool parallelism."""

from __future__ import annotations

import os
import subprocess
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

from pytest import MonkeyPatch

from tools.dev import build_mypyc, mypyc_build_cache

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_build_mypyc_defaults_to_cpu_count_minus_one(monkeypatch: MonkeyPatch) -> None:
    """Keep one CPU free when mypyc chooses its native build job count."""
    monkeypatch.setattr(build_mypyc.os, "cpu_count", lambda: 8)

    parsed = build_mypyc._setup_parser().parse_args([])

    assert parsed.jobs == 7


def test_build_mypyc_uses_canonical_inertia_module_identity() -> None:
    """Compile the canonical package name from its authoritative source."""
    assert not any(module.startswith("angr_platforms.angr_platforms.") for module in build_mypyc.TARGET_MODULES)
    assert build_mypyc._module_to_path("inertia.validation.validation_calls") == (
        "inertia/validation/validation_calls.py"
    )


def test_build_mypyc_rejects_nested_alias_target() -> None:
    """Refuse native modules that would duplicate public runtime type identity."""
    try:
        build_mypyc._module_to_path("inertia.validation.validation_calls")
    except ValueError as exc:
        assert "split runtime type identity" in str(exc)
    else:
        raise AssertionError("nested mypyc target unexpectedly accepted")


def test_build_mypyc_requires_main_and_native_helper_artifacts(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Treat a half-written separate mypyc extension pair as stale."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-lib"))
    source_path = tmp_path / "inertia_decompiler" / "sample.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("value = 1\n", encoding="utf-8")
    state = build_mypyc.ModuleState(
        module="inertia_decompiler.sample",
        source_path=source_path,
        marker_path=tmp_path / "sample.stamp",
    )
    target_dir = tmp_path / "native-lib" / "inertia_decompiler"
    target_dir.mkdir(parents=True)
    suffix = EXTENSION_SUFFIXES[0]
    (target_dir / f"sample{suffix}").write_bytes(b"main")

    assert len(build_mypyc._module_artifact_candidates(state)) == 1
    assert build_mypyc._build_stale([state]) == [state]

    (target_dir / f"sample__mypyc{suffix}").write_bytes(b"native")
    state.marker_path.write_text("ready\n", encoding="utf-8")
    newest = max(path.stat().st_mtime for path in build_mypyc._module_artifact_candidates(state))
    os.utime(state.marker_path, (newest + 1, newest + 1))
    assert build_mypyc._build_stale([state]) == []


def test_build_mypyc_reconciles_only_changed_module_artifacts(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Preserve unchanged artifacts while removing a retired module exactly."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-cache/lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))

    build_mypyc._ensure_build_layout(["example.alpha"])
    sentinel = tmp_path / "native-cache" / "old-extension.so"
    sentinel.write_bytes(b"native")
    artifact_dir = tmp_path / "native-cache" / "lib" / "example"
    artifact_dir.mkdir(parents=True)
    suffix = EXTENSION_SUFFIXES[0]
    alpha_main = artifact_dir / f"alpha{suffix}"
    alpha_native = artifact_dir / f"alpha__mypyc{suffix}"
    alpha_main.write_bytes(b"main")
    alpha_native.write_bytes(b"native")
    build_mypyc._ensure_build_layout(["example.alpha"])
    assert sentinel.is_file()
    assert alpha_main.is_file()
    assert alpha_native.is_file()

    build_mypyc._ensure_build_layout(["example.beta"])
    assert sentinel.is_file()
    assert not alpha_main.exists()
    assert not alpha_native.exists()
    assert (tmp_path / "native-cache" / "build-schema.txt").read_text(encoding="utf-8") == (
        f"{build_mypyc.MYPYC_BUILD_SCHEMA}\n"
    )
    assert (tmp_path / "native-cache" / "module-cohort.txt").read_text(encoding="utf-8") == (
        "example.beta\n"
    )


def test_build_mypyc_schema_change_resets_complete_cache(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Discard every old artifact when native compatibility schema changes."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-cache/lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))
    build_mypyc._ensure_build_layout(["example.alpha"])
    sentinel = tmp_path / "native-cache" / "old-extension.so"
    sentinel.write_bytes(b"native")

    monkeypatch.setattr(build_mypyc, "MYPYC_BUILD_SCHEMA", "next-schema")
    build_mypyc._ensure_build_layout(["example.alpha"])

    assert not sentinel.exists()
    assert (tmp_path / "native-cache" / "build-schema.txt").read_text(encoding="utf-8") == (
        "next-schema\n"
    )


def test_build_mypyc_refuses_artifact_directory_outside_cache(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Fail closed before cache reconciliation can target an external path."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("outside-native-lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))

    try:
        build_mypyc._ensure_build_layout(["example.alpha"])
    except ValueError as exc:
        assert "escapes cache root" in str(exc)
    else:
        raise AssertionError("external mypyc artifact directory unexpectedly accepted")


def test_build_mypyc_refuses_nested_artifact_symlink_outside_cache(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Do not follow a nested package symlink while retiring one module."""
    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "MYPYC_CACHE_DIR", Path("native-cache"))
    monkeypatch.setattr(build_mypyc, "MYPYC_LIB_DIR", Path("native-cache/lib"))
    monkeypatch.setattr(build_mypyc, "MYPYC_CGEN_DIR", Path("native-cache/cgen"))
    build_mypyc._ensure_build_layout(["example.alpha"])
    package_parent = tmp_path / "native-cache" / "lib"
    package_parent.mkdir(parents=True)
    external_package = tmp_path / "external-package"
    external_package.mkdir()
    external_artifact = external_package / f"alpha{EXTENSION_SUFFIXES[0]}"
    external_artifact.write_bytes(b"external")
    (package_parent / "example").symlink_to(external_package, target_is_directory=True)

    try:
        build_mypyc._ensure_build_layout([])
    except ValueError as exc:
        assert "escapes cache root" in str(exc)
    else:
        raise AssertionError("nested external artifact symlink unexpectedly followed")
    assert external_artifact.read_bytes() == b"external"


def test_mypyc_import_smoke_identity_tracks_exact_inputs(tmp_path: Path) -> None:
    """Invalidate smoke evidence for same-size source, artifact, or cohort changes."""
    source_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    source_root.mkdir()
    artifact_root.mkdir()
    source = source_root / "module.py"
    copied_source = artifact_root / "example" / "module.py"
    artifact = artifact_root / f"module{EXTENSION_SUFFIXES[0]}"
    control = tmp_path / "control.py"
    source.write_text("x=1\n", encoding="utf-8")
    copied_source.parent.mkdir()
    copied_source.write_text("x=1\n", encoding="utf-8")
    artifact.write_bytes(b"native-a")
    control.write_text("schema=1\n", encoding="utf-8")

    def identity(*, modules: tuple[str, ...] = ("example.module",)) -> str:
        return mypyc_build_cache.build_mypyc_import_smoke_identity(
            modules=modules,
            package_sources={"example": source_root},
            artifact_root=artifact_root,
            control_inputs=(control,),
            schema="test-schema",
        )

    original = identity()
    source.write_text("x=2\n", encoding="utf-8")
    source_changed = identity()
    artifact.write_bytes(b"native-b")

    assert source_changed != original
    artifact_changed = identity()
    assert artifact_changed != source_changed
    copied_source.write_text("x=2\n", encoding="utf-8")
    assert identity() != artifact_changed
    assert identity(modules=("example.other",)) != identity()


def test_mypyc_import_smoke_attestation_is_exact_and_fail_closed(tmp_path: Path) -> None:
    """Accept only an atomically published exact ASCII identity."""
    path = tmp_path / "import-smoke.sha256"
    mypyc_build_cache.write_import_smoke_attestation(path, "expected")
    assert mypyc_build_cache.import_smoke_attestation_matches(path, "expected")

    path.write_bytes(b"\xff")
    assert not mypyc_build_cache.import_smoke_attestation_matches(path, "expected")
    assert not mypyc_build_cache.import_smoke_attestation_matches(tmp_path / "missing", "expected")


def test_mypyc_package_sync_removes_stale_source_but_preserves_native(tmp_path: Path) -> None:
    """Mirror copied package files without deleting native extension artifacts."""
    source_root = tmp_path / "source"
    output_root = tmp_path / "lib"
    source_root.mkdir()
    (source_root / "current.py").write_text("value = 1\n", encoding="utf-8")
    output_package = output_root / "example"
    output_package.mkdir(parents=True)
    stale = output_package / "stale.py"
    native = output_package / f"current{EXTENSION_SUFFIXES[0]}"
    stale.write_text("stale = True\n", encoding="utf-8")
    native.write_bytes(b"native")

    mypyc_build_cache.sync_isolated_package_sources(
        output_root=output_root,
        package_sources={"example": source_root},
    )

    assert (output_package / "current.py").read_text(encoding="utf-8") == "value = 1\n"
    assert not stale.exists()
    assert native.read_bytes() == b"native"


def test_build_mypyc_skips_only_attested_warm_import_smoke(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Avoid package sync and import only when exact warm evidence matches."""
    source = tmp_path / "sample.py"
    source.write_text("value = 1\n", encoding="utf-8")
    state = build_mypyc.ModuleState("example.sample", source, tmp_path / "sample.stamp")
    observed: list[str] = []

    monkeypatch.setattr(build_mypyc, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(build_mypyc, "TARGET_MODULES", ["example.sample"])
    monkeypatch.setattr(build_mypyc, "_ensure_build_layout", lambda modules: None)
    monkeypatch.setattr(build_mypyc, "_collect_module_states", lambda modules: [state])
    monkeypatch.setattr(build_mypyc, "_build_stale", lambda states, inplace=False: [])
    monkeypatch.setattr(build_mypyc, "_import_smoke_identity", lambda modules: "identity")
    monkeypatch.setattr(build_mypyc, "import_smoke_attestation_matches", lambda path, identity: True)
    monkeypatch.setattr(build_mypyc, "_prepare_isolated_package", lambda: observed.append("sync"))
    monkeypatch.setattr(build_mypyc, "_publish_import_smoke", lambda states: observed.append("smoke") or 0)

    assert build_mypyc.main([]) == 0
    assert observed == []

    monkeypatch.setattr(build_mypyc, "import_smoke_attestation_matches", lambda path, identity: False)
    assert build_mypyc.main([]) == 0
    assert observed == ["sync", "smoke"]


def test_make_parallel_defaults_share_cpu_budget() -> None:
    """Keep tools on N-1 CPUs and pytest on its bounded default pool."""
    make_fragment = """print-parallel:
	@printf '%s\\n' '$(PARALLEL_JOBS)' '$(PYTEST_ARGS)' '$(PYTEST_ALL_WORKERS)' '$(PYTEST_ALL_HEAVY_WORKERS)' '$(PYTEST_ALL_HEAVY_SHARDS)' '$(LINT_JOBS)' '$(MYPYC_JOBS)' '$(PIPELINE_WORKERS)'
"""
    env = {**os.environ, "PYTEST_ADDOPTS": ""}
    for inherited_make_variable in (
        "MAKEFLAGS",
        "MFLAGS",
        "MAKELEVEL",
        "LINT_JOBS",
        "MYPYC_JOBS",
        "PARALLEL_JOBS",
        "PIPELINE_WORKERS",
        "PYTEST_ALL_HEAVY_SHARDS",
        "PYTEST_ALL_HEAVY_WORKERS",
        "PYTEST_ALL_WORKERS",
        "PYTEST_WORKERS",
        "PYTEST_ARGS",
    ):
        env.pop(inherited_make_variable, None)
    result = subprocess.run(
        [
            "make",
            "-s",
            "--no-print-directory",
            "--eval",
            make_fragment,
            "CPU_COUNT=8",
            "print-parallel",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.stdout.splitlines() == [
        "7",
        "--tb=short --no-header -p tools.dev.pytest_directory_cache -n 3 --dist loadgroup --durations=5",
        "3",
        "2",
        "16",
        "7",
        "7",
        "7",
    ]
