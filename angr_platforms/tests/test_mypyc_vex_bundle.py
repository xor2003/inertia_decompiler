"""Isolated mypyc trees stage a byte-verified Cython VEX extension bundle."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
import sysconfig
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

from scripts import mypyc_build_cache

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_FILE = REPO_ROOT / "angr_platforms/angr_platforms/X86_16/lifter_backend.py"


def _backend():
    spec = importlib.util.spec_from_file_location("vex_backend_contract_bundle_test", BACKEND_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BACKEND = _backend()
SOURCE_BYTES = b"# pure Python lifter\n"
EXTENSION_BYTES = b"test extension identity"
BUNDLE_RELATIVE = Path("identity/lib/angr_platforms/X86_16") / ("lift_86_16" + EXTENSION_SUFFIXES[0])


def _write_repo_build(repo_root: Path, *, source_bytes: bytes = SOURCE_BYTES, extension: str | None = None) -> Path:
    """Install the backend contract and a verified cache manifest in a root."""
    package_source = repo_root / "angr_platforms" / "angr_platforms" / "X86_16"
    package_source.mkdir(parents=True)
    shutil.copyfile(BACKEND_FILE, package_source / "lifter_backend.py")
    (package_source / "lift_86_16.py").write_bytes(source_bytes)
    cache = repo_root / ".cache" / "cython-vex"
    artifact = cache / BUNDLE_RELATIVE
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(EXTENSION_BYTES)
    manifest = {
        "schema": BACKEND.BUILD_SCHEMA,
        "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "extension": extension if extension is not None else BUNDLE_RELATIVE.as_posix(),
        "extension_sha256": hashlib.sha256(EXTENSION_BYTES).hexdigest(),
    }
    (cache / "active.json").write_text(json.dumps(manifest))
    return artifact


def _isolated_package(artifact_root: Path, *, source_bytes: bytes = SOURCE_BYTES) -> Path:
    """Create the flat copied package directory the isolated tree would hold."""
    package_dir = artifact_root / "angr_platforms" / "X86_16"
    package_dir.mkdir(parents=True)
    (package_dir / "lift_86_16.py").write_bytes(source_bytes)
    shutil.copyfile(BACKEND_FILE, package_dir / "lifter_backend.py")
    return package_dir


def test_stage_isolated_vex_extension_binds_to_copied_source(tmp_path: Path) -> None:
    """The staged bundle is a byte copy verified against the copied lifter."""
    repo_root = tmp_path / "repo"
    artifact_root = tmp_path / "lib"
    artifact = _write_repo_build(repo_root)
    package_dir = _isolated_package(artifact_root)

    directory = mypyc_build_cache.stage_isolated_vex_extension(repo_root=repo_root, artifact_root=artifact_root)

    bundle = package_dir / BACKEND.PACKAGE_BUNDLE
    staged_extension = bundle / BUNDLE_RELATIVE
    assert (bundle / "active.json").read_bytes() == (repo_root / ".cache" / "cython-vex" / "active.json").read_bytes()
    assert staged_extension.read_bytes() == artifact.read_bytes()
    assert directory == staged_extension.parent.resolve()
    assert BACKEND.verified_packaged_extension_directory(package_dir) == staged_extension.parent.resolve()


def test_stage_isolated_vex_extension_fails_closed_without_verified_build(tmp_path: Path) -> None:
    """A missing source build removes a previous bundle instead of reusing it."""
    repo_root = tmp_path / "repo"
    artifact_root = tmp_path / "lib"
    _write_repo_build(repo_root)
    (repo_root / ".cache" / "cython-vex" / "active.json").unlink()
    package_dir = _isolated_package(artifact_root)
    bundle = package_dir / BACKEND.PACKAGE_BUNDLE
    bundle.mkdir(parents=True)
    (bundle / "active.json").write_text("{}")
    (bundle / f"stale{EXTENSION_SUFFIXES[0]}").write_bytes(b"stale")

    assert mypyc_build_cache.stage_isolated_vex_extension(repo_root=repo_root, artifact_root=artifact_root) is None
    assert not bundle.exists()


def test_stage_isolated_vex_extension_rejects_diverged_copied_source(tmp_path: Path) -> None:
    """A staged manifest must match the copied source bytes, not the repository."""
    repo_root = tmp_path / "repo"
    artifact_root = tmp_path / "lib"
    _write_repo_build(repo_root, source_bytes=b"# repository source\n")
    package_dir = _isolated_package(artifact_root, source_bytes=b"# diverged copy\n")

    assert mypyc_build_cache.stage_isolated_vex_extension(repo_root=repo_root, artifact_root=artifact_root) is None
    assert BACKEND.verified_packaged_extension_directory(package_dir) is None


def test_stage_isolated_vex_extension_refuses_foreign_extension_path(tmp_path: Path) -> None:
    """A manifest escaping its cache cannot verify and stages nothing."""
    repo_root = tmp_path / "repo"
    artifact_root = tmp_path / "lib"
    _write_repo_build(repo_root, extension=str(tmp_path / "outside.so"))
    package_dir = _isolated_package(artifact_root)

    assert mypyc_build_cache.stage_isolated_vex_extension(repo_root=repo_root, artifact_root=artifact_root) is None
    assert not (package_dir / BACKEND.PACKAGE_BUNDLE).exists()


def test_package_sync_clears_stale_bundle_manifest_but_keeps_native(tmp_path: Path) -> None:
    """Source sync removes non-source extras; staging re-adds a fresh manifest."""
    source_root = tmp_path / "source-pkg"
    (source_root / "X86_16").mkdir(parents=True)
    (source_root / "X86_16" / "lift_86_16.py").write_bytes(SOURCE_BYTES)
    artifact_root = tmp_path / "lib"
    package_dir = _isolated_package(artifact_root)
    bundle = package_dir / BACKEND.PACKAGE_BUNDLE
    bundle.mkdir()
    manifest = bundle / "active.json"
    manifest.write_text("{}")
    native = bundle / f"stale{EXTENSION_SUFFIXES[0]}"
    native.write_bytes(b"native")

    mypyc_build_cache.sync_isolated_package_sources(
        output_root=artifact_root,
        package_sources={"angr_platforms": source_root},
    )

    assert not manifest.exists()
    assert native.read_bytes() == b"native"


def test_import_smoke_identity_tracks_bundle_manifest_and_extension(tmp_path: Path) -> None:
    """Bundle contents, absence, and mutation all change the smoke identity."""
    source_root = tmp_path / "source-pkg"
    (source_root / "X86_16").mkdir(parents=True)
    (source_root / "X86_16" / "lift_86_16.py").write_bytes(SOURCE_BYTES)
    artifact_root = tmp_path / "lib"
    package_dir = _isolated_package(artifact_root)
    bundle = package_dir / BACKEND.PACKAGE_BUNDLE / "identity"
    bundle.mkdir(parents=True)
    manifest = bundle.parent / "active.json"
    manifest.write_text('{"schema": 1}')
    staged_extension = bundle / ("lift_86_16" + EXTENSION_SUFFIXES[0])
    staged_extension.write_bytes(b"native")

    def identity() -> str:
        return mypyc_build_cache.build_mypyc_import_smoke_identity(
            modules=("angr_platforms.X86_16.lift_86_16",),
            package_sources={"angr_platforms": source_root},
            artifact_root=artifact_root,
            control_inputs=(),
            schema="test-schema",
        )

    base = identity()
    manifest.write_text('{"schema": 2}')
    manifest_changed = identity()
    staged_extension.write_bytes(b"changed")
    artifact_changed = identity()
    manifest.unlink()
    staged_extension.unlink()
    missing = identity()

    assert len({base, manifest_changed, artifact_changed, missing}) == 4
