"""Loader controls for the optional native hotspot cohort.

The import boundary must bind exactly the artifact the selected backend
receipt records: interpreted ``.py`` for ``python``, the verified
``.cache/cython-hotspots`` extension for ``cython``/verified ``auto``.
Verifier negative controls prove stale or escaping manifests never activate,
and non-cohort modules always keep their ordinary import path.
"""

from __future__ import annotations

import json
import sys
import sysconfig
from importlib.machinery import EXTENSION_SUFFIXES, ExtensionFileLoader
from pathlib import Path

import pytest

from inertia.hotspot_import import (
    BACKEND_ENV,
    HotspotBackend,
    HotspotImportFinder,
)
from inertia.native_bundle import file_digest

pytestmark = pytest.mark.decompiler

_PACKAGE_DIR = Path(__file__).resolve().parents[2] / "inertia"
_MODULE = "inertia.cli.sidecar_policy"
_STEM = "sidecar_policy"


def _module_cache(cache: Path, module: str = _MODULE) -> Path:
    """Return the per-module confinement directory for a fake bundle."""
    return cache.joinpath(*module.split("."))


def _write_bundle(cache: Path, source: Path, *, extension_bytes: bytes = b"native") -> Path:
    """Publish one schema-1 manifest layout matching the production builder."""
    module_cache = _module_cache(cache)
    lib = module_cache / "cohort" / "lib" / "inertia" / "cli"
    lib.mkdir(parents=True)
    extension = lib / (_STEM + EXTENSION_SUFFIXES[0])
    extension.write_bytes(extension_bytes)
    manifest = {
        "schema": 1,
        "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "source_sha256": file_digest(source),
        "extension": str(extension.relative_to(module_cache)),
        "extension_sha256": file_digest(extension),
    }
    module_cache.mkdir(parents=True, exist_ok=True)
    (module_cache / "active.json").write_text(json.dumps(manifest))
    return extension


def _write_cohort(cache: Path, modules: list[str]) -> None:
    """Publish the cohort member list the production builder emits."""
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "cohort.json").write_text(json.dumps({"schema": 1, "modules": modules}))


def _finder(cache: Path, backend: str, monkeypatch: pytest.MonkeyPatch) -> HotspotImportFinder:
    """Build a finder bound to one backend mode and cache root."""
    monkeypatch.setenv(BACKEND_ENV, backend)
    return HotspotImportFinder(_PACKAGE_DIR, cache)


def test_python_mode_never_loads_native(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``python`` returns no spec even beside a verified extension."""
    source = _PACKAGE_DIR / "cli" / "sidecar_policy.py"
    _write_bundle(tmp_path, source)
    _write_cohort(tmp_path, [_MODULE])
    finder = _finder(tmp_path, "python", monkeypatch)
    assert finder.find_spec(_MODULE) is None


def test_auto_mode_loads_verified_extension(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``auto`` binds the extension only when source and artifact digests match."""
    source = _PACKAGE_DIR / "cli" / "sidecar_policy.py"
    _write_bundle(tmp_path, source)
    _write_cohort(tmp_path, [_MODULE])
    finder = _finder(tmp_path, "auto", monkeypatch)
    spec = finder.find_spec(_MODULE)
    assert spec is not None
    assert isinstance(spec.loader, ExtensionFileLoader)
    assert spec.name == _MODULE


def test_cython_mode_loads_verified_extension(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``cython`` binds the verified extension for a cohort member."""
    source = _PACKAGE_DIR / "cli" / "sidecar_policy.py"
    _write_bundle(tmp_path, source)
    _write_cohort(tmp_path, [_MODULE])
    finder = _finder(tmp_path, "cython", monkeypatch)
    spec = finder.find_spec(_MODULE)
    assert spec is not None
    assert isinstance(spec.loader, ExtensionFileLoader)


def test_cython_mode_refuses_stale_cohort_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``cython`` fails loudly when a cohort member's build is stale."""
    source = _PACKAGE_DIR / "cli" / "sidecar_policy.py"
    _write_bundle(tmp_path, source, extension_bytes=b"forged")
    module_cache = _module_cache(tmp_path)
    manifest = json.loads((module_cache / "active.json").read_text())
    manifest["extension_sha256"] = "0" * 64
    (module_cache / "active.json").write_text(json.dumps(manifest))
    _write_cohort(tmp_path, [_MODULE])
    finder = _finder(tmp_path, "cython", monkeypatch)
    with pytest.raises(ImportError, match="missing or stale"):
        finder.find_spec(_MODULE)


def test_cython_mode_refuses_missing_cohort_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``cython`` fails loudly when a cohort member never produced a bundle."""
    _write_cohort(tmp_path, [_MODULE])
    finder = _finder(tmp_path, "cython", monkeypatch)
    with pytest.raises(ImportError, match="missing or stale"):
        finder.find_spec(_MODULE)


def test_auto_mode_falls_back_on_stale_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``auto`` interprets Python when the recorded artifact no longer verifies."""
    source = _PACKAGE_DIR / "cli" / "sidecar_policy.py"
    _write_bundle(tmp_path, source)
    module_cache = _module_cache(tmp_path)
    manifest = json.loads((module_cache / "active.json").read_text())
    manifest["source_sha256"] = "0" * 64
    (module_cache / "active.json").write_text(json.dumps(manifest))
    _write_cohort(tmp_path, [_MODULE])
    finder = _finder(tmp_path, "auto", monkeypatch)
    assert finder.find_spec(_MODULE) is None


def test_non_cohort_modules_keep_ordinary_imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Modules outside the builder's cohort resolve normally in every mode."""
    _write_cohort(tmp_path, [_MODULE])
    for backend in ("python", "auto", "cython"):
        finder = _finder(tmp_path, backend, monkeypatch)
        assert finder.find_spec("inertia.cli.generated_c_artifacts") is None, backend
        assert finder.find_spec("inertia.hotspot_import") is None, backend
        assert finder.find_spec("os.path") is None, backend
        assert finder.find_spec("inertia.cli") is None, backend


def test_malformed_cohort_manifest_is_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A corrupt cohort list yields no members instead of a guessing cohort."""
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "cohort.json").write_text("{not json")
    finder = _finder(tmp_path, "cython", monkeypatch)
    assert finder.cohort() == frozenset()


def test_invalid_backend_env_is_loud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unknown backend selections raise instead of silently choosing a lane."""
    monkeypatch.setenv(BACKEND_ENV, "wasm")
    finder = HotspotImportFinder(_PACKAGE_DIR, tmp_path)
    with pytest.raises(ValueError, match=BACKEND_ENV):
        finder.backend()


def test_backend_modes() -> None:
    """The tri-state enum keeps the canonical lane names."""
    assert [backend.value for backend in HotspotBackend] == ["python", "cython", "auto"]
