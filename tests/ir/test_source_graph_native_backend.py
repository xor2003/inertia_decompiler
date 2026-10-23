"""Loader controls for the optional native source-graph binding.

The ordinary import boundary must bind exactly the artifact the selected
backend receipt records: interpreted ``.py`` for ``python``, the verified
``.cache/cython-source-graph`` extension for ``cython``/verified ``auto``.
Verifier negative controls prove stale or escaping manifests never activate.
"""

from __future__ import annotations

import json
import sys
import sysconfig
from importlib.machinery import EXTENSION_SUFFIXES, ExtensionFileLoader
from pathlib import Path

import pytest

import inertia.ir.source_graph_binding as graph
from inertia.ir.source_graph_import import (
    BACKEND_ENV,
    SourceGraphBackend,
    SourceGraphImportFinder,
    selected_source_graph_backend,
)
from inertia.native_bundle import file_digest, verified_bundle_directory

pytestmark = pytest.mark.decompiler

_PACKAGE_DIR = Path(graph.__file__).resolve().parent


def _write_bundle(cache: Path, source: Path, *, extension_bytes: bytes = b"native") -> Path:
    """Publish one schema-1 manifest layout matching the production builder."""
    lib = cache / "cohort" / "lib" / "inertia" / "ir"
    lib.mkdir(parents=True)
    extension = lib / ("source_graph_binding" + EXTENSION_SUFFIXES[0])
    extension.write_bytes(extension_bytes)
    manifest = {
        "schema": 1,
        "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "source_sha256": file_digest(source),
        "extension": str(extension.relative_to(cache)),
        "extension_sha256": file_digest(extension),
    }
    (cache / "active.json").write_text(json.dumps(manifest))
    return extension


def test_selected_backend_matches_loaded_artifact() -> None:
    """The recorded receipt must agree with the module origin actually bound."""
    backend = selected_source_graph_backend()
    path = Path(graph.__file__).resolve()
    if backend is SourceGraphBackend.PYTHON:
        assert path == _PACKAGE_DIR / "source_graph_binding.py", f"backend={backend} loaded {path}"
    else:
        assert path.suffix == ".so" and ".cache/cython-source-graph" in path.as_posix(), (
            f"backend={backend} loaded {path}"
        )


def test_verified_bundle_activates_in_cython_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A digest-exact manifest binds the extension through an ExtensionFileLoader."""
    source = tmp_path / "pkg" / "source_graph_binding.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"# candidate\n")
    cache = tmp_path / "cache"
    extension = _write_bundle(cache, source)
    monkeypatch.setenv(BACKEND_ENV, "cython")
    finder = SourceGraphImportFinder(source.parent, cache)
    spec = finder.find_spec("inertia.ir.source_graph_binding")
    assert spec is not None and isinstance(spec.loader, ExtensionFileLoader)
    assert Path(spec.origin) == extension


@pytest.mark.parametrize(
    "corrupt",
    [
        "schema",
        "source_sha256",
        "extension_sha256",
        "cache_tag",
        "extension_name",
        "escape",
    ],
)
def test_verifier_rejects_corrupted_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corrupt: str,
) -> None:
    """Every schema/ABI/digest/confinement mismatch must refuse activation."""
    source = tmp_path / "pkg" / "source_graph_binding.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"# candidate\n")
    cache = tmp_path / "cache"
    _write_bundle(cache, source)
    manifest = json.loads((cache / "active.json").read_text())
    if corrupt == "schema":
        manifest["schema"] = 2
    elif corrupt == "source_sha256":
        manifest["source_sha256"] = "0" * 64
    elif corrupt == "extension_sha256":
        manifest["extension_sha256"] = "0" * 64
    elif corrupt == "cache_tag":
        manifest["cache_tag"] = "cpython-999"
    elif corrupt == "extension_name":
        manifest["extension"] = manifest["extension"].replace("source_graph_binding", "other_module")
    elif corrupt == "escape":
        manifest["extension"] = "../outside.so"
        (tmp_path / "outside.so").write_bytes(b"escape")
    (cache / "active.json").write_text(json.dumps(manifest))
    assert verified_bundle_directory(
        cache / "active.json", cache, source, "source_graph_binding",
    ) is None
    monkeypatch.setenv(BACKEND_ENV, "cython")
    finder = SourceGraphImportFinder(source.parent, cache)
    with pytest.raises(ImportError):
        finder.find_spec("inertia.ir.source_graph_binding")


def test_missing_build_refuses_only_cython_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Absent artifacts are a loud refusal in ``cython`` and a fallback in ``auto``."""
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "source_graph_binding.py").write_bytes(b"# candidate\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv(BACKEND_ENV, "cython")
    finder = SourceGraphImportFinder(package, cache)
    with pytest.raises(ImportError):
        finder.find_spec("inertia.ir.source_graph_binding")
    monkeypatch.setenv(BACKEND_ENV, "auto")
    fallback = SourceGraphImportFinder(package, cache)
    spec = fallback.find_spec("inertia.ir.source_graph_binding")
    assert spec is not None and Path(spec.origin).name == "source_graph_binding.py"


def test_other_modules_and_bogus_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The finder is exact-module only and rejects unknown backend values."""
    package = tmp_path / "pkg"
    package.mkdir()
    finder = SourceGraphImportFinder(package, tmp_path / "cache")
    assert finder.find_spec("inertia.ir.source_graph_json") is None
    monkeypatch.setenv(BACKEND_ENV, "bogus")
    with pytest.raises(ValueError, match=BACKEND_ENV):
        finder.find_spec("inertia.ir.source_graph_binding")
