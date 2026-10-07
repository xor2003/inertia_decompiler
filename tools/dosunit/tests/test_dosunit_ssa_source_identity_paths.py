"""Fresh source identity parity and mutation controls for production lowering."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import tools.dosunit.reporting.ssa_provenance as owner
from tools.dosunit.contracts.model import canonical_json_bytes

_ROOT = Path(owner.__file__).resolve().parents[3]


def _reference_hash(root: Path) -> str:
    """Retain the original source-set/key contract as an independent oracle."""
    paths = [root / "tools/dosunit/compare/straightline_ssa.py",
             root / "tools/dosunit/catalog/solver_slice.py",
             root / "tools/dosunit/reporting/ssa_provenance.py"]
    paths.extend((root / "inertia").rglob("*.py"))
    paths.extend((root / "tools/dosunit").rglob("*.py"))
    sources = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted(set(paths))}
    return hashlib.sha256(canonical_json_bytes(sources)).hexdigest()


def test_installed_layout_hashes_frontend_and_preserves_missing_source_errors(tmp_path: Path, monkeypatch) -> None:
    source_owner = tmp_path / "tools/dosunit/reporting/ssa_provenance.py"
    source_owner.parent.mkdir(parents=True)
    for path in ("tools/dosunit/reporting/ssa_provenance.py", "tools/dosunit/compare/straightline_ssa.py", "tools/dosunit/catalog/solver_slice.py"):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("source")
    migrated = tmp_path / "inertia/frontend/x86_16/arch_86_16.py"
    migrated.parent.mkdir(parents=True)
    migrated.write_text("first")
    monkeypatch.setattr(owner, "__file__", str(source_owner))
    before = owner._semantic_hash()
    migrated.write_text("other")
    assert owner._semantic_hash() != before
    (tmp_path / "tools/dosunit/compare/straightline_ssa.py").unlink()
    with pytest.raises(FileNotFoundError):
        owner._semantic_hash()


@pytest.mark.parametrize("suffix", [".", "nested/child.py", "Unicode \u03b1 space.py", "a/../child.py"])
def test_exact_path_key_parity(tmp_path: Path, suffix: str) -> None:
    source = tmp_path / suffix
    assert owner._relative_source_key(source, tmp_path) == str(source.relative_to(tmp_path))


def test_outside_root_failure_remains_loud(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        owner._relative_source_key(tmp_path.parent / "sibling.py", tmp_path)


def test_full_owned_source_set_keys_match_current_owner() -> None:
    paths = sorted({_ROOT / "tools/dosunit/compare/straightline_ssa.py",
                        _ROOT / "tools/dosunit/catalog/solver_slice.py",
                        _ROOT / "tools/dosunit/reporting/ssa_provenance.py",
                        *(_ROOT / "tools/dosunit").rglob("*.py"),
                        *(_ROOT / "inertia").rglob("*.py")})
    assert paths
    assert [owner._relative_source_key(p, _ROOT) for p in paths] == [str(p.relative_to(_ROOT)) for p in paths]
    assert owner._semantic_hash() == _reference_hash(_ROOT)


@pytest.mark.parametrize("mutation_path", [
    "inertia/frontend/x86_16/lift_86_16.py",
    "inertia/__init__.py",
    "inertia/frontend/__init__.py",
    "inertia/frontend/x86_16/__init__.py",
    "inertia/frontend/x86_16/control_coordinates.py",
])
def test_digest_parity_and_same_size_same_timestamp_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation_path: str) -> None:
    source_owner = tmp_path / "tools/dosunit/reporting/ssa_provenance.py"
    source_owner.parent.mkdir(parents=True)
    source_owner.write_text("owner bytes\n")
    for path, data in (("tools/dosunit/compare/straightline_ssa.py", "ssa bytes\n"), ("tools/dosunit/catalog/solver_slice.py", "solver bytes\n")):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data)
    nested = source_owner.parent / "nested"
    nested.mkdir()
    (nested / "\u03b1 child.py").write_text("nested bytes\n")
    frontend = tmp_path / "inertia/frontend/x86_16"
    frontend.mkdir(parents=True)
    mutable = tmp_path / mutation_path
    mutable.parent.mkdir(parents=True, exist_ok=True)
    mutable.write_bytes(b"first")
    monkeypatch.setattr(owner, "__file__", str(source_owner))
    before = _reference_hash(tmp_path)
    assert owner._semantic_hash() == before
    stat = mutable.stat()
    mutable.write_bytes(b"other")
    os.utime(mutable, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    changed = owner._semantic_hash()
    assert changed == _reference_hash(tmp_path) and changed != before
    new = frontend / "new.py"
    new.write_bytes(b"new")
    added = owner._semantic_hash()
    assert added == _reference_hash(tmp_path) and added != changed
    new.unlink()
    assert owner._semantic_hash() == changed
    assert hashlib.sha256(mutable.read_bytes()).digest() != hashlib.sha256(b"first").digest()
