"""Mypyc build and import-artifact ownership for developer tooling.

Layer: Tooling/gates.
Responsibility: reconcile mypyc schema and module-cohort changes, and isolate
only native artifacts that can participate in project imports.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class _DigestWriter(Protocol):
    """Minimal hashlib writer contract used by identity assembly."""

    def update(self, data: bytes, /) -> None:
        """Consume bytes into the digest state."""


@dataclass(frozen=True, slots=True)
class MypycBuildCacheLayout:
    """Describe the isolated mypyc cache paths and compatibility schema."""

    repo_root: Path
    cache_dir: Path
    lib_dir: Path
    cgen_dir: Path
    schema: str

    def __post_init__(self) -> None:
        """Refuse cleanup roots outside the configured cache tree."""
        cache_root = self.cache_root.resolve()
        for owned_dir in (self.lib_dir, self.cgen_dir):
            if not (self.repo_root / owned_dir).resolve().is_relative_to(cache_root):
                raise ValueError(f"mypyc artifact directory escapes cache root: {owned_dir}")

    @property
    def cache_root(self) -> Path:
        """Return the absolute cache root."""
        return self.repo_root / self.cache_dir


def iter_importable_project_extensions(repo_root: Path) -> tuple[Path, ...]:
    """List project extensions reachable through normal source-package imports."""
    search_roots = (
        repo_root / "inertia_decompiler",
        repo_root / "angr_platforms" / "angr_platforms",
    )
    candidates = set(repo_root.glob("*.so"))
    for search_root in search_roots:
        if search_root.is_dir():
            candidates.update(search_root.rglob("*.so"))
    suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    return tuple(sorted(path for path in candidates if path.name.endswith(suffixes)))


@contextmanager
def disable_importable_project_extensions(repo_root: Path) -> Iterator[None]:
    """Temporarily park importable project extensions and restore every file."""
    modules = iter_importable_project_extensions(repo_root)
    moved: list[tuple[Path, Path]] = []
    try:
        for index, path in enumerate(modules):
            parked = path.with_name(f".{path.name}.pure-python-{os.getpid()}-{index}")
            if parked.exists():
                raise FileExistsError(f"pure-Python extension parking path exists: {parked}")
            path.replace(parked)
            moved.append((parked, path))
        yield
    finally:
        conflicts: list[Path] = []
        for parked, original in reversed(moved):
            if not parked.exists():
                continue
            if original.exists():
                conflicts.append(original)
                continue
            parked.replace(original)
        if conflicts:
            paths = ", ".join(str(path) for path in sorted(conflicts))
            raise FileExistsError(f"cannot restore parked Python extensions: {paths}")


def sync_isolated_package_sources(
    *,
    output_root: Path,
    package_sources: Mapping[str, Path],
) -> None:
    """Copy source packages beside isolated native artifacts for smoke imports."""
    for package_name, source_dir in package_sources.items():
        package_output = output_root / package_name
        expected = {
            path.relative_to(source_dir)
            for path in source_dir.rglob("*")
            if path.is_file() and _is_copied_package_file(path, source_dir)
        }
        if package_output.is_dir():
            extension_suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
            for path in sorted(package_output.rglob("*"), reverse=True):
                if path.is_file() and path.relative_to(package_output) not in expected:
                    if not path.name.endswith(extension_suffixes):
                        path.unlink()
                elif path.is_dir():
                    with suppress(OSError):
                        path.rmdir()
        shutil.copytree(
            source_dir,
            package_output,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                ".cache",
                ".pytest_cache",
                "__pycache__",
                "*.egg-info",
                "*.pyc",
                "*.so",
                "*.so.*",
                "*.c",
                "*.pyx",
            ),
        )


def _is_copied_package_file(path: Path, source_root: Path) -> bool:
    """Return whether package synchronization includes one source path."""
    relative = path.relative_to(source_root)
    if any(part in {".cache", ".pytest_cache", "__pycache__"} or part.endswith(".egg-info") for part in relative.parts):
        return False
    name = path.name
    return not (
        name.endswith((".pyc", ".so", ".c", ".pyx"))
        or ".so." in name
    )


def _content_digest(path: Path) -> bytes:
    """Hash one file without accepting a concurrent in-place mutation."""
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise OSError(f"mypyc import input changed while hashing: {path}")
    return digest.digest()


def _update_identity_file(digest: _DigestWriter, *, label: str, path: Path) -> None:
    """Add one path and its exact content digest to an import identity."""
    encoded_label = label.encode("utf-8")
    digest.update(len(encoded_label).to_bytes(8, "big"))
    digest.update(encoded_label)
    digest.update(_content_digest(path))


def _update_package_identity_files(
    digest: _DigestWriter,
    *,
    package_name: str,
    source_root: Path,
    artifact_root: Path,
) -> None:
    """Add one package's source and copied files to an import identity."""
    for path in sorted(candidate for candidate in source_root.rglob("*") if candidate.is_file()):
        if _is_copied_package_file(path, source_root):
            _update_identity_file(
                digest,
                label=f"source:{package_name}/{path.relative_to(source_root).as_posix()}",
                path=path,
            )
    copied_root = artifact_root / package_name
    if copied_root.is_dir():
        for path in sorted(candidate for candidate in copied_root.rglob("*") if candidate.is_file()):
            if _is_copied_package_file(path, copied_root):
                _update_identity_file(
                    digest,
                    label=f"copy:{package_name}/{path.relative_to(copied_root).as_posix()}",
                    path=path,
                )


def build_mypyc_import_smoke_identity(
    *,
    modules: Iterable[str],
    package_sources: Mapping[str, Path],
    artifact_root: Path,
    control_inputs: Iterable[Path],
    schema: str,
) -> str:
    """Return an exact identity for a successful isolated import smoke result."""
    digest = hashlib.sha256()
    for field in (schema, sys.implementation.cache_tag, sys.version, *sorted(set(modules))):
        encoded = field.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    for package_name, source_root in sorted(package_sources.items()):
        _update_package_identity_files(
            digest, package_name=package_name, source_root=source_root, artifact_root=artifact_root
        )
    extension_suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    for path in sorted(candidate for candidate in artifact_root.rglob("*") if candidate.is_file()):
        if path.name.endswith(extension_suffixes):
            _update_identity_file(
                digest,
                label=f"artifact:{path.relative_to(artifact_root).as_posix()}",
                path=path,
            )
    for path in sorted(set(control_inputs)):
        _update_identity_file(digest, label=f"control:{path.name}", path=path)
    return digest.hexdigest()


def import_smoke_attestation_matches(path: Path, identity: str) -> bool:
    """Return whether a readable attestation exactly matches current inputs."""
    try:
        return path.read_text(encoding="ascii").strip() == identity
    except (OSError, UnicodeError):
        return False


def write_import_smoke_attestation(path: Path, identity: str) -> None:
    """Atomically publish a successful import-smoke identity."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(f"{identity}\n", encoding="ascii")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def run_compiled_import_smoke(
    *,
    modules: Iterable[str],
    lib_path: Path,
    source_path: Path,
    python_executable: Path,
) -> int:
    """Import every requested native host from one isolated package tree."""
    module_names = tuple(modules)
    extension_suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    script = "\n".join(
        (
            "import importlib",
            "import os",
            f"names = {module_names!r}",
            f"lib = os.path.realpath({str(lib_path)!r})",
            f"extension_suffixes = {extension_suffixes!r}",
            "paths = []",
            "for name in names:",
            "    module = importlib.import_module(name)",
            "    module_file = module.__file__",
            "    path = '' if module_file is None else os.path.realpath(module_file)",
            "    paths.append((name, path))",
            "bad_location = [(name, path) for name, path in paths if os.path.commonpath((lib, path)) != lib]",
            "bad_native = [(name, path) for name, path in paths if not path.endswith(extension_suffixes)]",
            "print(paths)",
            "raise SystemExit(1 if bad_location or bad_native else 0)",
        )
    )
    result = subprocess.run(
        [str(python_executable), "-c", script],
        cwd=source_path.parent,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(lib_path), str(source_path)))},
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        print("mypyc: compiled import smoke failed")
        return result.returncode
    print(f"mypyc: compiled import smoke passed for {len(module_names)} modules")
    return 0


def _read_lines(path: Path) -> tuple[str, ...]:
    """Read a small cache contract file, refusing missing or unreadable state."""
    try:
        return tuple(line for line in path.read_text(encoding="utf-8").splitlines() if line)
    except OSError:
        return ()


def _remove_module_artifacts(
    layout: MypycBuildCacheLayout,
    module: str,
    module_to_path: Callable[[str], str],
) -> None:
    """Remove one retired module's importable artifacts and generated sources."""
    module_parts = module.split(".")
    if not module_parts or any(not part.isidentifier() for part in module_parts):
        raise ValueError(f"invalid mypyc module name: {module!r}")
    cache_root = layout.cache_root.resolve()
    stem = module_parts[-1]
    target_dir = layout.repo_root / layout.lib_dir / Path(*module_parts[:-1])
    generated_dir = layout.repo_root / layout.cgen_dir / Path(*module_parts[:-1])
    if any(not owned_dir.resolve().is_relative_to(cache_root) for owned_dir in (target_dir, generated_dir)):
        raise ValueError(f"mypyc module artifact directory escapes cache root: {module!r}")
    for artifact_stem in (stem, f"{stem}__mypyc"):
        for suffix in importlib.machinery.EXTENSION_SUFFIXES:
            (target_dir / f"{artifact_stem}{suffix}").unlink(missing_ok=True)

    source_path = Path(module_to_path(module))
    marker_name = str(source_path).replace("/", "__") + ".stamp"
    (layout.cache_root / marker_name).unlink(missing_ok=True)

    for generated_name in (
        f"{stem}.c",
        f"{stem}.h",
        f"__native_{stem}.c",
        f"__native_{stem}.h",
    ):
        (generated_dir / generated_name).unlink(missing_ok=True)


def reconcile_mypyc_build_cache(
    layout: MypycBuildCacheLayout,
    modules: Iterable[str],
    module_to_path: Callable[[str], str],
) -> None:
    """Reconcile schema and cohort state while preserving unrelated artifacts."""
    requested_modules = tuple(sorted(set(modules)))
    cache_root = layout.cache_root
    schema_path = cache_root / "build-schema.txt"
    cohort_path = cache_root / "module-cohort.txt"
    schema_lines = _read_lines(schema_path)
    current_schema = schema_lines[0] if schema_lines else ""

    if current_schema != layout.schema:
        shutil.rmtree(cache_root, ignore_errors=True)
        cache_root.mkdir(parents=True, exist_ok=True)
        previous_modules: tuple[str, ...] = ()
    else:
        cache_root.mkdir(parents=True, exist_ok=True)
        cohort_lines = _read_lines(cohort_path)
        # Read the old combined schema/cohort format during one-way migration.
        previous_modules = cohort_lines or schema_lines[1:]

    requested = frozenset(requested_modules)
    for retired_module in sorted(set(previous_modules) - requested):
        _remove_module_artifacts(layout, retired_module, module_to_path)

    schema_path.write_text(f"{layout.schema}\n", encoding="utf-8")
    cohort_path.write_text("".join(f"{module}\n" for module in requested_modules), encoding="utf-8")
