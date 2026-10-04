"""Content-bound provenance for real-mode SSA artifacts.

Layer: dosunit evidence reporting.
Responsibility: bind fresh lowering to immutable binary and semantic sources,
and expose stale or legacy artifacts without inventing binary provenance.
"""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any, Final

from tools.dosunit.model import canonical_json_bytes, stable_id

_SOURCE_HASH_WORKERS: Final[int] = 3
REAL16_MODEL: Final[str] = 'dosunit.segmented-real16.v1'
SSA_PACKAGES: Final[tuple[str, ...]] = ('angr', 'cle', 'pyvex', 'z3-solver')


@dataclass(frozen=True)
class LoweringIdentity:
    """The inputs frozen before lowering begins."""

    binary_hash: str
    semantic_hash: str


def _digest(path: Path) -> str:
    """Hash an exact file, allowing read errors to remain visible."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_source_key(path: Path, root: Path) -> str:
    """Return the same native path key as relative_to for owned descendants.

    Exact public parts prove the common case without allocating ancestor paths.
    Every other case uses pathlib itself, preserving case/anchor rules and
    ValueError for an outside-root source. Equal paths retain the dot key.
    """
    source_parts, root_parts = path.parts, root.parts
    if source_parts[:len(root_parts)] == root_parts:
        return os.sep.join(source_parts[len(root_parts):]) or "."
    return str(path.relative_to(root))


def _digest_source_chunk(items: tuple[tuple[str, Path], ...]) -> dict[str, str]:
    """Read one independent source chunk freshly, propagating every read error."""
    return {key: _digest(path) for key, path in items}


def _semantic_hash() -> str:
    """Bind the SSA owner, solver helpers and X86_16 frontend sources."""
    root = Path(__file__).resolve().parents[2]
    frontend = root / 'angr_platforms/angr_platforms/X86_16'
    paths = [root / 'tools/dosunit/straightline_ssa.py',
             root / 'tools/dosunit/solver_slice.py', Path(__file__)]
    paths.extend((root / 'angr_platforms/__init__.py',
                  root / 'angr_platforms/angr_platforms/__init__.py',
                  root / 'angr_platforms/angr_platforms/import_identity.py'))
    paths.extend(frontend.rglob('*.py'))
    paths.extend((root / 'tools/dosunit').rglob('*.py'))
    # Canonical relative strings identify the same source set without repeated
    # rich Path comparisons. Read every file freshly, in deterministic key order.
    by_key = {_relative_source_key(path, root): path for path in paths}
    items = tuple(sorted(by_key.items()))
    chunks = tuple(items[index::_SOURCE_HASH_WORKERS] for index in range(_SOURCE_HASH_WORKERS))
    # Independent IO and hashlib's C work overlap within this invocation only.
    # No bytes/digests/executor survive the call or cross a freshness boundary.
    with ThreadPoolExecutor(max_workers=_SOURCE_HASH_WORKERS) as executor:
        sources = {key: digest for chunk in executor.map(_digest_source_chunk, chunks)
                   for key, digest in chunk.items()}
    return hashlib.sha256(canonical_json_bytes(sources)).hexdigest()


def begin_lowering(path: Path) -> LoweringIdentity:
    """Capture immutable binary and source identity before calling the lifter."""
    return LoweringIdentity(_digest(path), _semantic_hash())


def seal_lowering(document: dict[str, Any], path: Path, identity: LoweringIdentity) -> None:
    """Attach checked provenance only if inputs stayed unchanged throughout lowering."""
    if begin_lowering(path) != identity:
        raise RuntimeError('binary or semantic sources changed during SSA lowering')
    document['provenance'] = {
        'binary_sha256': identity.binary_hash, 'semantic_sha256': identity.semantic_hash,
        'model': REAL16_MODEL,
        'packages': {name: version(name) for name in SSA_PACKAGES},
        'parameters': document.get('parameters'),
    }
    document['id'] = stable_id('ssa', {key: value for key, value in document.items() if key != 'id'})


def checked_provenance(document: dict[str, Any]) -> dict[str, Any]:
    """Check artifact identity against current executable and semantic sources.

    Missing historical provenance is reported as unavailable. Reading an
    absent declared executable is a visible error rather than a guessed hash.
    This check establishes artifact freshness, not semantic equivalence.
    """
    provenance = document.get('provenance')
    if not isinstance(provenance, dict):
        return {'complete': False, 'reason': 'legacy_artifact_without_provenance'}
    executable = document.get('exe')
    if not isinstance(executable, str) or not executable:
        return {'complete': False, 'reason': 'artifact_without_executable_identity'}
    current = begin_lowering(Path(executable))
    packages = {name: version(name) for name in SSA_PACKAGES}
    complete = (provenance.get('binary_sha256') == current.binary_hash
                and provenance.get('semantic_sha256') == current.semantic_hash
                and provenance.get('packages') == packages
                and provenance.get('parameters') == document.get('parameters'))
    expected_id = stable_id('ssa', {key: value for key, value in document.items() if key != 'id'})
    complete = complete and document.get('id') == expected_id
    return {'complete': complete, 'reason': 'current_artifact' if complete else 'stale_artifact',
            'binary_sha256': current.binary_hash, 'semantic_sha256': current.semantic_hash}
