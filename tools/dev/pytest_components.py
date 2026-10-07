"""Repository-wide pytest component selection.

Layer: Test infrastructure.
Responsibility: attach reviewed component ownership before pytest selection.

Package ownership contract (canonical tools/dev package):
Layer: Tooling.
Owns development infrastructure, gates, and focused test support for repository tooling.
Do not perform decompiler pipeline semantics or CLI/reporting ownership here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.dev.component_catalog import derive_test_catalog, load_components

ROOT: Path = Path(__file__).resolve().parents[2]
CATALOG: Path = ROOT / "reference" / "test-components.json"
COMPONENTS: dict[str, str] = {component.name: component.description for component in load_components()}
OWNERSHIP_KEY: pytest.StashKey[dict[str, tuple[str, ...]]] = pytest.StashKey()


def load_component_catalog(path: Path) -> dict[str, tuple[str, ...]]:
    """Validate the explicit component-to-module catalog and reverse its index."""
    # Legacy catalogs remain supported for isolated plugin controls and callers.
    # The live repository consumes its authoritative split declarations.
    directory = path.parent / "components"
    document = derive_test_catalog(load_components(directory)) if directory.is_dir() else json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != set(COMPONENTS):
        raise ValueError("component catalog must list exactly the registered components")
    owners: dict[str, list[str]] = {}
    for component, paths in document.items():
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise ValueError(f"{component}: expected a list of relative module paths")
        if len(paths) != len(set(paths)):
            raise ValueError(f"{component}: duplicate module path")
        for module in paths:
            if not module.endswith(".py") or Path(module).is_absolute() or ".." in Path(module).parts:
                raise ValueError(f"{component}: invalid module path {module!r}")
            owners.setdefault(module, []).append(component)
    return {module: tuple(labels) for module, labels in owners.items()}


def pytest_configure(config: pytest.Config) -> None:
    """Register component markers and load ownership once per pytest process."""
    for name, description in COMPONENTS.items():
        config.addinivalue_line("markers", f"{name}: {description}")
    try:
        config.stash[OWNERSHIP_KEY] = load_component_catalog(CATALOG)
    except (ValueError, OSError) as error:
        raise pytest.UsageError(f"Invalid test component catalog: {error}") from error


@pytest.hookimpl(tryfirst=True)  # type: ignore[untyped-decorator]  # Pluggy preserves the typed hook.
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Label all items before -m filtering; reject unowned repository tests.

    Explicit component marks can classify a new module or specialize mixed
    tests. Catalog marks are additive. Existing skip/resource marks are kept.
    External and generated scratch tests are outside the repository inventory.
    """
    ownership = config.stash[OWNERSHIP_KEY]
    missing: set[str] = set()
    for item in items:
        path = Path(item.path).resolve()
        if not path.is_relative_to(ROOT):
            continue
        relative = path.relative_to(ROOT)
        if any(part.startswith((".", "pytest-of-")) for part in relative.parts):
            continue
        if relative.parts[0] == "vendor":
            continue
        for component in ownership.get(relative.as_posix(), ()):
            item.add_marker(component)
        if not any(mark.name in COMPONENTS for mark in item.iter_markers()):
            missing.add(relative.as_posix())
    if missing:
        raise pytest.UsageError(
            "Tests without component ownership (update reference/test-components.json "
            "or add explicit component markers):\n" + "\n".join(sorted(missing))
        )
