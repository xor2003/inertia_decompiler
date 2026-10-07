"""Read the authoritative per-component navigation and test declarations.

Layer: Tooling/gates.
Responsibility: provide validated component metadata and derive legacy test
catalog views without changing pytest marks, node selection or resource policy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parents[2]
DECLARATIONS: Path = ROOT / "reference" / "components"


@dataclass(frozen=True, slots=True)
class Component:
    """A reviewed owner and its public navigation and module-test surfaces."""

    name: str
    order: int
    description: str
    sources: tuple[str, ...]
    public_api: tuple[str, ...]
    dependencies: tuple[str, ...]
    guide: str
    tests: tuple[str, ...]
    focus: tuple[str, ...]
    consumers: tuple[str, ...]
    quality_sources: tuple[str, ...]
    routine_tests: tuple[str, ...]

    def owns(self, path: str) -> bool:
        """Match explicit source paths or descendant paths of declared roots."""
        return any(path == source.rstrip("/") or path.startswith(source.rstrip("/") + "/")
                   for source in self.sources)


def _string_list(document: dict[str, object], field: str, path: Path) -> tuple[str, ...]:
    """Reject malformed/duplicate lists instead of silently discarding entries."""
    value = document.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{path}: {field} must be a list of nonempty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{path}: {field} contains duplicate entries")
    return tuple(value)


def _relative_path(value: str, context: str) -> None:
    """Require canonical repository-relative paths and reject path escapes."""
    parts = value.split("/")
    if Path(value).is_absolute() or "\\" in value or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{context}: invalid repository path {value!r}")


def _load_component(path: Path) -> Component:
    """Load one declaration with explicit schema and path validation."""
    document = json.loads(path.read_text(encoding="utf-8"))
    fields = {"name", "order", "description", "sources", "public_api", "dependencies", "guide", "tests", "focus", "consumers",
              "quality_sources", "routine_tests"}
    if not isinstance(document, dict) or set(document) != fields:
        raise ValueError(f"{path}: expected component fields {sorted(fields)}")
    for field in ("name", "description", "guide"):
        if not isinstance(document[field], str) or not document[field]:
            raise ValueError(f"{path}: {field} must be a nonempty string")
    if document["name"] != path.stem:
        raise ValueError(f"{path}: name must match the declaration filename")
    if not isinstance(document["order"], int) or isinstance(document["order"], bool) or document["order"] < 0:
        raise ValueError(f"{path}: order must be a nonnegative integer")
    component = Component(
        name=document["name"], order=document["order"], description=document["description"], guide=document["guide"],
        sources=_string_list(document, "sources", path),
        public_api=_string_list(document, "public_api", path),
        dependencies=_string_list(document, "dependencies", path),
        tests=_string_list(document, "tests", path),
        focus=_string_list(document, "focus", path),
        consumers=_string_list(document, "consumers", path),
        quality_sources=_string_list(document, "quality_sources", path),
        routine_tests=_string_list(document, "routine_tests", path),
    )
    for value in (*component.sources, component.guide, *component.consumers, *component.quality_sources):
        _relative_path(value, str(path))
    for value in (*component.tests, *component.focus, *component.routine_tests):
        module = value.split("::", 1)[0]
        _relative_path(module, str(path))
        if not Path(module).name.startswith("test_") or not module.endswith(".py"):
            raise ValueError(f"{path}: invalid pytest module {value!r}")
    return component


def load_components(directory: Path = DECLARATIONS) -> tuple[Component, ...]:
    """Read deterministic declarations and validate dependency/focus references."""
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise ValueError(f"{directory}: no component declarations")
    components = tuple(sorted((_load_component(path) for path in paths), key=lambda component: component.order))
    if tuple(component.order for component in components) != tuple(range(len(components))):
        raise ValueError(f"{directory}: component order must be unique and contiguous")
    names = {component.name for component in components}
    for component in components:
        if set(component.dependencies) - names:
            raise ValueError(f"{component.name}: unknown component dependencies")
        if any(target.split("::", 1)[0] not in component.tests for target in (*component.focus, *component.routine_tests)):
            raise ValueError(f"{component.name}: focused tests must belong to the component")
    return components


def derive_test_catalog(components: tuple[Component, ...]) -> dict[str, list[str]]:
    """Derive the legacy component-to-test view without dropping shared labels."""
    return {component.name: list(component.tests) for component in components}


def routine_test_targets() -> tuple[str, ...]:
    """Derive explicitly reviewed routine targets; never enroll directory globs."""
    return tuple(dict.fromkeys(target for component in load_components() for target in component.routine_tests))


def make_quality_projection(components: tuple[Component, ...]) -> str:
    """Generate the Make quality view from exactly the reviewed pilot entries."""
    sources = tuple(dict.fromkeys(path for component in components for path in component.quality_sources))
    tests = tuple(dict.fromkeys(target for component in components for target in component.routine_tests))
    ruff_targets = tuple(dict.fromkeys((*sources, *(target.split('::', 1)[0] for target in tests))))
    return (
        "# Generated by tools.dev.component_catalog_cli; edit reference/components/*.json.\n"
        f"QA_TYPED_FILES += {' '.join(sources)}\n"
        f"QA_RUFF_TARGETS += {' '.join(ruff_targets)}\n"
        f"QA_PYTEST_TARGETS += {' '.join(tests)}\n"
    )


def validate_component_paths(components: tuple[Component, ...], root: Path = ROOT) -> tuple[str, ...]:
    """Report missing maintained paths without inspecting generated scratch."""
    missing: list[str] = []
    for component in components:
        for path in (*component.sources, component.guide, *component.tests, *component.consumers, *component.quality_sources):
            if not (root / path).exists():
                missing.append(f"{component.name}: missing {path}")
    return tuple(missing)
