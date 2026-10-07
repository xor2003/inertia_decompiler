"""Component declarations, derived compatibility views and task routing."""

import json
from pathlib import Path

import pytest

from tools.dev.component_catalog import (
    ROOT,
    derive_test_catalog,
    load_components,
    make_quality_projection,
    validate_component_paths,
)
from tools.dev.task_context import build_task_context, components_for_files

pytestmark = pytest.mark.tooling


def _declaration(name: str = "tooling") -> dict[str, object]:
    return {
        "name": name, "order": 0, "description": "Repository infrastructure", "sources": ["tools/dev"],
        "public_api": [], "dependencies": [], "guide": "tools/dev/README.md",
        "tests": ["tools/dev/tests/test_example.py"], "focus": [], "consumers": [],
        "quality_sources": [], "routine_tests": [],
    }


def _write(tmp_path: Path, document: dict[str, object]) -> Path:
    directory = tmp_path / "components"
    directory.mkdir()
    (directory / "tooling.json").write_text(json.dumps(document))
    return directory


def test_split_catalog_matches_export_and_paths():
    components = load_components()
    exported = json.loads((ROOT / "reference/test-components.json").read_text())
    assert derive_test_catalog(components) == exported
    assert make_quality_projection(components) == (ROOT / "reference/components.mk").read_text()
    assert not validate_component_paths(components)


@pytest.mark.parametrize("defect", ["escape", "duplicate", "dependency", "focus", "name", "unknown_field"])
def test_invalid_declaration_refuses(tmp_path: Path, defect: str):
    document = _declaration()
    if defect == "escape":
        document["sources"] = ["../outside"]
    elif defect == "duplicate":
        document["tests"] = ["test_a.py", "test_a.py"]
    elif defect == "dependency":
        document["dependencies"] = ["missing"]
    elif defect == "focus":
        document["focus"] = ["test_other.py::test_case"]
    elif defect == "name":
        document["name"] = "wrong"
    else:
        document["typo"] = []
    with pytest.raises(ValueError):
        load_components(_write(tmp_path, document))


def test_missing_paths_are_visible(tmp_path: Path):
    components = load_components(_write(tmp_path, _declaration()))
    missing = validate_component_paths(components, tmp_path)
    assert "tooling: missing tools/dev/tests/test_example.py" in missing


def test_specific_owner_beats_generic_scripts_owner():
    owners = components_for_files(("tools/compiler_id/report/py.py",))
    assert tuple(owner.name for owner in owners) == ("compiler_detector",)


def test_context_routes_compiler_tool_without_decompiler_imports():
    tests = ("tools/compiler_id/tests/test_flags.py",)
    context = build_task_context(("tools/compiler_id/report.py",), tests)
    assert context["selected_tests"] == tests
    assert context["focused_command"][-1] == tests[0]
    assert context["owners"][0]["name"] == "compiler_detector"
    assert len(json.dumps(context)) < 8000
