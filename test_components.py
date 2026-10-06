"""Component catalog coverage and pytest selection regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pytest_components import CATALOG, COMPONENTS, ROOT, load_component_catalog

pytest_plugins = ["pytester"]
pytestmark = pytest.mark.tooling


def test_catalog_covers_owned_modules() -> None:
    """Every test module has reviewed labels; removed files leave no stale rows."""
    owners = load_component_catalog(CATALOG)
    paths = set(ROOT.glob("angr_platforms/tests/test_*.py"))
    paths.update(ROOT.glob("artifacts/*/test_*.py"))
    paths.add(Path(__file__).resolve())
    expected = {path.relative_to(ROOT).as_posix() for path in paths}
    assert expected == set(owners)
    assert all((ROOT / path).is_file() for path in owners)


@pytest.mark.parametrize("defect", ["unknown_component", "duplicate", "escape", "string"])
def test_catalog_rejects_invalid_ownership(tmp_path: Path, defect: str) -> None:
    """Malformed catalogs fail instead of silently losing ownership."""
    document: dict[str, object] = {component: [] for component in COMPONENTS}
    if defect == "unknown_component":
        document["typo"] = []
    elif defect == "duplicate":
        document["tooling"] = ["test_a.py", "test_a.py"]
    elif defect == "escape":
        document["tooling"] = ["../test_a.py"]
    else:
        document["tooling"] = "test_a.py"
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        load_component_catalog(path)


def install_sample(pytester: pytest.Pytester, entries: dict[str, list[str]]) -> None:
    """Install the actual root hook into an isolated miniature repository."""
    pytester.makeconftest((ROOT / "pytest_components.py").read_text())
    catalog = {component: entries.get(component, []) for component in COMPONENTS}
    reference = pytester.path / "reference"
    reference.mkdir()
    (reference / "test-components.json").write_text(json.dumps(catalog))


def test_marker_selection_and_existing_skip(pytester: pytest.Pytester) -> None:
    """Component filtering covers parameters and preserves existing skips."""
    install_sample(pytester, {"ssa_z3": ["test_proof.py"], "decompiler": ["test_c.py"]})
    pytester.makepyfile(
        test_proof="""
        import pytest
        @pytest.mark.parametrize('value', [0, 1])
        def test_proof(value): assert value in (0, 1)
        @pytest.mark.skip(reason='existing skip')
        def test_skip(): assert False
        """,
        test_c="def test_c(): assert False",
    )
    result = pytester.runpytest("-m", "ssa_z3", "--strict-markers", "-q")
    result.assert_outcomes(passed=2, skipped=1, deselected=1)


def test_unowned_test_cannot_hide_behind_selection(pytester: pytest.Pytester) -> None:
    """Unknown ownership fails before marker deselection can hide it."""
    install_sample(pytester, {})
    pytester.makepyfile("def test_unknown(): pass")
    result = pytester.runpytest("-m", "ssa_z3", "-q")
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*Tests without component ownership*"])


def test_explicit_marks_and_artifact_paths(pytester: pytest.Pytester) -> None:
    """Mixed explicit components and artifact modules share the root hook."""
    install_sample(pytester, {"ssa_z3": ["artifacts/driver/test_example.py"]})
    artifact = pytester.path / "artifacts" / "driver"
    artifact.mkdir(parents=True)
    (artifact / "test_example.py").write_text("def test_artifact(): pass\n")
    pytester.makepyfile("""
        import pytest
        @pytest.mark.ada_script
        @pytest.mark.signatures
        def test_integration(): pass
    """)
    result = pytester.runpytest("-m", "ssa_z3 or (ada_script and signatures)", "-q")
    result.assert_outcomes(passed=2)
