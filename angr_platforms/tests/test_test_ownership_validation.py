"""Preserve exhaustive diagnostic order and per-invocation source-index reuse."""

from pathlib import Path

import pytest

from scripts import test_ownership_manifest as manifest
from scripts.pytest_source_structure import PytestSourceIndex


def test_validation_reports_all_independent_rule_obligations_in_order() -> None:
    rule = manifest.TestOwnershipRule("", (), (), tier="slow", fallback=True)
    violations = manifest.validate_manifest_targets((rule,))
    assert tuple(item.target for item in violations) == ("<owner>", "<paths>", "<tests>", "slow", "<reason>")
    assert all(item.owner == "" for item in violations)


def test_validation_reuses_one_index_without_skipping_per_node_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_path = "angr_platforms/tests/test_fixture.py"
    source = tmp_path / test_path
    source.parent.mkdir(parents=True)
    source.write_text("def test_a():\n    pass\n\n@pytest.mark.skip(reason='fixture')\ndef test_b():\n    pass\n")
    monkeypatch.setattr(manifest, "REPO_ROOT", tmp_path)
    original_loader = manifest.load_pytest_source_index
    reads: list[Path] = []

    def load(path: Path, skip_calls: frozenset[str]) -> PytestSourceIndex:
        reads.append(path)
        return original_loader(path, skip_calls)

    monkeypatch.setattr(manifest, "load_pytest_source_index", load)
    rules = (
        manifest.TestOwnershipRule("first", (test_path,), (f"{test_path}::test_a", f"{test_path}::test_b")),
        manifest.TestOwnershipRule("second", (test_path,), (f"{test_path}::test_a",)),
    )
    assert manifest.validate_manifest_targets(rules) == (
        manifest.ManifestViolation("first", f"{test_path}::test_b",
                                   "fast ownership pytest targets must not use skip/xfail at line 4"),
    )
    assert reads == [source]
