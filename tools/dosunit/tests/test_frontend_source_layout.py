"""Frontend migrations must remain inside the flat32 semantic source seal."""

from __future__ import annotations

from pathlib import Path

from tools.dosunit.reporting import flat32_proof_report as owner


def test_flat32_seal_includes_frontend_and_migrated_sources(tmp_path: Path, monkeypatch) -> None:
    shared = tmp_path / "tools/dosunit/reporting/flat32_proof_report.py"
    shared.parent.mkdir(parents=True)
    shared.write_text("owner")
    driver = tmp_path / "tools/comparator/cli.py"
    driver.parent.mkdir(parents=True)
    driver.write_text("driver")
    canonical = tmp_path / "inertia/frontend/x86_16/arch_86_16.py"
    canonical.parent.mkdir(parents=True)
    canonical.write_text("first")
    monkeypatch.setattr(owner, "__file__", str(shared))
    before = owner._semantic_sources(driver)
    assert str(canonical) in before
    canonical.write_text("other")
    assert owner._semantic_sources(driver) != before
    before = owner._semantic_sources(driver)
    canonical.unlink()
    assert owner._semantic_sources(driver) != before
