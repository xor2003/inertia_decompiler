"""Changed owned arithmetic dependencies must invalidate flat32 proof identity."""
import os

import pytest

import tools.dosunit.flat32_proof_report as report


@pytest.mark.parametrize("relative", [
    "ssa_constant_terms.py", "nested/helper.py",
    "../../angr_platforms/angr_platforms/X86_16/semantics/helper.py",
    "../../angr_platforms/__init__.py",
    "../../angr_platforms/angr_platforms/__init__.py",
    "../../angr_platforms/angr_platforms/import_identity.py",
])
def test_owned_helper_is_part_of_semantic_identity(tmp_path, monkeypatch, relative):
    shared = tmp_path / 'tools' / 'dosunit'
    driver = tmp_path / 'driver'
    shared.mkdir(parents=True)
    driver.mkdir()
    (tmp_path / 'angr_platforms/angr_platforms').mkdir(parents=True)
    for name in ('straightline_ssa.py', 'proof_contracts.py', 'proof_obligations.py',
                 'proof_serialization.py', 'proof_projection.py', 'flat32_proof_report.py'):
        (shared / name).write_text('initial')
    for name in ('z3cmp32.py', 'flat32_adapter.py', 'flat32_cfg.py', 'flat32_region.py', 'flat32_verdict.py'):
        (driver / name).write_text('initial')
    dependency = (shared / relative).resolve()
    dependency.parent.mkdir(parents=True, exist_ok=True)
    dependency.write_text('first semantic implementation')
    monkeypatch.setattr(report, '__file__', str(shared / 'flat32_proof_report.py'))
    before = report._semantic_sources(driver / 'z3cmp32.py')
    stat = dependency.stat()
    dependency.write_text('other semantic implementation')
    os.utime(dependency, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    after = report._semantic_sources(driver / 'z3cmp32.py')
    assert str(dependency) in before
    assert before != after
    dependency.unlink()
    assert report._semantic_sources(driver / "z3cmp32.py") != after
