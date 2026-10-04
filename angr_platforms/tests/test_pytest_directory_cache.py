"""Regression controls for directory caching without test-selection changes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import pytest_directory_cache as cache

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("scenario", ["plain", "duplicate", "parametrized", "missing", "import_error"])
def test_directory_cache_preserves_collection(tmp_path: Path, scenario: str) -> None:
    """Ordinary pytest and the cache retain ordered items and failure exits."""
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\n", encoding="utf-8")
    recorder = tmp_path / "collection_receipt.py"
    recorder.write_text(
        "import json,os\nfrom pathlib import Path\n"
        "def pytest_collection_finish(session):\n"
        "    Path(os.environ['COLLECTION_RECEIPT']).write_text(json.dumps([item.nodeid for item in session.items]))\n",
        encoding="utf-8",
    )
    paths: list[str] = []
    for index in range(12):
        path = tmp_path / f"test_item_{index:02}.py"
        source = "def test_ok():\n    assert True\n"
        if scenario == "parametrized":
            source = "import pytest\n@pytest.mark.parametrize('value', [0,1])\ndef test_ok(value):\n    assert value in (0,1)\n"
        if scenario == "import_error" and index == 0:
            source = "raise RuntimeError('intentional collection error')\n"
        path.write_text(source, encoding="utf-8")
        paths.append(str(path))
    if scenario == "duplicate":
        paths.extend((paths[0], paths[1] + "::test_ok"))
    if scenario == "missing":
        paths[0] += "::test_missing"
    outcomes: list[tuple[int, list[str]]] = []
    for enabled in (False, True):
        receipt = tmp_path / f"receipt-{enabled}.json"
        environment = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join((str(ROOT), str(tmp_path))),
            "COLLECTION_RECEIPT": str(receipt),
        }
        command = [sys.executable, "-m", "pytest", "-c", str(config), "--collect-only", "-q", "-p", "collection_receipt"]
        if enabled:
            command.extend(("-p", "scripts.pytest_directory_cache"))
        result = subprocess.run(command + paths, cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
        assert receipt.exists(), result.stdout + result.stderr
        outcomes.append((result.returncode, json.loads(receipt.read_text())))
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == {"missing": 4, "import_error": 2}.get(scenario, 0)
    if scenario in ("plain", "duplicate", "parametrized"):
        assert len(outcomes[0][1]) == (24 if scenario == "parametrized" else 12)


def test_directory_cache_rechecks_source_and_bounds(
    tmp_path: Path, request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changed directory listings invalidate reuse; capacity overflow bypasses it."""
    collector = pytest.Dir.from_parent(request.session, path=tmp_path)
    report = pytest.CollectReport(collector.nodeid, "passed", None, [])
    state = cache.DirectoryReports()
    record = cache.Record(state)
    lookup = cache.Lookup(state)

    def retain() -> None:
        hook = record.pytest_make_collect_report(collector)
        next(hook)
        with pytest.raises(StopIteration) as finished:
            hook.send(report)
        assert finished.value.value is report

    retain()
    assert lookup.pytest_make_collect_report(collector) is report
    original = tmp_path.stat()
    os.utime(tmp_path, ns=(original.st_atime_ns, original.st_mtime_ns + 1))
    assert lookup.pytest_make_collect_report(collector) is None
    state.reports.clear()
    monkeypatch.setattr(cache, "MAX_DIRECTORIES", 0)
    retain()
    assert lookup.pytest_make_collect_report(collector) is None


def test_custom_collectors_are_not_cached(tmp_path: Path, request: pytest.FixtureRequest) -> None:
    """Custom directory hooks retain their own collection behavior."""
    class CustomDirectory(pytest.Dir):
        pass

    collector = CustomDirectory.from_parent(request.session, path=tmp_path)
    assert cache.directory_stamp(collector) is None
