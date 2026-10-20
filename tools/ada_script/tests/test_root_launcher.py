# test/test_root_launcher.py
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "ada.py"


def _run_launcher(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(LAUNCHER), *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=60,
    )


def test_root_launcher_help(tmp_path):
    result = _run_launcher("--help", cwd=tmp_path)
    assert result.returncode == 0
    output = result.stdout + result.stderr
    assert 'usage' in output.lower()
    for option in ('--backend', '--signature-catalog', '--runtime'):
        assert option in output


def test_root_launcher_invalid_option(tmp_path):
    result = _run_launcher("unused.exe", "--definitely-invalid-option", cwd=tmp_path)
    assert result.returncode == 2
    assert 'usage' in result.stderr.lower()
    assert 'error' in result.stderr.lower()
    assert '--definitely-invalid-option' in result.stderr
