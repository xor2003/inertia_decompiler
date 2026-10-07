import subprocess
import sys
from pathlib import Path

from inertia.cli.cache_lock import cache_path_lock


def test_cache_path_lock_reclaims_crashed_owner(tmp_path: Path) -> None:
    lock_path = tmp_path / "artifact.lock"
    script = (
        "import os,sys; from pathlib import Path; "
        "from inertia.cli.cache_lock import cache_path_lock; "
        "lock=cache_path_lock(Path(sys.argv[1])); lock.__enter__(); os._exit(0)"
    )

    result = subprocess.run([sys.executable, "-c", script, str(lock_path)], check=False)

    assert result.returncode == 0
    assert lock_path.exists()

    with cache_path_lock(lock_path, timeout_seconds=0.5):
        assert lock_path.exists()
    assert not lock_path.exists()


def test_cache_path_lock_reclaims_dead_legacy_pid(tmp_path: Path) -> None:
    lock_path = tmp_path / "legacy.lock"
    lock_path.write_text("999999999\n", encoding="ascii")

    with cache_path_lock(lock_path, timeout_seconds=0.5):
        assert lock_path.exists()
    assert not lock_path.exists()
