from __future__ import annotations

import threading
from pathlib import Path

from tools.compiler_toolchain.msc6_toolchain_lock import msc6_toolchain_lock


def test_msc6_toolchain_lock_serializes_contending_workers(tmp_path: Path) -> None:
    compiler_dir = tmp_path / "BIN"
    compiler_dir.mkdir()
    (compiler_dir / "CL.EXE").write_bytes(b"compiler")

    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def hold_first() -> None:
        with msc6_toolchain_lock(tmp_path):
            first_entered.set()
            assert release_first.wait(timeout=2.0)

    def enter_second() -> None:
        with msc6_toolchain_lock(tmp_path):
            second_entered.set()

    first = threading.Thread(target=hold_first)
    second = threading.Thread(target=enter_second)
    first.start()
    assert first_entered.wait(timeout=2.0)
    second.start()
    assert not second_entered.wait(timeout=0.1)

    release_first.set()
    first.join(timeout=2.0)
    second.join(timeout=2.0)
    assert not first.is_alive()
    assert not second.is_alive()
    assert second_entered.is_set()
