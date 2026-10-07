from __future__ import annotations

from pathlib import Path

from tools.dosunit.architectures.ir_edges import _load_lightweight_lifter_project


def test_lightweight_project_preserves_mz_image_and_entry(tmp_path: Path) -> None:
    image = b"\x90\xc3"
    header = bytearray(32)
    header[:2] = b"MZ"
    header[2:4] = (len(header) + len(image)).to_bytes(2, "little")
    header[4:6] = (1).to_bytes(2, "little")
    header[8:10] = (2).to_bytes(2, "little")
    executable = tmp_path / "minimal.exe"
    executable.write_bytes(header + image)

    project = _load_lightweight_lifter_project(executable)

    assert project.arch.name == "86_16"
    assert project.entry == 0x1000
    assert project.loader.memory.load(project.entry, len(image)) == image
