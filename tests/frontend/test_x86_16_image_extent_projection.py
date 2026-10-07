"""CLI image-extent projections against the absolute inclusive ``max_addr`` contract.

Layer: Tests.
Responsibility: pin discovery's derived image end and object-memory byte count
to the real DOSMZ backend contract on a generated nonzero-base MZ fixture.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.load_dos_mz import DOSMZ

import inertia.cli.cli_function_discovery as discovery

_IMAGE_LEN = 0x140
# Nonzero bases are required: a zero base makes ``linked_base + max_addr + 1``
# numerically identical to the correct ``max_addr + 1`` and cannot detect the
# double-add regression.
_BASE_ADDRS = (0x10000, 0x24000)


def _write_tiny_mz(path: Path, image: bytes) -> Path:
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x08:0x0A] = (4).to_bytes(2, "little")  # header_paragraphs
    path.write_bytes(bytes(header) + image)
    return path


def _mz_project(tmp_path: Path, base_addr: int) -> angr.Project:
    sample = _write_tiny_mz(
        tmp_path / f"tiny-{base_addr:x}.exe",
        bytes(index & 0xFF for index in range(_IMAGE_LEN)),
    )
    project = angr.Project(sample, main_opts={"base_addr": base_addr})
    main_object = project.loader.main_object
    assert isinstance(main_object, DOSMZ)
    # The generated fixture must expose the contract under test.
    assert main_object.linked_base == base_addr
    assert main_object.max_addr == base_addr + _IMAGE_LEN - 1
    return project


@pytest.mark.parametrize("base_addr", _BASE_ADDRS)
def test_seed_scan_windows_fallback_ends_at_real_exclusive_image_end(
    tmp_path, monkeypatch, base_addr
):
    project = _mz_project(tmp_path, base_addr)
    main_object = project.loader.main_object
    monkeypatch.setattr(discovery, "_metadata_code_windows", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "_mz_segment_windows", lambda *_args, **_kwargs: [])

    windows = discovery._seed_scan_windows(project)

    assert windows == [(main_object.linked_base, main_object.max_addr + 1)]


@pytest.mark.parametrize("base_addr", _BASE_ADDRS)
def test_direct_addr_bounded_recovery_caps_image_end_at_real_eof(
    tmp_path, monkeypatch, base_addr
):
    project = _mz_project(tmp_path, base_addr)
    main_object = project.loader.main_object
    captured: dict[str, object] = {}

    def fake_recover(_project, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(), SimpleNamespace(addr=kwargs["candidate_addr"])

    monkeypatch.setattr(discovery, "_recover_candidate_function_pair", fake_recover)
    candidate_addr = main_object.linked_base + 0x10

    recovered = discovery._recover_direct_addr_bounded_8616(
        project,
        main_object.linked_base,
        candidate_addr,
        None,
        timeout=5,
        window=0x180,
        lst_metadata=None,
        prefer_lst_direct=False,
    )

    assert recovered[1].addr == candidate_addr
    # The bounded region may never extend into unbacked space past EOF.
    assert captured["image_end"] == main_object.max_addr + 1


@pytest.mark.parametrize("base_addr", _BASE_ADDRS)
def test_main_object_code_load_requests_relative_byte_extent(
    tmp_path, monkeypatch, base_addr
):
    project = _mz_project(tmp_path, base_addr)
    main_object = project.loader.main_object
    requested: list[tuple[int, int]] = []
    real_load = type(main_object.memory).load

    def recording_load(self, addr, n):
        requested.append((addr, n))
        return real_load(self, addr, n)

    monkeypatch.setattr(type(main_object.memory), "load", recording_load)

    resolved = discovery._load_main_object_code_8616(project)

    assert resolved is not None
    linked_base, code = resolved
    extent = main_object.max_addr - main_object.linked_base + 1
    assert linked_base == main_object.linked_base
    assert requested == [(0, extent)]
    assert len(code) == extent == _IMAGE_LEN
