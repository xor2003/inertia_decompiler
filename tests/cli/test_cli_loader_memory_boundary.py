"""Main-object Clemory reads refuse only on genuinely unbacked memory.

Layer: Tests.
Responsibility: pin the four ``cli_function_discovery`` object-image reads to
the installed ``Clemory.load`` contract: an unbacked object-relative origin
raises ``KeyError`` and yields the typed no-result, while unexpected loader
failures (``TypeError`` from a ``list[int]`` backer, or any other defect such
as ``RuntimeError``) propagate instead of collapsing into "no evidence".
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import angr
import archinfo
import pytest
from inertia.frontend.x86_16.load_dos_mz import DOSMZ
from cle.memory import Clemory

import inertia.cli.cli_function_discovery as discovery

_IMAGE_LEN = 0x140
# Nonzero base keeps linked-base-relative offsets distinct from absolutes.
_BASE_ADDR = 0x10000
# A backer that starts past the object-relative origin leaves offset 0
# unallocated, so ``Clemory.load(0, n)`` takes its real ``KeyError`` path.
_GAP_BACKER_OFFSET = 0x20


def _write_tiny_mz(path: Path, image: bytes) -> Path:
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x08:0x0A] = (4).to_bytes(2, "little")  # header_paragraphs
    path.write_bytes(bytes(header) + image)
    return path


def _mz_project(tmp_path: Path) -> angr.Project:
    sample = _write_tiny_mz(
        tmp_path / "tiny.exe", bytes(index & 0xFF for index in range(_IMAGE_LEN))
    )
    project = angr.Project(sample, main_opts={"base_addr": _BASE_ADDR})
    main_object = project.loader.main_object
    assert isinstance(main_object, DOSMZ)
    assert main_object.linked_base == _BASE_ADDR
    assert main_object.max_addr == _BASE_ADDR + _IMAGE_LEN - 1
    return project


def _gap_backed_clemory(arch: archinfo.Arch) -> Clemory:
    memory = Clemory(arch)
    memory.add_backer(_GAP_BACKER_OFFSET, bytearray(_IMAGE_LEN))
    return memory


def _list_backed_clemory(arch: archinfo.Arch) -> Clemory:
    memory = Clemory(arch)
    memory.add_backer(0, [0x90] * _IMAGE_LEN)
    return memory


def _defective_load(self: Clemory, addr: int, n: int) -> bytes:
    raise RuntimeError("simulated unexpected loader read defect")


def _prologue_scan_read(project: angr.Project) -> object:
    return discovery._prologue_scan_context_8616(project, [project.entry])


def _exe_seed_read(project: angr.Project) -> object:
    return discovery._exe_seed_context_8616(project, include_library_functions=False)


_OBJECT_IMAGE_READS: tuple[tuple[str, Callable[[angr.Project], object], object], ...] = (
    ("prologue_scan_context", _prologue_scan_read, None),
    ("load_main_object_code", discovery._load_main_object_code_8616, None),
    ("exe_seed_context", _exe_seed_read, None),
    (
        "rank_pre_entry_source_seeds",
        discovery._rank_pre_entry_source_function_seeds_8616,
        [],
    ),
)

_READ_IDS = [name for name, _invoke, _expected in _OBJECT_IMAGE_READS]


@pytest.mark.parametrize(
    ("_name", "invoke", "expected"), _OBJECT_IMAGE_READS, ids=_READ_IDS
)
def test_unbacked_object_memory_returns_typed_no_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _name: str,
    invoke: Callable[[angr.Project], object],
    expected: object,
) -> None:
    """A genuine unbacked-origin ``KeyError`` yields the typed no-result."""
    project = _mz_project(tmp_path)
    main_object = project.loader.main_object
    monkeypatch.setattr(main_object, "memory", _gap_backed_clemory(project.arch))

    result = invoke(project)

    if expected is None:
        assert result is None
    else:
        assert result == expected


@pytest.mark.parametrize(
    ("_name", "invoke", "_expected"), _OBJECT_IMAGE_READS, ids=_READ_IDS
)
def test_unexpected_loader_defect_propagates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _name: str,
    invoke: Callable[[angr.Project], object],
    _expected: object,
) -> None:
    """An unexpected ``RuntimeError`` from ``load`` must not be swallowed."""
    project = _mz_project(tmp_path)
    main_object = project.loader.main_object
    monkeypatch.setattr(type(main_object.memory), "load", _defective_load)

    with pytest.raises(RuntimeError):
        invoke(project)


@pytest.mark.parametrize(
    ("_name", "invoke", "_expected"), _OBJECT_IMAGE_READS, ids=_READ_IDS
)
def test_list_backed_object_memory_propagates_type_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _name: str,
    invoke: Callable[[angr.Project], object],
    _expected: object,
) -> None:
    """CLE's ``list[int]`` backer ``TypeError`` is a defect, not missing memory."""
    project = _mz_project(tmp_path)
    main_object = project.loader.main_object
    monkeypatch.setattr(main_object, "memory", _list_backed_clemory(project.arch))

    with pytest.raises(TypeError):
        invoke(project)
