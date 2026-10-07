"""Regression evidence for verified PE32 loader acceleration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.comparator import verified_pe as flat32_fast_pe


def test_verified_pe_cache_requires_matching_executable_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fast PE load is accepted only after full-load code-byte agreement."""
    exe = tmp_path / "candidate.exe"
    exe.write_bytes(b"MZ\x00\x01")
    code = {"full": b"\x90\xc3", "fast": b"\x90\xc3"}
    data = {"full": b"\x11\x22", "fast": b"\x00\x00"}
    missing_fast_data = {"value": False}
    calls: list[bool] = []
    section = SimpleNamespace(
        name="CODE", min_addr=0x401000, max_addr=0x401001, memsize=2,
        is_executable=True, is_readable=True, is_writable=False,
    )
    data_section = SimpleNamespace(
        name=".idata", min_addr=0x402000, max_addr=0x402001, memsize=2,
        is_executable=False, is_readable=True, is_writable=True,
    )

    def fake_load(_path: Path, *, perform_relocations: bool = True) -> SimpleNamespace:
        calls.append(perform_relocations)
        image = SimpleNamespace(
            linked_base=0x400000, mapped_base=0x400000, sections=[section, data_section]
        )
        kind = "full" if perform_relocations else "fast"
        content = {0x401000: code[kind], 0x402000: data[kind]}
        if not perform_relocations and missing_fast_data["value"]:
            del content[0x402000]
        memory = SimpleNamespace(
            load=lambda address, _size: content[address],
            backers=lambda: iter(sorted(content.items())),
            store=lambda address, value: content.__setitem__(address, bytes(value)),
        )
        return SimpleNamespace(entry=0x401000, arch=SimpleNamespace(name="X86", bits=32), loader=SimpleNamespace(main_object=image, memory=memory))

    monkeypatch.setattr(flat32_fast_pe, "load32", fake_load)
    cache = tmp_path / "cache"
    first = flat32_fast_pe.load32_verified(exe, cache)
    assert first is not None and calls == [True, False]
    calls.clear()
    second = flat32_fast_pe.load32_verified(exe, cache)
    assert second is not first and calls == [False]
    assert second.loader.memory.load(0x402000, 2) == data["full"]

    certificate = next(cache.glob("pe32-image-v3-*.json"))
    damaged = json.loads(certificate.read_text())
    damaged["data_patches"][0]["bytes"] = "!"
    certificate.write_text(json.dumps(damaged))
    calls.clear()
    flat32_fast_pe.load32_verified(exe, cache)
    assert calls == [False, True, False]

    missing_fast_data["value"] = True
    calls.clear()
    incomplete = flat32_fast_pe.load32_verified(exe, cache)
    assert incomplete.loader.memory.load(0x402000, 2) == data["full"]
    assert calls == [False, True, False]
    missing_fast_data["value"] = False

    code["fast"] = b"\xcc\xc3"
    calls.clear()
    third = flat32_fast_pe.load32_verified(exe, cache)
    assert third is not second and calls == [False, True, False]

    code["fast"] = code["full"]
    exe.write_bytes(b"MZ\x00\x02")
    calls.clear()
    flat32_fast_pe.load32_verified(exe, cache)
    assert calls == [True, False]


def test_elf_loader_remains_on_original_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The PE optimization does not change ELF loading."""
    exe = tmp_path / "candidate.elf"
    exe.write_bytes(b"\x7fELF")
    calls: list[Path] = []

    def fake_load(path: Path) -> object:
        calls.append(path)
        return object()

    monkeypatch.setattr(flat32_fast_pe, "load32", fake_load)
    flat32_fast_pe.load32_verified(exe, tmp_path / "cache")
    assert calls == [exe]


def test_unsectioned_mapped_bytes_must_match_before_cache_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Loader-created bytes outside sections remain part of the image proof."""
    import angr

    exe = tmp_path / "mapped.exe"
    exe.write_bytes(b"MZtest")
    calls = []

    def fake_load(path: Path, *, perform_relocations: bool = True) -> angr.Project:
        calls.append(perform_relocations)
        project = angr.load_shellcode(b"abcd", arch="x86", load_address=0x400000)
        project.loader.memory.store(0x400002, b"X" if perform_relocations else b"Y")
        return project

    monkeypatch.setattr(flat32_fast_pe, "load32", fake_load)
    cache = tmp_path / "cache"
    first = flat32_fast_pe.load32_verified(exe, cache)
    second = flat32_fast_pe.load32_verified(exe, cache)
    assert first.loader.memory.load(0x400002, 1) == b"X"
    assert second.loader.memory.load(0x400002, 1) == b"X"
    assert calls == [True, False, True, False]
    assert not list(cache.glob("*.json"))
