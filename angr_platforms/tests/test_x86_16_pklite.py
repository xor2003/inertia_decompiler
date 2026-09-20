"""Bounded Deark execution and output validation must fail closed."""

import struct
import subprocess
from pathlib import Path

import pytest
from angr_platforms.X86_16 import pklite
from angr_platforms.X86_16.mz_image import UnpackedMZImage
from angr_platforms.X86_16.packed_mz import PackedMZError, PackedMZErrorKind, detect_packer_in_bytes

from inertia_decompiler import project_loading
from inertia_decompiler.cache import _cache_runtime_environment


def _packed():
    data = bytearray(UnpackedMZImage(b"\x90" * 32, (), 0, 0, 2, 256).to_mz_bytes())
    data[0x1c:0x1c] = b"\0" * 16
    struct.pack_into("<H", data, 8, 3)
    struct.pack_into("<H", data, 2, len(data))
    struct.pack_into("<H", data, 24, 0x30)
    data[0x1e:0x24] = b"PKLITE"
    return bytes(data)


def _output():
    return UnpackedMZImage(bytes.fromhex("b83412c3"), ((0, 1),), 0, 0, 0x20, 256,
                           min_alloc=3, max_alloc=0x100, overlay_number=6).to_mz_bytes()


def _decoder(monkeypatch, payload, returncode=0):
    monkeypatch.setattr(pklite.shutil, "which", lambda name: "/native/deark")

    def run(command, **kwargs):
        assert command[:3] == ["/native/deark", "-m", "pklite"]
        assert kwargs["timeout"] == 60
        assert Path(command[-1]).read_bytes() == _packed()
        if payload is not None:
            Path(command[command.index("-t") + 1]).write_bytes(payload)
        return subprocess.CompletedProcess(command, returncode, "", "decoder detail")

    monkeypatch.setattr(pklite.subprocess, "run", run)


def test_deark_retains_unapplied_relocations_and_registers(monkeypatch):
    _decoder(monkeypatch, _output())
    image = pklite.unpack_pklite(_packed())
    assert image.image == bytes.fromhex("b83412c3")
    assert image.relocations == ((0, 1),)
    assert (image.entry_cs, image.entry_ip, image.stack_ss, image.stack_sp) == (0, 0, 0x20, 256)
    assert (image.min_alloc, image.max_alloc) == (3, 0x100)
    assert image.overlay_number == 6


def test_loader_routes_pklite_to_native_decoder(monkeypatch, tmp_path):
    _decoder(monkeypatch, _output())
    path = tmp_path / "sample.exe"
    path.write_bytes(_packed())
    stream = project_loading._decoded_packed_stream(path, detect_packer_in_bytes(_packed()))
    assert stream.read() == _output()


@pytest.mark.parametrize("corruption", ["not_mz", "truncated", "entry", "relocation", "table", "packed", "trailing"])
def test_invalid_decoder_output_is_rejected(monkeypatch, corruption):
    output = bytearray(_output())
    if corruption == "not_mz":
        output[:2] = b"??"
    elif corruption == "truncated":
        output = output[:-1]
    elif corruption == "entry":
        struct.pack_into("<H", output, 20, 0xffff)
    elif corruption == "relocation":
        struct.pack_into("<H", output, 28, 0xffff)
    elif corruption == "table":
        struct.pack_into("<H", output, 24, 0xffff)
    elif corruption == "packed":
        output = bytearray(_packed())
    else:
        output += b"unmodelled overlay"
    _decoder(monkeypatch, bytes(output))
    with pytest.raises(PackedMZError) as error:
        pklite.unpack_pklite(_packed())
    assert error.value.kind is PackedMZErrorKind.MALFORMED_PKLITE


@pytest.mark.parametrize("payload,returncode", [(None, 0), (_output(), 1)])
def test_failed_or_empty_decoder_is_rejected(monkeypatch, payload, returncode):
    _decoder(monkeypatch, payload, returncode)
    with pytest.raises(PackedMZError, match="Deark failed"):
        pklite.unpack_pklite(_packed())


def test_missing_deark_has_installation_hint(monkeypatch):
    monkeypatch.setattr(pklite.shutil, "which", lambda name: None)
    with pytest.raises(PackedMZError, match=r"github\.com/jsummers/deark") as error:
        pklite.unpack_pklite(_packed())
    assert error.value.kind is PackedMZErrorKind.UNPACKER_UNAVAILABLE


def test_decoder_timeout_is_typed(monkeypatch):
    monkeypatch.setattr(pklite.shutil, "which", lambda name: "/native/deark")

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(pklite.subprocess, "run", timeout)
    with pytest.raises(PackedMZError) as error:
        pklite.unpack_pklite(_packed())
    assert error.value.kind is PackedMZErrorKind.UNPACKER_TIMEOUT


def test_decoder_replacement_changes_semantic_cache_identity(monkeypatch, tmp_path):
    executable = tmp_path / "deark"
    executable.write_bytes(b"first decoder")
    executable.chmod(0o700)
    monkeypatch.setenv("INERTIA_DEARK_PATH", str(executable))
    before = _cache_runtime_environment()
    executable.write_bytes(b"new decoder")
    assert _cache_runtime_environment() != before
