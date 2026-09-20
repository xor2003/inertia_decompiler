"""Decode PKLITE containers with Deark, never by guessing executed stub effects.

Layer: frontend (loader).
Responsibility: run a bounded external decoder and validate its MZ container,
entry and unapplied relocation records before the ordinary DOS loader sees it.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from .mz_image import MZHeaderView, UnpackedMZImage
from .packed_mz import PackedMZError, PackedMZErrorKind, PackerType, detect_packer_in_bytes

_MAX_OUTPUT_BYTES: int = 32 * 1024 * 1024
_DEARK_TIMEOUT: int = 60
_DEARK_SOURCE: str = "https://github.com/jsummers/deark"


def _validated_image(data: bytes) -> UnpackedMZImage:
    """Reject truncated, still-packed, trailing-overlay or out-of-bounds output."""
    header = MZHeaderView.parse(data)
    if header is None:
        raise PackedMZError(PackedMZErrorKind.MALFORMED_PKLITE, "Deark output is not an MZ executable")
    valid_extent = header.declared_file_size == len(data) and 28 <= header.header_size < len(data)
    table_end = header.relocation_offset + header.relocation_count * 4
    valid_table = header.relocation_count == 0 or 28 <= header.relocation_offset <= table_end <= header.header_size
    if not valid_extent or not valid_table:
        raise PackedMZError(PackedMZErrorKind.MALFORMED_PKLITE, "invalid MZ extent, relocation table or unsupported overlay")
    if detect_packer_in_bytes(data) is not None:
        raise PackedMZError(PackedMZErrorKind.MALFORMED_PKLITE, "Deark output is still packed")
    image = data[header.header_size:]
    if (header.entry_cs << 4) + header.entry_ip >= len(image):
        raise PackedMZError(PackedMZErrorKind.MALFORMED_PKLITE, "decoded entry lies outside the load image")
    relocations: list[tuple[int, int]] = []
    for index in range(header.relocation_count):
        offset, segment = struct.unpack_from("<HH", data, header.relocation_offset + index * 4)
        if (segment << 4) + offset + 2 > len(image):
            raise PackedMZError(PackedMZErrorKind.MALFORMED_PKLITE, "decoded relocation lies outside the load image")
        relocations.append((segment, offset))
    return UnpackedMZImage(image, tuple(relocations), header.entry_cs, header.entry_ip,
                           header.stack_ss, header.stack_sp, header.min_alloc, header.max_alloc, header.overlay_number)


def unpack_pklite(data: bytes) -> UnpackedMZImage:
    """Unpack a recognized PKLITE MZ with an optional native Deark installation."""
    detection = detect_packer_in_bytes(data)
    if detection is None or detection.packer_type is not PackerType.PKLITE:
        raise PackedMZError(PackedMZErrorKind.UNSUPPORTED_PACKER, "expected a recognized PKLITE MZ executable")
    executable = shutil.which(os.environ.get("INERTIA_DEARK_PATH", "deark"))
    if executable is None:
        raise PackedMZError(PackedMZErrorKind.UNPACKER_UNAVAILABLE,
                            f"Deark not found; build {_DEARK_SOURCE} and set INERTIA_DEARK_PATH or add deark to PATH")
    with tempfile.TemporaryDirectory(prefix="inertia-pklite-") as directory:
        source = Path(directory) / "packed.exe"
        output = Path(directory) / "unpacked.exe"
        source.write_bytes(data)
        command = [executable, "-m", "pklite", "-maxfilesize", str(_MAX_OUTPUT_BYTES),
                   "-t", str(output), "-file", str(source)]
        try:
            result = subprocess.run(command, cwd=directory, capture_output=True, text=True,
                                    errors="replace", timeout=_DEARK_TIMEOUT, check=False)
        except subprocess.TimeoutExpired as error:
            raise PackedMZError(PackedMZErrorKind.UNPACKER_TIMEOUT, "Deark exceeded its 60-second budget") from error
        except OSError as error:
            raise PackedMZError(PackedMZErrorKind.UNPACKER_UNAVAILABLE, f"cannot execute Deark: {error}") from error
        if result.returncode != 0 or not output.is_file():
            detail = (result.stderr or result.stdout)[-2000:]
            raise PackedMZError(PackedMZErrorKind.MALFORMED_PKLITE,
                                f"Deark failed (exit {result.returncode}) or produced no executable: {detail}")
        if output.stat().st_size > _MAX_OUTPUT_BYTES:
            raise PackedMZError(PackedMZErrorKind.MALFORMED_PKLITE, "Deark output exceeds the size limit")
        return _validated_image(output.read_bytes())
