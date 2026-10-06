"""Layer: validation binary loading.

Responsibility: reuse a verified unrelocated PE image only when its executable
bytes match and bounded data fixups reconstruct the normal CLE image.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import angr
import cle
import pefile
from flat32_adapter import load32

from tools.dosunit import flat32_pe_loader
from tools.dosunit.flat32_proof_report import loaded_image_identity

if TYPE_CHECKING:
    from collections.abc import Mapping


_CERTIFICATE_VERSION = 3
_MAX_PATCH_BYTES = 1_048_576


def _image_fingerprint(project: angr.Project) -> dict[str, Any] | None:
    """Describe every mapped section, or decline an incomplete image."""
    image = project.loader.main_object
    sections: list[dict[str, Any]] = []
    for section in image.sections:
        item: dict[str, Any] = {
            "name": str(section.name),
            "start": int(section.min_addr),
            "end": int(section.max_addr),
            "executable": bool(section.is_executable),
            "readable": bool(section.is_readable),
            "writable": bool(section.is_writable),
        }
        try:
            content = project.loader.memory.load(section.min_addr, section.memsize)
        except KeyError:
            return None
        item["sha256"] = hashlib.sha256(content).hexdigest()
        sections.append(item)
    return {
        "arch": project.arch.name,
        "linked_base": int(image.linked_base),
        "mapped_base": int(image.mapped_base),
        "sections": sections,
        "mapped_image": loaded_image_identity(project),
    }


def _compatible_code_images(full: dict[str, Any], fast: dict[str, Any]) -> bool:
    """Require identical layout and executable bytes before data patching."""
    if any(full[key] != fast[key] for key in ("arch", "linked_base", "mapped_base")):
        return False
    full_sections = full["sections"]
    fast_sections = fast["sections"]
    if len(full_sections) != len(fast_sections):
        return False
    for normal, unrelocated in zip(full_sections, fast_sections, strict=True):
        if {key: value for key, value in normal.items() if key != "sha256"} != {
            key: value for key, value in unrelocated.items() if key != "sha256"
        }:
            return False
        if normal["executable"] and normal["sha256"] != unrelocated["sha256"]:
            return False
    return True


def _bounded_data_patches(
    full_project: angr.Project, full: dict[str, Any], fast: dict[str, Any]
) -> list[dict[str, Any]] | None:
    """Record only data sections changed by CLE relocations, within a hard cap."""
    if not _compatible_code_images(full, fast):
        return None
    patches: list[dict[str, Any]] = []
    total = 0
    for section, normal, unrelocated in zip(
        full_project.loader.main_object.sections, full["sections"], fast["sections"], strict=True
    ):
        if normal["sha256"] == unrelocated["sha256"]:
            continue
        content = full_project.loader.memory.load(section.min_addr, section.memsize)
        total += len(content)
        if total > _MAX_PATCH_BYTES:
            return None
        patches.append({"start": int(section.min_addr), "size": len(content), "bytes": base64.b64encode(content).decode()})
    return patches


def _apply_data_patches(project: angr.Project, patches: object) -> bool:
    """Restore certified data bytes before checking the entire image hash."""
    if not isinstance(patches, list):
        return False
    total = 0
    for patch in patches:
        if not isinstance(patch, dict):
            return False
        start, size, encoded = patch.get("start"), patch.get("size"), patch.get("bytes")
        if type(start) is not int or type(size) is not int or not isinstance(encoded, str):
            return False
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return False
        total += len(content)
        if size != len(content) or total > _MAX_PATCH_BYTES:
            return False
        project.loader.memory.store(start, content)
    return True


def _loader_stamp() -> dict[str, str | int]:
    """Invalidate certificates when the loader implementation version changes."""
    return {
        "version": _CERTIFICATE_VERSION,
        "angr": angr.__version__,
        "cle": cle.__version__,
        "pefile": pefile.__version__,
        "pe_loader_source": hashlib.sha256(Path(flat32_pe_loader.__file__).read_bytes()).hexdigest(),
    }


def _read_certificate(path: Path) -> dict[str, Any] | None:
    """Treat absent or damaged cache files as misses."""
    try:
        payload = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_certificate(path: Path, payload: Mapping[str, Any]) -> None:
    """Publish a fully written certificate for other comparator shards."""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f"{path.name}.", delete=False
    ) as temporary:
        json.dump(payload, temporary, sort_keys=True)
        temporary_path = Path(temporary.name)
    try:
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def load32_verified(exe_path: Path, cache_dir: Path | None) -> angr.Project:
    """Skip costly PE relocation parsing only after full-load code-byte proof.

    ``cache_dir=None`` disables the certificate layer entirely: no read, write
    or lock, and the result is the same ``load32`` image a cache miss returns.
    """
    with exe_path.open("rb") as stream:
        magic = stream.read(2)
    if magic != b"MZ" or cache_dir is None:
        return load32(exe_path)
    digest = hashlib.sha256(exe_path.read_bytes()).hexdigest()
    cache_dir.mkdir(parents=True, exist_ok=True)
    certificate_path = cache_dir / f"pe32-image-v{_CERTIFICATE_VERSION}-{digest}.json"
    lock_path = certificate_path.with_suffix(".lock")
    stamp = _loader_stamp()
    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            certificate = _read_certificate(certificate_path)
            if certificate is not None and certificate.get("stamp") == stamp and certificate.get("exe_sha256") == digest:
                fast = load32(exe_path, perform_relocations=False)
                unrelocated = _image_fingerprint(fast)
                if (
                    unrelocated is not None
                    and unrelocated == certificate.get("unrelocated_fingerprint")
                    and _apply_data_patches(fast, certificate.get("data_patches"))
                ):
                    relocated = _image_fingerprint(fast)
                    if relocated is not None and relocated == certificate.get("relocated_fingerprint"):
                        return fast
            full = load32(exe_path)
            image = full.loader.main_object
            if image.linked_base != image.mapped_base:
                return full
            fast = load32(exe_path, perform_relocations=False)
            full_fingerprint = _image_fingerprint(full)
            fast_fingerprint = _image_fingerprint(fast)
            if full_fingerprint is None or fast_fingerprint is None:
                return full
            patches = _bounded_data_patches(full, full_fingerprint, fast_fingerprint)
            if (patches is not None and _apply_data_patches(fast, patches)
                    and _image_fingerprint(fast) == full_fingerprint):
                _write_certificate(
                    certificate_path,
                    {"stamp": stamp, "exe_sha256": digest, "relocated_fingerprint": full_fingerprint,
                     "unrelocated_fingerprint": fast_fingerprint, "data_patches": patches},
                )
            return full
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
