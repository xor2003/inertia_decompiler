"""Fingerprint concrete inputs to the existing compiler round-trip owner.

Layer: Tooling/gates.
Responsibility: retain source and tool identity without treating hashes as
semantic coverage or silently assuming compiler defaults are unchanged.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
from dataclasses import dataclass
from enum import StrEnum
from importlib import metadata
from pathlib import Path

OWNED_PYTHON_TREES: tuple[str, ...] = (
    "scripts", "inertia_decompiler", "angr_platforms/angr_platforms",
)


class KVMAccessStatus(StrEnum):
    """Typed host-acceleration availability at the runner boundary."""

    READ_WRITE = "read_write"
    MISSING = "missing"
    DENIED = "denied"
    OTHER_ERROR = "other_error"


@dataclass(frozen=True, slots=True)
class KVMAccessEvidence:
    """Retain the device-open verdict without calling it DOS validation."""

    status: KVMAccessStatus
    error_number: int | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        """Return a stable JSON representation of the device-open attempt."""
        return {"status": self.status.value, "errno": self.error_number}


@dataclass(frozen=True, slots=True)
class RuntimeEnvironmentSnapshot:
    """Identity of the Python execution environment used by a round trip."""

    python_version: str
    python_implementation: str
    python_cache_tag: str | None
    system: str
    release: str
    machine: str
    installed_distributions: tuple[tuple[str, str], ...]
    kvm: KVMAccessEvidence

    def to_dict(self) -> dict[str, object]:
        """Retain complete version rows, including duplicate distributions."""
        return {
            "scope": "runtime_environment_v1_versions_not_binary_hashes",
            "python_version": self.python_version,
            "python_implementation": self.python_implementation,
            "python_cache_tag": self.python_cache_tag,
            "system": self.system,
            "release": self.release,
            "machine": self.machine,
            "installed_distributions": [list(item) for item in self.installed_distributions],
            "kvm": self.kvm.to_dict(),
        }


def kvm_access_evidence(device: Path = Path("/dev/kvm")) -> KVMAccessEvidence:
    """Test whether the current process can open the KVM device read-write."""
    try:
        descriptor = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    except FileNotFoundError as error:
        return KVMAccessEvidence(KVMAccessStatus.MISSING, error.errno)
    except PermissionError as error:
        return KVMAccessEvidence(KVMAccessStatus.DENIED, error.errno)
    except OSError as error:
        return KVMAccessEvidence(KVMAccessStatus.OTHER_ERROR, error.errno)
    os.close(descriptor)
    return KVMAccessEvidence(KVMAccessStatus.READ_WRITE)


def runtime_environment_snapshot(*, kvm_device: Path = Path("/dev/kvm")) -> RuntimeEnvironmentSnapshot:
    """Capture deterministic Python/package/platform facts for one runner launch."""
    distributions = tuple(
        sorted(
            (
                (distribution.metadata.get("Name") or "<unnamed>").casefold(),
                distribution.version or "<unknown>",
            )
            for distribution in metadata.distributions()
        )
    )
    return RuntimeEnvironmentSnapshot(
        python_version=sys.version,
        python_implementation=platform.python_implementation(),
        python_cache_tag=sys.implementation.cache_tag,
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        installed_distributions=distributions,
        kvm=kvm_access_evidence(kvm_device),
    )


def implementation_fingerprint(root: Path) -> dict[str, str | int]:
    """Hash owned Python sources, including uncommitted and untracked helpers.

    Root entrypoints and the listed implementation trees are covered. Generated
    caches, tests outside those trees, installed dependencies and native modules
    are not: this is a source identity, not a complete environment snapshot.
    """
    files = set(root.glob("*.py"))
    for relative in OWNED_PYTHON_TREES:
        files.update((root / relative).rglob("*.py"))
    digest = hashlib.sha256()
    count = 0
    size = 0
    for path in sorted(files):
        relative_path = path.relative_to(root)
        if {".cache", "__pycache__"}.intersection(relative_path.parts) or not path.is_file():
            continue
        with path.open("rb") as stream:
            content_digest = hashlib.file_digest(stream, "sha256").digest()
        digest.update(relative_path.as_posix().encode("utf-8") + b"\0" + content_digest)
        count += 1
        size += path.stat().st_size
    return {"scope": "owned_python_v1", "sha256": digest.hexdigest(), "files": count, "bytes": size}


def input_fingerprint(path: Path) -> dict[str, str | int]:
    """Hash a file or sorted toolchain tree, including relative file names."""
    if not path.exists():
        return {"path": str(path), "error": "missing"}
    if path.is_file():
        with path.open("rb") as stream:
            fingerprint = hashlib.file_digest(stream, "sha256").hexdigest()
        return {"path": str(path.resolve()), "sha256": fingerprint, "files": 1, "bytes": path.stat().st_size}
    files = sorted(item for item in path.rglob("*") if item.is_file())
    digest = hashlib.sha256()
    size = 0
    for item in files:
        relative = str(item.relative_to(path))
        with item.open("rb") as stream:
            content_digest = hashlib.file_digest(stream, "sha256").digest()
        digest.update(relative.encode("utf-8") + b"\0" + content_digest)
        size += item.stat().st_size
    return {"path": str(path.resolve()), "sha256": digest.hexdigest(), "files": len(files), "bytes": size}
