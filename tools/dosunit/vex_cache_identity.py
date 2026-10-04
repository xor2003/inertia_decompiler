"""Bind reusable VEX blocks to the loaded image and current lifting model.

Layer: dosunit lowering evidence.
Responsibility: derive a fresh identity once per cached lowering invocation,
including source dependencies, registered lifters, native artifacts and decode
configuration. No identity or source bytes survive the invocation boundary.
"""

from __future__ import annotations

import hashlib
import os
import sys
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from tools.dosunit import ssa_provenance
from tools.dosunit.flat32_proof_report import loaded_image_identity
from tools.dosunit.model import stable_id

if TYPE_CHECKING:
    import angr


def _artifact_identity(path: Path) -> dict[str, str]:
    """Read an implementation artifact freshly; missing files remain loud errors."""
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.resolve()), "sha256": digest}


def _registered_implementations(architecture: str) -> dict[str, list[dict[str, Any]]]:
    """Seal ordered third-party registries and actual Python/Cython module files."""
    from pyvex.lifting import lifters
    from pyvex.lifting.lift_function import postprocessors

    result: dict[str, list[dict[str, Any]]] = {}
    for kind, registry in (("lifters", lifters), ("postprocessors", postprocessors)):
        implementations = []
        for implementation in registry.get(architecture, ()):
            module = sys.modules[implementation.__module__]
            if module.__file__ is None:
                raise ValueError(f"VEX {kind} implementation has no file identity: {module.__name__}")
            implementations.append({
                "class": f"{implementation.__module__}.{implementation.__qualname__}",
                "artifact": _artifact_identity(Path(module.__file__)),
            })
        result[kind] = implementations
    return result


def _native_artifacts() -> list[dict[str, str]]:
    """Bind installed libVEX bytes rather than relying on a package version alone."""
    import pyvex

    directory = Path(pyvex.__file__).parent / "lib"
    paths = [directory / name for name in ("libpyvex.so", "libpyvex.dylib", "pyvex.dll")]
    artifacts = [_artifact_identity(path) for path in paths if path.is_file()]
    if not artifacts:
        raise FileNotFoundError(f"no native VEX artifact in {directory}")
    return artifacts


def _archinfo_identity(info: dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalize the empty CFFI cache pointer without dropping hardware metadata."""
    if info is None:
        return None
    import pyvex

    copied = dict(info)
    hardware = copied.get("hwcache_info")
    if isinstance(hardware, dict):
        hardware = dict(hardware)
        pointer = hardware.get("caches")
        if pointer is not None and pointer != pyvex.ffi.NULL:
            raise ValueError("nonempty VEX hardware cache descriptors need an explicit identity")
        hardware["caches"] = None
        copied["hwcache_info"] = hardware
    return copied


def _vex_architecture_identity(architecture: object) -> object:
    """Handle the real16 PyvexArch adapter as well as ordinary VEX names."""
    from pyvex.arches import PyvexArch

    if architecture is None or isinstance(architecture, str):
        return architecture
    if not isinstance(architecture, PyvexArch):
        raise TypeError("unsupported VEX architecture descriptor")
    return {
        "name": architecture.name, "bits": architecture.bits,
        "memory_endness": architecture.memory_endness,
        "instruction_endness": architecture.instruction_endness,
        "vex_arch": architecture.vex_arch,
        "vex_archinfo": _archinfo_identity(architecture.vex_archinfo),
    }


def vex_cache_identity(project: angr.Project) -> str:
    """Freeze the loaded bytes and all owned lifting inputs for one cache lookup.

    Arch/registry objects are third-party boundaries. Cache identity is separate
    from ABI/proof identity: SSA projections and proofs are recomputed even when
    an unchanged VEX block is reused. Block address/size/optimization level remain
    part of each entry's key.
    """
    arch = project.arch
    frontend_key: list[object] | None = None
    if arch.name == "86_16":
        from angr_platforms.X86_16.arch_86_16 import Arch86_16

        if not isinstance(arch, Arch86_16):
            raise TypeError("real16 VEX cache requires the owned architecture contract")
        from pyvex.arches import PyvexArch

        frontend_key = [
            f"{item.__module__}.{item.__qualname__}" if isinstance(item, type)
            else _vex_architecture_identity(item) if isinstance(item, PyvexArch)
            else item
            for item in arch.lifting_semantics_key_8616()
        ]
    return cast(str, stable_id("vex-model", {
        "schema": 1,
        "sources": ssa_provenance._semantic_hash(),
        "loaded_image": loaded_image_identity(project),
        "architecture": {
            "class": f"{type(arch).__module__}.{type(arch).__qualname__}",
            "name": arch.name, "bits": arch.bits,
            "memory_endness": str(arch.memory_endness),
            "register_endness": str(arch.register_endness),
            "instruction_endness": str(arch.instruction_endness),
            "registers": arch.registers,
            "vex_arch": _vex_architecture_identity(arch.vex_arch),
            "vex_archinfo": _archinfo_identity(arch.vex_archinfo),
            "frontend_semantics": frontend_key,
        },
        "implementations": _registered_implementations(arch.name),
        "native": _native_artifacts(),
        "packages": {name: version(name) for name in ("angr", "cle", "archinfo", "pyvex", "capstone")},
        "python_abi": sys.implementation.cache_tag,
        "environment": {key: value for key, value in os.environ.items() if key.startswith("INERTIA_")},
    }))
