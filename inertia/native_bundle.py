"""Layer: build/runtime verification.

Responsibility: own the shared exact-source/ABI verification for optional
pure-mode Cython extensions. The ``build_cython_vex`` schema-1 manifest is
the canonical contract; every accelerated module reuses this single
verification path instead of growing competing cache or digest machinery.
"""

from __future__ import annotations

import hashlib
import json
import sys
import sysconfig
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

BUILD_SCHEMA: int = 1


def file_digest(path: Path) -> str:
    """Fingerprint source or extension bytes without relying on timestamps."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_bundle_directory(
    manifest_path: Path, confinement: Path, source: Path, extension_name: str,
) -> Path | None:
    """Apply schema/ABI/source/digest/confinement checks to one manifest layout.

    ``extension_name`` is the module's import basename. A manifest activates
    an extension only when its exact source bytes, interpreter cache tag,
    SOABI, recorded artifact digest and in-confinement path all match; any
    mismatch returns ``None`` so the caller falls back or refuses per its
    own backend mode.
    """
    try:
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, dict):
            return None
        if manifest["schema"] != BUILD_SCHEMA:
            return None
        if manifest["cache_tag"] != sys.implementation.cache_tag or manifest["soabi"] != sysconfig.get_config_var("SOABI"):
            return None
        if manifest["source_sha256"] != file_digest(source):
            return None
        relative_path = manifest["extension"]
        if not isinstance(relative_path, str):
            return None
        extension = (confinement / relative_path).resolve()
        if not extension.is_relative_to(confinement.resolve()):
            return None
        if extension.name not in {extension_name + suffix for suffix in EXTENSION_SUFFIXES}:
            return None
        if manifest["extension_sha256"] != file_digest(extension):
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return extension.parent
