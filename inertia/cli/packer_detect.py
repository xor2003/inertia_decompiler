# cython: language_level=3, infer_types=True
"""Compatibility access to frontend-owned packed-MZ detection.

Layer: CLI/fallback/reporting compatibility.
Responsibility: expose historical packer-detection helpers while delegating all classification to the
X86-16 frontend loader contract.
Forbidden: defining signatures, unpacking images, or creating a second packer classification truth.
"""

from __future__ import annotations
import typing
import cython

from pathlib import Path

from inertia.frontend.x86_16.packed_mz import (
    PackerDetection,
    PackerType,
    detect_packer,
    detect_packer_in_bytes,
)

__all__ = (
    "PackerDetection",
    "PackerType",
    "detect_packer",
    "detect_packer_in_bytes",
    "get_packer_name",
    "is_packed",
)


@cython.ccall
def is_packed(binary_path: Path) -> cython.bint:
    """Return whether the frontend recognizes a packed DOS MZ executable."""
    return detect_packer(binary_path) is not None


@cython.ccall
def get_packer_name(binary_path: Path) -> object:
    """Return the frontend's human-readable packer label, when recognized."""
    detection: object
    detection = detect_packer(binary_path)
    return None if detection is None else detection.label
