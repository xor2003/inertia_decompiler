"""Read optional signature caches through their canonical class owner.

Layer: Tooling/optional evidence.
Responsibility: preserve supported serialized identities after package relocation
and distinguish unusable cache data from defects in object reconstruction.
Decoding does not authorize signature matches or semantic evidence.
"""

from __future__ import annotations

import logging
import pickle
from io import BytesIO
from pathlib import Path


class SignatureCacheClassLookupError(LookupError):
    """A serialized cache refers to an unavailable module or class."""


class _SignatureCacheUnpickler(pickle.Unpickler):
    """Resolve historical parser globals without restoring global import aliases."""

    def find_class(self, module: str, name: str) -> object:
        """Map the historical parser owner; retain causes for missing classes."""
        if module == "omf_pat":
            module = "tools.signatures.omf_pat"
        try:
            resolved: object = super().find_class(module, name)
        except (ImportError, AttributeError) as error:
            raise SignatureCacheClassLookupError(f"{module}.{name}") from error
        return resolved


def loads_signature_pickle(payload: bytes) -> object:
    """Decode trusted local cache bytes; constructor failures remain loud."""
    decoded: object = _SignatureCacheUnpickler(BytesIO(payload)).load()
    return decoded


def read_signature_pickle(path: Path) -> object | None:
    """Return a decoded cache or a diagnosed cache miss for known IO/data errors.

    Keep filesystem reads separate from decoding: an OSError raised by a cached
    object's constructor is a program defect, not an unreadable cache file.
    """
    logger = logging.getLogger(__name__)
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        logger.warning("Cannot read signature cache %s: %s", path, error)
        return None
    try:
        return loads_signature_pickle(payload)
    except (pickle.UnpicklingError, EOFError, SignatureCacheClassLookupError) as error:
        logger.warning("Invalid signature cache %s: %s", path, error)
        return None
