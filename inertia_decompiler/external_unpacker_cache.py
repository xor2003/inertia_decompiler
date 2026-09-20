"""Identify the native decoder consumed by packed-input recovery.

Layer: CLI/fallback/reporting.
Responsibility: invalidate semantic caches when the external Deark executable
changes, including a replacement at the same configured path.
"""

import os
import shutil
from pathlib import Path

from .cache_file_digest import cache_file_digest_8616


def deark_cache_identity() -> str | None:
    """Return the installed decoder's content digest, or no available decoder."""
    executable = shutil.which(os.environ.get("INERTIA_DEARK_PATH", "deark"))
    if executable is None:
        return None
    try:
        return cache_file_digest_8616(Path(executable)).sha256
    except OSError:
        return "unreadable"
