"""Write accepted generated C separately from CLI diagnostics.

Layer: CLI/fallback/reporting.
Responsibility: persist validated per-function C payloads byte-for-byte for
translation-unit assembly and external compilation gates. This module does not
parse, repair, or infer semantics from rendered C.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def write_generated_function_c(
    output_dir: Path,
    *,
    address: int,
    name: str,
    payload: str,
) -> Path:
    """Atomically write one validated function payload without transforming it."""
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _SAFE_NAME_RE.sub("_", name).strip("._") or f"sub_{address:x}"
    destination = output_dir / f"{address:08x}-{safe_name}.c"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, destination)
    return destination


def write_generated_translation_unit_c(
    output_dir: Path,
    *,
    payload: str,
    complete: bool,
) -> Path:
    """Atomically persist deterministic complete or honest partial batch C."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = "translation-unit.c" if complete else "partial-translation-unit.c"
    destination = output_dir / filename
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, destination)
    counterpart_name = "partial-translation-unit.c" if complete else "translation-unit.c"
    (output_dir / counterpart_name).unlink(missing_ok=True)
    return destination


__all__ = ["write_generated_function_c", "write_generated_translation_unit_c"]
