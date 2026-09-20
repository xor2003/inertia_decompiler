"""Load optional binary signatures without consulting source/debug sidecars.

Layer: CLI/fallback/reporting.
Responsibility: publish binary-match labels through the existing metadata
contract; do not infer call semantics from library names or source listings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import angr
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.sidecar_parsers import _detect_flair_metadata


def load_binary_signature_metadata(
    binary: Path, project: angr.Project, *, pat_backend: str | None = None,
    signature_catalog: Path | None = None,
) -> LSTMetadata | None:
    """Attach signature evidence only, leaving debug/source fields empty."""
    labels, ranges, formats = _detect_flair_metadata(
        binary, project, pat_backend=pat_backend, signature_catalog=signature_catalog,
    )
    metadata = None
    if labels or ranges:
        metadata = LSTMetadata(
            data_labels={}, code_labels=labels, code_ranges=ranges,
            signature_code_addrs=frozenset(labels), absolute_addrs=True,
            source_format="+".join(dict.fromkeys(formats)),
        )
        for addr, name in labels.items():
            project.kb.labels[addr] = name
    # Third-party angr project extension consumed by existing discovery owners.
    cast(Any, project)._inertia_lst_metadata = metadata
    return metadata
