"""Create isolated projects for mutating discovery evidence scans.

Layer: CLI/fallback/reporting.
Responsibility: keep caller-evidence discovery mutations out of the target decompilation project.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, cast

import angr
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler.project_loading import _build_project_cached


class _DiscoverySignaturePolicy(Protocol):
    """Owned optional policy attachments on a third-party angr project."""

    _inertia_lst_metadata: object
    _inertia_include_library_functions: object


def _copy_signature_policy(source: angr.Project, target: angr.Project) -> None:
    """Copy matched-address evidence, never mutable source/debug metadata."""
    source_policy = cast(_DiscoverySignaturePolicy, source)
    target_policy = cast(_DiscoverySignaturePolicy, target)
    # Either attachment may be absent on a partially initialized angr project.
    try:
        metadata = source_policy._inertia_lst_metadata
    except AttributeError:
        metadata = None
    try:
        include_libraries = source_policy._inertia_include_library_functions
    except AttributeError:
        include_libraries = False
    copied = None
    if isinstance(metadata, LSTMetadata) and metadata.signature_code_addrs:
        addresses = metadata.signature_code_addrs
        copied = LSTMetadata(
            data_labels={},
            code_labels={addr: name for addr, name in metadata.code_labels.items() if addr in addresses},
            code_ranges={addr: span for addr, span in metadata.code_ranges.items() if addr in addresses},
            signature_code_addrs=addresses, absolute_addrs=metadata.absolute_addrs,
            source_format=metadata.source_format,
        )
    target_policy._inertia_lst_metadata = copied
    target_policy._inertia_include_library_functions = bool(include_libraries)


def isolated_discovery_evidence_project_8616(project: angr.Project) -> angr.Project:
    """Return a separate project for scans that mutate angr's knowledge base."""
    try:
        main_object = project.loader.main_object
        binary = main_object.binary
        linked_base = main_object.linked_base
        entry_point = project.entry
    except (AttributeError, TypeError):
        return project
    if not isinstance(binary, str | Path) or not isinstance(linked_base, int) or not isinstance(entry_point, int):
        return project
    try:
        isolated = _build_project_cached(
            str(binary),
            force_blob=False,
            base_addr=linked_base,
            entry_point=entry_point,
        )
    except (OSError, ValueError):
        return project
    if isolated is not project:
        _copy_signature_policy(project, isolated)
    return isolated
