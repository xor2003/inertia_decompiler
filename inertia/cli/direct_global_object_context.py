"""Hydrate direct-global Widening evidence for CLI-created projects.

Layer: CLI/fallback/reporting orchestration.
Responsibility: load or persist typed direct-global evidence and ask the owning
Lowering/Widening pipeline to classify complete recovered function catalogs.
"""

from __future__ import annotations

from collections.abc import Sequence

from inertia.lowering.project_global_object_layout import (
    recover_project_direct_global_object_layout_evidence_8616,
)
from inertia.lowering.segmented_global_loads import (
    collect_project_direct_global_width_evidence_8616,
)
from inertia.widening.global_object_layout import (
    DirectGlobalObjectLayoutEvidence8616,
)

from .direct_global_object_cache import (
    load_direct_global_object_cache_8616,
    store_direct_global_object_cache_8616,
)
from .project_evidence_transport import (
    attach_project_direct_global_object_layout_evidence_8616,
    project_direct_global_object_layout_evidence_8616,
)


def attach_available_direct_global_object_evidence_8616(
    project: object,
    cache_key: dict[str, object] | None,
) -> bool:
    """Attach persisted evidence unless the project already owns it."""
    if project_direct_global_object_layout_evidence_8616(project) is not None:
        return True
    if cache_key is None:
        return False
    evidence = load_direct_global_object_cache_8616(cache_key)
    if evidence is None:
        return False
    attach_project_direct_global_object_layout_evidence_8616(project, evidence)
    return True


def publish_recovered_direct_global_object_evidence_8616(
    evidence_project: object,
    functions: Sequence[object],
    target_project: object,
    *,
    cache_key: dict[str, object] | None,
) -> DirectGlobalObjectLayoutEvidence8616:
    """Classify one complete catalog and publish its immutable census."""
    evidence = recover_project_direct_global_object_layout_evidence_8616(
        evidence_project,
        functions,
        (collect_project_direct_global_width_evidence_8616,),
    )
    attach_project_direct_global_object_layout_evidence_8616(
        evidence_project,
        evidence,
    )
    if target_project is not evidence_project:
        attach_project_direct_global_object_layout_evidence_8616(
            target_project,
            evidence,
        )
    if cache_key is not None:
        store_direct_global_object_cache_8616(cache_key, evidence)
    return evidence


__all__ = [
    "attach_available_direct_global_object_evidence_8616",
    "publish_recovered_direct_global_object_evidence_8616",
]
