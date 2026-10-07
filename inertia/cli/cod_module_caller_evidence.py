"""Seed caller return-use evidence for isolated COD procedure images.

Layer: CLI/fallback/reporting.
Responsibility: build a byte-faithful COD module project, invoke the typed
binary caller-use collector, and remap its evidence onto an isolated procedure
project. This module does not infer return types or inspect assembly/source
text; Types/Lowering consumes the resulting evidence independently.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from typing import Protocol, cast

from inertia.frontend.x86_16.cod_analysis_image import build_cod_module_analysis_image_8616
from inertia.frontend.x86_16.cod_extract import CODProcMetadata, extract_cod_listing_metadata
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    collect_caller_return_use_evidence_8616,
    record_caller_return_use_evidence_8616,
)

from .project_loading import _build_project_from_bytes

__all__ = ["record_cod_module_caller_return_use_evidence_8616"]

_ANALYSIS_IMAGE_BASE = 0x10000
_LOGGER = logging.getLogger(__name__)


class _CallerArgumentEvidenceSurface8616(Protocol):
    """Owned caller-analysis context carried by the isolated angr project."""

    _inertia_caller_evidence_project_8616: object
    _inertia_caller_evidence_target_8616: int
    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_caller_target_aliases_8616: tuple[int, ...]


def _unknown_evidence_8616(target_addr: int) -> CallerReturnUseEvidence8616:
    """Return one closed failure result for unavailable module evidence."""
    return CallerReturnUseEvidence8616(
        target_addr=target_addr,
        verdict=CallerReturnUseVerdict8616.UNKNOWN,
        raw_fact_count=0,
        normalized_fact_count=0,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=1,
        used_callsite_count=0,
        unused_callsite_count=0,
        callsite_addrs=(),
    )


def record_cod_module_caller_return_use_evidence_8616(
    cod_metadata: CODProcMetadata,
    isolated_target_addr: int,
    isolated_project: object,
) -> CallerReturnUseEvidence8616:
    """Record full-module caller evidence on one isolated COD procedure project."""
    if cod_metadata.cod_path is None or not cod_metadata.instruction_offsets:
        evidence = _unknown_evidence_8616(isolated_target_addr)
        record_caller_return_use_evidence_8616(isolated_project, isolated_target_addr, evidence)
        return evidence
    try:
        cod_path = Path(cod_metadata.cod_path)
        listing = extract_cod_listing_metadata(cod_path)
        module_image = build_cod_module_analysis_image_8616(
            cod_path,
            listing,
            image_base=_ANALYSIS_IMAGE_BASE,
        )
        target_original_addr = cod_metadata.instruction_offsets[0]
        target_analysis_addr = module_image.analysis_addr(
            target_original_addr,
            image_base=_ANALYSIS_IMAGE_BASE,
        )
        evidence_project = _build_project_from_bytes(
            module_image.code,
            base_addr=_ANALYSIS_IMAGE_BASE,
            entry_point=_ANALYSIS_IMAGE_BASE,
        )
        isolated_surface = cast(_CallerArgumentEvidenceSurface8616, isolated_project)
        isolated_surface._inertia_caller_evidence_project_8616 = evidence_project
        isolated_surface._inertia_caller_evidence_target_8616 = target_analysis_addr
        isolated_surface._inertia_caller_function_ranges_8616 = module_image.analysis_ranges(
            image_base=_ANALYSIS_IMAGE_BASE
        )
        isolated_surface._inertia_caller_target_aliases_8616 = (target_analysis_addr,)
        evidence = collect_caller_return_use_evidence_8616(
            evidence_project,
            target_analysis_addr,
            isolated_surface._inertia_caller_function_ranges_8616,
        )
        remapped_facts = tuple(
            replace(
                fact,
                caller_addr=module_image.original_addr(
                    fact.caller_addr,
                    image_base=_ANALYSIS_IMAGE_BASE,
                ),
                callsite_addr=module_image.original_addr(
                    fact.callsite_addr,
                    image_base=_ANALYSIS_IMAGE_BASE,
                ),
                witness_instruction_addr=(
                    module_image.original_addr(
                        fact.witness_instruction_addr,
                        image_base=_ANALYSIS_IMAGE_BASE,
                    )
                    if isinstance(fact.witness_instruction_addr, int)
                    else None
                ),
            )
            for fact in evidence.facts
        )
        remapped = replace(
            evidence,
            target_addr=isolated_target_addr,
            callsite_addrs=tuple(fact.callsite_addr for fact in remapped_facts),
            facts=remapped_facts,
        )
    except (OSError, TypeError, ValueError) as exc:
        _LOGGER.debug("COD module caller evidence unavailable: %s", exc)
        remapped = _unknown_evidence_8616(isolated_target_addr)
    except Exception as exc:  # Dynamic angr/CLE project and disassembler boundary.
        _LOGGER.debug("COD module caller evidence analysis failed: %s", exc)
        remapped = _unknown_evidence_8616(isolated_target_addr)
    record_caller_return_use_evidence_8616(isolated_project, isolated_target_addr, remapped)
    return remapped
