"""Layer: Types/Lowering.

Responsibility: reason about segment-register evidence before conservative segmented-memory lowering.
Forbidden: inventing segment bases, flattening SS/DS/ES, or using postprocess shape as semantic proof.

Real-mode x86 uses segment:offset addressing. This module tracks:
- Segment register assignments (CS, DS, ES, SS)
- Association confidence between segments and specific memory spaces
- Far pointer vs near pointer distinctions
- Segment stability across function calls

Evidence: register assignments, memory access patterns, consistency across functions
"""

from __future__ import annotations

import logging
import os
import typing
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from .alias.alias_model import _stack_storage_facts_for_segmented_address_8616
from .c_ast_utils import _replace_c_children_8616
from .lowering.real_mode_linear import (
    lower_stable_ds_es_linear_global_dereferences_8616,
)
from .lowering.segmented_memory_lowering import apply_runtime_segment_lowering_8616
from .lowering.stack_c_ast_matching import _match_bp_stack_dereference_8616
from .lowering.stack_lowering_from_facts import _canonical_stack_offset_8616, _stack_object_name

if TYPE_CHECKING:
    pass

logger: logging.Logger = logging.getLogger(__name__)


def _publish_segmented_memory_evidence_8616(
    codegen: object,
    summary: dict[str, dict[str, dict[str, object]]],
    lowering: dict[str, dict[str, object]],
) -> None:
    """Publish segment evidence across the dynamic third-party angr codegen/project boundary."""
    # Dynamic codegen boundary: segmented-memory evidence is optional metadata on angr codegen.
    typing.cast(typing.Any, codegen)._inertia_segmented_memory_summary = summary
    # Dynamic codegen boundary: lowering policy is optional metadata on angr codegen.
    typing.cast(typing.Any, codegen)._inertia_segmented_memory_lowering = lowering
    project = getattr(codegen, "project", None)
    if project is not None:
        # Dynamic project boundary: mirror evidence for CLI/reporting consumers attached to angr project.
        project._inertia_segmented_memory_summary = summary
        # Dynamic project boundary: mirror lowering policy for CLI/reporting consumers attached to angr project.
        project._inertia_segmented_memory_lowering = lowering


def _typed_ir_address_spaces_8616(codegen: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Read typed IR address-space summaries from the dynamic angr codegen boundary."""
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    summary = getattr(artifact, "summary", None)
    if not isinstance(summary, dict):
        return (), ()
    address_counts = summary.get("address_space_counts", {})
    stable_counts = summary.get("stable_address_space_counts", {})
    if not isinstance(address_counts, dict):
        address_counts = {}
    if not isinstance(stable_counts, dict):
        stable_counts = {}
    return tuple(sorted(str(key) for key in address_counts)), tuple(sorted(str(key) for key in stable_counts))


class SegmentRegister(Enum):
    """x86-16 segment registers."""

    CS = "code"  # Code segment
    DS = "data"  # Data segment
    ES = "extra"  # Extra segment
    SS = "stack"  # Stack segment
    FS = "fs"  # FS register (80386+)
    GS = "gs"  # GS register (80386+)


@dataclass(frozen=True)
class SegmentAssignment:
    """A segment register assignment at a location."""

    segment_reg: SegmentRegister
    value: int | None  # Literal value if known (e.g., 0x1000)
    source: str  # "literal", "register", "parameter", "return_value"
    location: str  # Where (function name, line number, etc.)
    confidence: float  # 0.0-1.0

    def __repr__(self) -> str:
        val_str = f"0x{self.value:04x}" if self.value is not None else "unknown"
        return f"{self.segment_reg.name}={val_str} ({self.confidence:.1%})"


@dataclass
class SegmentAssociation:
    """Association of a segment with a specific memory space or purpose."""

    segment_reg: SegmentRegister
    associated_space: str  # "code", "data", "stack", "unknown", etc.
    classification: str = "unknown"
    evidence_count: int = 0
    assignments: set[SegmentAssignment] = field(default_factory=set)
    stability: float = 0.5  # 0.0-1.0: how stable across functions
    known_values: set[int] = field(default_factory=set)

    def add_evidence(self, assignment: SegmentAssignment) -> None:
        """Add evidence for this association."""
        self.assignments.add(assignment)
        self.evidence_count += 1
        if assignment.value is not None:
            self.known_values.add(assignment.value)
        # Increase stability with more consistent evidence
        self.stability = min(1.0, 0.5 + (self.evidence_count * 0.05))

    def __repr__(self) -> str:
        return (
            f"{self.segment_reg.name}→{self.associated_space}"
            f" [{self.classification}]"
            f" (stability={self.stability:.1%}, evidence={self.evidence_count})"
        )


@dataclass
class SegmentedPointer:
    """A segmented pointer expression (segment:offset)."""

    segment_reg: SegmentRegister
    offset_expr: str  # Expression for offset part
    known_base: int | None  # Known segment value if constant
    element_type: str  # What this points to
    confidence: float  # 0.0-1.0 based on evidence

    def __repr__(self) -> str:
        seg_str = f"0x{self.known_base:04x}" if self.known_base else self.segment_reg.name
        return f"MK_FP({seg_str}, {self.offset_expr})"


@dataclass
class FarPointerRecovery:
    """Recovered far pointer structure."""

    name: str
    pointer_id: int
    segment_part: SegmentedPointer
    access_count: int = 0
    functions: set[str] = field(default_factory=set)

    def __repr__(self) -> str:
        return f"FarPtr({self.name}: {self.segment_part}, {len(self.functions)} functions)"


@dataclass(frozen=True)
class SegmentLoweringDecision:
    """Conservative lowering policy for one segment register."""

    segment_reg: SegmentRegister
    classification: str
    associated_space: str
    confidence: float
    allow_linear_lowering: bool
    allow_object_lowering: bool
    reason: str

    def requires_explicit_segmented_form(self) -> bool:
        """Return whether lowering must keep an explicit segmented-memory form."""
        return not self.allow_linear_lowering


class SegmentedAddressClassifier:
    """Classifies segmented memory accesses.

    Categories:
    - single: Always same segment (high confidence association)
    - const: Constant segment value known
    - over_associated: Multiple different segments (ambiguous)
    """

    @staticmethod
    def _segment_set(segment_accesses: list[SegmentAssignment]) -> set[SegmentRegister]:
        return {s.segment_reg for s in segment_accesses}

    @staticmethod
    def _value_set(segment_accesses: list[SegmentAssignment]) -> set[int]:
        return {s.value for s in segment_accesses if s.value is not None}

    def _is_over_associated(self, segment_accesses: list[SegmentAssignment]) -> bool:
        segments = self._segment_set(segment_accesses)
        values = self._value_set(segment_accesses)
        return len(segments) > 1 or len(values) > 1

    def _is_const(self, segment_accesses: list[SegmentAssignment]) -> bool:
        values = self._value_set(segment_accesses)
        return len(values) == 1

    def _is_single(self, segment_accesses: list[SegmentAssignment]) -> bool:
        segments = self._segment_set(segment_accesses)
        return len(segments) == 1

    def classify(self, segment_accesses: list[SegmentAssignment]) -> str:
        """Classify segmented address pattern.

        Args:
            segment_accesses: List of segment assignments/accesses

        Returns:
            Classification: "single", "const", "over_associated", "unknown"
        """
        if not segment_accesses:
            return "unknown"

        if self._is_over_associated(segment_accesses):
            return "over_associated"
        if self._is_const(segment_accesses):
            return "const"
        if self._is_single(segment_accesses):
            return "single"
        return "unknown"


class SegmentAssociationAnalyzer:
    """Analyzes and builds segment associations across functions.

    Algorithm:
    1. Collect all segment register assignments
    2. Classify by stability (single, const, over-associated)
    3. Build per-segment associations (CS→code, DS→data, etc.)
    4. Detect far pointer patterns
    5. Score confidence based on consistency
    """

    def __init__(self) -> None:
        """Initialize empty segment association state."""
        self.associations: dict[SegmentRegister, SegmentAssociation] = {
            seg: SegmentAssociation(segment_reg=seg, associated_space="unknown") for seg in SegmentRegister
        }
        self.far_pointers: dict[str, FarPointerRecovery] = {}
        self.next_pointer_id = 0
        self.classifier = SegmentedAddressClassifier()

    def analyze(self, assignments: list[SegmentAssignment]) -> None:
        """Analyze segment assignments and build associations.

        Args:
            assignments: List of SegmentAssignment throughout binary
        """
        # Group by segment register
        by_segment: dict[SegmentRegister, list[SegmentAssignment]] = {}
        for assignment in assignments:
            if assignment.segment_reg not in by_segment:
                by_segment[assignment.segment_reg] = []
            by_segment[assignment.segment_reg].append(assignment)

        # Analyze each segment
        for segment_reg, accesses in by_segment.items():
            classification = self.classifier.classify(accesses)

            # Infer associated space based on pattern
            if segment_reg == SegmentRegister.CS:
                associated_space = "code"
            elif segment_reg == SegmentRegister.SS:
                associated_space = "stack"
            elif segment_reg in (SegmentRegister.DS, SegmentRegister.ES):
                associated_space = "data"
            else:
                associated_space = "unknown"

            assoc = self.associations[segment_reg]
            assoc.associated_space = associated_space
            assoc.classification = classification

            for access in accesses:
                assoc.add_evidence(access)

            assoc.stability = self._classification_stability(classification, assoc.evidence_count)

    def detect_far_pointers(self, pointer_expressions: list[SegmentedPointer]) -> dict[str, FarPointerRecovery]:
        """Detect and recover far pointer patterns.

        Args:
            pointer_expressions: List of segmented pointers found

        Returns:
            Dictionary mapping pointer name to FarPointerRecovery
        """
        for ptr in pointer_expressions:
            name = f"far_ptr_{self.next_pointer_id}"
            self.next_pointer_id += 1

            recovery = FarPointerRecovery(
                name=name, pointer_id=self.next_pointer_id, segment_part=ptr, access_count=0, functions=set()
            )

            self.far_pointers[name] = recovery

        return self.far_pointers

    def get_association_confidence(self, segment_reg: SegmentRegister) -> float:
        """Get confidence in a segment's association."""
        assoc = self.associations.get(segment_reg)
        if assoc is None:
            return 0.0
        return assoc.stability

    def summarize(self) -> dict[str, dict[str, dict[str, object]]]:
        """Summarize segment associations into stable, over-associated, and unknown buckets."""
        stable: dict[str, dict[str, object]] = {}
        over_associated: dict[str, dict[str, object]] = {}
        unknown: dict[str, dict[str, object]] = {}

        for segment_reg, assoc in self.associations.items():
            if assoc.evidence_count == 0:
                continue
            entry = {
                "space": assoc.associated_space,
                "classification": assoc.classification,
                "confidence": assoc.stability,
                "evidence_count": assoc.evidence_count,
                "known_values": tuple(sorted(assoc.known_values)),
            }
            if assoc.classification in {"single", "const"}:
                stable[segment_reg.name] = entry
            elif assoc.classification == "over_associated":
                over_associated[segment_reg.name] = entry
            else:
                unknown[segment_reg.name] = entry

        return {
            "stable": stable,
            "over_associated": over_associated,
            "unknown": unknown,
        }

    def lowering_decision(self, segment_reg: SegmentRegister) -> SegmentLoweringDecision:
        """Return the conservative lowering policy for one segment register."""
        assoc = self.associations[segment_reg]
        classification = assoc.classification
        space = assoc.associated_space
        confidence = assoc.stability

        if assoc.evidence_count == 0:
            return SegmentLoweringDecision(
                segment_reg=segment_reg,
                classification="unknown",
                associated_space=space,
                confidence=0.0,
                allow_linear_lowering=False,
                allow_object_lowering=False,
                reason="no evidence",
            )

        if classification == "const":
            return SegmentLoweringDecision(
                segment_reg=segment_reg,
                classification=classification,
                associated_space=space,
                confidence=confidence,
                allow_linear_lowering=True,
                allow_object_lowering=space in {"data", "stack"},
                reason="constant segment value",
            )

        if classification == "single":
            return SegmentLoweringDecision(
                segment_reg=segment_reg,
                classification=classification,
                associated_space=space,
                confidence=confidence,
                allow_linear_lowering=False,
                allow_object_lowering=False,
                reason="stable segment register but no constant base",
            )

        if classification == "over_associated":
            return SegmentLoweringDecision(
                segment_reg=segment_reg,
                classification=classification,
                associated_space=space,
                confidence=confidence,
                allow_linear_lowering=False,
                allow_object_lowering=False,
                reason="multiple incompatible segment bases",
            )

        return SegmentLoweringDecision(
            segment_reg=segment_reg,
            classification=classification,
            associated_space=space,
            confidence=confidence,
            allow_linear_lowering=False,
            allow_object_lowering=False,
            reason="unknown association",
        )

    def lowering_summary(self) -> dict[str, dict[str, object]]:
        """Summarize conservative lowering decisions for observed segment registers."""
        summary: dict[str, dict[str, object]] = {}
        for segment_reg, assoc in self.associations.items():
            if assoc.evidence_count == 0:
                continue
            decision = self.lowering_decision(segment_reg)
            summary[segment_reg.name] = {
                "classification": decision.classification,
                "space": decision.associated_space,
                "confidence": decision.confidence,
                "allow_linear_lowering": decision.allow_linear_lowering,
                "allow_object_lowering": decision.allow_object_lowering,
                "reason": decision.reason,
            }
        return summary

    @staticmethod
    def _classification_stability(classification: str, evidence_count: int) -> float:
        base = min(1.0, 0.5 + (evidence_count * 0.05))
        if classification == "const":
            return min(1.0, base + 0.2)
        if classification == "single":
            return min(0.9, base)
        if classification == "over_associated":
            return max(0.2, min(0.45, base - 0.25))
        return max(0.1, min(0.35, base - 0.2))


def _can_lower_ss_address_to_stack_slot_8616(codegen: object, analyzer: SegmentAssociationAnalyzer | None) -> bool:
    """Decide SS stack-slot lowering from dynamic third-party angr codegen metadata."""

    def _impl() -> bool:
        """Read optional segment assignments at the dynamic angr codegen boundary."""
        assignments = list(
            cast(tuple[SegmentAssignment, ...], getattr(codegen, "_inertia_segment_assignments", ()) or ())
        )
        if not assignments or analyzer is None:
            typed_spaces, stable_spaces = _typed_ir_address_spaces_8616(codegen)
            if stable_spaces and "ss" not in stable_spaces and "ss" not in typed_spaces:
                return False
            # Dynamic codegen boundary: typed IR address-space diagnostics are optional metadata on angr codegen.
            typing.cast(typing.Any, codegen)._inertia_typed_ir_address_spaces = typed_spaces
            # Dynamic codegen boundary: stable typed IR address-space diagnostics are optional metadata on angr codegen.
            typing.cast(typing.Any, codegen)._inertia_typed_ir_stable_address_spaces = stable_spaces
            return True

        decision = analyzer.lowering_decision(SegmentRegister.SS)
        typed_spaces, stable_spaces = _typed_ir_address_spaces_8616(codegen)
        # Dynamic codegen boundary: typed IR address-space diagnostics are optional metadata on angr codegen.
        typing.cast(typing.Any, codegen)._inertia_typed_ir_address_spaces = typed_spaces
        # Dynamic codegen boundary: stable typed IR address-space diagnostics are optional metadata on angr codegen.
        typing.cast(typing.Any, codegen)._inertia_typed_ir_stable_address_spaces = stable_spaces
        if stable_spaces and "ss" not in stable_spaces and "ss" not in typed_spaces:
            return False
        return decision.associated_space == "stack" and decision.classification in {"single", "const"}

    return _impl()


def _existing_stack_cvar_for_offset_8616(codegen: object, offset: int) -> object | None:
    """Find an existing stack C variable through the dynamic third-party angr codegen boundary."""
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return None

    region = getattr(getattr(codegen, "cfunc", None), "addr", None)
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable):
            continue
        if _canonical_stack_offset_8616(variable.offset) != _canonical_stack_offset_8616(offset):
            continue
        variable_region = variable.region
        if isinstance(region, int) and isinstance(variable_region, int) and variable_region != region:
            continue
        return cast(object, cvar)
    return None


def _recover_stack_slot_from_segmented_operand_8616(node: object, codegen: object) -> object | None:
    """Recover an SS:BP stack slot through the dynamic third-party angr C-AST/codegen boundary."""

    def _impl() -> object | None:
        """Inspect optional C-AST/codegen attributes at the dynamic angr boundary."""
        codegen_dynamic = cast(Any, codegen)
        project = getattr(getattr(codegen, "project", None), "arch", None)
        if project is None:
            return None

        displacement = _match_bp_stack_dereference_8616(node, codegen_dynamic.project, codegen)
        if displacement is None:
            return None

        width_bits = getattr(getattr(node, "type", None), "size", None)
        width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
        region = getattr(getattr(codegen, "cfunc", None), "addr", None)
        facts = _stack_storage_facts_for_segmented_address_8616("ss", displacement, width, region=region)
        if facts is None or facts.identity is None:
            return None

        existing = _existing_stack_cvar_for_offset_8616(codegen, displacement)
        if existing is not None:
            requested_size = int(width or 1)
            existing_var = getattr(existing, "variable", None)
            if isinstance(existing_var, SimStackVariable):
                existing_size = getattr(existing_var, "size", None)
                if not isinstance(existing_size, int) or existing_size < requested_size:
                    existing_var.size = requested_size
            return existing

        name = _stack_object_name(displacement, codegen=codegen)
        stack_var = SimStackVariable(displacement, width or 1, base="bp", name=name, region=region)
        cvar = structured_c.CVariable(stack_var, variable_type=getattr(node, "type", None), codegen=codegen)

        variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use[stack_var] = cvar

        unified_locals = getattr(getattr(codegen, "cfunc", None), "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            unified_locals[stack_var] = {(cvar, getattr(cvar, "variable_type", None) or getattr(node, "type", None))}

        return cast(object, cvar)

    return _impl()


def _apply_ss_stack_slot_recovery_8616(codegen: object, analyzer: SegmentAssociationAnalyzer) -> bool:
    """Rewrite SS-segment dereferences to stack slots when the analyzer allows it."""
    if not _can_lower_ss_address_to_stack_slot_8616(codegen, analyzer):
        return False

    changed = False

    def transform(node: object) -> object:
        nonlocal changed
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        replacement = _recover_stack_slot_from_segmented_operand_8616(node, codegen)
        if replacement is not None:
            changed = True
            return replacement
        return node

    codegen_dynamic = cast(Any, codegen)
    root = getattr(codegen_dynamic.cfunc, "statements", None)
    if root is not None:
        new_root = transform(root)
        if new_root is not root:
            codegen_dynamic.cfunc.statements = new_root
            if hasattr(codegen_dynamic.cfunc, "body"):
                codegen_dynamic.cfunc.body = new_root
        if _replace_c_children_8616(codegen_dynamic.cfunc.statements, transform):
            changed = True
    return changed


def _apply_segmented_memory_reasoning_8616(codegen: object) -> bool:
    """Run the segmented-memory association pass; may raise (caller catches)."""
    # Dynamic codegen boundary: pass status is optional metadata on angr codegen.
    typing.cast(typing.Any, codegen)._inertia_segmented_memory_applied = True
    # Dynamic codegen boundary: pass counters are optional metadata on angr codegen.
    typing.cast(typing.Any, codegen)._inertia_segmented_memory_stats = {
        "segment_assignments": 0,
        "associations_built": 0,
        "far_pointers_detected": 0,
    }

    assignments = list(
        cast(tuple[SegmentAssignment, ...], getattr(codegen, "_inertia_segment_assignments", ()) or ())
    )
    analyzer = SegmentAssociationAnalyzer()
    if assignments:
        analyzer.analyze(assignments)
        summary = analyzer.summarize()
        lowering = analyzer.lowering_summary()
        _publish_segmented_memory_evidence_8616(codegen, summary, lowering)
        # Dynamic codegen boundary: analyzed segment counters are optional metadata on angr codegen.
        typing.cast(typing.Any, codegen)._inertia_segmented_memory_stats = {
            "segment_assignments": len(assignments),
            "associations_built": sum(
                len(summary[bucket]) for bucket in ("stable", "over_associated", "unknown")
            ),
            "far_pointers_detected": 0,
        }
    else:
        _publish_segmented_memory_evidence_8616(
            codegen,
            {
                "stable": {},
                "over_associated": {},
                "unknown": {},
            },
            {},
        )

    changed = False
    target = str(
        getattr(getattr(codegen, "project", None), "_inertia_c_target", "portable-flat") or "portable-flat"
    )
    project = getattr(codegen, "project", None)
    current_stage = str(getattr(project, "_inertia_decompiler_stage", "") or "")
    if current_stage.startswith("structuring:"):
        # Structuring must remain validation-stable. Defer all segmented-memory
        # AST rewrites to post-structuring layers.
        return False
    if lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project):
        changed = True
    if _apply_ss_stack_slot_recovery_8616(codegen, analyzer):
        changed = True

    # Keep structuring-time tail validation stable: defer runtime segment
    # helper call materialization outside structuring pass execution.  SS
    # stack recovery must run first so stack slots materialize as
    # variables instead of generic segmented runtime helper calls.
    if not current_stage.startswith("structuring:"):  # noqa: SIM102
        if apply_runtime_segment_lowering_8616(codegen, target=target):
            changed = True

    logger.debug("Segmented memory association reasoning pass completed")
    return changed


def apply_x86_16_segmented_memory_reasoning(codegen: object) -> bool:
    """Apply segmented memory association reasoning to an angr codegen object.

    This is the entry point for Phase 3 decompiler framework integration.

    Args:
        codegen: The decompiler codegen object

    Returns:
        True if significant segmented memory reasoning occurred, False otherwise

    Note:
        Phase 3 establishes conservative association reasoning before
        later phases attempt pointer lowering or object recovery.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    try:
        return _apply_segmented_memory_reasoning_8616(codegen)
    except Exception as ex:
        if os.environ.get("INERTIA_DEBUG_SEGMENTED_MEMORY") == "1":
            logger.exception("Segmented memory reasoning pass failed")
        else:
            logger.warning("Segmented memory reasoning pass failed: %s", ex)
        # Dynamic codegen boundary: preserve diagnostic failure reason on angr codegen.
        typing.cast(typing.Any, codegen)._inertia_segmented_memory_error = str(ex)
        return False


def _lower_stable_ss_stack_accesses_8616(codegen: object) -> bool:
    """Analysis-only postprocess pass: collect segment evidence, skip transformation.

    The actual SS stack lowering runs later in cli_decompilation.py rewrite passes
    so it is transparent to the postprocess tail validator.
    """
    return _apply_segmented_memory_analysis_only_8616(codegen)


def _apply_segmented_memory_analysis_only_8616(codegen: object) -> bool:
    """Run segment association analysis at the dynamic codegen boundary without transforming codegen."""
    if getattr(codegen, "cfunc", None) is None:
        return False
    try:
        # Dynamic codegen boundary: pass status is optional metadata on angr codegen.
        typing.cast(typing.Any, codegen)._inertia_segmented_memory_applied = True
        assignments = list(
            cast(tuple[SegmentAssignment, ...], getattr(codegen, "_inertia_segment_assignments", ()) or ())
        )
        analyzer = SegmentAssociationAnalyzer()
        if assignments:
            analyzer.analyze(assignments)
            summary = analyzer.summarize()
            lowering = analyzer.lowering_summary()
            _publish_segmented_memory_evidence_8616(codegen, summary, lowering)
            # Dynamic codegen boundary: analysis-only counters are optional metadata on angr codegen.
            typing.cast(typing.Any, codegen)._inertia_segmented_memory_stats = {
                "segment_assignments": len(assignments),
                "associations_built": sum(
                    len(summary.get(bucket, ())) for bucket in ("stable", "over_associated", "unknown")
                ),
                "far_pointers_detected": 0,
            }
        else:
            _publish_segmented_memory_evidence_8616(codegen, _empty_segment_summary_8616(), {})
        # Do NOT transform codegen — let cli_decompilation.py lowering handle that
        return False
    except Exception as ex:
        logger.warning("Segmented memory analysis-only pass failed: %s", ex)
        # Dynamic codegen boundary: preserve analysis-only failure reason on angr codegen.
        typing.cast(typing.Any, codegen)._inertia_segmented_memory_error = str(ex)
        return False


def _empty_segment_summary_8616() -> dict[str, dict[str, dict[str, object]]]:
    """Return the empty segmented-memory evidence summary shape."""
    return {"stable": {}, "over_associated": {}, "unknown": {}}
