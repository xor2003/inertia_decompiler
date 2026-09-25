"""Pre-rewrite invariant checks for semantic correctness.

Layer: Pipeline governance.
Responsibility: owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.

AGENTS rule: Rewrite must not hide bad alias/type/condition recovery.
If invariants fail, rewrite is skipped and honest partial output is emitted.

Forbidden: semantic recovery, type inference, condition reconstruction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

from ..c_ast_utils import _iter_c_nodes_deep_8616

__all__ = [
    "InvariantCheck",
    "InvariantReport",
    "InvariantStatus",
    "format_invariant_report_8616",
    "validate_before_rewrite_8616",
]


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic codegen/C-AST boundary: read optional third-party attributes."""
    return getattr(obj, name, default)


class InvariantStatus(Enum):
    """Structured result state for one pre-rewrite invariant check."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class InvariantCheck:
    """One invariant verdict plus compact evidence for diagnostics."""

    name: str
    status: InvariantStatus
    detail: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def is_blocking(self) -> bool:
        """Return whether this check must block rewrite."""
        return self.status == InvariantStatus.FAILED


@dataclass(slots=True)
class InvariantReport:
    """Aggregate pre-rewrite invariant status for one function."""

    function_addr: int = 0
    function_name: str = ""
    checks: list[InvariantCheck] = field(default_factory=list)
    rewrite_blocked: bool = False
    skip_reason: str = ""

    @property
    def all_passed(self) -> bool:
        """Return whether no failed invariant blocks rewrite."""
        return not self.rewrite_blocked and all(c.status != InvariantStatus.FAILED for c in self.checks)

    @property
    def failed_checks(self) -> list[InvariantCheck]:
        """Return checks that should block rewrite."""
        return [c for c in self.checks if c.is_blocking]

    def to_dict(self) -> dict[str, object]:
        """Serialize the report for JSON diagnostics."""
        return {
            "function_addr": self.function_addr,
            "function_name": self.function_name,
            "rewrite_blocked": self.rewrite_blocked,
            "skip_reason": self.skip_reason,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "detail": c.detail,
                    "evidence": list(c.evidence),
                }
                for c in self.checks
            ],
        }


def validate_before_rewrite_8616(
    codegen: object,
    *,
    c_text: str = "",
    project: object | None = None,
) -> InvariantReport:
    """Run pre-rewrite invariant checks against a function ready for rewrite.

    Checks:
        1. No linear ``(ss << 4)`` expressions surviving in generated C.
        2. No ``stack[...]`` indexing — all SS:BP offsets must be named variables.
        3. No ``if (tmp_*)`` conditions when typed ConditionIR is available.
        4. No ``if (flags & ...)`` raw flag conditions.
        5. No ``uncollected`` validation treated as success.
        6. All proven SS stack slots materialized as named variables.

    Returns InvariantReport.  If ``rewrite_blocked`` is True, the caller MUST skip
    rewrite/formatting and emit honest partial output.
    """
    report = InvariantReport()
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    if cfunc is not None:
        report.function_addr = _dynamic_attr_8616(cfunc, "addr", 0)
        report.function_name = _dynamic_attr_8616(cfunc, "name", "") or ""

    # Check 1: No linear SS expressions in output
    _check_no_ss_linear_expr(c_text, report)

    # Check 2: No stack[...] indexing
    _check_no_stack_indexing(c_text, report)

    # Check 3: No tmp-based conditions when typed IR exists
    _check_no_tmp_conditions(c_text, codegen, report)

    # Check 4: No raw flag conditions
    _check_no_raw_flag_conditions(c_text, report)

    # Check 5: Validation uncollected not treated as success
    _check_validation_not_uncollected(codegen, report)

    # Check 6: Proven stack slots materialized
    _check_stack_slots_materialized(codegen, report)

    # Check 7: Stack facts consumed (quantitative gate)
    _check_stack_facts_consumed(codegen, report)

    # Check 8: Condition facts consumed (quantitative gate)
    _check_condition_facts_consumed(codegen, report)

    # Check 9: Goto targets must resolve to emitted C labels
    _check_goto_targets_resolved(codegen, report)

    # Determine if rewrite should be blocked
    failed = report.failed_checks
    if failed:
        report.rewrite_blocked = True
        report.skip_reason = f"{len(failed)} invariant(s) failed: " + ", ".join(c.name for c in failed)

    return report


def format_invariant_report_8616(report: InvariantReport) -> str:
    """Format an invariant report for diagnostic output."""
    lines: list[str] = [
        f"Pre-rewrite invariant report ({report.function_name or hex(report.function_addr)})",
        "=" * 60,
    ]
    for c in report.checks:
        status_mark = "PASS" if c.status == InvariantStatus.PASSED else c.status.value.upper()
        lines.append(f"  [{status_mark:>8}] {c.name}")
        if c.detail:
            lines.append(f"           {c.detail}")
    if report.rewrite_blocked:
        lines.append("")
        lines.append(f"  REWRITE BLOCKED: {report.skip_reason}")
    else:
        lines.append("")
        lines.append("  All invariants passed — rewrite allowed.")
    return "\n".join(lines)


# ── individual check implementations ──


def _check_no_ss_linear_expr(c_text: str, report: InvariantReport) -> None:
    """Check: no ``(ss << 4)`` linear expressions in generated C."""
    import re

    pattern = re.compile(r"\(\s*ss\s*<<\s*4\s*\)", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []
    if matches:
        report.checks.append(
            InvariantCheck(
                name="no_ss_linear_expr",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} linear SS expressions in output",
                evidence=tuple(matches[:5]),
            )
        )
    else:
        report.checks.append(InvariantCheck(name="no_ss_linear_expr", status=InvariantStatus.PASSED))


def _check_no_stack_indexing(c_text: str, report: InvariantReport) -> None:
    """Check: no ``stack[...]`` syntax in output — all SS:BP mapped to named variables."""
    import re

    pattern = re.compile(r"stack\[", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []
    if matches:
        report.checks.append(
            InvariantCheck(
                name="no_stack_indexing",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} stack[...] indexings",
                evidence=tuple(matches[:5]),
            )
        )
    else:
        report.checks.append(InvariantCheck(name="no_stack_indexing", status=InvariantStatus.PASSED))


def _check_no_tmp_conditions(c_text: str, codegen: object, report: InvariantReport) -> None:
    """Check: no ``if (tmp_*)`` when typed ConditionIR is available."""
    import re

    pattern = re.compile(r"tmp_\d+", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []

    # Check if typed conditions exist in the function
    has_typed_conditions = bool(
        _dynamic_attr_8616(codegen, "_inertia_typed_conditions", None) or _dynamic_attr_8616(codegen, "_inertia_condition_facts", None)
    )

    if matches and has_typed_conditions:
        report.checks.append(
            InvariantCheck(
                name="no_tmp_conditions",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} tmp-based condition(s) despite available typed conditions",
                evidence=tuple(sorted(set(matches))[:5]),
            )
        )
    elif matches:
        report.checks.append(
            InvariantCheck(
                name="no_tmp_conditions",
                status=InvariantStatus.UNCERTAIN,
                detail=f"found {len(matches)} tmp-based condition(s) — no typed conditions available",
            )
        )
    else:
        report.checks.append(InvariantCheck(name="no_tmp_conditions", status=InvariantStatus.PASSED))


def _check_no_raw_flag_conditions(c_text: str, report: InvariantReport) -> None:
    """Check: no ``if (flags & ...)`` raw flag conditions."""
    import re

    pattern = re.compile(r"\b(flags|eflags)\s*&", re.IGNORECASE)
    matches = pattern.findall(c_text) if c_text else []
    if matches:
        report.checks.append(
            InvariantCheck(
                name="no_raw_flag_conditions",
                status=InvariantStatus.FAILED,
                detail=f"found {len(matches)} raw flag condition(s)",
                evidence=tuple(matches[:5]),
            )
        )
    else:
        report.checks.append(InvariantCheck(name="no_raw_flag_conditions", status=InvariantStatus.PASSED))


def _check_validation_not_uncollected(codegen: object, report: InvariantReport) -> None:
    """Check: uncollected validation is not treated as success."""
    validation_passed = bool(_dynamic_attr_8616(codegen, "_inertia_validation_passed", False))
    validation_uncollected = bool(_dynamic_attr_8616(codegen, "_inertia_validation_uncollected", False))
    validation_verdict = _dynamic_attr_8616(codegen, "_inertia_validation_verdict", None)

    if validation_uncollected and validation_passed:
        report.checks.append(
            InvariantCheck(
                name="validation_not_uncollected",
                status=InvariantStatus.FAILED,
                detail="uncollected treated as passed",
            )
        )
    elif validation_uncollected:
        report.checks.append(
            InvariantCheck(
                name="validation_not_uncollected",
                status=InvariantStatus.UNCERTAIN,
                detail=f"validation uncollected (verdict={validation_verdict})",
            )
        )
    else:
        report.checks.append(
            InvariantCheck(
                name="validation_not_uncollected",
                status=InvariantStatus.PASSED,
            )
        )


def _canonical_stack_offset_8616(offset: object) -> object:
    """Normalize a stack offset into the canonical negative-spill range."""
    if not isinstance(offset, int):
        return offset
    if 0x8000 <= offset <= 0xFFFF:
        return offset - 0x10000
    return offset


def _collect_unmaterialized_stack_slots_8616(
    codegen: object,
    semantic_alias_facts: object,
) -> list[str]:
    """Collect stack slots whose proven identities were never materialized."""
    from ..alias.alias_model_impl import AliasFailure, AliasStorageFacts, _StackSlotIdentity

    failures: list[str] = []
    provisional_count = 0
    for fact in semantic_alias_facts:
        if isinstance(fact, AliasFailure):
            # PROVISIONAL SS addresses (push/pop/call/ret traffic) are stack
            # activity, not stack variables.  Per AGENTS rule: stack activity
            # may exist while stack_facts = 0 — this is valid and must not be
            # treated as failure.
            if "provisional" in fact.reason.lower():
                provisional_count += 1
                continue
            failures.append(f"SS offset={fact.offset} reason={fact.reason}")
        elif isinstance(fact, AliasStorageFacts):
            if fact.identity and fact.identity[0] == "stack":
                # Stack slot identified — check if it's been materialized
                identity_val = fact.identity[1]
                if not isinstance(identity_val, _StackSlotIdentity):
                    failures.append(f"stack identity has invalid contract type: {type(identity_val).__name__}")
                    continue
                offset = _canonical_stack_offset_8616(identity_val.offset)
                if offset is not None:
                    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
                    variables = _dynamic_attr_8616(cfunc, "variables_in_use", {}) if cfunc else {}
                    # Check if any variable matches this offset
                    from angr.sim_variable import SimStackVariable

                    found = any(
                        isinstance(v, SimStackVariable)
                        and _canonical_stack_offset_8616(_dynamic_attr_8616(v, "offset", None)) == offset
                        for v in variables
                    )
                    if not found:
                        failures.append(
                            f"stack slot offset={offset} identified but not materialized in variables_in_use"
                        )
    return failures


def _check_stack_slots_materialized(codegen: object, report: InvariantReport) -> None:
    """Check: all proven SS stack slots have been materialized as named variables."""
    semantic_alias_facts = _dynamic_attr_8616(codegen, "_inertia_semantic_alias_facts", None)
    if not semantic_alias_facts:
        report.checks.append(
            InvariantCheck(
                name="stack_slots_materialized",
                status=InvariantStatus.SKIPPED,
                detail="no semantic alias facts available for verification",
            )
        )
        return

    failures = _collect_unmaterialized_stack_slots_8616(codegen, semantic_alias_facts)

    if failures:
        report.checks.append(
            InvariantCheck(
                name="stack_slots_materialized",
                status=InvariantStatus.FAILED,
                detail=f"{len(failures)} un-materialized stack slot(s)",
                evidence=tuple(failures[:5]),
            )
        )
    else:
        report.checks.append(InvariantCheck(name="stack_slots_materialized", status=InvariantStatus.PASSED))


def _check_stack_facts_consumed(codegen: object, report: InvariantReport) -> None:
    """Quantitative gate: if stack alias facts exist, at least one must be materialized.

    AGENTS rule: facts produced but not consumed is a pipeline failure.
    If stack_fact_count > 0 and stack_materialized_count == 0, block rewrite
    with a precise diagnostic indicating the next missing layer.
    """
    stack_facts = _dynamic_attr_8616(codegen, "_inertia_semantic_stack_fact_count", 0)
    materialized = _dynamic_attr_8616(codegen, "_inertia_semantic_stack_materialized_count", 0)

    if stack_facts == 0:
        report.checks.append(
            InvariantCheck(
                name="stack_facts_consumed",
                status=InvariantStatus.SKIPPED,
                detail="no stack alias facts produced — nothing to consume",
            )
        )
    elif stack_facts > 0 and materialized == 0:
        report.checks.append(
            InvariantCheck(
                name="stack_facts_consumed",
                status=InvariantStatus.FAILED,
                detail=f"stack_facts={stack_facts} but stack_materialized=0 — facts NOT consumed",
                evidence=(),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(
                name="stack_facts_consumed",
                status=InvariantStatus.PASSED,
                detail=f"stack_facts={stack_facts}, stack_materialized={materialized}",
            )
        )


def _check_condition_facts_consumed(codegen: object, report: InvariantReport) -> None:
    """Quantitative gate: if condition facts exist, at least one must be consumed.

    AGENTS rule: condition facts produced but no condition replacements applied
    means the materialization pass is missing.  Block rewrite so the problem
    is visible.
    """
    condition_facts = _dynamic_attr_8616(codegen, "_inertia_semantic_condition_fact_count", 0)
    materialized = _dynamic_attr_8616(codegen, "_inertia_semantic_condition_materialized_count", 0)

    if condition_facts == 0:
        report.checks.append(
            InvariantCheck(
                name="condition_facts_consumed",
                status=InvariantStatus.SKIPPED,
                detail="no condition facts produced — nothing to consume",
            )
        )
    elif condition_facts > 0 and materialized == 0:
        report.checks.append(
            InvariantCheck(
                name="condition_facts_consumed",
                status=InvariantStatus.FAILED,
                detail=(f"condition_facts={condition_facts} but condition_materialized=0 — facts NOT consumed"),
                evidence=(),
            )
        )
    else:
        report.checks.append(
            InvariantCheck(
                name="condition_facts_consumed",
                status=InvariantStatus.PASSED,
                detail=f"condition_facts={condition_facts}, condition_materialized={materialized}",
            )
        )


def _mapped_goto_label_8616(
    map_addr_to_label: object,
    target: int,
    target_idx: object,
) -> object | None:
    """Return the mapped label for one goto target, or None."""
    if not isinstance(map_addr_to_label, dict):
        return None
    mapped_label = map_addr_to_label.get((target, target_idx))
    if mapped_label is None and target_idx is not None:
        mapped_label = map_addr_to_label.get((target, None))
    return mapped_label


def _collect_unresolved_goto_targets_8616(
    root: object,
    cfunc: object,
    defined_labels: set[str],
    defined_all: set[str],
    map_addr_to_label: object,
) -> list[str]:
    """Collect goto targets with no emitted label."""
    from angr.analyses.decompiler.structured_codegen.c import CGoto

    unresolved: list[str] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CGoto):
            continue
        target = _dynamic_attr_8616(node, "target", None)
        target_idx = _dynamic_attr_8616(node, "target_idx", None)
        if not isinstance(target, int):
            continue

        mapped_label = _mapped_goto_label_8616(map_addr_to_label, target, target_idx)
        mapped_name = None
        if mapped_label is not None:
            mapped_name = _dynamic_attr_8616(mapped_label, "name", None)
        if mapped_name is None:
            mapped_name = _format_legacy_goto_label_name_8616(target)

        if mapped_name not in defined_all:
            unresolved.append(f"{mapped_name} (target={target:#x}, idx={target_idx})")
            continue

        # Mapping exists but label node may be missing from emitted statements.
        if mapped_label is not None:
            mapped_node_name = _dynamic_attr_8616(mapped_label, "name", None)
            if isinstance(mapped_node_name, str) and mapped_node_name not in defined_labels:
                unresolved.append(f"{mapped_node_name} (mapped-only, target={target:#x}, idx={target_idx})")
    return unresolved


def _check_goto_targets_resolved(codegen: object, report: InvariantReport) -> None:
    """Check: every CGoto target resolves to an emitted C label."""
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    root = _find_cfunc_root_8616(cfunc)
    if root is None:
        report.checks.append(
            InvariantCheck(
                name="goto_targets_resolved",
                status=InvariantStatus.SKIPPED,
                detail="no cfunc body available for goto-target validation",
            )
        )
        return

    defined_labels = _collect_cfunc_label_names_8616(root)
    mapped_labels = _collect_cfunc_map_addr_label_names_8616(cfunc)
    defined_all = defined_labels | set(mapped_labels)
    map_addr_to_label = _dynamic_attr_8616(cfunc, "map_addr_to_label", None) if cfunc is not None else None

    unresolved = _collect_unresolved_goto_targets_8616(
        root, cfunc, defined_labels, defined_all, map_addr_to_label,
    )

    if unresolved:
        report.checks.append(
            InvariantCheck(
                name="goto_targets_resolved",
                status=InvariantStatus.FAILED,
                detail=f"{len(unresolved)} unresolved goto target(s)",
                evidence=tuple(unresolved[:5]),
            )
        )
    else:
        report.checks.append(InvariantCheck(name="goto_targets_resolved", status=InvariantStatus.PASSED))


def _find_cfunc_root_8616(cfunc: object) -> object | None:
    """Return the first known C function body/root field."""
    if cfunc is None:
        return None
    for attr in ("body", "statements", "stmt"):
        value = _dynamic_attr_8616(cfunc, attr, None)
        if value is not None:
            return cast(object | None, value)
    return None


def _collect_cfunc_label_names_8616(root: object) -> set[str]:
    """Collect explicit CLabel names from an AST subtree."""
    from angr.analyses.decompiler.structured_codegen.c import CLabel

    labels: set[str] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CLabel):
            name = _dynamic_attr_8616(node, "name", None)
            if isinstance(name, str) and name:
                labels.add(name)
    return labels


def _collect_cfunc_map_addr_label_names_8616(codegen: object) -> list[str]:
    """Collect label names from codegen address-to-label maps."""
    mapping = _dynamic_attr_8616(codegen, "map_addr_to_label", None) if codegen is not None else None
    if not isinstance(mapping, dict):
        return []
    names: list[str] = []
    for node in mapping.values():
        name = _dynamic_attr_8616(node, "name", None)
        if isinstance(name, str) and name:
            names.append(name)
    return names


def _format_legacy_goto_label_name_8616(target: int) -> str:
    return f"LABEL_{target:#x}"


def classify_stack_blocker_8616(diag: dict[str, int]) -> str | None:
    """Classify stack-materialization blockers from diagnostics.

    Returns a human-readable blocker label, or None if no hard blocker is found.
    This is the canonical blocker taxonomy for stack lowering.
    """
    if diag.get("ss_stack_accesses", 0) > 0 and diag.get("stack_facts", 0) == 0:  # noqa: SIM102
        if diag.get("bp_stable_accesses", 0) == 0:
            return "stack activity detected but no stable frame"

    if diag.get("stack_facts", 0) > 0 and diag.get("stack_materialized", 0) == 0:
        return "stack facts not materialized"

    return None
